package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	store      *Store
	logs       *Ring
	audit      *AuditLog
	trip       *Tripwire
	limiter    *RateLimiter
	alerter    *Alerter
	schemas    *SchemaStore
	stats      *Stats
	trustProxy bool
	adminToken string
	maxBody    int64
	client     *http.Client
	startedAt  time.Time
	adminHTML  []byte

	// Admin-plane denials are audited coalesced: one record opens a
	// window, repeats inside it are counted and reported when the next
	// denial closes it. Uncoalesced, a flood of bad admin tokens would
	// grow the trail (and fsync) once per probe.
	adminDeniedMu    sync.Mutex
	adminDeniedUntil time.Time
	adminDeniedHeld  int
}

func NewServer(store *Store, logs *Ring, adminToken string, maxBody int64, adminHTML []byte) *Server {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 0, // governed by per-request context
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Server{
		store:      store,
		logs:       logs,
		limiter:    NewRateLimiter(),
		schemas:    NewSchemaStore(),
		stats:      NewStats(),
		adminToken: adminToken,
		maxBody:    maxBody,
		startedAt:  time.Now(),
		adminHTML:  adminHTML,
		client: &http.Client{
			Transport: transport,
			// Never follow redirects on forwarded requests; hand the 3xx
			// back to the caller instead of replaying the request.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Data plane. Every method reaches the handler: which ones a side may use
	// is that side's setting, so the 405 is answered there, once the account
	// is known.
	mux.HandleFunc("/t/{id}/{dir}", s.handleIngest)

	// Control plane.
	mux.HandleFunc("GET /api/admin/accounts", s.admin(s.handleAccountsList))
	mux.HandleFunc("POST /api/admin/accounts", s.admin(s.handleAccountCreate))
	mux.HandleFunc("GET /api/admin/accounts/{id}", s.admin(s.handleAccountGet))
	mux.HandleFunc("PUT /api/admin/accounts/{id}", s.admin(s.handleAccountUpdate))
	mux.HandleFunc("DELETE /api/admin/accounts/{id}", s.admin(s.handleAccountDelete))
	mux.HandleFunc("POST /api/admin/accounts/{id}/rotate", s.admin(s.handleRotate))
	mux.HandleFunc("POST /api/admin/accounts/{id}/test", s.admin(s.handleTest))
	mux.HandleFunc("GET /api/admin/accounts/{id}/discover", s.admin(s.handleDiscoverStatus))
	mux.HandleFunc("POST /api/admin/accounts/{id}/discover", s.admin(s.handleDiscoverSet))
	mux.HandleFunc("DELETE /api/admin/accounts/{id}/discover", s.admin(s.handleDiscoverReset))
	mux.HandleFunc("POST /api/admin/accounts/{id}/tripwire/reset", s.admin(s.handleTripwireReset))
	mux.HandleFunc("GET /api/admin/tripwire", s.admin(s.handleTripwireStatus))
	mux.HandleFunc("GET /api/admin/logs", s.admin(s.handleLogs))
	mux.HandleFunc("GET /api/admin/stats", s.admin(s.handleStats))

	// UI + health.
	mux.HandleFunc("GET /admin/", s.handleAdminUI)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})

	// Wrong-method and unknown-route fallbacks. ServeMux answers both
	// with plain text by default, which would be the only two responses
	// in the whole API that are not the documented JSON envelope.
	mux.HandleFunc("/api/admin/accounts", methodNotAllowed("GET", "POST"))
	mux.HandleFunc("/api/admin/accounts/{id}", methodNotAllowed("GET", "PUT", "DELETE"))
	mux.HandleFunc("/api/admin/accounts/{id}/rotate", methodNotAllowed("POST"))
	mux.HandleFunc("/api/admin/accounts/{id}/test", methodNotAllowed("POST"))
	mux.HandleFunc("/api/admin/accounts/{id}/discover", methodNotAllowed("GET", "POST", "DELETE"))
	mux.HandleFunc("/api/admin/accounts/{id}/tripwire/reset", methodNotAllowed("POST"))
	mux.HandleFunc("/api/admin/tripwire", methodNotAllowed("GET"))
	mux.HandleFunc("/api/admin/logs", methodNotAllowed("GET"))
	mux.HandleFunc("/api/admin/stats", methodNotAllowed("GET"))
	mux.HandleFunc("/admin/", methodNotAllowed("GET"))
	mux.HandleFunc("/healthz", methodNotAllowed("GET"))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		jsonErrorCode(w, http.StatusNotFound, "not_found", "no such route")
	})

	return s.recovered(mux)
}

// methodNotAllowed answers 405 with an Allow header and the standard
// error envelope.
func methodNotAllowed(allowed ...string) http.HandlerFunc {
	allow := strings.Join(allowed, ", ")
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		jsonErrorCode(w, http.StatusMethodNotAllowed, "method_not_allowed",
			"method not allowed; try "+allow)
	}
}

// recovered converts handler panics into a clean 500 instead of a dropped
// connection. The stack goes to the server log and an audit record only —
// never to the wire.
func (s *Server) recovered(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				path := safeLogValue(r.URL.Path, 200)
				log.Printf("panic serving %s %s: %v\n%s", safeLogValue(r.Method, 16), path, rec, debug.Stack())
				s.auditEmit("system", "server.panic", map[string]any{
					"method": safeLogValue(r.Method, 16), "path": path, "panic": fmt.Sprint(rec),
				})
				jsonErrorCode(w, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// auditEmit shields the data plane from audit I/O failures: they are
// loud in the server log but never fail a request.
func (s *Server) auditEmit(actor, event string, detail map[string]any) {
	if err := s.audit.Emit(actor, event, detail); err != nil {
		log.Printf("AUDIT WRITE FAILED (%s): %v", event, err)
	}
}

// auditRejected records an admin mutation that was refused, and answers
// the caller. Successful mutations were already audited; refused ones
// left no trace anywhere, so a client looping on a typo'd field was
// invisible server-side.
//
// Only field NAMES are recorded. An unknown field can carry a
// credential — "inbound_tokenn" with a real token in it is exactly the
// mistake this catches — so the value never reaches the log or the
// trail. Names are sanitised and bounded by FieldNames.
func (s *Server) auditRejected(w http.ResponseWriter, r *http.Request, account string, err error) {
	var ve ValidationErrors
	if !errors.As(err, &ve) {
		ve = ValidationErrors{{Message: err.Error(), kind: kindBadRequest}}
	}
	var (
		reason = ve.Kind()
		fields = ve.FieldNames()
		ip     = s.clientIP(r)
		path   = safeLogValue(r.URL.Path, 256)
		method = safeLogValue(r.Method, 16)
	)
	log.Printf("admin %s %s rejected from %s: %s %v", method, path, ip, reason, fields)
	s.auditEmit("admin", "account.rejected", map[string]any{
		"account": safeLogValue(account, 64),
		"method":  method,
		"path":    path,
		"ip":      ip,
		"reason":  reason,
		"fields":  fields,
	})
	writeValidationError(w, err)
}

// ---------------------------------------------------------------------------
// Data plane

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := r.PathValue("id")
	dirStr := r.PathValue("dir")

	entry := LogEntry{Time: start.UTC(), Account: id, Direction: dirStr, Method: safeLogValue(r.Method, 16)}
	defer func() {
		entry.LatencyMs = time.Since(start).Milliseconds()
		s.logs.Add(entry)
		s.stats.Record(entry)
	}()

	ip := s.clientIP(r)
	fail := func(status int, code, msg string) {
		entry.Status = status
		if status >= 500 || status == http.StatusUnauthorized {
			entry.Err = msg
		}
		jsonErrorCode(w, status, code, msg)
	}

	dir, ok := ParseDirection(dirStr)
	if !ok {
		fail(http.StatusNotFound, "bad_direction", "direction must be a2b or b2a")
		return
	}
	acct, ok := s.store.Get(id)
	if !ok {
		fail(http.StatusNotFound, "not_found", "unknown account")
		return
	}
	entry.AccountKnown = true

	from, to := acct.A, acct.B
	if dir == BtoA {
		from, to = acct.B, acct.A
	}
	// A method this side may not send is refused before the tripwire gate and
	// before authentication, which is where a wrong method has always been
	// refused. It is no credential guess, so it must not feed the tripwire, and
	// it must cost nothing: no audit record, no rate-limit token.
	method, known := dataMethod(r.Method)
	if !known || !from.allows(method) {
		allow := strings.Join(from.methodList(), ", ")
		w.Header().Set("Allow", allow)
		fail(http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed; try "+allow)
		return
	}

	// Tripwire gate sits in front of authentication: while locked, the
	// endpoint answers 429 to every caller, valid credentials included.
	// That is the point of a lockout — during an active credential-
	// guessing burst the safe state is closed.
	if locked, rem := s.trip.Gate(id); locked {
		w.Header().Set("Retry-After", strconv.Itoa(int(rem.Seconds())+1))
		entry.Status = http.StatusTooManyRequests
		entry.Err = "tripwire locked"
		s.auditEmit("account:"+id, "ingest.blocked", map[string]any{
			"account": id, "dir": dirStr, "method": method, "ip": ip, "unlock_in_sec": int(rem.Seconds()) + 1,
		})
		jsonErrorCode(w, http.StatusTooManyRequests, "account_locked", "account temporarily locked")
		return
	}

	if from.InboundToken == "" || !tokenEqual(bearerFrom(r), from.InboundToken) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="xlate"`)
		fail(http.StatusUnauthorized, "auth_invalid", "invalid token")
		s.auditEmit("account:"+id, "ingest.denied", map[string]any{
			"account": id, "dir": dirStr, "method": method, "ip": ip,
		})
		if info := s.trip.RecordDenied(id, ip); info != nil {
			s.onTrip(info)
		}
		return
	}
	if !acct.Enabled {
		fail(http.StatusForbidden, "account_disabled", "account disabled")
		s.auditEmit("account:"+id, "ingest.denied", map[string]any{
			"account": id, "dir": dirStr, "method": method, "ip": ip, "reason": "disabled",
		})
		return
	}
	// The rate limit comes after authentication on purpose: account ids are
	// not secrets, so metering anonymous traffic would let anyone who has
	// read one spend the partner's allowance. Floods without credentials are
	// the tripwire's business. It also comes before the body is read, so a
	// refused request costs almost nothing.
	if refusal := s.limiter.Allow(id, dir, acct.RateLimitPerMin); refusal != nil {
		secs := int(refusal.RetryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		entry.Status = http.StatusTooManyRequests
		entry.Err = "rate limited"
		entry.RateLimited = true
		if refusal.Report {
			s.auditEmit("account:"+id, "ingest.limited", map[string]any{
				"account": id, "dir": dirStr, "method": method, "ip": ip,
				"limit_per_min": acct.RateLimitPerMin, "refused": refusal.Suppressed,
			})
		}
		jsonErrorCode(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
		return
	}
	// Correlation headers are forwarded verbatim to the destination and
	// the caller is the opposite party, not an operator: refuse values
	// that could not legally be written into an outbound header.
	if err := validateCorrelationHeaders(r); err != nil {
		entry.Status = http.StatusBadRequest
		writeValidationError(w, err)
		return
	}

	body, err := readLimited(w, r, s.maxBody)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(http.StatusRequestEntityTooLarge, "payload_too_large", fmt.Sprintf("body exceeds %d bytes", s.maxBody))
		} else {
			fail(http.StatusBadRequest, "bad_body", "could not read body")
		}
		return
	}

	// POST, PUT and PATCH carry a JSON object, or an array where a row of the
	// map addresses one ("[].sku"). GET and DELETE carry no body, so their input
	// is the query string, translated as the same kind of object.
	// The query of a POST, PUT or PATCH is not read, as it never has been.
	var payload map[string]any
	query := !methodHasBody(method)
	if query {
		if len(body) > 0 {
			entry.Status = http.StatusBadRequest
			writeValidationError(w, ValidationErrors{{Field: "body",
				Message: method + " carries no body; send the parameters in the query string"}})
			return
		}
		entry.ReqBytes = len(r.URL.RawQuery)
		if payload, err = queryPayload(r.URL.RawQuery); err != nil {
			entry.Status = http.StatusBadRequest
			writeValidationError(w, err)
			return
		}
	} else {
		entry.ReqBytes = len(body)
		rooted := addressesRoot(acct.Map, dir)
		if payload, err = decodeBody(body, rooted); err != nil {
			msg := "body must be a single JSON object"
			if rooted {
				msg = "body must be a single JSON object or array"
			}
			fail(http.StatusBadRequest, "bad_json", msg)
			return
		}
	}

	// Record the payload's shape while onboarding. This runs before
	// Translate, which mutates the payload in place, and before the
	// no_target check below — the whole point is to learn a partner's
	// vocabulary from the requests they send while the account is still
	// half-wired. Paths and types only; never a value.
	if acct.discovering() {
		entry.Fields = s.schemas.Observe(acct.ID, dir, payload)
	}

	// Checked after decoding so an unwired account still yields its
	// schema to discovery. A request that cannot be forwarded is still a
	// request you can learn the field names from.
	if to.TargetURL == "" {
		fail(http.StatusBadGateway, "no_target", "destination side has no target_url configured")
		return
	}

	// A query carries filters and selectors. One that fails to convert and
	// travels on raw can be ignored by the destination, which widens what a GET
	// returns or a DELETE removes, so a query is always strict.
	tres := Translate(payload, acct.Map, dir, TranslateOptions{DropUnmapped: acct.DropUnmapped, Strict: acct.StrictTransforms || query})
	entry.Applied = tres.Applied
	entry.Warnings = tres.Warned
	if len(tres.Refused) > 0 {
		// An array the map addresses cannot be translated as mapped: too long,
		// not an array, or holding something that is not an object. Strict or
		// not, nothing is forwarded, because passing it on would show the
		// destination the sender's own field names. The sender is told which
		// of its own paths and why, never a value.
		refused := boundedRefusals(tres.Refused)
		entry.Status = http.StatusUnprocessableEntity
		entry.Err = "array refused"
		s.auditEmit("account:"+id, "ingest.rejected", map[string]any{
			"account": id, "dir": dirStr, "method": method, "ip": ip, "reason": "array", "fields": refusalPaths(refused),
		})
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":  "one or more arrays could not be translated as mapped",
			"code":   "array_invalid",
			"fields": refused,
		})
		return
	}
	if len(tres.Failed) > 0 {
		// Strict mode: nothing is forwarded. The sender is told which of its
		// own fields could not be converted. Never the destination's names
		// and never a value; the trail gets names only, like every record.
		entry.Status = http.StatusUnprocessableEntity
		entry.Err = "strict: transform refused"
		s.auditEmit("account:"+id, "ingest.rejected", map[string]any{
			"account": id, "dir": dirStr, "method": method, "ip": ip, "reason": "transform", "fields": boundedPaths(tres.Failed),
		})
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":  "one or more fields could not be converted to the destination's format",
			"code":   "transform_failed",
			"fields": transformFieldErrors(tres.Failed),
		})
		return
	}

	// A bodied method forwards the translated object. GET and DELETE forward
	// it as query parameters appended to the target's own. Scheme, host and
	// path are always the operator's: the caller adds encoded parameters and
	// nothing else.
	var (
		target  = to.TargetURL
		outBody io.Reader
	)
	if query {
		vals, err := queryValues(tres.Out)
		if err != nil {
			fail(http.StatusInternalServerError, "internal", "could not encode translated query")
			return
		}
		if target, err = withQuery(to.TargetURL, vals); errors.Is(err, errQueryClash) {
			entry.Status = http.StatusBadRequest
			writeValidationError(w, ValidationErrors{{Field: "query", Message: "contains a parameter that cannot be forwarded"}})
			return
		} else if err != nil {
			fail(http.StatusBadGateway, "bad_target", "invalid destination target_url")
			return
		}
	} else {
		b, err := json.Marshal(bodyOf(tres.Out))
		if err != nil {
			fail(http.StatusInternalServerError, "internal", "could not encode translated payload")
			return
		}
		outBody = bytes.NewReader(b)
	}

	ctx, cancel := context.WithTimeout(r.Context(), acct.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target, outBody)
	if err != nil {
		fail(http.StatusBadGateway, "bad_target", "invalid destination target_url")
		return
	}
	if outBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "xlate/"+version)
	if to.OutboundToken != "" {
		req.Header.Set("Authorization", "Bearer "+to.OutboundToken)
	}
	// Correlation headers pass through untouched (validated above).
	for _, h := range correlationHeaders {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// Detail goes to activity/audit logs only; the caller is the
		// opposite party and does not need our internal topology.
		// net/http embeds the request URL in the error, and target URLs
		// can carry a credential in the query; redact before it is stored.
		redacted := truncate(redactTargetErr(err, to.TargetURL), 240)
		entry.Status = http.StatusBadGateway
		entry.Err = redacted
		s.auditEmit("account:"+id, "ingest.error", map[string]any{
			"account": id, "dir": dirStr, "method": method, "kind": classifyNetErr(err), "err": redacted,
		})
		jsonErrorCode(w, http.StatusBadGateway, "upstream_failed", "upstream request failed")
		return
	}
	defer resp.Body.Close()
	entry.Upstream = resp.StatusCode

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBody+1))
	if err != nil {
		fail(http.StatusBadGateway, "upstream_read", "error reading upstream response")
		return
	}
	if int64(len(respBody)) > s.maxBody {
		fail(http.StatusBadGateway, "upstream_oversize", "upstream response too large")
		return
	}
	entry.RespBytes = len(respBody)

	// Reverse-map JSON object responses so the caller reads its own
	// vocabulary on the return leg. Anything else passes through raw.
	ct := resp.Header.Get("Content-Type")
	outResp := respBody
	if strings.Contains(ct, "json") && len(respBody) > 0 {
		if rm, err := decodeBody(respBody, addressesRoot(acct.Map, dir.Reverse())); err == nil {
			rr := Translate(rm, acct.Map, dir.Reverse(), TranslateOptions{Strict: acct.StrictTransforms})
			if len(rr.Failed) > 0 || len(rr.Refused) > 0 {
				// The destination has already acted on the request, so this
				// cannot undo it. It keeps a value in the wrong
				// representation, or an array in the destination's own field
				// names, from reaching the caller, who is told the response
				// was unusable, in no vocabulary but its own.
				reason, fields, why := "response_transform", boundedPaths(rr.Failed), "strict: response transform refused"
				if len(rr.Refused) > 0 {
					reason, fields, why = "response_array", refusalPaths(boundedRefusals(rr.Refused)), "array: response refused"
				}
				entry.Status = http.StatusBadGateway
				entry.Err = why
				entry.Warnings += rr.Warned
				s.auditEmit("account:"+id, "ingest.rejected", map[string]any{
					"account": id, "dir": dirStr, "method": method, "ip": ip, "reason": reason,
					"upstream": resp.StatusCode, "fields": fields,
				})
				jsonErrorCode(w, http.StatusBadGateway, "upstream_invalid", "upstream response could not be converted")
				return
			}
			if b, err := json.Marshal(bodyOf(rr.Out)); err == nil {
				outResp = b
				entry.Applied += rr.Applied
				// Return-leg warnings count too. Dropping them made a
				// permanently broken response format invisible: the value
				// failed open on every request and nothing said so.
				entry.Warnings += rr.Warned
			}
		}
	}

	if ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	// A relayed redirect must keep its Location or the caller gets a bare
	// 3xx it cannot act on (the redirect body names the target anyway, so
	// stripping the header hid nothing). Retry-After likewise carries the
	// actionable half of a relayed 429/503.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			w.Header().Set("Location", loc)
		}
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		w.Header().Set("Retry-After", ra)
	}
	w.Header().Set("X-Xlate-Applied", strconv.Itoa(entry.Applied))
	if entry.Warnings > 0 {
		w.Header().Set("X-Xlate-Warnings", strconv.Itoa(entry.Warnings))
	}
	entry.Status = resp.StatusCode
	s.auditEmit("account:"+id, "ingest.ok", map[string]any{
		"account": id, "dir": dirStr, "method": method, "upstream": resp.StatusCode,
		"req_bytes": entry.ReqBytes, "resp_bytes": entry.RespBytes,
		"applied": entry.Applied, "warnings": entry.Warnings,
	})
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(outResp)
}

// onTrip runs the tripwire procedure: audit first (fsynced), then alert,
// then the configured containment action. Ordering is deliberate — the
// forensic record must exist before anything that can fail or block.
func (s *Server) onTrip(info *TripInfo) {
	action := s.trip.Mode
	s.auditEmit("system", "tripwire.trip", map[string]any{
		"account": info.Account, "count": info.Count, "window_sec": int(s.trip.Window.Seconds()),
		"mode": action, "top_ips": info.TopIPs, "trip_number": info.Trips,
		"first_at": info.FirstAt.UTC().Format(time.RFC3339), "last_at": info.LastAt.UTC().Format(time.RFC3339),
	})
	s.logs.Add(LogEntry{
		Time: time.Now().UTC(), Account: info.Account, Direction: "trip",
		Status: http.StatusTooManyRequests,
		Err:    fmt.Sprintf("tripwire: %d refused attempts in %s (mode %s)", info.Count, s.trip.Window, action),
	})
	if action == "freeze" {
		// Only the flag is written. The request's copy of the account
		// predates its own fsyncs and any admin rotate or edit since.
		if err := s.store.SetEnabled(info.Account, false); err != nil {
			log.Printf("tripwire freeze failed for %s: %v", info.Account, err)
			s.auditEmit("system", "tripwire.freeze_failed", map[string]any{"account": info.Account, "err": err.Error()})
		} else {
			s.auditEmit("system", "account.frozen", map[string]any{"account": info.Account, "by": "tripwire"})
		}
	}
	s.alerter.Send(map[string]any{
		"event":        "tripwire",
		"instance":     "xlate/" + version,
		"ts":           time.Now().UTC().Format(time.RFC3339),
		"account":      info.Account,
		"count":        info.Count,
		"window_sec":   int(s.trip.Window.Seconds()),
		"mode":         action,
		"action_taken": map[string]string{"lock": "ingest locked", "freeze": "account disabled", "alert": "none"}[action],
		"lock_sec":     int(s.trip.LockFor.Seconds()),
		"first_at":     info.FirstAt.UTC().Format(time.RFC3339),
		"last_at":      info.LastAt.UTC().Format(time.RFC3339),
		"top_ips":      info.TopIPs,
		"trip_number":  info.Trips,
	})
}

// ---------------------------------------------------------------------------
// Control plane

func (s *Server) handleAccountsList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.List())
}

func (s *Server) handleAccountCreate(w http.ResponseWriter, r *http.Request) {
	var in accountInput
	if err := decodeStrict(w, r, &in); err != nil {
		s.auditRejected(w, r, "", err)
		return
	}
	out, err := s.store.Create(&in)
	if err != nil {
		if isRejection(err) {
			s.auditRejected(w, r, in.ID, err)
			return
		}
		writeStoreError(w, err)
		return
	}
	s.auditEmit("admin", "account.create", map[string]any{
		"account": out.ID, "name": out.Name, "enabled": out.Enabled, "map_size": len(out.Map),
		"a_methods": out.A.methodList(), "b_methods": out.B.methodList(),
	})
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleTripwireReset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.store.Get(id); !ok {
		jsonError(w, http.StatusNotFound, "account not found")
		return
	}
	s.trip.Reset(id)
	s.auditEmit("admin", "tripwire.reset", map[string]any{"account": id})
	writeJSON(w, http.StatusOK, map[string]any{"account": id, "tripwire": s.trip.Status(id)})
}

// handleTripwireStatus returns state for every account in one call so
// the UI can badge the table without N round trips.
func (s *Server) handleTripwireStatus(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{}
	for _, a := range s.store.List() {
		out[a.ID] = s.trip.Status(a.ID)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAccountGet(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		jsonError(w, http.StatusNotFound, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

func (s *Server) handleAccountUpdate(w http.ResponseWriter, r *http.Request) {
	var in accountInput
	if err := decodeStrict(w, r, &in); err != nil {
		s.auditRejected(w, r, r.PathValue("id"), err)
		return
	}
	in.ID = r.PathValue("id") // path is authoritative; IDs are immutable
	out, err := s.store.Update(&in)
	if err != nil {
		if isRejection(err) {
			s.auditRejected(w, r, in.ID, err)
			return
		}
		writeStoreError(w, err)
		return
	}
	s.auditEmit("admin", "account.update", map[string]any{
		"account": out.ID, "name": out.Name, "enabled": out.Enabled, "map_size": len(out.Map),
		"a_methods": out.A.methodList(), "b_methods": out.B.methodList(),
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.Delete(id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.trip.Reset(id)
	s.limiter.Forget(id)
	s.schemas.Forget(id)
	s.stats.Forget(id)
	s.auditEmit("admin", "account.delete", map[string]any{"account": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Side string `json:"side"`
		Kind string `json:"kind"`
	}
	if err := decodeStrict(w, r, &in); err != nil {
		s.auditRejected(w, r, r.PathValue("id"), err)
		return
	}
	var ve ValidationErrors
	if in.Side != "a" && in.Side != "b" {
		ve.add("side", `must be "a" or "b"`)
	}
	if in.Kind != "inbound" && in.Kind != "outbound" {
		ve.add("kind", `must be "inbound" or "outbound"`)
	}
	if len(ve) > 0 {
		s.auditRejected(w, r, r.PathValue("id"), ve)
		return
	}
	tok, err := s.store.Rotate(r.PathValue("id"), in.Side, in.Kind)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// The slot is auditable; the value is a credential and never is.
	s.auditEmit("admin", "account.rotate", map[string]any{
		"account": r.PathValue("id"), "side": in.Side, "kind": in.Kind,
	})
	writeJSON(w, http.StatusOK, map[string]string{"token": tok, "side": in.Side, "kind": in.Kind})
}

// handleDiscoverStatus returns what has been learned about a partner's
// vocabulary, per direction, plus starter mapping rows.
func (s *Server) handleDiscoverStatus(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		jsonError(w, http.StatusNotFound, "account not found")
		return
	}
	a2b := s.schemas.Report(acct.ID, AtoB)
	b2a := s.schemas.Report(acct.ID, BtoA)
	out := map[string]any{
		"account":  acct.ID,
		"active":   acct.discovering(),
		"a2b":      a2b,
		"b2a":      b2a,
		"suggest":  map[string]any{"a2b": suggestPairs(a2b, AtoB), "b2a": suggestPairs(b2a, BtoA)},
		"captures": "paths and JSON types only; values are never recorded",
	}
	if acct.DiscoverUntil != nil {
		out["until"] = acct.DiscoverUntil.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDiscoverSet opens or closes a discovery window. Switching it off
// also forgets everything observed, so the data does not linger.
func (s *Server) handleDiscoverSet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Minutes *int `json:"minutes"`
	}
	if err := decodeStrict(w, r, &in); err != nil {
		s.auditRejected(w, r, r.PathValue("id"), err)
		return
	}
	if in.Minutes == nil {
		var ve ValidationErrors
		ve.add("minutes", "is required (0 turns discovery off)")
		s.auditRejected(w, r, r.PathValue("id"), ve)
		return
	}
	maxMinutes := int(maxDiscoverWindow / time.Minute)
	if *in.Minutes < 0 || *in.Minutes > maxMinutes {
		var ve ValidationErrors
		ve.add("minutes", "must be between 0 and %d", maxMinutes)
		s.auditRejected(w, r, r.PathValue("id"), ve)
		return
	}

	id := r.PathValue("id")
	acct, ok := s.store.Get(id)
	if !ok {
		jsonError(w, http.StatusNotFound, "account not found")
		return
	}
	updated := acct.clone()
	if *in.Minutes == 0 {
		updated.DiscoverUntil = nil
	} else {
		until := time.Now().UTC().Add(time.Duration(*in.Minutes) * time.Minute)
		updated.DiscoverUntil = &until
	}
	enabled := updated.Enabled
	out, err := s.store.Update(&accountInput{Account: *updated, Enabled: &enabled})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if *in.Minutes == 0 {
		s.schemas.Forget(id)
	}
	// Discovery changes what the gateway retains about partner traffic,
	// so opening and closing the window is itself an audited event.
	s.auditEmit("admin", "account.discover", map[string]any{
		"account": id, "minutes": *in.Minutes, "active": out.discovering(),
	})
	s.handleDiscoverStatus(w, r)
}

// handleDiscoverReset forgets observations without closing the window.
func (s *Server) handleDiscoverReset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.store.Get(id); !ok {
		jsonError(w, http.StatusNotFound, "account not found")
		return
	}
	s.schemas.Forget(id)
	s.auditEmit("admin", "account.discover_reset", map[string]any{"account": id})
	s.handleDiscoverStatus(w, r)
}

// handleTest is a dry run: translate without forwarding.
func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Direction string          `json:"direction"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := decodeStrict(w, r, &in); err != nil {
		writeValidationError(w, err)
		return
	}
	acct, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		jsonError(w, http.StatusNotFound, "account not found")
		return
	}
	var ve ValidationErrors
	dir, dirOK := ParseDirection(in.Direction)
	if !dirOK {
		ve.add("direction", `must be "a2b" or "b2a"`)
	}
	// The same rule as the data plane: a bare array is a payload only where a
	// row addresses one on the sending side, and it previews as it would go out.
	var payload map[string]any
	if len(in.Payload) == 0 || bytes.Equal(bytes.TrimSpace(in.Payload), []byte("null")) {
		ve.add("payload", "must be a JSON object")
	} else if dirOK {
		rooted := addressesRoot(acct.Map, dir)
		var err error
		if payload, err = decodeBody(in.Payload, rooted); err != nil {
			if rooted {
				ve.add("payload", "must be a JSON object or array")
			} else {
				ve.add("payload", "must be a JSON object")
			}
		}
	}
	if len(ve) > 0 {
		writeValidationError(w, ve)
		return
	}
	res := Translate(payload, acct.Map, dir, TranslateOptions{DropUnmapped: acct.DropUnmapped, Strict: acct.StrictTransforms})
	warnings := res.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	out := map[string]any{
		"translated": bodyOf(res.Out),
		"applied":    res.Applied,
		"warnings":   warnings,
	}
	if omitted := res.Warned - len(warnings); omitted > 0 {
		out["warnings_omitted"] = omitted
	}
	// Only present when strict mode or the array rules would refuse this
	// payload, so the preview of what would have been forwarded is not
	// mistaken for it. Refused arrays leave the preview as the sender wrote it.
	if len(res.Failed) > 0 || len(res.Refused) > 0 {
		out["rejected"] = true
	}
	if len(res.Failed) > 0 {
		out["failed"] = res.Failed
	}
	if len(res.Refused) > 0 {
		out["refused"] = boundedRefusals(res.Refused)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	entries := s.logs.List(r.URL.Query().Get("account"), limit)
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// handleStats powers the dashboard: lifetime counters for this node
// plus a rolling per-minute series.
func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	snap := s.stats.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  version,
		"accounts": s.store.Count(),
		"stats":    snap,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"version":    version,
		"accounts":   s.store.Count(),
		"uptime_sec": int(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) handleAdminUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// frame-ancestors does not fall back to default-src; without it any
	// origin could frame the console around the admin-token prompt.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	_, _ = w.Write(s.adminHTML)
}

// ---------------------------------------------------------------------------
// Middleware + helpers

func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenEqual(bearerFrom(r), s.adminToken) {
			s.noteAdminDenied(r)
			w.Header().Set("WWW-Authenticate", `Bearer realm="xlate-admin"`)
			jsonError(w, http.StatusUnauthorized, "admin token required")
			return
		}
		h(w, r)
	}
}

// noteAdminDenied records a failed admin authentication. The data plane
// audits every denial; the admin plane coalesces to one record per 10s
// window (with a suppressed count) because the admin token is a single
// credential — per-attempt records add flood surface, not signal.
func (s *Server) noteAdminDenied(r *http.Request) {
	ip := s.clientIP(r)
	s.adminDeniedMu.Lock()
	now := time.Now()
	if now.Before(s.adminDeniedUntil) {
		s.adminDeniedHeld++
		s.adminDeniedMu.Unlock()
		return
	}
	held := s.adminDeniedHeld
	s.adminDeniedHeld = 0
	s.adminDeniedUntil = now.Add(10 * time.Second)
	s.adminDeniedMu.Unlock()

	// The path is client-controlled and %0A survives URL decoding, so it
	// is neutralised before it reaches the process log.
	path := safeLogValue(r.URL.Path, 200)
	detail := map[string]any{"ip": ip, "path": path}
	if held > 0 {
		detail["suppressed"] = held
	}
	log.Printf("admin auth denied (ip %s, path %s, %d more suppressed in the last window)", safeLogValue(ip, 64), path, held)
	s.auditEmit("admin", "admin.denied", detail)
}

// bearerFrom extracts credentials from Authorization: Bearer or, as a
// fallback for clients that cannot set it, X-Api-Key.
func bearerFrom(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

// tokenEqual compares hashes so the comparison is constant-time and
// independent of candidate length.
func tokenEqual(candidate, want string) bool {
	if want == "" {
		return false
	}
	hc := sha256.Sum256([]byte(candidate))
	hw := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(hc[:], hw[:]) == 1
}

func readLimited(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

// writeValidationError renders field-level detail when the failure is a
// ValidationErrors, and a plain envelope otherwise.
func writeValidationError(w http.ResponseWriter, err error) {
	var ve ValidationErrors
	if errors.As(err, &ve) && len(ve) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  ve.Error(),
			"code":   "validation_failed",
			"fields": []FieldError(ve),
		})
		return
	}
	jsonError(w, http.StatusBadRequest, err.Error())
}

// writeStoreError maps store failures onto status codes by sentinel
// rather than by matching on error prose.
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAccountNotFound):
		jsonError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errAccountExists):
		jsonErrorCode(w, http.StatusConflict, "already_exists", err.Error())
	default:
		writeValidationError(w, err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// jsonErrorCode is the error envelope: a human message plus a stable
// machine code integrators can branch on without string-matching.
func jsonErrorCode(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}

// jsonError derives a generic code from the status for call sites where
// a more specific one adds nothing (mostly admin validation).
func jsonError(w http.ResponseWriter, status int, msg string) {
	code := map[int]string{
		http.StatusBadRequest:            "bad_request",
		http.StatusUnauthorized:          "unauthorized",
		http.StatusForbidden:             "forbidden",
		http.StatusNotFound:              "not_found",
		http.StatusRequestEntityTooLarge: "payload_too_large",
		http.StatusTooManyRequests:       "rate_limited",
		http.StatusBadGateway:            "upstream_failed",
	}[status]
	if code == "" {
		code = "internal"
	}
	jsonErrorCode(w, status, code, msg)
}

// clientIP returns the peer address; with -trust-proxy it honors the
// first X-Forwarded-For hop instead. Off by default because XFF is
// attacker-controlled unless a trusted proxy strips it — and this value
// feeds tripwire forensics.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// classifyNetErr buckets upstream failures for the audit trail so
// operators can tell DNS rot from timeouts without parsing error prose.
func classifyNetErr(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "connect"
	}
	return "other"
}

// boundedPaths makes configured field paths safe and short enough for a log
// line, an audit record or an error body, and caps how many are listed.
func boundedPaths(paths []string) []string {
	if len(paths) > maxLoggedFields {
		paths = paths[:maxLoggedFields]
	}
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = safeLogValue(p, maxLoggedFieldName)
	}
	return out
}

// transformFieldErrors reports strict-mode failures in the same shape as
// every other field-level error.
func transformFieldErrors(paths []string) []FieldError {
	bounded := boundedPaths(paths)
	out := make([]FieldError, len(bounded))
	for i, p := range bounded {
		out[i] = FieldError{Field: p, Message: "value does not match its declared format"}
	}
	return out
}

// boundedRefusals is boundedPaths for refusals that carry their reason. The
// paths are the map's own plus an index, and the reasons are fixed text and
// counts, so no value and no partner-chosen string is in either.
func boundedRefusals(fes []FieldError) []FieldError {
	if len(fes) > maxLoggedFields {
		fes = fes[:maxLoggedFields]
	}
	out := make([]FieldError, len(fes))
	for i, fe := range fes {
		out[i] = FieldError{Field: safeLogValue(fe.Field, maxLoggedFieldName), Message: fe.Message}
	}
	return out
}

// refusalPaths lists only the paths, for the audit trail, which gets names.
func refusalPaths(fes []FieldError) []string {
	out := make([]string, len(fes))
	for i, fe := range fes {
		out[i] = fe.Field
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
