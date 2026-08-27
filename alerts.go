package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Tripwire tracks refused ingest attempts (401s) per account over a
// sliding window and fires once when the count exceeds the threshold.
//
// Semantics:
//   - keyed by account: credential guessing is an account-level signal,
//     and an attacker rotating source IPs must not evade it. Offending
//     IPs are tallied for the alert payload, not for triggering.
//   - only 401s feed the counter. 403s (disabled account) are an admin
//     decision already; counting them would let a frozen account
//     re-alarm forever.
//   - one alert per trip. The state stays tripped until the lock expires
//     (mode "lock"), or until manual reset (modes "freeze" and "alert").
//
// Modes:
//   - lock   temporary lockout; ingest answers 429 + Retry-After until
//     the lock expires, then the counter re-arms. In-memory: a
//     restart clears it (documented).
//   - freeze account.Enabled is persisted false; 403 until an admin
//     re-enables and resets. Survives restart.
//   - alert  notify only, no blocking.
type Tripwire struct {
	Threshold int
	Window    time.Duration
	LockFor   time.Duration
	Mode      string // lock | freeze | alert

	mu sync.Mutex
	m  map[string]*twState
}

// Retention bounds. Everything the tripwire keeps is sized by attacker
// traffic, so both dimensions need a ceiling:
//
//   - samples: only the newest Threshold+1 timestamps can change the
//     verdict, so older ones are dropped. Without this the slice grows
//     to hold every refused attempt inside the window and the prune
//     below re-scans all of them on every request — quadratic work under
//     exactly the flood it exists to detect.
//   - IPs: the tally is forensic colour for the alert's top-5, not a
//     trigger. Past the cap, known addresses keep counting and new ones
//     are ignored, so a source rotating through an IPv6 range cannot
//     grow the map without bound.
const (
	maxTrackedIPs    = 1024
	maxTripThreshold = 10000
)

// sampleCap is the most timestamps worth keeping for one account.
func (t *Tripwire) sampleCap() int {
	n := t.Threshold + 1
	if n < 1 {
		n = 1
	}
	if n > maxTripThreshold+1 {
		n = maxTripThreshold + 1
	}
	return n
}

type twState struct {
	times       []time.Time
	ips         map[string]int
	lockedUntil time.Time
	tripped     bool
	trips       int
	firstAt     time.Time
}

// TripInfo is handed to the server when a trip fires so it can audit,
// alert, and apply the mode's action.
type TripInfo struct {
	Account string
	Count   int
	FirstAt time.Time
	LastAt  time.Time
	TopIPs  []IPCount
	Trips   int
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

func NewTripwire(threshold int, window, lockFor time.Duration, mode string) *Tripwire {
	return &Tripwire{Threshold: threshold, Window: window, LockFor: lockFor, Mode: mode, m: map[string]*twState{}}
}

// RecordDenied registers a refused attempt. It returns non-nil exactly
// once per trip: the moment the count first exceeds Threshold.
func (t *Tripwire) RecordDenied(account, ip string) *TripInfo {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	st := t.m[account]
	if st == nil {
		st = &twState{ips: map[string]int{}}
		t.m[account] = st
	}
	// Prune outside the window. The slice is capped at sampleCap, so this
	// is bounded work per call rather than a scan of the whole flood.
	cut := now.Add(-t.Window)
	keep := st.times[:0]
	for _, ts := range st.times {
		if ts.After(cut) {
			keep = append(keep, ts)
		}
	}
	st.times = keep

	// A fully drained window re-arms an "alert"-mode account so a later
	// campaign alerts again. Without this an account alerts once per
	// process lifetime and every subsequent attack is silent. "freeze"
	// stays tripped on purpose: the account is disabled until an admin
	// intervenes, and "lock" re-arms in Gate when the lock expires.
	if st.tripped && t.Mode == "alert" && len(st.times) == 0 && st.lockedUntil.IsZero() {
		st.tripped = false
		st.ips = map[string]int{}
	}

	st.times = append(st.times, now)
	if lim := t.sampleCap(); len(st.times) > lim {
		// copy handles the overlap; only the newest samples are retained.
		st.times = append(st.times[:0], st.times[len(st.times)-lim:]...)
	}
	if _, known := st.ips[ip]; known || len(st.ips) < maxTrackedIPs {
		st.ips[ip]++
	}
	if len(st.times) == 1 {
		st.firstAt = now
	}
	if st.tripped || len(st.times) <= t.Threshold {
		return nil
	}
	st.tripped = true
	st.trips++
	if t.Mode == "lock" {
		st.lockedUntil = now.Add(t.LockFor)
	}
	return &TripInfo{
		Account: account,
		Count:   len(st.times),
		FirstAt: st.times[0],
		LastAt:  now,
		TopIPs:  topIPs(st.ips, 5),
		Trips:   st.trips,
	}
}

// Gate reports whether ingest for the account is currently locked and,
// if so, for how much longer. An expired lock re-arms the counter.
func (t *Tripwire) Gate(account string) (locked bool, remaining time.Duration) {
	if t == nil {
		return false, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.m[account]
	if st == nil || st.lockedUntil.IsZero() {
		return false, 0
	}
	if rem := time.Until(st.lockedUntil); rem > 0 {
		return true, rem
	}
	// Lock expired: re-arm the counter but carry the cumulative trip
	// count forward. It is the escalation signal — an account on its
	// fifth trip is a different conversation from one on its first —
	// and zeroing it made every alert read as "trip_number: 1".
	*st = twState{ips: map[string]int{}, trips: st.trips}
	return false, 0
}

// Reset clears counter, lock, and tripped flag (admin action).
func (t *Tripwire) Reset(account string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, account)
}

// Status describes tripwire state for the admin API/UI.
func (t *Tripwire) Status(account string) map[string]any {
	if t == nil {
		return map[string]any{"state": "armed", "count": 0}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.m[account]
	if st == nil {
		return map[string]any{"state": "armed", "count": 0}
	}
	cut := time.Now().Add(-t.Window)
	n := 0
	for _, ts := range st.times {
		if ts.After(cut) {
			n++
		}
	}
	out := map[string]any{"state": "armed", "count": n, "trips": st.trips}
	if st.tripped {
		out["state"] = "tripped"
	}
	if rem := time.Until(st.lockedUntil); rem > 0 {
		out["state"] = "locked"
		out["unlock_in_sec"] = int(rem.Seconds())
	}
	return out
}

func topIPs(m map[string]int, n int) []IPCount {
	out := make([]IPCount, 0, len(m))
	for ip, c := range m {
		out = append(out, IPCount{IP: ip, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Alerter delivers alert payloads to a webhook, optionally HMAC-signed.
// An unauthenticated alert channel is spoofable, which defeats the point
// of a security signal — set a secret in anything beyond a lab.
type Alerter struct {
	URL    string
	Secret string
	client *http.Client
	audit  *AuditLog
}

func NewAlerter(url, secret string, audit *AuditLog) *Alerter {
	if url == "" {
		return nil
	}
	return &Alerter{URL: url, Secret: secret, audit: audit, client: &http.Client{Timeout: 5 * time.Second}}
}

// Send dispatches asynchronously with one retry. Alert delivery must
// never block or fail the data plane; outcomes land in the audit trail.
func (a *Alerter) Send(payload map[string]any) {
	if a == nil {
		return
	}
	go func() {
		// A panic in a goroutine takes the whole process with it — the
		// handler's recover only covers the request goroutine. Alert
		// delivery must never be able to kill the gateway.
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic during alert delivery: %v", rec)
			}
		}()
		body, err := json.Marshal(payload)
		if err != nil {
			return
		}
		var lastErr error
		for attempt := 1; attempt <= 2; attempt++ {
			if err := a.post(body); err != nil {
				lastErr = err
				time.Sleep(2 * time.Second)
				continue
			}
			a.audit.Emit("system", "alert.sent", map[string]any{"url": redactURL(a.URL), "event": payload["event"], "attempt": attempt})
			return
		}
		log.Printf("alert delivery failed: %s: %s", redactURL(a.URL), redactErr(lastErr, a.URL))
		a.audit.Emit("system", "alert.failed", map[string]any{"url": redactURL(a.URL), "event": payload["event"], "err": redactErr(lastErr, a.URL)})
	}()
}

// redactURL reduces a webhook URL to scheme://host for logs and the
// audit trail. Webhook URLs routinely carry the credential in the path
// or query (Slack, Discord, generic token-in-query receivers), and the
// trail's own rule is that credentials never appear in it.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparseable webhook url)"
	}
	return u.Scheme + "://" + u.Host
}

// redactErr strips the full webhook URL out of an error's text —
// net/http errors embed the request URL verbatim.
func redactErr(err error, rawURL string) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), rawURL, redactURL(rawURL))
}

func (a *Alerter) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, a.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xlate/"+version)
	if a.Secret != "" {
		mac := hmac.New(sha256.New, []byte(a.Secret))
		mac.Write(body)
		req.Header.Set("X-Xlate-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &httpStatusError{resp.StatusCode}
	}
	return nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return "webhook returned " + http.StatusText(e.code) }
