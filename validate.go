package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits applied to every admin-supplied document. Each exists because
// the value it bounds escapes the request: into the state file, into an
// outbound HTTP header, or into a per-request loop on the data plane.
// Unbounded input in any of those places is unbounded work later.
const (
	maxNameLen        = 200
	maxLabelLen       = 80
	maxTargetURLLen   = 2048
	maxTokenLen       = 512
	minTokenLen       = 16
	maxMapPairs       = 500
	maxPathLen        = 256
	maxPathDepth      = 16
	maxFormatLen      = 128
	maxCorrelationLen = 256
	maxAdminBody      = 1 << 20
)

// FieldError locates one validation failure inside the submitted
// document, using dotted/indexed JSON paths ("map[2].a") so a client can
// map it straight back onto its own form.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`

	// kind classifies the failure for logging. It is unexported on
	// purpose: encoding/json skips it, so the documented response shape
	// is unchanged.
	kind string
}

// Failure classes recorded on the audit trail.
const (
	kindUnknownField = "unknown_field"
	kindInvalidField = "invalid_field"
	kindBadRequest   = "bad_request"
)

// ValidationErrors is the full set of problems found in one document.
// Validation is exhaustive rather than fail-fast: an admin fixing a
// mapping grid should see every bad row at once, not one per round trip.
type ValidationErrors []FieldError

func (v ValidationErrors) Error() string {
	if len(v) == 0 {
		return "invalid request"
	}
	parts := make([]string, 0, len(v))
	for _, fe := range v {
		if fe.Field == "" {
			parts = append(parts, fe.Message)
			continue
		}
		parts = append(parts, fe.Field+": "+fe.Message)
	}
	return strings.Join(parts, "; ")
}

func (v *ValidationErrors) add(field, format string, args ...any) {
	*v = append(*v, FieldError{Field: field, Message: fmt.Sprintf(format, args...), kind: kindInvalidField})
}

// Limits on what a rejection may write to the log and the audit trail.
// Field names come from the client, so they are bounded and stripped of
// anything that could forge a log line or bloat a record.
const (
	maxLoggedFields    = 20
	maxLoggedFieldName = 64
)

// isRejection reports whether err is refused input, as opposed to a
// missing or colliding account — those carry their own statuses and are
// not a client sending something malformed.
func isRejection(err error) bool {
	var ve ValidationErrors
	return errors.As(err, &ve)
}

// Kind reports the dominant failure class, used to label the audit
// record so operators can tell a typo'd setting from a bad value.
func (v ValidationErrors) Kind() string {
	kind := kindBadRequest
	for _, fe := range v {
		if fe.kind == kindUnknownField {
			return kindUnknownField
		}
		if fe.kind == kindInvalidField {
			kind = kindInvalidField
		}
	}
	return kind
}

// FieldNames returns the offending field names, sanitised and bounded,
// for logging. Names only — never values: an unknown field can carry a
// credential (a typo'd "inbound_tokenn" is exactly how that happens),
// and secrets do not belong in logs under any circumstances.
func (v ValidationErrors) FieldNames() []string {
	out := make([]string, 0, len(v))
	for _, fe := range v {
		if fe.Field == "" {
			continue
		}
		out = append(out, safeLogValue(fe.Field, maxLoggedFieldName))
		if len(out) == maxLoggedFields {
			break
		}
	}
	return out
}

// safeLogValue makes a client-supplied string safe to place in a log
// line or an audit record. Control characters are dropped — a raw
// newline in a field name or a URL path (%0A survives decoding) would
// otherwise forge a second log line — and the result is length-bounded.
func safeLogValue(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Primitive checks

// headerSafe reports whether s can be placed in an HTTP header value.
// Tokens and correlation identifiers are forwarded verbatim on the
// outbound request; a value carrying CR/LF or other control bytes must
// be refused at the API boundary rather than at write time.
func headerSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// checkAdminToken applies the inbound/outbound token rules to an
// operator-pinned admin token. A generated token is always strong; the
// override path (-admin-token, XLATE_ADMIN_TOKEN) is not, and it guards
// every credential in the state file. The error never echoes the value.
func checkAdminToken(tok string) error {
	switch {
	case len(tok) < minTokenLen:
		return fmt.Errorf("admin token must be at least %d characters", minTokenLen)
	case len(tok) > maxTokenLen:
		return fmt.Errorf("admin token must be at most %d characters", maxTokenLen)
	case !headerSafe(tok):
		return errors.New("admin token must contain only printable non-space ASCII")
	}
	return nil
}

// printableText rejects control characters (including CR/LF and NUL) in
// free-text fields that are rendered in the console and written to the
// state file.
func printableText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Dot-path validation

// validateDotPath enforces what the translation engine can actually
// address. Anything it cannot address cleanly is refused at config time,
// because at request time a bad path is silently a no-op.
func validateDotPath(p string) error {
	switch {
	case p == "":
		return errors.New("must not be empty")
	case len(p) > maxPathLen:
		return fmt.Errorf("must be at most %d characters", maxPathLen)
	case !printableText(p):
		return errors.New("must not contain control characters")
	case strings.HasPrefix(p, "."), strings.HasSuffix(p, "."):
		return errors.New("must not begin or end with a dot")
	case strings.Contains(p, ".."):
		return errors.New("must not contain an empty path segment")
	}
	if strings.TrimSpace(p) != p {
		return errors.New("must not have leading or trailing whitespace")
	}
	if n := strings.Count(p, ".") + 1; n > maxPathDepth {
		return fmt.Errorf("must be at most %d segments deep", maxPathDepth)
	}
	// Array indexing is out of scope; "items[0]" would silently address a
	// literal key named "items[0]" instead, so refuse it explicitly.
	if strings.ContainsAny(p, "[]") {
		return errors.New("array indexing is not supported")
	}
	return nil
}

// prefixConflict reports a path in set that is a strict dot-prefix of p
// (or vice versa). "customer" and "customer.id" on the same side cannot
// both be honoured: extracting one removes or shadows the other, and
// which wins depends on map order. Refuse the ambiguity.
func prefixConflict(set map[string]int, p string) (string, int, bool) {
	for cand, row := range set {
		short, long := cand, p
		if len(short) > len(long) {
			short, long = long, short
		}
		if short != long && strings.HasPrefix(long, short+".") {
			return cand, row, true
		}
	}
	return "", 0, false
}

// ---------------------------------------------------------------------------
// Date-format validation

// probeMoment differs from Go's reference time (2006-01-02 15:04:05 MST)
// in every component — year, month, day, 12- and 24-hour, minute,
// second, fraction, weekday and zone. Formatting with it therefore
// changes any string that contains a real layout element, which is what
// distinguishes a layout from a literal.
//
// It must NOT be the reference time itself: formatting the reference
// time with a reference layout returns the layout unchanged, so that
// comparison would reject every valid layout.
var probeMoment = time.Date(2021, 3, 14, 9, 26, 53, 589000000, time.UTC)

// validateDateFormat accepts a named format, an epoch keyword, or a Go
// reference layout that genuinely round-trips.
//
// Without this, a typo'd layout ("YYYY-MM-DD", a habit from every other
// date library) is accepted at config time and then fails open on every
// single request forever — the value forwards untransformed and the only
// symptom is a warning counter nobody is watching. Catching it here
// turns a silent permanent data bug into an immediate 400.
func validateDateFormat(f string) error {
	switch {
	case f == "":
		return errors.New("must not be empty")
	case len(f) > maxFormatLen:
		return fmt.Errorf("must be at most %d characters", maxFormatLen)
	case !printableText(f):
		return errors.New("must not contain control characters")
	}
	if f == epochSec || f == epochMS {
		return nil
	}
	if _, named := namedLayouts[f]; named {
		return nil
	}
	// A raw Go layout must substitute reference components when used to
	// format. "YYYY-MM-DD" contains none, so Format returns it unchanged.
	rendered := probeMoment.Format(f)
	if rendered == f {
		return fmt.Errorf("%q is not a Go reference layout (use one of %s, an epoch, "+
			"or a layout built from the reference time 2006-01-02 15:04:05)", f, knownFormatList())
	}
	// It must also parse back what it produced, or the reverse leg breaks
	// and every response silently fails open.
	parsed, err := time.Parse(f, rendered)
	if err != nil {
		return fmt.Errorf("layout %q formats to %q but cannot parse it back", f, rendered)
	}
	// And it must carry a whole calendar date. Substitution alone is too
	// weak a test: Go reads the "1" in "iso8601" as a month, so that
	// string formats and parses happily while encoding nothing. A layout
	// that drops the year, month or day silently rewrites every value
	// that passes through it — converting to an epoch would invent a
	// date. Requiring a lossless round trip of Y/M/D catches both.
	py, pm, pd := parsed.Date()
	wy, wm, wd := probeMoment.Date()
	if py != wy || pm != wm || pd != wd {
		return fmt.Errorf("layout %q does not carry a full calendar date: %q reads back as %s, "+
			"so converting through it would lose or invent date information",
			f, rendered, parsed.Format("2006-01-02"))
	}
	return nil
}

// documentedFormats are the named formats the README advertises. Kept
// here so a rename cannot silently drop one.
func documentedFormats() []string {
	return []string{"rfc3339", "rfc3339nano", "date", "datetime", "rfc1123", epochSec, epochMS}
}

func knownFormatList() string {
	names := make([]string, 0, len(namedLayouts)+2)
	for k := range namedLayouts {
		names = append(names, k)
	}
	names = append(names, epochSec, epochMS)
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func validateTransform(t *Transform, field string, ve *ValidationErrors) {
	if t == nil {
		return
	}
	if t.Kind != "date" {
		// No version number in the message: it is client-visible and a
		// pinned version drifts the moment the constant is bumped.
		ve.add(field+".kind", "unsupported transform kind %q (only \"date\" is supported)", t.Kind)
		return
	}
	if err := validateDateFormat(strings.TrimSpace(t.AFormat)); err != nil {
		ve.add(field+".a_format", "%s", err)
	}
	if err := validateDateFormat(strings.TrimSpace(t.BFormat)); err != nil {
		ve.add(field+".b_format", "%s", err)
	}
}

// ---------------------------------------------------------------------------
// Endpoint + account validation

func validateEndpoint(side string, ep Endpoint, ve *ValidationErrors) {
	if len(ep.Label) > maxLabelLen {
		ve.add(side+".label", "must be at most %d characters", maxLabelLen)
	}
	if !printableText(ep.Label) {
		ve.add(side+".label", "must not contain control characters")
	}

	if ep.TargetURL != "" {
		validateTargetURL(side+".target_url", ep.TargetURL, ve)
	}

	for _, tok := range []struct {
		field, val string
	}{
		{side + ".inbound_token", ep.InboundToken},
		{side + ".outbound_token", ep.OutboundToken},
	} {
		if tok.val == "" {
			continue
		}
		switch {
		case len(tok.val) < minTokenLen:
			ve.add(tok.field, "must be at least %d characters", minTokenLen)
		case len(tok.val) > maxTokenLen:
			ve.add(tok.field, "must be at most %d characters", maxTokenLen)
		case !headerSafe(tok.val):
			// Outbound tokens are written straight into an Authorization
			// header; inbound tokens are compared against one.
			ve.add(tok.field, "must contain only printable non-space ASCII")
		}
	}
}

func validateTargetURL(field, raw string, ve *ValidationErrors) {
	if len(raw) > maxTargetURLLen {
		ve.add(field, "must be at most %d characters", maxTargetURLLen)
		return
	}
	if !headerSafe(raw) {
		ve.add(field, "must not contain spaces or control characters")
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		ve.add(field, "is not a valid URL")
		return
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		ve.add(field, "must be an absolute http(s) URL")
		return
	}
	if u.Host == "" {
		ve.add(field, "must include a host")
		return
	}
	if u.User != nil {
		// Credentials in the URL would be logged by any intermediary and
		// silently override the account's outbound token semantics.
		ve.add(field, "must not embed credentials (use outbound_token)")
	}
	if u.Fragment != "" {
		ve.add(field, "must not contain a fragment")
	}
}

// validateAccountDoc runs every structural rule over a normalised
// account. applyDefaults must have run first.
func validateAccountDoc(a *Account) ValidationErrors {
	var ve ValidationErrors

	if !accountIDRe.MatchString(a.ID) {
		ve.add("id", "must match ^[a-z0-9][a-z0-9_-]{0,62}$")
	}
	if len(a.Name) > maxNameLen {
		ve.add("name", "must be at most %d characters", maxNameLen)
	}
	if !printableText(a.Name) {
		ve.add("name", "must not contain control characters")
	}
	if a.TimeoutSec < 0 || a.TimeoutSec > maxTimeoutSec {
		ve.add("timeout_sec", "must be between 1 and %d seconds (0 selects the default of %d)",
			maxTimeoutSec, defaultTimeoutSec)
	}
	// A discovery window that never closes is a privacy leak nobody
	// remembers to turn off, so the far end is bounded.
	if a.DiscoverUntil != nil && time.Until(*a.DiscoverUntil) > maxDiscoverWindow {
		ve.add("discover_until", "must be at most %s in the future", maxDiscoverWindow)
	}

	// Deterministic side order: ranging a map here made the reported side
	// depend on Go's map iteration order.
	validateEndpoint("a", a.A, &ve)
	validateEndpoint("b", a.B, &ve)

	if len(a.Map) > maxMapPairs {
		ve.add("map", "must contain at most %d pairs", maxMapPairs)
		return ve
	}

	seen := map[string]map[string]int{"a": {}, "b": {}}
	for i, p := range a.Map {
		row := fmt.Sprintf("map[%d]", i)
		for _, s := range []struct {
			side, val string
		}{{"a", p.A}, {"b", p.B}} {
			field := row + "." + s.side
			if s.val == "" {
				ve.add(field, "both sides of a mapping row are required")
				continue
			}
			if err := validateDotPath(s.val); err != nil {
				ve.add(field, "%s", err)
				continue
			}
			if prev, ok := seen[s.side][s.val]; ok {
				ve.add(field, "duplicates side %s field %q already used by map[%d]", s.side, s.val, prev)
				continue
			}
			if other, orow, clash := prefixConflict(seen[s.side], s.val); clash {
				ve.add(field, "conflicts with %q on side %s (map[%d]): one path is a parent of the other",
					other, s.side, orow)
				continue
			}
			seen[s.side][s.val] = i
		}
		validateTransform(p.Transform, row+".transform", &ve)
	}
	return ve
}

// ---------------------------------------------------------------------------
// Request decoding

// decodeStrict is the single entry point for admin request bodies.
//
// It is deliberately strict in ways encoding/json is not by default:
//   - the body is size-capped
//   - unknown fields are rejected, so a typo ("target_uri", "droppunmapped")
//     fails loudly instead of being silently ignored and losing config
//   - trailing data after the JSON value is rejected, so `{"a":1}{"b":2}`
//     cannot be read one way here and another way by a downstream parser
func decodeStrict(w http.ResponseWriter, r *http.Request, v any) error {
	if err := requireJSONContentType(r); err != nil {
		return err
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return decodeError(err)
	}
	if err := ensureNoTrailingData(dec); err != nil {
		return err
	}
	return nil
}

// requireJSONContentType enforces the media type when one is supplied.
// A body-bearing request that declares a non-JSON type is a client bug
// worth surfacing; a missing header stays acceptable so plain curl and
// the existing integrations keep working.
func requireJSONContentType(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return nil
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "application/json" || strings.HasSuffix(ct, "+json") {
		return nil
	}
	return ValidationErrors{{Field: "Content-Type", Message: fmt.Sprintf("must be application/json, got %q", ct)}}
}

func ensureNoTrailingData(dec *json.Decoder) error {
	if dec.More() {
		return ValidationErrors{{Message: "unexpected data after the JSON value"}}
	}
	// More() is false at EOF and at a closing delimiter alike; confirm EOF.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ValidationErrors{{Message: "unexpected data after the JSON value"}}
	}
	return nil
}

// decodeError converts json/library errors into a client-facing message
// without echoing the offending body back to the caller.
func decodeError(err error) error {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return ValidationErrors{{Message: fmt.Sprintf("body exceeds %d bytes", maxAdminBody)}}
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		field := typeErr.Field
		if field == "" {
			field = "body"
		}
		return ValidationErrors{{Field: field, Message: fmt.Sprintf("expected %s", typeErr.Type)}}
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return ValidationErrors{{Message: fmt.Sprintf("malformed JSON at byte %d", syntaxErr.Offset)}}
	}
	if errors.Is(err, io.EOF) {
		return ValidationErrors{{Message: "request body is empty"}}
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return ValidationErrors{{Message: "malformed JSON: unexpected end of input"}}
	}
	// DisallowUnknownFields reports as a plain error whose text names the
	// field in quotes; lift it into Field so clients get the same
	// structure as every other validation failure.
	if msg := err.Error(); strings.Contains(msg, "unknown field") {
		field := ""
		if i := strings.IndexByte(msg, '"'); i >= 0 {
			if j := strings.LastIndexByte(msg, '"'); j > i {
				field = msg[i+1 : j]
			}
		}
		return ValidationErrors{{
			Field:   field,
			Message: "unknown field; check for a typo, or a setting that does not exist",
			kind:    kindUnknownField,
		}}
	}
	return ValidationErrors{{Message: "invalid JSON body"}}
}

// decodeObjectStrict parses a data-plane payload. Unknown fields are the
// entire point here, so only the object-ness, numeric fidelity and
// trailing-data rules apply.
func decodeObjectStrict(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("null is not an object")
	}
	if err := ensureNoTrailingData(dec); err != nil {
		return nil, err
	}
	return m, nil
}

// validateCorrelationHeaders checks the headers forwarded verbatim to
// the destination. They are attacker-controlled: the caller is the
// opposite party, not an operator.
func validateCorrelationHeaders(r *http.Request) error {
	var ve ValidationErrors
	for _, h := range correlationHeaders {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		if len(v) > maxCorrelationLen {
			ve.add(h, "must be at most %d characters", maxCorrelationLen)
			continue
		}
		if !headerSafe(v) {
			ve.add(h, "must contain only printable non-space ASCII")
		}
	}
	if len(ve) > 0 {
		return ve
	}
	return nil
}

var correlationHeaders = []string{"Idempotency-Key", "X-Request-Id"}
