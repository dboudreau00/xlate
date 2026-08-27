package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newAPIWithTrail is newAPI plus the audit file path, so a test can
// assert on what a rejection actually wrote.
func newAPIWithTrail(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	trail := filepath.Join(dir, "audit.jsonl")

	store, err := OpenStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	audit, err := OpenAudit(trail)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, NewRing(200), testAdminToken, 2<<20, []byte("<html>admin</html>"))
	srv.audit = audit
	srv.trip = NewTripwire(5, 5*time.Minute, 15*time.Minute, "lock")

	ts := httptest.NewServer(srv.routes())
	t.Cleanup(func() {
		ts.Close()
		_ = audit.Close()
	})
	return ts, trail
}

func readTrail(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A rejected mutation must land on the trail naming the offending
// fields, so a client looping on a typo is visible server-side.
func TestRejectedMutationIsAudited(t *testing.T) {
	ts, trail := newAPIWithTrail(t)

	r := admin(t, ts, "POST", "/api/admin/accounts", `{"id":"acme","target_uri":"http://x/"}`)
	if r.status != 400 {
		t.Fatalf("want 400, got %d: %s", r.status, r.body)
	}

	got := readTrail(t, trail)
	if !strings.Contains(got, `"event":"account.rejected"`) {
		t.Fatalf("rejection was not audited:\n%s", got)
	}
	for _, want := range []string{`"reason":"unknown_field"`, `"target_uri"`, `"method":"POST"`} {
		if !strings.Contains(got, want) {
			t.Errorf("audit record missing %s:\n%s", want, got)
		}
	}
}

// The whole point of recording names and not values: an unknown field is
// very often a typo'd credential field, with a live credential in it.
func TestRejectionNeverRecordsFieldValues(t *testing.T) {
	ts, trail := newAPIWithTrail(t)
	const secret = "xk_super_secret_live_token_do_not_log"

	// A typo'd token field: the name is unknown, the value is a real token.
	r := admin(t, ts, "POST", "/api/admin/accounts",
		`{"id":"acme","a":{"inbound_tokenn":"`+secret+`"}}`)
	if r.status != 400 {
		t.Fatalf("want 400, got %d: %s", r.status, r.body)
	}

	got := readTrail(t, trail)
	if strings.Contains(got, secret) {
		t.Fatal("the value of a typo'd credential field reached the audit trail")
	}
	if !strings.Contains(got, "inbound_tokenn") {
		t.Errorf("the field name should be recorded:\n%s", got)
	}
	// It must not come back on the wire either.
	if strings.Contains(string(r.body), secret) {
		t.Error("the value was echoed in the error response")
	}
}

// Field names and paths are client-controlled, so neither may forge a
// log line or an audit record.
func TestRejectionSanitisesClientControlledText(t *testing.T) {
	ts, trail := newAPIWithTrail(t)

	// %0A decodes into the path, and a JSON key may hold anything.
	admin(t, ts, "PUT", "/api/admin/accounts/ev%0Ail", `{"bad\nname":1}`)

	got := readTrail(t, trail)
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, `{"seq":`) {
			t.Errorf("audit line is not a whole record — text was injected: %q", line)
		}
	}
	if strings.Contains(got, "ev\nil") {
		t.Error("a raw newline from the URL path reached the trail")
	}
}

// The chain must still verify after rejections are appended.
func TestRejectionsKeepAuditChainValid(t *testing.T) {
	ts, trail := newAPIWithTrail(t)

	mustCreate(t, ts, map[string]any{"id": "ok"})
	admin(t, ts, "POST", "/api/admin/accounts", `{"id":"x","nope":1}`)
	admin(t, ts, "PUT", "/api/admin/accounts/ok", `{"timeout_sec":-1}`)
	admin(t, ts, "POST", "/api/admin/accounts/ok/rotate", `{"side":"z","kind":"inbound"}`)

	got := readTrail(t, trail)
	for _, want := range []string{`"reason":"unknown_field"`, `"timeout_sec"`, `"side"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in trail:\n%s", want, got)
		}
	}
	if err := VerifyAudit(trail, discardWriter{}); err != nil {
		t.Fatalf("chain broken by rejection records: %v", err)
	}
}

// Rejections are labelled so an operator can separate a typo'd setting
// from a bad value without parsing prose.
func TestRejectionReasonClassification(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"unknown field", `{"id":"a","nope":1}`, "unknown_field"},
		{"invalid value", `{"id":"a","timeout_sec":-1}`, "invalid_field"},
		{"malformed json", `{`, "bad_request"},
		{"unknown wins over invalid", `{"id":"BAD ID","nope":1}`, "unknown_field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, trail := newAPIWithTrail(t)
			admin(t, ts, "POST", "/api/admin/accounts", tc.body)
			if got := readTrail(t, trail); !strings.Contains(got, `"reason":"`+tc.want+`"`) {
				t.Errorf("want reason %q:\n%s", tc.want, got)
			}
		})
	}
}

// Bound what a single rejection can append: field names are attacker
// influenced, and the trail is fsynced for account.* events.
func TestRejectionFieldListIsBounded(t *testing.T) {
	var ve ValidationErrors
	for i := 0; i < maxLoggedFields*3; i++ {
		ve.add("field"+itoa(i), "bad")
	}
	if got := len(ve.FieldNames()); got != maxLoggedFields {
		t.Errorf("field list not capped: got %d, want %d", got, maxLoggedFields)
	}

	ve = ValidationErrors{}
	ve.add(strings.Repeat("n", maxLoggedFieldName*4), "bad")
	if got := len(ve.FieldNames()[0]); got > maxLoggedFieldName+4 {
		t.Errorf("field name not truncated: %d chars", got)
	}
}

func TestSafeLogValue(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", "plain"},
		{"with\nnewline", "withnewline"},
		{"with\r\ncrlf", "withcrlf"},
		{"tab\there", "tabhere"},
		{"nul\x00byte", "nulbyte"},
	} {
		if got := safeLogValue(tc.in, 64); got != tc.want {
			t.Errorf("safeLogValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
