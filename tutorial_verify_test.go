//go:build tutorial

// Replays TUTORIAL.md against a real server and prints the actual
// responses, so the documented output cannot drift from reality.
//
//	go test -tags tutorial -run TestTutorial -v ./...
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTutorialTranscript(t *testing.T) {
	psp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		t.Logf("\n[§5] PSP received: %s", b)
		t.Logf("[§5] PSP saw auth: %s", r.Header.Get("Authorization"))
		t.Logf("[§5] PSP saw Idempotency-Key: %s", r.Header.Get("Idempotency-Key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"payment_proof":"P-777","status":"settled"}`)
	}))
	defer psp.Close()

	ts := newAPI(t, func(s *Server) {
		s.trip = NewTripwire(5, 5*time.Minute, 15*time.Minute, "lock")
	})

	pretty := func(b []byte) string {
		var v any
		if json.Unmarshal(b, &v) != nil {
			return string(b)
		}
		out, _ := json.MarshalIndent(v, "", "  ")
		return string(out)
	}

	// -- §2 create -----------------------------------------------------
	r := admin(t, ts, "POST", "/api/admin/accounts", `{
    "id": "acme",
    "name": "Acme billing PSP",
    "a": {"label": "Acme"},
    "b": {"label": "PSP"},
    "map": [
      {"a": "payment_id",  "b": "payment_proof"},
      {"a": "customer.id", "b": "cust_id"},
      {"a": "amount",      "b": "value"}
    ]
  }`)
	t.Logf("\n[§2] POST /api/admin/accounts -> %d\n%s", r.status, pretty(r.body))
	if r.status != 201 {
		t.Fatal("create failed")
	}
	acct := r.json(t)
	atok := sideToken(acct, "a")

	// -- §3 dry run ----------------------------------------------------
	r = admin(t, ts, "POST", "/api/admin/accounts/acme/test", `{
    "direction": "a2b",
    "payload": {
      "payment_id": "P-777",
      "customer": {"id": "C-1", "name": "Ada"},
      "amount": 1999,
      "internal_note": "not mapped"
    }
  }`)
	t.Logf("\n[§3] dry run -> %d\n%s", r.status, pretty(r.body))

	// -- §4/§5 real request --------------------------------------------
	r = admin(t, ts, "PUT", "/api/admin/accounts/acme", `{
    "name": "Acme billing PSP",
    "a": {"label": "Acme"},
    "b": {"label": "PSP", "target_url": "`+psp.URL+`/payments",
          "outbound_token": "psp-secret-credential-value"},
    "map": [
      {"a": "payment_id",  "b": "payment_proof"},
      {"a": "customer.id", "b": "cust_id"},
      {"a": "amount",      "b": "value"}
    ]
  }`)
	if r.status != 200 {
		t.Fatalf("[§4] PUT failed: %d %s", r.status, r.body)
	}

	r = call(t, ts, "POST", "/t/acme/a2b", atok,
		`{"payment_id":"P-777","customer":{"id":"C-1"},"amount":1999}`,
		map[string]string{"Idempotency-Key": "order-777"})
	t.Logf("\n[§5] ingest -> %d\n  X-Xlate-Applied: %q\n  X-Xlate-Warnings: %q\n  body: %s",
		r.status, r.hdr.Get("X-Xlate-Applied"), r.hdr.Get("X-Xlate-Warnings"), r.body)

	// -- §6 date transform ---------------------------------------------
	r = admin(t, ts, "PUT", "/api/admin/accounts/acme", `{
    "name": "Acme billing PSP",
    "a": {"label": "Acme"},
    "b": {"label": "PSP", "target_url": "`+psp.URL+`/payments",
          "outbound_token": "psp-secret-credential-value"},
    "map": [
      {"a": "payment_id",  "b": "payment_proof"},
      {"a": "customer.id", "b": "cust_id"},
      {"a": "amount",      "b": "value"},
      {"a": "created_at",  "b": "created_epoch",
       "transform": {"kind": "date", "a_format": "rfc3339", "b_format": "unix"}}
    ]
  }`)
	if r.status != 200 {
		t.Fatalf("[§6] PUT with transform failed: %d %s", r.status, r.body)
	}

	r = admin(t, ts, "POST", "/api/admin/accounts/acme/test",
		`{"direction":"a2b","payload":{"created_at":"2024-03-01T09:00:00Z"}}`)
	t.Logf("\n[§6] a2b date -> %s", strings.TrimSpace(string(r.body)))

	r = admin(t, ts, "POST", "/api/admin/accounts/acme/test",
		`{"direction":"b2a","payload":{"created_epoch":1709283600}}`)
	t.Logf("[§6] b2a date -> %s", strings.TrimSpace(string(r.body)))

	r = admin(t, ts, "PUT", "/api/admin/accounts/acme",
		`{"map":[{"a":"created_at","b":"created_epoch",
       "transform":{"kind":"date","a_format":"YYYY-MM-DD","b_format":"unix"}}]}`)
	t.Logf("\n[§6] bad layout -> %d\n%s", r.status, pretty(r.body))

	// -- §8 rotate -----------------------------------------------------
	r = admin(t, ts, "POST", "/api/admin/accounts/acme/rotate", `{"side":"a","kind":"inbound"}`)
	t.Logf("\n[§8] rotate -> %d %s", r.status, strings.TrimSpace(string(r.body)))
	atok = sideToken(admin(t, ts, "GET", "/api/admin/accounts/acme", nil).json(t), "a")

	// -- §9 tripwire ---------------------------------------------------
	codes := []string{}
	for i := 0; i < 6; i++ {
		bad := call(t, ts, "POST", "/t/acme/a2b", "wrong", `{}`)
		codes = append(codes, itoa(bad.status))
	}
	t.Logf("\n[§9] six bad tokens -> %s", strings.Join(codes, " "))

	r = call(t, ts, "POST", "/t/acme/a2b", atok, `{"payment_id":"P-1"}`)
	t.Logf("[§9] valid token after trip -> %d  Retry-After: %q\n  %s",
		r.status, r.hdr.Get("Retry-After"), strings.TrimSpace(string(r.body)))

	r = admin(t, ts, "GET", "/api/admin/tripwire", nil)
	t.Logf("[§9] tripwire status -> %s", strings.TrimSpace(string(r.body)))

	// -- unknown field -------------------------------------------------
	r = admin(t, ts, "POST", "/api/admin/accounts", `{"id":"x","target_uri":"http://x/"}`)
	t.Logf("\n[troubleshooting] unknown field -> %d\n%s", r.status, pretty(r.body))

	// -- healthz -------------------------------------------------------
	r = call(t, ts, "GET", "/healthz", "", nil)
	t.Logf("\n[§1] healthz -> %s", strings.TrimSpace(string(r.body)))
}
