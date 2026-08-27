package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Paths the in-process suite did not reach: read-only admin routes, the
// delete path, the tripwire admin surface, and the whole alert delivery
// chain. The end-to-end suite exercises most of them, but it drives a
// subprocess, so none of it registers as coverage — and behaviour a
// coverage report cannot see is behaviour nobody notices going stale.

func TestAdminReadRoutes(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, map[string]any{"id": "zeta", "name": "Zeta"})
	mustCreate(t, ts, map[string]any{"id": "alpha", "name": "Alpha"})

	t.Run("list is sorted by id", func(t *testing.T) {
		r := admin(t, ts, "GET", "/api/admin/accounts", nil)
		if r.status != 200 {
			t.Fatalf("want 200, got %d: %s", r.status, r.body)
		}
		var list []map[string]any
		if err := json.Unmarshal(r.body, &list); err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0]["id"] != "alpha" || list[1]["id"] != "zeta" {
			t.Errorf("want [alpha zeta], got %s", r.body)
		}
	})

	t.Run("get returns one account", func(t *testing.T) {
		r := admin(t, ts, "GET", "/api/admin/accounts/alpha", nil)
		if r.status != 200 || r.json(t)["name"] != "Alpha" {
			t.Errorf("want Alpha, got %d %s", r.status, r.body)
		}
	})

	t.Run("healthz counts accounts and is unauthenticated", func(t *testing.T) {
		r := call(t, ts, "GET", "/healthz", "", nil)
		if r.status != 200 {
			t.Fatalf("want 200, got %d", r.status)
		}
		h := r.json(t)
		if h["ok"] != true || h["version"] != version {
			t.Errorf("unexpected health: %s", r.body)
		}
		if got := h["accounts"]; got == nil || got.(interface{ String() string }).String() != "2" {
			t.Errorf("accounts: want 2, got %v", got)
		}
	})

	t.Run("admin ui is served with security headers", func(t *testing.T) {
		r := call(t, ts, "GET", "/admin/", "", nil)
		if r.status != 200 || !strings.Contains(string(r.body), "<html") {
			t.Fatalf("want HTML, got %d: %s", r.status, r.body)
		}
		if !strings.Contains(r.hdr.Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("missing CSP: %q", r.hdr.Get("Content-Security-Policy"))
		}
		if r.hdr.Get("X-Content-Type-Options") != "nosniff" {
			t.Error("missing nosniff")
		}
	})

	t.Run("root redirects to the console", func(t *testing.T) {
		r := call(t, ts, "GET", "/", "", nil)
		if r.status != http.StatusFound || r.hdr.Get("Location") != "/admin/" {
			t.Errorf("want 302 -> /admin/, got %d %q", r.status, r.hdr.Get("Location"))
		}
	})
}

func TestAccountDelete(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, map[string]any{"id": "doomed"})

	if r := admin(t, ts, "DELETE", "/api/admin/accounts/doomed", nil); r.status != 204 {
		t.Fatalf("delete: want 204, got %d: %s", r.status, r.body)
	}
	if r := admin(t, ts, "GET", "/api/admin/accounts/doomed", nil); r.status != 404 {
		t.Errorf("after delete: want 404, got %d", r.status)
	}
	if r := admin(t, ts, "DELETE", "/api/admin/accounts/doomed", nil); r.status != 404 {
		t.Errorf("second delete: want 404, got %d", r.status)
	}
	if r := call(t, ts, "GET", "/healthz", "", nil); r.json(t)["accounts"].(interface{ String() string }).String() != "0" {
		t.Errorf("account count did not drop: %s", r.body)
	}
}

func TestTripwireAdminSurface(t *testing.T) {
	ts := newAPI(t, func(s *Server) {
		s.trip = NewTripwire(1, time.Minute, time.Hour, "lock")
	})
	acct := mustCreate(t, ts, map[string]any{"id": "tw", "enabled": true,
		"b": map[string]any{"target_url": "http://127.0.0.1:1/never"}})

	t.Run("status starts armed", func(t *testing.T) {
		r := admin(t, ts, "GET", "/api/admin/tripwire", nil)
		if r.status != 200 {
			t.Fatalf("want 200, got %d", r.status)
		}
		st, _ := r.json(t)["tw"].(map[string]any)
		if st == nil || st["state"] != "armed" {
			t.Errorf("want armed, got %s", r.body)
		}
	})

	// Threshold 1 fires on the second refusal.
	for i := 0; i < 2; i++ {
		call(t, ts, "POST", "/t/tw/a2b", "bad-token", map[string]any{"x": 1})
	}

	t.Run("status reports the lock", func(t *testing.T) {
		r := admin(t, ts, "GET", "/api/admin/tripwire", nil)
		st, _ := r.json(t)["tw"].(map[string]any)
		if st == nil || st["state"] != "locked" {
			t.Fatalf("want locked, got %s", r.body)
		}
		if st["unlock_in_sec"] == nil {
			t.Error("locked state should report unlock_in_sec")
		}
	})

	t.Run("valid credentials are locked out too", func(t *testing.T) {
		r := call(t, ts, "POST", "/t/tw/a2b", sideToken(acct, "a"), map[string]any{"x": 1})
		if r.status != 429 || r.json(t)["code"] != "account_locked" {
			t.Errorf("want 429/account_locked, got %d %s", r.status, r.body)
		}
		if r.hdr.Get("Retry-After") == "" {
			t.Error("missing Retry-After")
		}
	})

	t.Run("reset clears the lock", func(t *testing.T) {
		r := admin(t, ts, "POST", "/api/admin/accounts/tw/tripwire/reset", nil)
		if r.status != 200 {
			t.Fatalf("want 200, got %d: %s", r.status, r.body)
		}
		st, _ := r.json(t)["tripwire"].(map[string]any)
		if st == nil || st["state"] != "armed" {
			t.Errorf("want armed after reset, got %s", r.body)
		}
	})

	t.Run("reset of an unknown account is 404", func(t *testing.T) {
		if r := admin(t, ts, "POST", "/api/admin/accounts/ghost/tripwire/reset", nil); r.status != 404 {
			t.Errorf("want 404, got %d", r.status)
		}
	})
}

// The alert path: trip -> audit -> signed webhook -> containment.
func TestAlertDeliveryAndFreeze(t *testing.T) {
	type got struct {
		body []byte
		sig  string
	}
	received := make(chan got, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		received <- got{b, r.Header.Get("X-Xlate-Signature")}
		w.WriteHeader(200)
	}))
	defer hook.Close()

	ts := newAPI(t, func(s *Server) {
		s.trip = NewTripwire(0, time.Minute, time.Hour, "freeze")
		s.alerter = NewAlerter(hook.URL, "shared-secret", s.audit)
	})
	mustCreate(t, ts, map[string]any{"id": "frz", "enabled": true,
		"b": map[string]any{"target_url": "http://127.0.0.1:1/never"}})

	call(t, ts, "POST", "/t/frz/a2b", "bad-token", map[string]any{"x": 1})

	select {
	case a := <-received:
		if a.sig == "" || !strings.HasPrefix(a.sig, "sha256=") {
			t.Errorf("alert not signed: %q", a.sig)
		}
		if !strings.Contains(string(a.body), `"account":"frz"`) {
			t.Errorf("unexpected alert payload: %s", a.body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no alert delivered")
	}

	// freeze must persist enabled=false.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if admin(t, ts, "GET", "/api/admin/accounts/frz", nil).json(t)["enabled"] == false {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("freeze mode did not persist enabled=false")
}

func TestAlerterHandlesFailureAndNilCases(t *testing.T) {
	if NewAlerter("", "secret", nil) != nil {
		t.Error("an empty URL must produce no alerter")
	}
	var nilAlerter *Alerter
	nilAlerter.Send(map[string]any{"event": "x"}) // must not panic

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	a := NewAlerter(bad.URL, "", nil)
	if err := a.post([]byte(`{"event":"x"}`)); err == nil {
		t.Error("a 500 from the webhook should be an error")
	} else if !strings.Contains(err.Error(), "webhook returned") {
		t.Errorf("unexpected error text: %v", err)
	}

	unreachable := NewAlerter("http://127.0.0.1:1/nope", "", nil)
	if err := unreachable.post([]byte(`{}`)); err == nil {
		t.Error("an unreachable webhook should be an error")
	}
}

func TestClassifyNetErr(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "nope.invalid"}, "dns"},
		// A DNS timeout stays "dns": the more specific label is the more
		// useful one for an operator.
		{"dns timeout", &net.DNSError{Err: "timeout", IsTimeout: true}, "dns"},
		{"timeout", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, "timeout"},
		{"deadline", context.DeadlineExceeded, "timeout"},
		{"connect", &net.OpError{Op: "dial", Err: errors.New("refused")}, "connect"},
		{"other", errors.New("something else"), "other"},
		{"wrapped connect", errors.Join(errors.New("ctx"), &net.OpError{Op: "dial", Err: errors.New("x")}), "connect"},
	} {
		if got := classifyNetErr(tc.err); got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("want short, got %q", got)
	}
	got := truncate(strings.Repeat("x", 50), 10)
	if len([]rune(got)) != 11 || !strings.HasSuffix(got, "…") {
		t.Errorf("want 10 chars plus an ellipsis, got %q", got)
	}
}

func TestNewAdminTokenIsDistinctAndPrefixed(t *testing.T) {
	a, b := newAdminToken(), newAdminToken()
	if a == b {
		t.Error("admin tokens must not repeat")
	}
	for _, tok := range []string{a, b} {
		if !strings.HasPrefix(tok, "xadm_") {
			t.Errorf("missing prefix: %q", tok)
		}
		if len(tok) < minTokenLen {
			t.Errorf("token too short: %q", tok)
		}
		if !headerSafe(tok) {
			t.Errorf("token is not header-safe: %q", tok)
		}
	}
}

func TestDirectionStringAndReverseRoundTrip(t *testing.T) {
	for _, s := range []string{"a2b", "b2a"} {
		d, ok := ParseDirection(s)
		if !ok {
			t.Fatalf("%s should parse", s)
		}
		if d.String() != s {
			t.Errorf("String(): want %q, got %q", s, d.String())
		}
		if d.Reverse().Reverse() != d {
			t.Errorf("double reverse should be identity for %s", s)
		}
		if d.Reverse() == d {
			t.Errorf("reverse of %s should differ", s)
		}
	}
	if _, ok := ParseDirection("sideways"); ok {
		t.Error("sideways should not parse")
	}
}

func TestDisplayAddr(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{":8080", "localhost:8080"},
		{"127.0.0.1:9000", "127.0.0.1:9000"},
		{"0.0.0.0:80", "0.0.0.0:80"},
	} {
		if got := displayAddr(tc.in); got != tc.want {
			t.Errorf("displayAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRingListFiltersAndBounds(t *testing.T) {
	r := NewRing(3)
	if NewRing(0) == nil {
		t.Error("a zero-size ring should still be usable")
	}
	for i, acct := range []string{"a", "b", "a", "c"} {
		r.Add(LogEntry{Account: acct, Status: 200 + i})
	}
	// Capacity 3: the oldest entry was overwritten.
	if got := len(r.List("", 100)); got != 3 {
		t.Errorf("want 3 entries, got %d", got)
	}
	if got := r.List("a", 100); len(got) != 1 {
		t.Errorf("want 1 entry for account a, got %d", len(got))
	}
	if got := r.List("", 2); len(got) != 2 {
		t.Errorf("limit ignored: got %d", len(got))
	}
	// Newest first.
	if got := r.List("", 1); len(got) != 1 || got[0].Account != "c" {
		t.Errorf("want newest first, got %+v", got)
	}
}
