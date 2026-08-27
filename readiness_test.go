package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// clientIP feeds the tripwire's per-IP tally and every audit record, so
// both proxy modes need pinning: honouring the first X-Forwarded-For hop
// when -trust-proxy is set, and — more important — ignoring the header
// entirely when it is not, since otherwise any client could launder its
// address in the security logs.
func TestClientIPTrustProxy(t *testing.T) {
	req := func(xff string) *http.Request {
		r := httptest.NewRequest("POST", "/t/x/a2b", nil)
		r.RemoteAddr = "203.0.113.9:4242"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	trusted := &Server{trustProxy: true}
	direct := &Server{trustProxy: false}

	if got := trusted.clientIP(req("198.51.100.7, 10.0.0.1")); got != "198.51.100.7" {
		t.Errorf("trust-proxy: want first hop 198.51.100.7, got %q", got)
	}
	if got := trusted.clientIP(req("198.51.100.7")); got != "198.51.100.7" {
		t.Errorf("trust-proxy single hop: want 198.51.100.7, got %q", got)
	}
	if got := trusted.clientIP(req("")); got != "203.0.113.9" {
		t.Errorf("trust-proxy without header: want peer address, got %q", got)
	}
	if got := direct.clientIP(req("198.51.100.7")); got != "203.0.113.9" {
		t.Errorf("untrusted: X-Forwarded-For must be ignored, got %q", got)
	}
}

// The request leg enforces -max-body via MaxBytesReader; the response
// leg has its own cap on what it will read back from the destination.
// Untested, a regression here would either truncate upstream responses
// silently or buffer unbounded ones.
func TestIngestResponseOversize(t *testing.T) {
	big := strings.Repeat("x", 8192)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"pad":"`+big+`"}`)
	}))
	defer up.Close()

	ts := newAPI(t, func(s *Server) { s.maxBody = 2048 })
	acct := mustCreate(t, ts, map[string]any{
		"id": "oversize", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "x", "b": "y"}},
	})
	tok := sideToken(acct, "a")

	r := call(t, ts, "POST", "/t/oversize/a2b", tok, map[string]any{"x": 1})
	if r.status != 502 {
		t.Fatalf("want 502 for oversized upstream response, got %d: %s", r.status, r.body)
	}
	if got := r.json(t)["code"]; got != "upstream_oversize" {
		t.Errorf("code want upstream_oversize, got %v", got)
	}
}

// Redirects are relayed, never followed — and a relayed redirect must
// keep its Location header or the caller gets a bare 3xx it cannot act
// on. Retry-After passes through for the same reason on relayed 429s.
func TestIngestRelaysRedirectLocation(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.example/v2/endpoint")
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer up.Close()

	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{
		"id": "redir", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "x", "b": "y"}},
	})
	tok := sideToken(acct, "a")

	r := call(t, ts, "POST", "/t/redir/a2b", tok, map[string]any{"x": 1})
	if r.status != http.StatusTemporaryRedirect {
		t.Fatalf("want 307 relayed, got %d: %s", r.status, r.body)
	}
	if got := r.hdr.Get("Location"); got != "https://elsewhere.example/v2/endpoint" {
		t.Errorf("Location not relayed: %q", got)
	}
	if got := r.hdr.Get("Retry-After"); got != "120" {
		t.Errorf("Retry-After not relayed: %q", got)
	}
}
