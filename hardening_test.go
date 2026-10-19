package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for the 2026-10 security review of v0.4.0.

// logCapture swaps the process logger's output for a buffer. log's own
// mutex serialises writers; the extra one covers the test's read.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func captureLog(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	prev := log.Writer()
	log.SetOutput(c)
	t.Cleanup(func() { log.SetOutput(prev) })
	return c
}

func TestCheckAdminToken(t *testing.T) {
	good := []string{
		strings.Repeat("a", minTokenLen),
		"xadm_" + strings.Repeat("0", 64),
		strings.Repeat("z", maxTokenLen),
	}
	for _, tok := range good {
		if err := checkAdminToken(tok); err != nil {
			t.Errorf("%d-char token refused: %v", len(tok), err)
		}
	}
	bad := map[string]string{
		"a":                                   "at least",
		strings.Repeat("a", minTokenLen-1):    "at least",
		strings.Repeat("a", maxTokenLen+1):    "at most",
		"has a space in it, sixteen+ chars":   "printable",
		"newline\nin the middle of a token":   "printable",
		"non-ascii-é-token-long-enough":       "printable",
		"tab\tinside-a-sufficiently-long-one": "printable",
	}
	for tok, want := range bad {
		err := checkAdminToken(tok)
		if err == nil {
			t.Errorf("token %q should be refused", tok)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("token %q: want error containing %q, got %q", tok, want, err)
		}
		if len(tok) >= 8 && strings.Contains(err.Error(), tok) {
			t.Errorf("error echoes the token: %q", err)
		}
	}
}

// %0A survives URL decoding, so a path containing it would forge a second
// process-log line if it were printed raw.
func TestAdminDeniedLogCannotBeForged(t *testing.T) {
	logs := captureLog(t)
	ts := newAPI(t)

	r := call(t, ts, "GET", "/api/admin/accounts/foo%0aFAKE%20EVENT:%20account.delete%0d%0a", "", nil)
	if r.status != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", r.status, r.body)
	}

	out := logs.String()
	var denied []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "admin auth denied") {
			denied = append(denied, line)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "FAKE EVENT") {
			t.Errorf("forged log line made it into the process log: %q", line)
		}
	}
	if len(denied) != 1 {
		t.Fatalf("want exactly one denial line, got %d in:\n%s", len(denied), out)
	}
	if strings.Contains(denied[0], "\r") {
		t.Errorf("carriage return survived into the log line: %q", denied[0])
	}
	if !strings.Contains(denied[0], "fooFAKE EVENT: account.delete") {
		t.Errorf("denial line lost the (neutralised) path: %q", denied[0])
	}
}

func TestRedactTargetErr(t *testing.T) {
	const secret = "sk_live_abc123"
	target := "https://partner.example/v1/pay?api_key=" + secret

	// The configured string and net/http's re-serialised form differ here:
	// the raw target carries an unescaped space the client will encode.
	rawTarget := "https://partner.example/v1/pay?api_key=" + secret + "&memo=a b"
	serialised := "https://partner.example/v1/pay?api_key=" + secret + "&memo=a%20b"

	for _, tc := range []struct {
		name string
		err  error
		raw  string
	}{
		{"same form", &url.Error{Op: "Post", URL: target, Err: errors.New("dial tcp 10.0.0.1:443: connect: connection refused")}, target},
		{"re-serialised form", &url.Error{Op: "Post", URL: serialised, Err: errors.New("context deadline exceeded")}, rawTarget},
		{"wrapped", fmt.Errorf("forward: %w", &url.Error{Op: "Post", URL: target, Err: errors.New("EOF")}), "https://elsewhere.example/"},
	} {
		got := redactTargetErr(tc.err, tc.raw)
		if strings.Contains(got, secret) {
			t.Errorf("%s: credential survived redaction: %s", tc.name, got)
		}
		if !strings.Contains(got, "https://partner.example") {
			t.Errorf("%s: host should stay for diagnosis: %s", tc.name, got)
		}
	}
	if got := redactTargetErr(nil, target); got != "" {
		t.Errorf("nil error should redact to empty, got %q", got)
	}
}

// End to end: a failed forward must not put the target's query-string
// credential in the activity ring or on the audit trail.
func TestUpstreamFailureDoesNotLogTargetCredential(t *testing.T) {
	const secret = "sk_live_must_not_be_logged"
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	acct := mustCreate(t, ts, map[string]any{"id": "leaky", "enabled": true,
		"b": map[string]any{"target_url": "http://127.0.0.1:1/pay?api_key=" + secret}})

	r := call(t, ts, "POST", "/t/leaky/a2b", sideToken(acct, "a"), map[string]any{"x": 1})
	if r.status != http.StatusBadGateway {
		t.Fatalf("want 502, got %d: %s", r.status, r.body)
	}
	if bytes.Contains(r.body, []byte(secret)) {
		t.Errorf("credential reached the caller: %s", r.body)
	}

	entries := srv.logs.List("leaky", 10)
	if len(entries) == 0 || entries[0].Err == "" {
		t.Fatalf("expected a logged upstream error, got %+v", entries)
	}
	for _, e := range entries {
		if strings.Contains(e.Err, secret) {
			t.Errorf("credential in the activity ring: %s", e.Err)
		}
	}
	if !strings.Contains(entries[0].Err, "127.0.0.1:1") {
		t.Errorf("host should remain for diagnosis: %s", entries[0].Err)
	}

	trail, err := os.ReadFile(srv.audit.f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(trail, []byte(secret)) {
		t.Errorf("credential on the audit trail:\n%s", trail)
	}
	if !bytes.Contains(trail, []byte("ingest.error")) {
		t.Errorf("expected an ingest.error record:\n%s", trail)
	}
}

// Go strips Authorization on a cross-origin redirect but not
// X-Xlate-Signature, so following one would give a third party a valid
// HMAC and the alert body.
func TestAlerterDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	var gotSig atomic.Value
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotSig.Store(r.Header.Get("X-Xlate-Signature"))
	}))
	defer elsewhere.Close()
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusFound)
	}))
	defer hook.Close()

	a := NewAlerter(hook.URL, "shared-secret", nil)
	err := a.post([]byte(`{"event":"tripwire.fired"}`))
	if err == nil {
		t.Fatal("a 302 from the webhook must be reported as a failure")
	}
	var se *httpStatusError
	if !errors.As(err, &se) || se.code != http.StatusFound {
		t.Errorf("want httpStatusError 302, got %T %v", err, err)
	}
	if n := hits.Load(); n != 0 {
		sig, _ := gotSig.Load().(string)
		t.Errorf("redirect target was contacted %d time(s), signature %q", n, sig)
	}
}

func TestAdminUIRefusesFraming(t *testing.T) {
	ts := newAPI(t)
	r := call(t, ts, "GET", "/admin/", "", nil)
	if r.status != http.StatusOK {
		t.Fatalf("want 200, got %d", r.status)
	}
	if got := r.hdr.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options: want DENY, got %q", got)
	}
	if csp := r.hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP lacks frame-ancestors 'none': %s", csp)
	}
}

// A client that declares a body and then stalls must not hold the
// connection: net/http drains the unread body before writing even a 401,
// and without ReadTimeout that drain has no deadline. The production
// listener config is used with only its timeout shortened for the test.
func TestStalledBodyDoesNotHoldConnection(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	mustCreate(t, ts, map[string]any{"id": "stall", "enabled": true})

	// The real routes behind the production listener config. An
	// unauthenticated ingest is refused without reading the body, which
	// is the path that exposed the drain.
	hs := newHTTPServer("", srv.routes())
	if hs.ReadTimeout <= 0 || hs.ReadTimeout > time.Minute {
		t.Fatalf("ReadTimeout must be set and bounded, got %v", hs.ReadTimeout)
	}
	if hs.ReadHeaderTimeout <= 0 || hs.IdleTimeout <= 0 {
		t.Fatalf("header/idle timeouts must stay set: %v / %v", hs.ReadHeaderTimeout, hs.IdleTimeout)
	}
	hs.ReadTimeout = time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	defer hs.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST /t/stall/a2b HTTP/1.1\r\nHost: x\r\nContent-Length: 200000\r\n\r\n")
	start := time.Now()
	_ = c.SetReadDeadline(start.Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no response to a stalled-body request within 10s (ReadTimeout not enforced): %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 401") {
		t.Errorf("unexpected response: %q", buf[:n])
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("response took %v with a 1s ReadTimeout", d)
	} else {
		t.Logf("stalled request answered after %v", d)
	}
}

// encoding/json refuses nesting past 10000 levels, so a body-cap-sized
// nest is rejected rather than overflowing the stack. Pinned because the
// decoder's depth guard is what the data plane relies on.
func TestHugeNestingIsRefusedNotFatal(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "nest", "enabled": true})

	const depth = 300000
	body := strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat(`}`, depth)
	if len(body) > 2<<20 {
		t.Fatal("test body exceeds the default body cap; shrink depth")
	}
	r := call(t, ts, "POST", "/t/nest/a2b", sideToken(acct, "a"), body)
	if r.status < 400 || r.status >= 500 {
		t.Errorf("want a 4xx for an over-deep body, got %d: %s", r.status, r.body)
	}
	// The server must still answer afterwards.
	if h := call(t, ts, "GET", "/healthz", "", nil); h.status != http.StatusOK {
		t.Errorf("server unhealthy after the deep body: %d", h.status)
	}
}
