//go:build e2e

// End-to-end verification of the shipped binary.
//
// These tests build xlate, run it as a real subprocess against a real
// mock upstream, and assert the behaviour the README documents. They
// cover server.go, which the unit suite does not touch at all.
//
//	go test -tags e2e -v ./...
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const adminTok = "xadm_e2e_pinned_token_for_tests"

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "xlate-bin")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "xlate")
		if isWindows() {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, ".")
		if b, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build failed: %v\n%s", err, b)
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

func isWindows() bool { return os.PathSeparator == '\\' }

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// instance is a running xlate subprocess plus the paths it writes to.
type instance struct {
	base      string
	dir       string
	statePath string
	auditPath string
	cmd       *exec.Cmd
	log       *bytes.Buffer
	stopped   bool
}

// start launches xlate with a pinned admin token on a free port and
// waits for /healthz to answer.
func start(t *testing.T, extra ...string) *instance {
	t.Helper()
	bin := binary(t)
	dir := t.TempDir()
	port := freePort(t)
	in := &instance{
		base:      fmt.Sprintf("http://127.0.0.1:%d", port),
		dir:       dir,
		statePath: filepath.Join(dir, "state.json"),
		auditPath: filepath.Join(dir, "audit.jsonl"),
		log:       &bytes.Buffer{},
	}
	args := append([]string{
		"-listen", fmt.Sprintf("127.0.0.1:%d", port),
		"-state", in.statePath,
		"-audit", in.auditPath,
		"-admin-token", adminTok,
	}, extra...)
	in.cmd = exec.Command(bin, args...)
	in.cmd.Stdout = in.log
	in.cmd.Stderr = in.log
	if err := in.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.stop() })

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(in.base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return in
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("xlate did not become ready\n%s", in.log.String())
	return nil
}

func (in *instance) stop() {
	if in.stopped {
		return
	}
	in.stopped = true
	_ = in.cmd.Process.Kill()
	_, _ = in.cmd.Process.Wait()
}

// do issues a request and returns status, headers and body.
func do(t *testing.T, method, url, token string, body any, hdr map[string]string) (int, http.Header, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			rdr = strings.NewReader(v)
		case []byte:
			rdr = bytes.NewReader(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			rdr = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	// Do not follow redirects: we assert on 3xx directly.
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("response is not a JSON object: %v\nbody: %s", err, b)
	}
	return m
}

// upstream is the mock "System B".
type upstream struct {
	*httptest.Server
	mu     sync.Mutex
	body   []byte
	hdr    http.Header
	status int
	ct     string
	reply  string
	hits   int
}

func newUpstream() *upstream {
	u := &upstream{status: 200, ct: "application/json", reply: `{"ok":true}`}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.body, u.hdr, u.hits = b, r.Header.Clone(), u.hits+1
		status, ct, reply := u.status, u.ct, u.reply
		u.mu.Unlock()
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	return u
}

func (u *upstream) got() (map[string]any, http.Header, int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(u.body))
	dec.UseNumber()
	_ = dec.Decode(&m)
	return m, u.hdr, u.hits
}

func (u *upstream) respond(status int, ct, body string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status, u.ct, u.reply = status, ct, body
}

// mkAccount creates an account and returns the stored document.
func mkAccount(t *testing.T, in *instance, acct map[string]any) map[string]any {
	t.Helper()
	st, _, body := do(t, "POST", in.base+"/api/admin/accounts", adminTok, acct, nil)
	if st != 201 {
		t.Fatalf("create account: want 201, got %d: %s", st, body)
	}
	return decode(t, body)
}

func endpoint(m map[string]any, side string) map[string]any {
	return m[side].(map[string]any)
}

func inboundToken(m map[string]any, side string) string {
	return endpoint(m, side)["inbound_token"].(string)
}

// ---------------------------------------------------------------------------

func TestHealthAndRootRedirect(t *testing.T) {
	in := start(t)

	st, _, body := do(t, "GET", in.base+"/healthz", "", nil, nil)
	if st != 200 {
		t.Fatalf("healthz: want 200, got %d", st)
	}
	h := decode(t, body)
	if h["ok"] != true {
		t.Errorf("healthz ok: want true, got %v", h["ok"])
	}
	// Pinned to the constant so a version bump cannot drift from what the
	// binary actually reports.
	if h["version"] != version {
		t.Errorf("version: want %s, got %v", version, h["version"])
	}

	st, hdr, _ := do(t, "GET", in.base+"/", "", nil, nil)
	if st != http.StatusFound {
		t.Errorf("GET /: want 302, got %d", st)
	}
	if loc := hdr.Get("Location"); loc != "/admin/" {
		t.Errorf("GET / Location: want /admin/, got %q", loc)
	}
}

func TestAdminAuthRequired(t *testing.T) {
	in := start(t)

	for _, tc := range []struct{ name, token string }{
		{"no token", ""},
		{"wrong token", "xadm_nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, hdr, body := do(t, "GET", in.base+"/api/admin/accounts", tc.token, nil, nil)
			if st != 401 {
				t.Fatalf("want 401, got %d: %s", st, body)
			}
			if got := decode(t, body)["code"]; got != "unauthorized" {
				t.Errorf("code: want unauthorized, got %v", got)
			}
			if !strings.Contains(hdr.Get("WWW-Authenticate"), "xlate-admin") {
				t.Errorf("missing WWW-Authenticate challenge, got %q", hdr.Get("WWW-Authenticate"))
			}
		})
	}

	// X-Api-Key is documented as an alternative credential header.
	st, _, body := do(t, "GET", in.base+"/api/admin/accounts", "", nil,
		map[string]string{"X-Api-Key": adminTok})
	if st != 200 {
		t.Errorf("X-Api-Key fallback: want 200, got %d: %s", st, body)
	}
}

func TestAccountLifecycleAndValidation(t *testing.T) {
	in := start(t)

	acct := mkAccount(t, in, map[string]any{
		"id": "acme", "name": "Acme", "enabled": true,
		"a":   map[string]any{"label": "A", "target_url": "http://127.0.0.1:1/a"},
		"b":   map[string]any{"label": "B", "target_url": "http://127.0.0.1:1/b"},
		"map": []map[string]any{{"a": "payment_id", "b": "payment_proof"}},
	})

	// Inbound tokens are generated when the caller leaves them blank.
	for _, side := range []string{"a", "b"} {
		if tok := inboundToken(acct, side); !strings.HasPrefix(tok, "xk_") {
			t.Errorf("side %s inbound token not generated: %q", side, tok)
		}
	}

	t.Run("duplicate id is a conflict", func(t *testing.T) {
		st, _, _ := do(t, "POST", in.base+"/api/admin/accounts", adminTok,
			map[string]any{"id": "acme"}, nil)
		if st != http.StatusConflict {
			t.Errorf("want 409, got %d", st)
		}
	})

	t.Run("invalid id rejected", func(t *testing.T) {
		for _, id := range []string{"", "Acme", "-bad", "has space", strings.Repeat("a", 64)} {
			st, _, _ := do(t, "POST", in.base+"/api/admin/accounts", adminTok,
				map[string]any{"id": id}, nil)
			if st != 400 {
				t.Errorf("id %q: want 400, got %d", id, st)
			}
		}
	})

	t.Run("non-http target rejected", func(t *testing.T) {
		st, _, _ := do(t, "POST", in.base+"/api/admin/accounts", adminTok,
			map[string]any{"id": "badurl", "a": map[string]any{"target_url": "file:///etc/passwd"}}, nil)
		if st != 400 {
			t.Errorf("want 400, got %d", st)
		}
	})

	t.Run("duplicate mapping field rejected", func(t *testing.T) {
		st, _, _ := do(t, "POST", in.base+"/api/admin/accounts", adminTok,
			map[string]any{"id": "dupe", "map": []map[string]any{
				{"a": "x", "b": "y"}, {"a": "x", "b": "z"},
			}}, nil)
		if st != 400 {
			t.Errorf("want 400, got %d", st)
		}
	})

	t.Run("blank tokens on PUT retain stored values", func(t *testing.T) {
		want := inboundToken(acct, "a")
		st, _, body := do(t, "PUT", in.base+"/api/admin/accounts/acme", adminTok,
			map[string]any{"id": "acme", "name": "Acme Renamed", "enabled": true,
				"a": map[string]any{"label": "A"}, "b": map[string]any{"label": "B"}}, nil)
		if st != 200 {
			t.Fatalf("want 200, got %d: %s", st, body)
		}
		if got := inboundToken(decode(t, body), "a"); got != want {
			t.Errorf("inbound token was not retained: want %q, got %q", want, got)
		}
	})

	t.Run("id is immutable via PUT path", func(t *testing.T) {
		st, _, body := do(t, "PUT", in.base+"/api/admin/accounts/acme", adminTok,
			map[string]any{"id": "hijack", "name": "x"}, nil)
		if st != 200 {
			t.Fatalf("want 200, got %d: %s", st, body)
		}
		if got := decode(t, body)["id"]; got != "acme" {
			t.Errorf("path must be authoritative for id: got %v", got)
		}
	})

	t.Run("rotate returns a new token and persists it", func(t *testing.T) {
		before := inboundToken(acct, "a")
		st, _, body := do(t, "POST", in.base+"/api/admin/accounts/acme/rotate", adminTok,
			map[string]any{"side": "a", "kind": "inbound"}, nil)
		if st != 200 {
			t.Fatalf("want 200, got %d: %s", st, body)
		}
		tok, _ := decode(t, body)["token"].(string)
		if tok == "" || tok == before {
			t.Fatalf("rotate did not produce a new token: %q", tok)
		}
		_, _, get := do(t, "GET", in.base+"/api/admin/accounts/acme", adminTok, nil, nil)
		if got := inboundToken(decode(t, get), "a"); got != tok {
			t.Errorf("rotated token not persisted: want %q, got %q", tok, got)
		}
	})

	t.Run("rotate rejects bad side and kind", func(t *testing.T) {
		for _, p := range []map[string]any{{"side": "c", "kind": "inbound"}, {"side": "a", "kind": "sideways"}} {
			st, _, _ := do(t, "POST", in.base+"/api/admin/accounts/acme/rotate", adminTok, p, nil)
			if st != 400 {
				t.Errorf("%v: want 400, got %d", p, st)
			}
		}
	})

	t.Run("delete then 404", func(t *testing.T) {
		st, _, _ := do(t, "DELETE", in.base+"/api/admin/accounts/acme", adminTok, nil, nil)
		if st != 204 {
			t.Fatalf("delete: want 204, got %d", st)
		}
		st, _, _ = do(t, "GET", in.base+"/api/admin/accounts/acme", adminTok, nil, nil)
		if st != 404 {
			t.Errorf("get after delete: want 404, got %d", st)
		}
	})
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	in := start(t)
	mkAccount(t, in, map[string]any{"id": "persist", "name": "Persisted"})
	in.stop()

	// Relaunch against the same state file.
	port := freePort(t)
	cmd := exec.Command(binary(t),
		"-listen", fmt.Sprintf("127.0.0.1:%d", port),
		"-state", in.statePath, "-audit", in.auditPath, "-admin-token", adminTok)
	buf := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = buf, buf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := http.Get(base + "/healthz"); err == nil {
			r.Body.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	st, _, body := do(t, "GET", base+"/api/admin/accounts/persist", adminTok, nil, nil)
	if st != 200 {
		t.Fatalf("account did not survive restart: %d %s\n%s", st, body, buf)
	}

	// State file must be owner-only where the OS models it.
	if !isWindows() {
		fi, err := os.Stat(in.statePath)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("state file perms: want 0600, got %o", perm)
		}
	}
}

func TestDataPlaneHappyPath(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	acct := mkAccount(t, in, map[string]any{
		"id": "gw", "enabled": true,
		"a": map[string]any{"label": "A", "target_url": "http://127.0.0.1:1/unused"},
		"b": map[string]any{"label": "B", "target_url": up.URL, "outbound_token": "b-outbound-secret"},
		"map": []map[string]any{
			{"a": "payment_id", "b": "payment_proof"},
			{"a": "customer.id", "b": "cust_id"},
		},
	})
	tokA := inboundToken(acct, "a")

	up.respond(200, "application/json", `{"payment_proof":"PROOF-9","cust_id":"C-1","extra":"kept"}`)

	st, hdr, body := do(t, "POST", in.base+"/t/gw/a2b", tokA,
		map[string]any{"payment_id": "P-9", "customer": map[string]any{"id": "C-1"}, "note": "passthrough"},
		map[string]string{"Idempotency-Key": "idem-1", "X-Request-Id": "req-1"})

	if st != 200 {
		t.Fatalf("ingest: want 200, got %d: %s", st, body)
	}

	sent, sentHdr, hits := up.got()
	if hits != 1 {
		t.Fatalf("upstream hits: want 1, got %d", hits)
	}
	t.Run("request fields renamed A->B", func(t *testing.T) {
		if sent["payment_proof"] != "P-9" {
			t.Errorf("payment_id should arrive as payment_proof=P-9, got %v", sent["payment_proof"])
		}
		if _, still := sent["payment_id"]; still {
			t.Errorf("source field payment_id should have been removed, got %v", sent)
		}
		if sent["cust_id"] != "C-1" {
			t.Errorf("customer.id should arrive as cust_id=C-1, got %v", sent["cust_id"])
		}
		if sent["note"] != "passthrough" {
			t.Errorf("unmapped field should pass through, got %v", sent["note"])
		}
		// Documented: extracting the last key leaves the empty parent.
		if c, ok := sent["customer"].(map[string]any); !ok || len(c) != 0 {
			t.Errorf("empty parent object should remain, got %v", sent["customer"])
		}
	})

	t.Run("outbound credentials and correlation headers", func(t *testing.T) {
		if got := sentHdr.Get("Authorization"); got != "Bearer b-outbound-secret" {
			t.Errorf("outbound token: want side B's, got %q", got)
		}
		if got := sentHdr.Get("Idempotency-Key"); got != "idem-1" {
			t.Errorf("Idempotency-Key not passed through: %q", got)
		}
		if got := sentHdr.Get("X-Request-Id"); got != "req-1" {
			t.Errorf("X-Request-Id not passed through: %q", got)
		}
		if got := sentHdr.Get("User-Agent"); !strings.HasPrefix(got, "xlate/") {
			t.Errorf("User-Agent: want xlate/..., got %q", got)
		}
	})

	t.Run("response reverse-mapped into A's vocabulary", func(t *testing.T) {
		out := decode(t, body)
		if out["payment_id"] != "PROOF-9" {
			t.Errorf("payment_proof should return as payment_id, got %v", out)
		}
		if out["customer"] == nil {
			t.Errorf("cust_id should return as customer.id, got %v", out)
		} else if c, ok := out["customer"].(map[string]any); !ok || c["id"] != "C-1" {
			t.Errorf("nested destination not rebuilt on return leg: %v", out["customer"])
		}
		if out["extra"] != "kept" {
			t.Errorf("unmapped response field should pass through, got %v", out["extra"])
		}
	})

	t.Run("X-Xlate-Applied counts both legs", func(t *testing.T) {
		n, err := strconv.Atoi(hdr.Get("X-Xlate-Applied"))
		if err != nil || n != 4 {
			t.Errorf("X-Xlate-Applied: want 4 (2 request + 2 response), got %q", hdr.Get("X-Xlate-Applied"))
		}
	})

	t.Run("b2a is the mirrored pipeline", func(t *testing.T) {
		// Point A at the same mock so the return leg has a destination.
		st, _, put := do(t, "PUT", in.base+"/api/admin/accounts/gw", adminTok, map[string]any{
			"id": "gw", "enabled": true,
			"a": map[string]any{"label": "A", "target_url": up.URL, "outbound_token": "a-outbound-secret"},
			"b": map[string]any{"label": "B", "target_url": up.URL},
			"map": []map[string]any{
				{"a": "payment_id", "b": "payment_proof"},
				{"a": "customer.id", "b": "cust_id"},
			},
		}, nil)
		if st != 200 {
			t.Fatalf("update: %d %s", st, put)
		}
		tokB := inboundToken(decode(t, put), "b")
		up.respond(200, "application/json", `{"payment_id":"P-back"}`)

		st, _, body := do(t, "POST", in.base+"/t/gw/b2a", tokB,
			map[string]any{"payment_proof": "P-fwd"}, nil)
		if st != 200 {
			t.Fatalf("b2a: want 200, got %d: %s", st, body)
		}
		sent, sentHdr, _ := up.got()
		if sent["payment_id"] != "P-fwd" {
			t.Errorf("b2a should rename payment_proof->payment_id, got %v", sent)
		}
		if got := sentHdr.Get("Authorization"); got != "Bearer a-outbound-secret" {
			t.Errorf("b2a should use side A's outbound token, got %q", got)
		}
		if out := decode(t, body); out["payment_proof"] != "P-back" {
			t.Errorf("b2a response should reverse-map to B's vocabulary, got %v", out)
		}
	})
}

func TestNumericFidelityEndToEnd(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	acct := mkAccount(t, in, map[string]any{
		"id": "num", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "id_a", "b": "id_b"}},
	})
	const big = "9007199254740993" // 2^53+1: lossy through float64
	up.respond(200, "application/json", `{"id_b":`+big+`}`)

	st, _, body := do(t, "POST", in.base+"/t/num/a2b", inboundToken(acct, "a"),
		`{"id_a":`+big+`}`, nil)
	if st != 200 {
		t.Fatalf("want 200, got %d: %s", st, body)
	}
	sent, _, _ := up.got()
	if fmt.Sprint(sent["id_b"]) != big {
		t.Errorf("request 64-bit id lost precision: want %s, got %v", big, sent["id_b"])
	}
	if got := decode(t, body)["id_a"]; fmt.Sprint(got) != big {
		t.Errorf("response 64-bit id lost precision: want %s, got %v", big, got)
	}
}

func TestDateTransformEndToEnd(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	acct := mkAccount(t, in, map[string]any{
		"id": "dates", "enabled": true,
		"b": map[string]any{"target_url": up.URL},
		"map": []map[string]any{{
			"a": "created_at", "b": "created_epoch",
			"transform": map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"},
		}},
	})
	up.respond(200, "application/json", `{"created_epoch":1700000000}`)

	st, hdr, body := do(t, "POST", in.base+"/t/dates/a2b", inboundToken(acct, "a"),
		map[string]any{"created_at": "2023-11-14T22:13:20Z"}, nil)
	if st != 200 {
		t.Fatalf("want 200, got %d: %s", st, body)
	}
	sent, _, _ := up.got()
	if fmt.Sprint(sent["created_epoch"]) != "1700000000" {
		t.Errorf("a2b date fx: want epoch 1700000000, got %v", sent["created_epoch"])
	}
	if got := decode(t, body)["created_at"]; got != "2023-11-14T22:13:20Z" {
		t.Errorf("return leg should un-convert to A's representation, got %v", got)
	}
	if w := hdr.Get("X-Xlate-Warnings"); w != "" {
		t.Errorf("clean transform should emit no warnings, got %q", w)
	}
}

// TestTransformFailOpen covers the documented fail-open rule on the
// request leg, and probes whether the same holds on the response leg.
func TestTransformFailOpen(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	acct := mkAccount(t, in, map[string]any{
		"id": "failopen", "enabled": true,
		"b": map[string]any{"target_url": up.URL},
		"map": []map[string]any{{
			"a": "created_at", "b": "created_epoch",
			"transform": map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"},
		}},
	})
	tok := inboundToken(acct, "a")

	t.Run("request leg forwards untransformed and warns", func(t *testing.T) {
		up.respond(200, "application/json", `{}`)
		st, hdr, body := do(t, "POST", in.base+"/t/failopen/a2b", tok,
			map[string]any{"created_at": "not-a-date"}, nil)
		if st != 200 {
			t.Fatalf("fail-open should still forward: got %d: %s", st, body)
		}
		sent, _, _ := up.got()
		if sent["created_epoch"] != "not-a-date" {
			t.Errorf("value should forward untransformed, got %v", sent["created_epoch"])
		}
		if hdr.Get("X-Xlate-Warnings") != "1" {
			t.Errorf("X-Xlate-Warnings: want 1, got %q", hdr.Get("X-Xlate-Warnings"))
		}
	})

	t.Run("response leg warning is surfaced", func(t *testing.T) {
		up.respond(200, "application/json", `{"created_epoch":"not-an-epoch"}`)
		st, hdr, body := do(t, "POST", in.base+"/t/failopen/a2b", tok,
			map[string]any{"created_at": "2023-11-14T22:13:20Z"}, nil)
		if st != 200 {
			t.Fatalf("want 200, got %d: %s", st, body)
		}
		if got := decode(t, body)["created_at"]; got != "not-an-epoch" {
			t.Errorf("response value should fail open untransformed, got %v", got)
		}
		if hdr.Get("X-Xlate-Warnings") != "1" {
			t.Errorf("return-leg parse failures must surface on X-Xlate-Warnings; want 1, got %q",
				hdr.Get("X-Xlate-Warnings"))
		}
	})
}

func TestDataPlaneErrorEnvelope(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t, "-max-body", "1024")

	acct := mkAccount(t, in, map[string]any{
		"id": "errs", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "x", "b": "y"}},
	})
	tok := inboundToken(acct, "a")

	check := func(t *testing.T, gotStatus, wantStatus int, body []byte, wantCode string) {
		t.Helper()
		if gotStatus != wantStatus {
			t.Errorf("status: want %d, got %d (%s)", wantStatus, gotStatus, body)
		}
		m := decode(t, body)
		if m["code"] != wantCode {
			t.Errorf("code: want %q, got %v", wantCode, m["code"])
		}
		if m["error"] == nil || m["error"] == "" {
			t.Errorf("error envelope must carry a human message, got %s", body)
		}
	}

	t.Run("401 auth_invalid", func(t *testing.T) {
		st, hdr, body := do(t, "POST", in.base+"/t/errs/a2b", "wrong", map[string]any{"x": 1}, nil)
		check(t, st, 401, body, "auth_invalid")
		if !strings.Contains(hdr.Get("WWW-Authenticate"), "xlate") {
			t.Errorf("missing WWW-Authenticate, got %q", hdr.Get("WWW-Authenticate"))
		}
	})
	t.Run("404 not_found", func(t *testing.T) {
		st, _, body := do(t, "POST", in.base+"/t/nosuch/a2b", tok, map[string]any{"x": 1}, nil)
		check(t, st, 404, body, "not_found")
	})
	t.Run("404 bad_direction", func(t *testing.T) {
		st, _, body := do(t, "POST", in.base+"/t/errs/sideways", tok, map[string]any{"x": 1}, nil)
		check(t, st, 404, body, "bad_direction")
	})
	t.Run("413 payload_too_large", func(t *testing.T) {
		big := `{"x":"` + strings.Repeat("A", 1600) + `"}`
		st, _, body := do(t, "POST", in.base+"/t/errs/a2b", tok, big, nil)
		check(t, st, 413, body, "payload_too_large")
	})
	t.Run("400 on non-object body", func(t *testing.T) {
		for _, b := range []string{`[1,2]`, `"str"`, `null`, `{`} {
			st, _, body := do(t, "POST", in.base+"/t/errs/a2b", tok, b, nil)
			if st != 400 {
				t.Errorf("body %s: want 400, got %d (%s)", b, st, body)
			}
		}
	})
	t.Run("403 account_disabled", func(t *testing.T) {
		st, _, put := do(t, "PUT", in.base+"/api/admin/accounts/errs", adminTok,
			map[string]any{"id": "errs", "enabled": false, "b": map[string]any{"target_url": up.URL}}, nil)
		if st != 200 {
			t.Fatalf("disable: %d %s", st, put)
		}
		st, _, body := do(t, "POST", in.base+"/t/errs/a2b", tok, map[string]any{"x": 1}, nil)
		check(t, st, 403, body, "account_disabled")
	})
	t.Run("502 no_target", func(t *testing.T) {
		st, _, put := do(t, "PUT", in.base+"/api/admin/accounts/errs", adminTok,
			map[string]any{"id": "errs", "enabled": true, "b": map[string]any{"target_url": ""}}, nil)
		if st != 200 {
			t.Fatalf("clear target: %d %s", st, put)
		}
		st, _, body := do(t, "POST", in.base+"/t/errs/a2b", tok, map[string]any{"x": 1}, nil)
		check(t, st, 502, body, "no_target")
	})
	t.Run("502 upstream_failed hides internal topology", func(t *testing.T) {
		dead := fmt.Sprintf("http://127.0.0.1:%d/gone", freePort(t))
		st, _, put := do(t, "PUT", in.base+"/api/admin/accounts/errs", adminTok,
			map[string]any{"id": "errs", "enabled": true, "b": map[string]any{"target_url": dead}}, nil)
		if st != 200 {
			t.Fatalf("point at dead upstream: %d %s", st, put)
		}
		st, _, body := do(t, "POST", in.base+"/t/errs/a2b", tok, map[string]any{"x": 1}, nil)
		check(t, st, 502, body, "upstream_failed")
		if strings.Contains(string(body), "127.0.0.1") {
			t.Errorf("upstream detail leaked to the caller: %s", body)
		}
	})
}

func TestRedirectsAreRelayedNotFollowed(t *testing.T) {
	var followed bool
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			followed = true
			w.WriteHeader(200)
			return
		}
		http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	in := start(t)
	acct := mkAccount(t, in, map[string]any{
		"id": "redir", "enabled": true,
		"b": map[string]any{"target_url": redirector.URL + "/start"},
	})
	st, _, _ := do(t, "POST", in.base+"/t/redir/a2b", inboundToken(acct, "a"),
		map[string]any{"a": 1}, nil)
	if st != http.StatusTemporaryRedirect {
		t.Errorf("redirect should be relayed verbatim: want 307, got %d", st)
	}
	if followed {
		t.Error("xlate followed the redirect and replayed the body")
	}
}

func TestDropUnmapped(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	acct := mkAccount(t, in, map[string]any{
		"id": "drop", "enabled": true, "drop_unmapped": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "keep_a", "b": "keep_b"}},
	})
	up.respond(200, "application/json", `{"keep_b":"v","unmapped_resp":"present"}`)

	st, _, body := do(t, "POST", in.base+"/t/drop/a2b", inboundToken(acct, "a"),
		map[string]any{"keep_a": "v", "dropme": "gone"}, nil)
	if st != 200 {
		t.Fatalf("want 200, got %d: %s", st, body)
	}
	sent, _, _ := up.got()
	if _, present := sent["dropme"]; present {
		t.Errorf("drop_unmapped should remove unmapped request fields, got %v", sent)
	}
	if sent["keep_b"] != "v" {
		t.Errorf("mapped field missing: %v", sent)
	}
	// README: responses are never drop-filtered.
	if got := decode(t, body)["unmapped_resp"]; got != "present" {
		t.Errorf("responses must not be drop-filtered, got %v", got)
	}
}

func TestAdminDryRunAndLogs(t *testing.T) {
	in := start(t)
	mkAccount(t, in, map[string]any{
		"id": "dry", "enabled": true,
		"map": []map[string]any{{
			"a": "created_at", "b": "created_epoch",
			"transform": map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"},
		}},
	})

	st, _, body := do(t, "POST", in.base+"/api/admin/accounts/dry/test", adminTok,
		map[string]any{"direction": "a2b", "payload": map[string]any{"created_at": "2023-11-14T22:13:20Z"}}, nil)
	if st != 200 {
		t.Fatalf("dry run: want 200, got %d: %s", st, body)
	}
	res := decode(t, body)
	tr, _ := res["translated"].(map[string]any)
	if fmt.Sprint(tr["created_epoch"]) != "1700000000" {
		t.Errorf("dry run should apply transforms, got %v", tr)
	}
	if fmt.Sprint(res["applied"]) != "1" {
		t.Errorf("applied: want 1, got %v", res["applied"])
	}
	if _, isArr := res["warnings"].([]any); !isArr {
		t.Errorf("warnings should always be an array, got %T", res["warnings"])
	}

	t.Run("dry run rejects bad input", func(t *testing.T) {
		st, _, _ := do(t, "POST", in.base+"/api/admin/accounts/dry/test", adminTok,
			map[string]any{"direction": "nope", "payload": map[string]any{}}, nil)
		if st != 400 {
			t.Errorf("bad direction: want 400, got %d", st)
		}
		st, _, _ = do(t, "POST", in.base+"/api/admin/accounts/dry/test", adminTok,
			map[string]any{"direction": "a2b"}, nil)
		if st != 400 {
			t.Errorf("missing payload: want 400, got %d", st)
		}
	})

	t.Run("dry run forwards nothing and is not logged as ingest", func(t *testing.T) {
		_, _, body := do(t, "GET", in.base+"/api/admin/logs?account=dry", adminTok, nil, nil)
		entries, _ := decode(t, body)["entries"].([]any)
		if len(entries) != 0 {
			t.Errorf("dry run must not produce ingest activity, got %d entries", len(entries))
		}
	})

	t.Run("ingest is logged with metadata only", func(t *testing.T) {
		up := newUpstream()
		defer up.Close()
		_, _, put := do(t, "PUT", in.base+"/api/admin/accounts/dry", adminTok,
			map[string]any{"id": "dry", "enabled": true, "b": map[string]any{"target_url": up.URL}}, nil)
		tok := inboundToken(decode(t, put), "a")
		do(t, "POST", in.base+"/t/dry/a2b", tok, map[string]any{"secret_pan": "4111111111111111"}, nil)

		_, _, body := do(t, "GET", in.base+"/api/admin/logs?account=dry", adminTok, nil, nil)
		if strings.Contains(string(body), "4111111111111111") {
			t.Errorf("payload body leaked into the activity log: %s", body)
		}
		entries, _ := decode(t, body)["entries"].([]any)
		if len(entries) != 1 {
			t.Fatalf("want 1 log entry, got %d", len(entries))
		}
		e := entries[0].(map[string]any)
		if fmt.Sprint(e["status"]) != "200" || e["account"] != "dry" {
			t.Errorf("unexpected log entry: %v", e)
		}
	})
}

func TestAdminUISecurityHeaders(t *testing.T) {
	in := start(t)
	st, hdr, body := do(t, "GET", in.base+"/admin/", "", nil, nil)
	if st != 200 {
		t.Fatalf("admin ui: want 200, got %d", st)
	}
	if len(body) == 0 || !bytes.Contains(body, []byte("<html")) {
		t.Errorf("admin ui did not serve HTML")
	}
	for h, want := range map[string]string{
		"Content-Type":           "text/html",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if !strings.Contains(hdr.Get(h), want) {
			t.Errorf("%s: want %q, got %q", h, want, hdr.Get(h))
		}
	}
	csp := hdr.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "connect-src 'self'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %s", want, csp)
		}
	}
	// The admin token must never be baked into the served page.
	if bytes.Contains(body, []byte(adminTok)) {
		t.Error("admin token is embedded in the admin UI")
	}
}

func TestTripwireLockAndSignedAlert(t *testing.T) {
	type alert struct {
		body []byte
		sig  string
	}
	alerts := make(chan alert, 4)
	const secret = "alert-hmac-secret"
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		alerts <- alert{b, r.Header.Get("X-Xlate-Signature")}
		w.WriteHeader(200)
	}))
	defer hook.Close()

	up := newUpstream()
	defer up.Close()
	in := start(t,
		"-trip-threshold", "2", "-trip-window", "5m", "-trip-lock", "4s", "-trip-mode", "lock",
		"-alert-webhook", hook.URL, "-alert-secret", secret)

	acct := mkAccount(t, in, map[string]any{
		"id": "trip", "enabled": true,
		"b": map[string]any{"target_url": up.URL},
	})
	tok := inboundToken(acct, "a")

	// Threshold 2 => the tripwire fires when exceeded, i.e. on the 3rd 401.
	for i := 1; i <= 3; i++ {
		st, _, _ := do(t, "POST", in.base+"/t/trip/a2b", "bad-token", map[string]any{"x": 1}, nil)
		if st != 401 {
			t.Fatalf("attempt %d: want 401, got %d", i, st)
		}
	}

	t.Run("valid credentials are locked out too", func(t *testing.T) {
		st, hdr, body := do(t, "POST", in.base+"/t/trip/a2b", tok, map[string]any{"x": 1}, nil)
		if st != 429 {
			t.Fatalf("want 429 after trip, got %d: %s", st, body)
		}
		if decode(t, body)["code"] != "account_locked" {
			t.Errorf("code: want account_locked, got %s", body)
		}
		ra, err := strconv.Atoi(hdr.Get("Retry-After"))
		if err != nil || ra <= 0 {
			t.Errorf("Retry-After: want a positive integer, got %q", hdr.Get("Retry-After"))
		}
	})

	t.Run("alert is delivered and HMAC-signed", func(t *testing.T) {
		select {
		case a := <-alerts:
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(a.body)
			want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if a.sig != want {
				t.Errorf("X-Xlate-Signature mismatch:\n want %s\n got  %s", want, a.sig)
			}
			p := decode(t, a.body)
			if p["account"] != "trip" || p["event"] != "tripwire" {
				t.Errorf("unexpected alert payload: %s", a.body)
			}
			if fmt.Sprint(p["count"]) != "3" {
				t.Errorf("alert count: want 3, got %v", p["count"])
			}
			if strings.Contains(string(a.body), tok) || strings.Contains(string(a.body), "bad-token") {
				t.Errorf("alert payload contains credential material: %s", a.body)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no alert delivered within 10s")
		}
	})

	t.Run("admin sees tripwire state", func(t *testing.T) {
		_, _, body := do(t, "GET", in.base+"/api/admin/tripwire", adminTok, nil, nil)
		all := decode(t, body)
		stt, _ := all["trip"].(map[string]any)
		if stt == nil || stt["state"] != "locked" {
			t.Errorf("tripwire status: want locked, got %s", body)
		}
	})

	t.Run("lock expires and re-arms", func(t *testing.T) {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			st, _, _ := do(t, "POST", in.base+"/t/trip/a2b", tok, map[string]any{"x": 1}, nil)
			if st == 200 {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Error("lock never expired: ingest still refused after 20s (lock was 4s)")
	})

	t.Run("admin reset clears state", func(t *testing.T) {
		st, _, body := do(t, "POST", in.base+"/api/admin/accounts/trip/tripwire/reset", adminTok, nil, nil)
		if st != 200 {
			t.Fatalf("reset: want 200, got %d: %s", st, body)
		}
		res, _ := decode(t, body)["tripwire"].(map[string]any)
		if res["state"] != "armed" {
			t.Errorf("after reset: want armed, got %v", res)
		}
	})
}

func TestTripwireFreezeMode(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t, "-trip-threshold", "1", "-trip-window", "5m", "-trip-mode", "freeze")

	mkAccount(t, in, map[string]any{
		"id": "frz", "enabled": true, "b": map[string]any{"target_url": up.URL},
	})
	for i := 0; i < 2; i++ {
		do(t, "POST", in.base+"/t/frz/a2b", "bad", map[string]any{"x": 1}, nil)
	}
	// Freeze is persisted, so the account document must show it.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, _, body := do(t, "GET", in.base+"/api/admin/accounts/frz", adminTok, nil, nil)
		if decode(t, body)["enabled"] == false {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, _, body := do(t, "GET", in.base+"/api/admin/accounts/frz", adminTok, nil, nil)
	t.Errorf("freeze mode should persist enabled=false, got %s", body)
}

func TestAuditTrailIntegrity(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	acct := mkAccount(t, in, map[string]any{
		"id": "aud", "enabled": true, "b": map[string]any{"target_url": up.URL},
	})
	tok := inboundToken(acct, "a")
	do(t, "POST", in.base+"/t/aud/a2b", tok, map[string]any{"pan": "4111111111111111"}, nil)
	do(t, "POST", in.base+"/t/aud/a2b", "bad", map[string]any{"x": 1}, nil)
	do(t, "POST", in.base+"/api/admin/accounts/aud/rotate", adminTok,
		map[string]any{"side": "a", "kind": "inbound"}, nil)
	in.stop()

	raw, err := os.ReadFile(in.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected several audit records, got %d:\n%s", len(lines), raw)
	}

	t.Run("no secrets on the trail", func(t *testing.T) {
		s := string(raw)
		if strings.Contains(s, "4111111111111111") {
			t.Error("payload body captured in the audit trail")
		}
		if strings.Contains(s, tok) || strings.Contains(s, adminTok) || strings.Contains(s, "xk_") {
			t.Error("token material captured in the audit trail")
		}
	})

	t.Run("expected events present", func(t *testing.T) {
		s := string(raw)
		for _, ev := range []string{"server.start", "account.create", "ingest.ok", "ingest.denied", "account.rotate"} {
			if !strings.Contains(s, `"event":"`+ev+`"`) {
				t.Errorf("missing audit event %q", ev)
			}
		}
	})

	verify := func(t *testing.T, path string) (string, error) {
		t.Helper()
		out, err := exec.Command(binary(t), "-verify-audit", path).CombinedOutput()
		return string(out), err
	}

	t.Run("intact chain verifies", func(t *testing.T) {
		out, err := verify(t, in.auditPath)
		if err != nil {
			t.Fatalf("verification of an untouched trail failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "audit chain OK") {
			t.Errorf("unexpected verifier output: %s", out)
		}
	})

	tamper := func(t *testing.T, name string, mutate func([]string) []string) {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "tampered.jsonl")
			if err := os.WriteFile(p, []byte(strings.Join(mutate(append([]string{}, lines...)), "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := verify(t, p)
			if err == nil {
				t.Errorf("tampering was NOT detected: %s", out)
			}
		})
	}
	tamper(t, "edited record detected", func(l []string) []string {
		l[1] = strings.Replace(l[1], `"actor":"admin"`, `"actor":"nobody"`, 1)
		if !strings.Contains(l[1], "nobody") { // fall back to any field edit
			l[1] = strings.Replace(l[1], `"event":"`, `"event":"x`, 1)
		}
		return l
	})
	tamper(t, "deleted record detected", func(l []string) []string {
		return append(l[:1], l[2:]...)
	})
	tamper(t, "reordered records detected", func(l []string) []string {
		l[1], l[2] = l[2], l[1]
		return l
	})
	tamper(t, "appended forged record detected", func(l []string) []string {
		return append(l, `{"seq":999,"time":"2030-01-01T00:00:00Z","actor":"attacker","event":"account.delete","prev":"`+genesisHash+`","hash":"deadbeef"}`)
	})

	t.Run("restart extends the same chain", func(t *testing.T) {
		port := freePort(t)
		cmd := exec.Command(binary(t),
			"-listen", fmt.Sprintf("127.0.0.1:%d", port),
			"-state", in.statePath, "-audit", in.auditPath, "-admin-token", adminTok)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		base := fmt.Sprintf("http://127.0.0.1:%d", port)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if r, err := http.Get(base + "/healthz"); err == nil {
				r.Body.Close()
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		do(t, "POST", base+"/api/admin/accounts", adminTok, map[string]any{"id": "after"}, nil)
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()

		out, err := verify(t, in.auditPath)
		if err != nil {
			t.Fatalf("chain broken across restart: %v\n%s", err, out)
		}
		after, _ := os.ReadFile(in.auditPath)
		if len(after) <= len(raw) {
			t.Error("restart did not append to the existing trail")
		}
	})
}

func TestPanicRecoveryDoesNotLeakStack(t *testing.T) {
	// There is no injectable panic path from the wire, so this asserts the
	// negative: malformed admin input is rejected cleanly, never with a 500
	// carrying a Go stack trace.
	in := start(t)
	for _, body := range []string{`{"id":`, `{"map":[{"a":".bad.","b":"x"}]}`, `{"timeout_sec":-5}`, `[]`} {
		st, _, resp := do(t, "POST", in.base+"/api/admin/accounts", adminTok, body, nil)
		if st >= 500 {
			t.Errorf("body %s produced %d: %s", body, st, resp)
		}
		if bytes.Contains(resp, []byte("goroutine ")) || bytes.Contains(resp, []byte(".go:")) {
			t.Errorf("stack trace leaked to the wire: %s", resp)
		}
	}
}

func TestConcurrentIngestIsRaceFree(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	acct := mkAccount(t, in, map[string]any{
		"id": "conc", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "x", "b": "y"}},
	})
	tok := inboundToken(acct, "a")
	up.respond(200, "application/json", `{"y":1}`)

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cred := tok
			if i%4 == 0 {
				cred = "bad" // mix in denials so the tripwire is exercised concurrently
			}
			req, _ := http.NewRequest("POST", in.base+"/t/conc/a2b",
				strings.NewReader(`{"x":`+strconv.Itoa(i)+`}`))
			req.Header.Set("Authorization", "Bearer "+cred)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err.Error()
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			switch resp.StatusCode {
			case 200, 401, 429:
			default:
				errs <- fmt.Sprintf("unexpected status %d", resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if strings.Contains(in.log.String(), "panic") {
		t.Errorf("server logged a panic:\n%s", in.log.String())
	}
}
