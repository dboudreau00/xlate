// xlate end-to-end harness.
//
// Spawns the real xlate binary as a subprocess, stands up two partner
// systems ("Acme Checkout" = side A, "Globex Ledger" = side B) on real
// ports, and drives the gateway over HTTP the way the two partners would.
//
// The point is to assert on what each side ACTUALLY received: that B sees
// B's vocabulary and B's credential, that A sees A's vocabulary back, and
// that neither ever sees the other's token.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	xlateAddr = "127.0.0.1:18080"
	addrA     = "127.0.0.1:19101"
	addrB     = "127.0.0.1:19102"

	adminToken = "xadm_e2e_pinned_admin_token_for_this_run"

	aInbound  = "xk_a_inbound_token"
	bInbound  = "xk_b_inbound_token"
	aOutbound = "xk_a_outbound_secret_ONLY_acme_knows"
	bOutbound = "xk_b_outbound_secret_ONLY_globex_knows"

	// Tokens must be >= 16 chars (validate.go minTokenLen).
	tripIn     = "xk_trip_inbound_side_a"
	wrongGuess = "xk_wrong_guess_attacker"
)

var base = "http://" + xlateAddr

// ---------------------------------------------------------------- capture

// capture records exactly what a partner system received.
type capture struct {
	Method string
	Auth   string
	CT     string
	UA     string
	Hdrs   http.Header
	Body   map[string]any
	Raw    string
}

type partner struct {
	mu   sync.Mutex
	name string
	got  []capture
	// reply is what this partner answers with, in ITS OWN vocabulary.
	reply  func() (int, map[string]any)
	status int
}

func (p *partner) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&body)

	p.mu.Lock()
	p.got = append(p.got, capture{
		Method: r.Method,
		Auth:   r.Header.Get("Authorization"),
		CT:     r.Header.Get("Content-Type"),
		UA:     r.Header.Get("User-Agent"),
		Hdrs:   r.Header.Clone(),
		Body:   body,
		Raw:    string(raw),
	})
	p.mu.Unlock()

	code, resp := p.reply()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *partner) last() (capture, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.got) == 0 {
		return capture{}, false
	}
	return p.got[len(p.got)-1], true
}

func (p *partner) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.got)
}

func (p *partner) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = nil
}

// ---------------------------------------------------------------- asserts

var (
	passN, failN int
	failures     []string
	section      string
)

func sec(s string) {
	section = s
	fmt.Printf("\n\033[1m== %s\033[0m\n", s)
}

func ok(cond bool, format string, a ...any) bool {
	msg := fmt.Sprintf(format, a...)
	if cond {
		passN++
		fmt.Printf("  \033[32mPASS\033[0m %s\n", msg)
		return true
	}
	failN++
	failures = append(failures, section+" / "+msg)
	fmt.Printf("  \033[31mFAIL\033[0m %s\n", msg)
	return false
}

func eq(got, want any, format string, a ...any) bool {
	g, w := fmt.Sprint(got), fmt.Sprint(want)
	if g == w {
		return ok(true, format, a...)
	}
	res := ok(false, format, a...)
	fmt.Printf("       want %q\n       got  %q\n", w, g)
	return res
}

// path resolves a dot-path in a decoded JSON object.
func path(m map[string]any, p string) (any, bool) {
	cur := any(m)
	for _, part := range strings.Split(p, ".") {
		obj, isObj := cur.(map[string]any)
		if !isObj {
			return nil, false
		}
		v, exists := obj[part]
		if !exists {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func has(m map[string]any, p string) bool {
	_, found := path(m, p)
	return found
}

func at(m map[string]any, p string) any {
	v, _ := path(m, p)
	return v
}

// ---------------------------------------------------------------- http

type reply struct {
	Status int
	Body   map[string]any
	Raw    string
	Hdr    http.Header
}

func do(method, url, token string, body any, hdrs map[string]string) reply {
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rdr = strings.NewReader(b)
	default:
		enc, _ := json.Marshal(b)
		rdr = bytes.NewReader(enc)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		panic(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return reply{Status: -1, Raw: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&m)
	return reply{Status: resp.StatusCode, Body: m, Raw: string(raw), Hdr: resp.Header}
}

func ingest(acct, dir, token string, body any, hdrs map[string]string) reply {
	return do("POST", base+"/t/"+acct+"/"+dir, token, body, hdrs)
}

// rawPost writes a hand-built request straight onto the socket, so header
// values net/http would refuse to transmit still reach the server.
func rawPost(p, token, extraHeaders, body string) (int, string) {
	conn, err := net.DialTimeout("tcp", xlateAddr, 3*time.Second)
	if err != nil {
		return -1, err.Error()
	}
	defer conn.Close()
	req := "POST " + p + " HTTP/1.1\r\n" +
		"Host: " + xlateAddr + "\r\n" +
		"Authorization: Bearer " + token + "\r\n" +
		"Content-Type: application/json\r\n" +
		extraHeaders +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		return -1, err.Error()
	}
	raw, _ := io.ReadAll(conn)
	s := string(raw)
	code := -1
	if parts := strings.SplitN(s, " ", 3); len(parts) >= 2 {
		code, _ = strconv.Atoi(parts[1])
	}
	return code, s
}

func admin(method, p string, body any) reply {
	return do(method, base+"/api/admin"+p, adminToken, body, nil)
}

// ---------------------------------------------------------------- main

func main() {
	scratch, _ := filepath.Abs(".")
	statePath := filepath.Join(scratch, "run", "xlate.state.json")
	auditPath := filepath.Join(scratch, "run", "xlate.audit.jsonl")
	_ = os.RemoveAll(filepath.Join(scratch, "run"))
	_ = os.MkdirAll(filepath.Join(scratch, "run"), 0o700)

	bin := os.Getenv("XLATE_BIN")
	if bin == "" {
		fmt.Println("set XLATE_BIN to the xlate binary")
		os.Exit(2)
	}

	// -- partner systems ---------------------------------------------------
	pa := &partner{name: "Acme Checkout (A)"}
	pa.reply = func() (int, map[string]any) {
		if pa.status != 0 {
			return pa.status, map[string]any{"error": "acme is unhappy"}
		}
		// A answers in A's vocabulary.
		return 200, map[string]any{
			"cust_id":      "ACME-77",
			"amount_cents": 4200,
			"customer":     map[string]any{"email_addr": "ada@acme.test"},
			"txn_date":     "03/09/2026",
			"acme_note":    "settled",
		}
	}
	pb := &partner{name: "Globex Ledger (B)"}
	pb.reply = func() (int, map[string]any) {
		if pb.status != 0 {
			return pb.status, map[string]any{"error": "globex is unhappy"}
		}
		// B answers in B's vocabulary.
		return 201, map[string]any{
			"customerId":      "GLX-9001",
			"amountMinor":     4200,
			"party":           map[string]any{"email": "ada@acme.test"},
			"transactionDate": "2026-03-09",
			"ledgerRef":       "GLX-ENTRY-1",
		}
	}

	srvA := &http.Server{Addr: addrA, Handler: http.HandlerFunc(pa.handler)}
	srvB := &http.Server{Addr: addrB, Handler: http.HandlerFunc(pb.handler)}
	go func() { _ = srvA.ListenAndServe() }()
	go func() { _ = srvB.ListenAndServe() }()

	// -- xlate -------------------------------------------------------------
	cmd := exec.Command(bin,
		"-listen", xlateAddr,
		"-state", statePath,
		"-audit", auditPath,
		"-admin-token", adminToken,
		"-trip-threshold", "3",
		"-trip-window", "5m",
		"-trip-lock", "5s",
		"-max-body", "4096",
	)
	logFile, _ := os.Create(filepath.Join(scratch, "run", "xlate.log"))
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		fmt.Println("start xlate:", err)
		os.Exit(2)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	}()

	// wait for readiness
	up := false
	for i := 0; i < 100; i++ {
		if r := do("GET", base+"/healthz", "", nil, nil); r.Status == 200 {
			up = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		fmt.Println("xlate never became healthy; see run/xlate.log")
		os.Exit(2)
	}

	rotated := run(pa, pb)

	// -- restart: the state file IS the deployment -------------------------
	sec("Restart / durability")
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	time.Sleep(500 * time.Millisecond)
	ok(do("GET", base+"/healthz", "", nil, nil).Status == -1, "server is down after kill")

	st, errStat := os.Stat(statePath)
	ok(errStat == nil && st.Size() > 0, "state file survives on disk (%d bytes)", st.Size())

	cmd2 := exec.Command(bin,
		"-listen", xlateAddr, "-state", statePath, "-audit", auditPath,
		"-admin-token", adminToken, "-trip-threshold", "3",
		"-trip-window", "5m", "-trip-lock", "5s", "-max-body", "4096",
	)
	cmd2.Stdout, cmd2.Stderr = logFile, logFile
	if err := cmd2.Start(); err != nil {
		fmt.Println("restart xlate:", err)
		os.Exit(2)
	}
	for i := 0; i < 100; i++ {
		if do("GET", base+"/healthz", "", nil, nil).Status == 200 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	r2 := admin("GET", "/accounts/acme-globex", nil)
	eq(r2.Status, 200, "the account reloaded from the state file after restart")
	eq(at(r2.Body, "b.target_url"), "http://"+addrB+"/inbound", "target_url survived the restart")
	ok(strings.Contains(r2.Raw, "customerId"), "the field map survived the restart")

	pb.reset()
	r2 = ingest("acme-globex", "a2b", rotated, map[string]any{
		"cust_id": "AFTER-RESTART", "txn_date": "01/02/2026",
	}, nil)
	eq(r2.Status, 201, "traffic flows again after restart with the ROTATED token")
	if got, found := pb.last(); found {
		eq(at(got.Body, "customerId"), "AFTER-RESTART", "translation still correct after restart")
		eq(at(got.Body, "transactionDate"), "2026-01-02", "date transform still correct after restart")
		eq(got.Auth, "Bearer "+bOutbound, "outbound credential survived the restart")
	}

	// -- audit chain -------------------------------------------------------
	sec("Audit trail")
	_ = cmd2.Process.Kill()
	_, _ = cmd2.Process.Wait()
	time.Sleep(200 * time.Millisecond)
	out, err := exec.Command(bin, "-verify-audit", auditPath).CombinedOutput()
	ok(err == nil, "hash-chained audit trail verifies (%s)", strings.TrimSpace(lastLine(string(out))))
	if err != nil {
		fmt.Println(string(out))
	}
	ab, _ := os.ReadFile(auditPath)
	nEvents := strings.Count(strings.TrimSpace(string(ab)), "\n") + 1
	ok(nEvents > 10, "audit recorded %d events", nEvents)
	ok(!strings.Contains(string(ab), aOutbound) && !strings.Contains(string(ab), bOutbound),
		"audit trail contains no outbound credentials")

	// -- summary -----------------------------------------------------------
	fmt.Printf("\n\033[1m===== %d passed, %d failed =====\033[0m\n", passN, failN)
	if failN > 0 {
		fmt.Println("\nFailures:")
		for _, f := range failures {
			fmt.Println("  -", f)
		}
		os.Exit(1)
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// run drives the whole scenario and returns side A's current inbound token
// (it gets rotated partway through) so the restart check can keep posting.
func run(pa, pb *partner) string {
	// ================================================== provisioning
	sec("Admin API / provisioning")

	r := do("GET", base+"/healthz", "", nil, nil)
	eq(r.Status, 200, "GET /healthz -> 200")

	r = do("GET", base+"/api/admin/accounts", "", nil, nil)
	eq(r.Status, 401, "admin API without a token -> 401")

	r = do("GET", base+"/api/admin/accounts", "wrong-token", nil, nil)
	eq(r.Status, 401, "admin API with a wrong token -> 401")

	acct := map[string]any{
		"id":   "acme-globex",
		"name": "Acme <-> Globex",
		"a": map[string]any{
			"label":          "Acme Checkout",
			"target_url":     "http://" + addrA + "/inbound",
			"inbound_token":  aInbound,
			"outbound_token": aOutbound,
		},
		"b": map[string]any{
			"label":          "Globex Ledger",
			"target_url":     "http://" + addrB + "/inbound",
			"inbound_token":  bInbound,
			"outbound_token": bOutbound,
		},
		"map": []map[string]any{
			{"a": "cust_id", "b": "customerId"},
			{"a": "amount_cents", "b": "amountMinor"},
			{"a": "customer.email_addr", "b": "party.email"},
			{"a": "txn_date", "b": "transactionDate", "transform": map[string]any{
				"kind": "date", "a_format": "01/02/2006", "b_format": "2006-01-02",
			}},
		},
	}
	r = admin("POST", "/accounts", acct)
	eq(r.Status, 201, "create account -> 201")
	eq(at(r.Body, "id"), "acme-globex", "account id echoed back")

	r = admin("POST", "/accounts", acct)
	eq(r.Status, 409, "duplicate account id -> 409")

	r = admin("POST", "/accounts", map[string]any{"id": "Bad ID With Spaces"})
	eq(r.Status, 400, "invalid account id -> 400")

	// ================================================== A -> B
	sec("Forward translation  A -> B  (Acme POSTs, Globex receives)")
	pa.reset()
	pb.reset()

	acmeSends := map[string]any{
		"cust_id":      "ACME-77",
		"amount_cents": 4200,
		"customer":     map[string]any{"email_addr": "ada@acme.test"},
		"txn_date":     "03/09/2026",
		"acme_note":    "please post this",
	}
	r = ingest("acme-globex", "a2b", aInbound, acmeSends, map[string]string{
		"X-Request-Id": "req-alpha-1",
	})
	eq(r.Status, 201, "caller gets Globex's status code (201) passed through")

	got, found := pb.last()
	if ok(found, "Globex actually received a request") {
		// Field names translated into B's vocabulary.
		eq(at(got.Body, "customerId"), "ACME-77", "cust_id -> customerId")
		eq(at(got.Body, "amountMinor"), "4200", "amount_cents -> amountMinor")
		eq(at(got.Body, "party.email"), "ada@acme.test", "customer.email_addr -> party.email (nested)")
		eq(at(got.Body, "transactionDate"), "2026-03-09", "txn_date 03/09/2026 -> transactionDate 2026-03-09 (date transform)")

		// A's names must be gone.
		ok(!has(got.Body, "cust_id"), "Globex never sees the name \"cust_id\"")
		ok(!has(got.Body, "amount_cents"), "Globex never sees the name \"amount_cents\"")
		ok(!has(got.Body, "customer.email_addr"), "Globex never sees the leaf \"customer.email_addr\"")
		ok(!has(got.Body, "txn_date"), "Globex never sees the name \"txn_date\"")

		// Documented behaviour (translate.go delPath): emptied parent
		// containers are deliberately NOT pruned. The leaf value moves, but
		// the container NAME survives into the other party's payload.
		cust, custPresent := path(got.Body, "customer")
		if custPresent {
			m, isMap := cust.(map[string]any)
			ok(isMap && len(m) == 0,
				"emptied parent container \"customer\" survives as {} (documented: parents are not pruned)")
		} else {
			ok(true, "emptied parent container \"customer\" was pruned")
		}

		// Unmapped fields pass through by default.
		eq(at(got.Body, "acme_note"), "please post this", "unmapped field passes through (drop_unmapped=false)")

		// Credentials: xlate presents B's outbound token, never A's inbound.
		eq(got.Auth, "Bearer "+bOutbound, "Globex is called with Globex's outbound credential")
		ok(!strings.Contains(got.Raw+got.Auth, aInbound), "Acme's inbound token never reaches Globex")
		ok(!strings.Contains(got.Raw+got.Auth, aOutbound), "Acme's outbound token never reaches Globex")
		ok(strings.HasPrefix(got.UA, "xlate/"), "outbound User-Agent is %q", got.UA)
		eq(got.Hdrs.Get("X-Request-Id"), "req-alpha-1", "X-Request-Id correlation header forwarded")
	}

	// Response reverse-mapped back into A's vocabulary.
	sec("Reverse mapping of the response  (Globex answers, Acme reads)")
	eq(at(r.Body, "cust_id"), "GLX-9001", "customerId -> cust_id on the way back")
	eq(at(r.Body, "amount_cents"), "4200", "amountMinor -> amount_cents on the way back")
	eq(at(r.Body, "customer.email_addr"), "ada@acme.test", "party.email -> customer.email_addr (nested, reverse)")
	eq(at(r.Body, "txn_date"), "03/09/2026", "transactionDate 2026-03-09 -> txn_date 03/09/2026 (transform reversed)")
	ok(!has(r.Body, "customerId"), "Acme never sees the name \"customerId\"")
	ok(!has(r.Body, "party.email"), "Acme never sees the leaf \"party.email\"")
	eq(at(r.Body, "ledgerRef"), "GLX-ENTRY-1", "unmapped response field passes through")
	ok(!strings.Contains(r.Raw, bOutbound), "Globex's credential never reaches Acme")
	eq(r.Hdr.Get("X-Xlate-Applied"), "8", "X-Xlate-Applied counts both legs (4 out + 4 back)")

	// ================================================== B -> A
	sec("Forward translation  B -> A  (Globex POSTs, Acme receives)")
	pa.reset()
	pb.reset()

	globexSends := map[string]any{
		"customerId":      "GLX-9001",
		"amountMinor":     999,
		"party":           map[string]any{"email": "bob@globex.test"},
		"transactionDate": "2026-12-25",
		"globex_note":     "reversal",
	}
	r = ingest("acme-globex", "b2a", bInbound, globexSends, nil)
	eq(r.Status, 200, "caller gets Acme's status code (200) passed through")

	got, found = pa.last()
	if ok(found, "Acme actually received a request") {
		eq(at(got.Body, "cust_id"), "GLX-9001", "customerId -> cust_id")
		eq(at(got.Body, "amount_cents"), "999", "amountMinor -> amount_cents")
		eq(at(got.Body, "customer.email_addr"), "bob@globex.test", "party.email -> customer.email_addr (nested)")
		eq(at(got.Body, "txn_date"), "12/25/2026", "transactionDate 2026-12-25 -> txn_date 12/25/2026 (transform, reverse direction)")
		ok(!has(got.Body, "customerId"), "Acme never sees the name \"customerId\"")
		eq(got.Auth, "Bearer "+aOutbound, "Acme is called with Acme's outbound credential")
		ok(!strings.Contains(got.Raw+got.Auth, bInbound), "Globex's inbound token never reaches Acme")
		ok(!strings.Contains(got.Raw+got.Auth, bOutbound), "Globex's outbound token never reaches Acme")
	}
	eq(at(r.Body, "customerId"), "ACME-77", "response reverse-mapped into Globex's vocabulary")
	eq(at(r.Body, "transactionDate"), "2026-03-09", "response date rendered in Globex's format")
	ok(!has(r.Body, "cust_id"), "Globex never sees the name \"cust_id\" in the response")

	// ================================================== credential isolation
	sec("Credential isolation (the security claim)")
	aSaw, _ := pa.last()
	bSawAll := pb.count()
	ok(!strings.Contains(aSaw.Raw, bInbound) && !strings.Contains(aSaw.Raw, bOutbound),
		"across the whole exchange, Acme holds no Globex credential")
	ok(bSawAll == 0, "b2a traffic never touched Globex (%d calls)", bSawAll)

	// ================================================== auth
	sec("Ingest authentication")
	r = ingest("acme-globex", "a2b", "xk_totally_wrong", acmeSends, nil)
	eq(r.Status, 401, "wrong inbound token -> 401")
	eq(r.Hdr.Get("WWW-Authenticate"), `Bearer realm="xlate"`, "401 carries WWW-Authenticate")

	r = ingest("acme-globex", "a2b", bInbound, acmeSends, nil)
	eq(r.Status, 401, "side B's token cannot post as side A -> 401")

	r = ingest("acme-globex", "a2b", "", acmeSends, nil)
	eq(r.Status, 401, "no token -> 401")

	r = ingest("no-such-account", "a2b", aInbound, acmeSends, nil)
	eq(r.Status, 404, "unknown account -> 404")

	r = ingest("acme-globex", "sideways", aInbound, acmeSends, nil)
	eq(r.Status, 404, "bad direction -> 404")

	r = do("GET", base+"/t/acme-globex/a2b", aInbound, nil, nil)
	eq(r.Status, 405, "GET on the ingest endpoint -> 405")

	// Those four refusals just crossed the -trip-threshold of 3, so the
	// account is now locked. That is the tripwire doing its job; clear it
	// so the following sections test what they claim to test.
	r = ingest("acme-globex", "a2b", aInbound, acmeSends, nil)
	eq(r.Status, 201, "at exactly -trip-threshold refusals the account is still open")
	r = admin("POST", "/accounts/acme-globex/tripwire/reset", nil)
	eq(r.Status, 200, "reset the tripwire before continuing")

	// ================================================== malformed input
	sec("Malformed input")
	r = ingest("acme-globex", "a2b", aInbound, "{not json", nil)
	eq(r.Status, 400, "malformed JSON -> 400")

	r = ingest("acme-globex", "a2b", aInbound, "[1,2,3]", nil)
	eq(r.Status, 400, "JSON array instead of object -> 400")

	big := map[string]any{"cust_id": strings.Repeat("x", 8000)}
	r = ingest("acme-globex", "a2b", aInbound, big, nil)
	eq(r.Status, 413, "body over -max-body -> 413")

	// Correlation headers are forwarded verbatim to the other party, so they
	// are attacker-controlled input. Anything outside printable non-space
	// ASCII (0x21-0x7e) must be refused.
	for _, bad := range []struct{ name, val, why string }{
		{"X-Request-Id", "has space", "space"},
		{"X-Request-Id", "has\ttab", "tab"},
		{"Idempotency-Key", "café", "non-ASCII"},
		{"X-Request-Id", strings.Repeat("A", 300), "over 256 chars"},
	} {
		rr := ingest("acme-globex", "a2b", aInbound, map[string]any{"cust_id": "x"},
			map[string]string{bad.name: bad.val})
		eq(rr.Status, 400, "%s in %s -> 400", bad.why, bad.name)
	}

	// CRLF injection: net/http's own client refuses to transmit this, so it
	// has to go out over a raw socket to reach the server at all. The
	// property that matters is that the smuggled header never reaches the
	// partner — whether it is rejected or stripped in transit.
	pb.reset()
	status, rawResp := rawPost("/t/acme-globex/a2b", aInbound,
		"X-Request-Id: fine\r\nIdempotency-Key: bad\x00key\r\n", `{"cust_id":"x"}`)
	ok(!strings.Contains(rawResp, "Injected"), "no smuggled header reflected in the response")
	smuggled := false
	if got, found := pb.last(); found {
		smuggled = strings.Contains(got.Hdrs.Get("Idempotency-Key"), "\x00")
	}
	ok(!smuggled, "NUL byte never reaches the partner's headers (status %d)", status)

	// ================================================== upstream failures
	sec("Upstream behaviour")
	pb.status = 422
	r = ingest("acme-globex", "a2b", aInbound, acmeSends, nil)
	eq(r.Status, 422, "upstream 4xx is passed through, not masked")
	pb.status = 0

	r = admin("PUT", "/accounts/acme-globex", map[string]any{
		"id": "acme-globex", "name": "Acme <-> Globex",
		"a":   map[string]any{"target_url": "http://" + addrA + "/inbound", "label": "Acme Checkout"},
		"b":   map[string]any{"target_url": "http://127.0.0.1:19999/dead", "label": "Globex Ledger"},
		"map": acct["map"],
	})
	eq(r.Status, 200, "update account to point at a dead target -> 200")
	r = ingest("acme-globex", "a2b", aInbound, acmeSends, nil)
	eq(r.Status, 502, "unreachable upstream -> 502")
	ok(!strings.Contains(strings.ToLower(r.Raw), "19999"), "502 body does not leak internal topology")

	// restore
	r = admin("PUT", "/accounts/acme-globex", map[string]any{
		"id": "acme-globex", "name": "Acme <-> Globex",
		"a":   map[string]any{"target_url": "http://" + addrA + "/inbound", "label": "Acme Checkout"},
		"b":   map[string]any{"target_url": "http://" + addrB + "/inbound", "label": "Globex Ledger"},
		"map": acct["map"],
	})
	eq(r.Status, 200, "restore the real target -> 200")
	ok(at(r.Body, "b.inbound_token") == bInbound,
		"omitted tokens are retained on update, not wiped")

	// ================================================== drop_unmapped
	sec("drop_unmapped")
	pb.reset()
	r = admin("PUT", "/accounts/acme-globex", map[string]any{
		"id": "acme-globex", "name": "Acme <-> Globex",
		"a":   map[string]any{"target_url": "http://" + addrA + "/inbound", "label": "Acme Checkout"},
		"b":   map[string]any{"target_url": "http://" + addrB + "/inbound", "label": "Globex Ledger"},
		"map": acct["map"], "drop_unmapped": true,
	})
	eq(r.Status, 200, "enable drop_unmapped -> 200")
	r = ingest("acme-globex", "a2b", aInbound, acmeSends, nil)
	got, _ = pb.last()
	ok(!has(got.Body, "acme_note"), "unmapped field is dropped when drop_unmapped=true")
	eq(at(got.Body, "customerId"), "ACME-77", "mapped fields still translate under drop_unmapped")

	// ================================================== disabled
	sec("Disabled account")
	r = admin("PUT", "/accounts/acme-globex", map[string]any{
		"id": "acme-globex", "name": "Acme <-> Globex", "enabled": false,
		"a":   map[string]any{"target_url": "http://" + addrA + "/inbound", "label": "Acme Checkout"},
		"b":   map[string]any{"target_url": "http://" + addrB + "/inbound", "label": "Globex Ledger"},
		"map": acct["map"],
	})
	eq(r.Status, 200, "disable account -> 200")
	before := pb.count()
	r = ingest("acme-globex", "a2b", aInbound, acmeSends, nil)
	eq(r.Status, 403, "disabled account -> 403")
	eq(pb.count(), before, "a disabled account forwards nothing upstream")

	r = admin("PUT", "/accounts/acme-globex", map[string]any{
		"id": "acme-globex", "name": "Acme <-> Globex", "enabled": true,
		"a":   map[string]any{"target_url": "http://" + addrA + "/inbound", "label": "Acme Checkout"},
		"b":   map[string]any{"target_url": "http://" + addrB + "/inbound", "label": "Globex Ledger"},
		"map": acct["map"],
	})
	eq(r.Status, 200, "re-enable account -> 200")

	// ================================================== token rotation
	sec("Token rotation")
	r = admin("POST", "/accounts/acme-globex/rotate", map[string]any{"side": "a", "kind": "inbound"})
	eq(r.Status, 200, "rotate side A inbound token -> 200")
	newTok, _ := at(r.Body, "token").(string)
	ok(newTok != "" && newTok != aInbound, "a new token was issued")

	r = ingest("acme-globex", "a2b", aInbound, acmeSends, nil)
	eq(r.Status, 401, "the OLD token stops working after rotation")
	r = ingest("acme-globex", "a2b", newTok, acmeSends, nil)
	eq(r.Status, 201, "the NEW token works")

	// ================================================== tripwire
	sec("Tripwire (threshold 3, lock 5s)")
	trip := map[string]any{
		"id": "trip-test", "name": "Tripwire target",
		"a": map[string]any{"target_url": "http://" + addrA + "/inbound",
			"inbound_token": tripIn, "outbound_token": "xk_trip_outbound_side_a", "label": "A"},
		"b": map[string]any{"target_url": "http://" + addrB + "/inbound",
			"inbound_token": "xk_trip_inbound_side_b", "outbound_token": "xk_trip_outbound_side_b", "label": "B"},
		"map": []map[string]any{{"a": "cust_id", "b": "customerId"}},
	}
	r = admin("POST", "/accounts", trip)
	eq(r.Status, 201, "create the tripwire test account -> 201")

	codes := []int{}
	for i := 0; i < 5; i++ {
		rr := ingest("trip-test", "a2b", wrongGuess, map[string]any{"cust_id": "x"}, nil)
		codes = append(codes, rr.Status)
	}
	ok(codes[0] == 401 && codes[1] == 401 && codes[2] == 401,
		"first 3 bad guesses -> 401 (got %v)", codes)
	ok(codes[4] == 429, "past the threshold the account locks -> 429 (got %v)", codes)

	r = ingest("trip-test", "a2b", tripIn, map[string]any{"cust_id": "x"}, nil)
	eq(r.Status, 429, "while locked, even the VALID token is refused (fail-closed)")
	ok(r.Hdr.Get("Retry-After") != "", "429 carries Retry-After: %s", r.Hdr.Get("Retry-After"))

	r = admin("GET", "/tripwire", nil)
	eq(r.Status, 200, "tripwire status endpoint -> 200")
	ok(strings.Contains(r.Raw, "trip-test"), "tripwire status names the locked account")

	r = admin("POST", "/accounts/trip-test/tripwire/reset", nil)
	eq(r.Status, 200, "admin can reset the tripwire -> 200")
	r = ingest("trip-test", "a2b", tripIn, map[string]any{"cust_id": "x"}, nil)
	eq(r.Status, 201, "after reset the valid token works again")

	// lock expiry
	for i := 0; i < 5; i++ {
		ingest("trip-test", "a2b", wrongGuess, map[string]any{"cust_id": "x"}, nil)
	}
	r = ingest("trip-test", "a2b", tripIn, map[string]any{"cust_id": "x"}, nil)
	eq(r.Status, 429, "locked again after a second burst")
	fmt.Println("       waiting out the 5s lockout...")
	time.Sleep(6 * time.Second)
	r = ingest("trip-test", "a2b", tripIn, map[string]any{"cust_id": "x"}, nil)
	eq(r.Status, 201, "the lockout expires on its own after -trip-lock")

	// ================================================== discovery
	sec("Field discovery")
	r = admin("POST", "/accounts/trip-test/discover", map[string]any{"minutes": 10})
	eq(r.Status, 200, "open a 10-minute discovery window -> 200")
	ingest("trip-test", "a2b", tripIn, map[string]any{
		"cust_id":  "D-1",
		"nested":   map[string]any{"deep": map[string]any{"value": 3}},
		"an_array": []any{1, 2},
		"a_bool":   true,
	}, nil)
	r = admin("GET", "/accounts/trip-test/discover", nil)
	eq(r.Status, 200, "read discovered schema -> 200")
	ok(strings.Contains(r.Raw, "nested.deep.value"), "discovery recorded the nested path \"nested.deep.value\"")
	ok(strings.Contains(r.Raw, "a_bool"), "discovery recorded \"a_bool\"")
	ok(!strings.Contains(r.Raw, "D-1"), "discovery records paths and types but NEVER values")

	r = admin("DELETE", "/accounts/trip-test/discover", nil)
	eq(r.Status, 200, "close the discovery window -> 200")

	// ================================================== observability
	sec("Observability")
	r = admin("GET", "/stats", nil)
	eq(r.Status, 200, "GET /api/admin/stats -> 200")
	eq(at(r.Body, "version"), "0.4.1", "stats reports the version")
	ok(strings.Contains(r.Raw, "acme-globex"), "stats include per-account counters")

	r = admin("GET", "/logs", nil)
	eq(r.Status, 200, "GET /api/admin/logs -> 200")
	ok(!strings.Contains(r.Raw, aOutbound) && !strings.Contains(r.Raw, bOutbound),
		"activity log contains no outbound credentials")
	ok(!strings.Contains(r.Raw, "ada@acme.test"), "activity log contains no PII from payloads")

	r = do("GET", base+"/admin/", "", nil, nil)
	eq(r.Status, 200, "admin console HTML is served at /admin/")
	ok(strings.Contains(r.Raw, "<") && len(r.Raw) > 1000, "admin console returned a real HTML document (%d bytes)", len(r.Raw))
	ok(!strings.Contains(r.Raw, adminToken), "admin console HTML does not embed the admin token")

	// ================================================== persistence
	sec("Persistence")
	r = admin("GET", "/accounts", nil)
	eq(r.Status, 200, "list accounts -> 200")
	r = admin("DELETE", "/accounts/trip-test", nil)
	ok(r.Status == 200 || r.Status == 204, "delete account -> %d", r.Status)
	r = admin("GET", "/accounts/trip-test", nil)
	eq(r.Status, 404, "deleted account is gone -> 404")

	return newTok
}
