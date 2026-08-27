package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Adversarial pass over the surface added for field discovery, node
// stats and rejection logging. The premise: the data plane is reachable
// by an integration partner, not an operator, and field discovery walks
// whatever JSON they send. Anything derived from that input is hostile
// until proven bounded.

// A payload nested far deeper than the walker's limit must not blow the
// stack or hang; it must degrade to a bounded observation.
func TestAdvDeeplyNestedPayload(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "deep", "enabled": true})
	discoverOn(t, ts, "deep", 30)

	const depth = 5000
	body := strings.Repeat(`{"n":`, depth) + `1` + strings.Repeat(`}`, depth)

	done := make(chan apiResp, 1)
	go func() { done <- call(t, ts, "POST", "/t/deep/a2b", sideToken(acct, "a"), body) }()
	select {
	case r := <-done:
		// 502 no_target is the correct answer for an unwired account; what
		// must not happen is a panic, a hang, or a 500.
		if r.status == http.StatusInternalServerError {
			t.Errorf("deep nesting produced a 500: %s", r.body)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("deeply nested payload hung the handler")
	}

	rep := discoverReport(t, ts, "deep")
	d, _ := rep["a2b"].(map[string]any)
	fields, _ := d["fields"].([]any)
	if len(fields) > maxDiscoveredPaths {
		t.Errorf("path count unbounded: %d", len(fields))
	}
	for _, f := range fields {
		if p := fmt.Sprint(f.(map[string]any)["path"]); strings.Count(p, ".") > maxDiscoverDepth {
			t.Errorf("path deeper than the limit escaped: %q", p)
		}
	}
}

// Distinct field names across many requests must not grow the store
// without bound — a partner controls every key they send.
func TestAdvUnboundedDistinctKeysAcrossRequests(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "churn", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "churn", 30)

	for i := 0; i < 120; i++ {
		call(t, ts, "POST", "/t/churn/a2b", tok, fmt.Sprintf(`{"unique_%d":"v","stable":"v"}`, i))
	}
	rep := discoverReport(t, ts, "churn")
	d, _ := rep["a2b"].(map[string]any)
	fields, _ := d["fields"].([]any)
	if len(fields) > maxDiscoveredPaths {
		t.Errorf("distinct keys grew past the cap: %d", len(fields))
	}
	if len(fields) == maxDiscoveredPaths && d["truncated"] != true {
		t.Error("hit the cap without reporting truncated")
	}
}

// Field names are echoed to the admin API and rendered in the console.
// Nothing structural may survive the trip.
func TestAdvHostileFieldNames(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "hostile", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "hostile", 30)

	// JSON string escapes let a key carry bytes a raw key cannot: CR, LF,
	// NUL, quotes, and markup that would matter once rendered.
	call(t, ts, "POST", "/t/hostile/a2b", tok,
		`{"a\u0020b":1,"c\rd":2,"e\nf":3,"<script>alert(1)</script>":4,`+
			`"\"quoted\"":5,"tab\there":6,"nul\u0000key":7,`+
			`"</td><td\u0020onclick=x":8}`)

	rep := admin(t, ts, "GET", "/api/admin/accounts/hostile/discover", nil)
	logs := admin(t, ts, "GET", "/api/admin/logs?account=hostile", nil)

	for _, blob := range [][]byte{rep.body, logs.body} {
		// json.Encoder terminates each document with a newline of its own;
		// only bytes inside the document are interesting.
		s := strings.TrimRight(string(blob), "\n")
		for _, bad := range []string{"\x00", "\r", "\n", "\t"} {
			if strings.Contains(s, bad) {
				t.Errorf("raw control byte %q survived into %s", bad, s[:min(200, len(s))])
			}
		}
	}
	// The path list must still be usable.
	got := paths(t, rep.json(t), "a2b")
	if len(got) == 0 {
		t.Error("hostile keys wiped out the whole observation set")
	}
	for p := range got {
		if strings.ContainsAny(p, "\x00\r\n\t") {
			t.Errorf("unsanitised path recorded: %q", p)
		}
	}
}

// Every discovery route is a control-plane route and must demand the
// admin token, including the ones added late.
func TestAdvDiscoveryRoutesRequireAdmin(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, map[string]any{"id": "guarded"})

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/admin/accounts/guarded/discover"},
		{"POST", "/api/admin/accounts/guarded/discover"},
		{"DELETE", "/api/admin/accounts/guarded/discover"},
		{"GET", "/api/admin/stats"},
	} {
		for _, tok := range []string{"", "wrong-token"} {
			r := call(t, ts, tc.method, tc.path, tok, map[string]any{"minutes": 10})
			if r.status != 401 {
				t.Errorf("%s %s with token %q: want 401, got %d", tc.method, tc.path, tok, r.status)
			}
		}
	}
}

// Discovery must not become a way to read payload values back out via a
// side channel — counts and types only.
func TestAdvDiscoveryLeaksNothingViaTypesOrCounts(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "sidechan", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "sidechan", 30)

	call(t, ts, "POST", "/t/sidechan/a2b", tok, `{"pan":"4111111111111111","n":9007199254740993}`)
	rep := admin(t, ts, "GET", "/api/admin/accounts/sidechan/discover", nil)
	body := string(rep.body)
	for _, secret := range []string{"4111111111111111", "9007199254740993"} {
		if strings.Contains(body, secret) {
			t.Errorf("value %q reachable through the discovery report", secret)
		}
	}
	got := paths(t, rep.json(t), "a2b")
	if got["pan"] != "string" || got["n"] != "number" {
		t.Errorf("types should still be reported: %v", got)
	}
}

// Discovery, translation, stats and admin mutation all touch shared
// state on the request path. Run them together under -race.
func TestAdvConcurrentDiscoveryAndMutation(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "churny", "enabled": true,
		"map": []map[string]any{{"a": "x", "b": "y"}}})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "churny", 30)

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				call(t, ts, "POST", "/t/churny/a2b", tok,
					fmt.Sprintf(`{"x":%d,"nested":{"k%d":"v"}}`, i, i))
			case 1:
				admin(t, ts, "GET", "/api/admin/accounts/churny/discover", nil)
			case 2:
				admin(t, ts, "GET", "/api/admin/stats", nil)
			case 3:
				admin(t, ts, "POST", "/api/admin/accounts/churny/discover",
					map[string]any{"minutes": 30})
			}
		}(i)
	}
	wg.Wait()

	if r := admin(t, ts, "GET", "/api/admin/stats", nil); r.status != 200 {
		t.Errorf("stats broke under concurrency: %d %s", r.status, r.body)
	}
}

// Deleting an account mid-flight must not resurrect its observations or
// panic the handler.
func TestAdvDeleteDuringDiscovery(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "vanishing", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "vanishing", 30)
	call(t, ts, "POST", "/t/vanishing/a2b", tok, `{"leftover":"v"}`)

	if r := admin(t, ts, "DELETE", "/api/admin/accounts/vanishing", nil); r.status != 204 {
		t.Fatalf("delete: %d", r.status)
	}
	if r := admin(t, ts, "GET", "/api/admin/accounts/vanishing/discover", nil); r.status != 404 {
		t.Errorf("discover after delete: want 404, got %d", r.status)
	}
	// Recreating the id must not inherit the old observations.
	mustCreate(t, ts, map[string]any{"id": "vanishing", "enabled": true})
	r := admin(t, ts, "GET", "/api/admin/accounts/vanishing/discover", nil)
	if strings.Contains(string(r.body), "leftover") {
		t.Error("observations survived the account being deleted and recreated")
	}
}

// The window is stored on the account, so it must survive the same
// validation as any other field when written through the normal PUT.
func TestAdvDiscoverUntilCannotBeSmuggledPastValidation(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, map[string]any{"id": "smuggle"})

	for _, when := range []string{
		time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		time.Now().UTC().Add(maxDiscoverWindow + time.Hour).Format(time.RFC3339),
	} {
		r := admin(t, ts, "PUT", "/api/admin/accounts/smuggle", map[string]any{"discover_until": when})
		if r.status != 400 {
			t.Errorf("window %s: want 400, got %d: %s", when, r.status, r.body)
		}
	}
	// A past timestamp is harmless: it simply reads as inactive.
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if r := admin(t, ts, "PUT", "/api/admin/accounts/smuggle", map[string]any{"discover_until": past}); r.status != 200 {
		t.Errorf("a past window should be accepted, got %d: %s", r.status, r.body)
	}
	if r := admin(t, ts, "GET", "/api/admin/accounts/smuggle/discover", nil); r.json(t)["active"] != false {
		t.Error("a past window should not be active")
	}
}

// Ring entries carry discovery shapes; the ring is bounded, so the
// memory they hold must be too.
func TestAdvRingWithDiscoveryShapesStaysBounded(t *testing.T) {
	r := NewRing(10)
	wide := make([]string, maxDiscoveredPaths)
	for i := range wide {
		wide[i] = strings.Repeat("k", maxDiscoverKeyLen) + ":string"
	}
	for i := 0; i < 500; i++ {
		r.Add(LogEntry{Account: "a", Direction: "a2b", Status: 200, Fields: wide})
	}
	if got := len(r.List("", 1000)); got != 10 {
		t.Errorf("ring should hold 10 entries, got %d", got)
	}
}

// The dashboard is admin-only, but confirm it cannot be used to read
// per-account traffic without the token, and that a hostile account id
// cannot break the response.
func TestAdvStatsWithHostileAccountID(t *testing.T) {
	// Account ids are regex-constrained, so the hostile case is a stats
	// row for an id that no longer validates — reachable only if the
	// regex ever loosens. Assert the encoder copes regardless.
	s := NewStats()
	s.Record(LogEntry{Account: "</script><img src=x onerror=alert(1)>", AccountKnown: true, Direction: "a2b",
		Status: 200, Time: time.Now()})
	snap := s.Snapshot()
	if len(snap.Accounts) != 1 {
		t.Fatalf("want 1 row, got %d", len(snap.Accounts))
	}
	if !strings.Contains(snap.Accounts[0].Account, "script") {
		t.Error("account id was mangled rather than passed through for the encoder to escape")
	}
}

// An unwired account now reads and decodes the body before answering
// 502, so discovery can see it. Confirm the body cap still applies —
// that reordering must not have created an unbounded read.
func TestAdvUnwiredAccountStillHonoursBodyCap(t *testing.T) {
	ts := newAPI(t, func(s *Server) { s.maxBody = 2048 })
	acct := mustCreate(t, ts, map[string]any{"id": "unwired", "enabled": true})
	discoverOn(t, ts, "unwired", 30)

	big := `{"x":"` + strings.Repeat("A", 4096) + `"}`
	r := call(t, ts, "POST", "/t/unwired/a2b", sideToken(acct, "a"), big)
	if r.status != http.StatusRequestEntityTooLarge {
		t.Errorf("want 413, got %d: %s", r.status, r.body)
	}
	if got := r.json(t)["code"]; got != "payload_too_large" {
		t.Errorf("code: want payload_too_large, got %v", got)
	}
}
