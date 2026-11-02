//go:build e2e

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The same crossings as TestEveryMethodCrossesInBothDirections, against the
// shipped binary as a subprocess, plus what only a process can show: the state
// file, a restart, the trail on disk and the process log.

// relaunch starts the binary again on an instance's state and trail and
// returns its base URL. The process is killed when the test ends.
func relaunch(t *testing.T, in *instance) string {
	t.Helper()
	port := freePort(t)
	cmd := exec.Command(binary(t),
		"-listen", fmt.Sprintf("127.0.0.1:%d", port),
		"-state", in.statePath, "-audit", in.auditPath, "-admin-token", adminTok)
	buf := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = buf, buf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := http.Get(base + "/healthz"); err == nil {
			r.Body.Close()
			return base
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("relaunched xlate did not become ready\n%s", buf)
	return ""
}

func TestEveryMethodCrossesInBothDirectionsOnTheRealBinary(t *testing.T) {
	in := start(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mkAccount(t, in, mtDoc("duo", a, b, mtAllMethods, mtAllMethods))

	for _, d := range mtDirections(a, b) {
		for _, method := range mtAllMethods {
			t.Run(d.name+" "+method, func(t *testing.T) {
				d.dest.answer(200, "application/json", d.reply)
				path, body, hdr := d.request(method)
				st, h, resp := do(t, method, in.base+path, d.token, body, hdr)
				d.expect(t, method, st, h, resp)
			})
		}
	}
}

func TestMethodGateOnTheRealBinary(t *testing.T) {
	in := start(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mkAccount(t, in, mtDoc("duo", a, b, []string{"GET", "POST"}, nil)) // B: the default
	mkAccount(t, in, mtDoc("trip", a, b, []string{"GET", "DELETE"}, nil))

	t.Run("a method that is not listed is a 405, with or without credentials", func(t *testing.T) {
		for i := 0; i < 8; i++ { // past the tripwire threshold on purpose
			for _, tc := range []struct{ method, dir, token, allow string }{
				{"DELETE", "a2b", "", "GET, POST"},
				{"PUT", "a2b", mtAIn, "GET, POST"},
				{"GET", "b2a", mtBIn, "POST"},
				{"PATCH", "b2a", "", "POST"},
			} {
				st, h, body := do(t, tc.method, in.base+"/t/duo/"+tc.dir, tc.token, nil, nil)
				if st != 405 || h.Get("Allow") != tc.allow || decode(t, body)["code"] != "method_not_allowed" {
					t.Fatalf("%s %s: want 405 Allow %q, got %d %q %s", tc.method, tc.dir, tc.allow, st, h.Get("Allow"), body)
				}
			}
		}
		if a.hits()+b.hits() != 0 {
			t.Error("a refused method reached a partner")
		}
		_, _, body := do(t, "GET", in.base+"/api/admin/tripwire", adminTok, nil, nil)
		if tw := decode(t, body)["duo"].(map[string]any); tw["state"] != "armed" || fmt.Sprint(tw["count"]) != "0" {
			t.Errorf("a wrong method fed the tripwire: %v", tw)
		}
	})

	t.Run("an unknown account or direction is a 404 whatever the method", func(t *testing.T) {
		for _, m := range []string{"GET", "DELETE", "POST"} {
			if st, _, body := do(t, m, in.base+"/t/ghost/a2b", mtAIn, nil, nil); st != 404 || decode(t, body)["code"] != "not_found" {
				t.Errorf("%s unknown account: %d %s", m, st, body)
			}
			if st, _, body := do(t, m, in.base+"/t/duo/sideways", mtAIn, nil, nil); st != 404 || decode(t, body)["code"] != "bad_direction" {
				t.Errorf("%s bad direction: %d %s", m, st, body)
			}
		}
	})

	t.Run("a listed method still needs credentials, and its refusals feed the tripwire", func(t *testing.T) {
		for i := 0; i < 6; i++ {
			m := []string{"GET", "DELETE"}[i%2]
			if st, _, _ := do(t, m, in.base+"/t/trip/a2b", "not-the-token", nil, nil); st != 401 {
				t.Fatalf("%s with a bad token: want 401, got %d", m, st)
			}
		}
		if st, _, body := do(t, "GET", in.base+"/t/trip/a2b", mtAIn, nil, nil); st != 429 || decode(t, body)["code"] != "account_locked" {
			t.Errorf("want 429 account_locked after the trip, got %d %s", st, body)
		}
	})
}

func TestQueryRulesOnTheRealBinary(t *testing.T) {
	in := start(t)
	a, b, third := newMtPartner(t), newMtPartner(t), newMtPartner(t)
	doc := mtDoc("duo", a, b, mtAllMethods, mtAllMethods) // strict_transforms is off
	doc["b"].(map[string]any)["target_url"] = b.URL + "/api?key=SECRET"
	mkAccount(t, in, doc)
	get := func(query string) (int, http.Header, []byte) {
		return do(t, "GET", in.base+"/t/duo/a2b?"+query, mtAIn, nil, nil)
	}

	t.Run("a query is strict whatever the account says", func(t *testing.T) {
		st, _, body := get("payment_id=p&created_at=yesterday")
		if st != 422 || decode(t, body)["code"] != "transform_failed" {
			t.Fatalf("want 422 transform_failed, got %d %s", st, body)
		}
		for _, leak := range []string{"created_epoch", "unix", "yesterday"} {
			if strings.Contains(string(body), leak) {
				t.Errorf("the refusal leaks %q: %s", leak, body)
			}
		}
	})
	t.Run("the target's own parameters win", func(t *testing.T) {
		for _, q := range []string{"key=evil", "KEY=evil", "%6bey=evil"} {
			if st, _, body := get(q); st != 400 || decode(t, body)["code"] != "validation_failed" {
				t.Errorf("?%s: want 400, got %d %s", q, st, body)
			}
		}
	})
	t.Run("a body on GET is refused", func(t *testing.T) {
		if st, _, body := do(t, "GET", in.base+"/t/duo/a2b", mtAIn, `{"payment_id":"p"}`, nil); st != 400 {
			t.Errorf("want 400, got %d %s", st, body)
		}
	})
	if b.hits() != 0 {
		t.Fatalf("a refused request reached the destination (%d hits)", b.hits())
	}

	t.Run("a clean query reaches the destination after the target's own", func(t *testing.T) {
		if st, _, body := get("payment_id=p-1&note=n"); st != 200 {
			t.Fatalf("%d %s", st, body)
		}
		if got := b.take(t); got.method != "GET" || got.uri != "/api?key=SECRET&note=n&payment_proof=p-1" {
			t.Errorf("destination request = %s %s", got.method, got.uri)
		}
	})
	t.Run("a redirect is relayed and never followed", func(t *testing.T) {
		b.mu.Lock()
		b.status, b.ct, b.reply, b.location = 302, "", "", third.URL+"/elsewhere"
		b.mu.Unlock()
		st, h, _ := get("payment_id=p-1")
		if st != 302 || h.Get("Location") != third.URL+"/elsewhere" {
			t.Errorf("got %d Location %q", st, h.Get("Location"))
		}
		if third.hits() != 0 {
			t.Error("the redirect was followed")
		}
	})
}

// The lists are part of the state file, survive a restart, and the trail and
// the process log stay free of what a query carried, also when a forward fails.
func TestMethodListsTrailAndLogOnTheRealBinary(t *testing.T) {
	in := start(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mkAccount(t, in, mtDoc("duo", a, b, []string{"GET", "DELETE"}, []string{"PUT"}))
	dead := mtDoc("dead", a, b, mtAllMethods, mtAllMethods)
	dead["b"].(map[string]any)["target_url"] = closedPort(t) + "/api?key=SECRET"
	mkAccount(t, in, dead)

	for _, m := range []string{"GET", "DELETE"} {
		st, _, body := do(t, m, in.base+"/t/dead/a2b?payment_id=PII-123&customer.id=PII-456", mtAIn, nil, nil)
		if st != 502 || decode(t, body)["code"] != "upstream_failed" || strings.Contains(string(body), "PII") {
			t.Fatalf("%s to a dead destination: %d %s", m, st, body)
		}
	}
	do(t, "GET", in.base+"/t/duo/a2b?payment_id=p", mtAIn, nil, nil)
	in.stop()

	state, err := os.ReadFile(in.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(state), `"inbound_methods"`); n != 4 {
		t.Errorf("the state file holds %d lists, want 4 (two accounts, two sides)", n)
	}

	trail, err := os.ReadFile(in.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for where, text := range map[string]string{"audit trail": string(trail), "process log": in.log.String()} {
		for _, leak := range []string{"PII-123", "PII-456", "SECRET", "payment_proof", "party.ref", "key=", mtAIn, mtBIn, mtAOut, mtBOut} {
			if strings.Contains(text, leak) {
				t.Errorf("the %s holds %q", where, leak)
			}
		}
	}
	methods := map[string]int{}
	var granted []any
	for _, line := range strings.Split(strings.TrimSpace(string(trail)), "\n") {
		rec := mtJSON(t, line).(map[string]any)
		d, _ := rec["detail"].(map[string]any)
		switch rec["event"] {
		case "ingest.error", "ingest.ok":
			methods[fmt.Sprint(rec["event"])+" "+fmt.Sprint(d["method"])]++
		case "account.create":
			if d["account"] == "duo" {
				granted = []any{d["a_methods"], d["b_methods"]}
			}
		}
	}
	if want := map[string]int{"ingest.error GET": 1, "ingest.error DELETE": 1, "ingest.ok GET": 1}; !reflect.DeepEqual(methods, want) {
		t.Errorf("trail methods = %v, want %v", methods, want)
	}
	if want := []any{[]any{"GET", "DELETE"}, []any{"PUT"}}; !reflect.DeepEqual(granted, want) {
		t.Errorf("account.create lists = %v, want %v", granted, want)
	}
	if out, err := exec.Command(binary(t), "-verify-audit", in.auditPath).CombinedOutput(); err != nil || !strings.Contains(string(out), "audit chain OK") {
		t.Errorf("the trail does not verify: %v\n%s", err, out)
	}

	// A restart keeps the lists: what was granted still works, nothing else does.
	base := relaunch(t, in)
	for _, tc := range []struct {
		method, dir, token string
		status             int
		allow              string
	}{
		{"GET", "a2b", mtAIn, 200, ""},
		{"PUT", "a2b", mtAIn, 405, "GET, DELETE"},
		{"PUT", "b2a", mtBIn, 200, ""},
		{"POST", "b2a", mtBIn, 405, "PUT"},
	} {
		var body any
		if methodHasBody(tc.method) {
			body = `{"payment_proof":"p"}`
		}
		st, h, resp := do(t, tc.method, base+"/t/duo/"+tc.dir, tc.token, body, nil)
		if st != tc.status || h.Get("Allow") != tc.allow {
			t.Errorf("after a restart, %s %s: want %d Allow %q, got %d %q %s", tc.method, tc.dir, tc.status, tc.allow, st, h.Get("Allow"), resp)
		}
	}
}
