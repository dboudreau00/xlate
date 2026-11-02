//go:build e2e

package main

import (
	"os"
	"strings"
	"testing"
)

// Top-level arrays against the shipped binary: a list answered bare, a list
// sent bare, a list wrapped on the other side, and what a refusal leaves behind.

func upstreamSaw(u *upstream) (body string, hits int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return string(u.body), u.hits
}

func TestTopLevelArraysEndToEnd(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	date := map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"}
	acct := mkAccount(t, in, map[string]any{
		"id": "rl", "enabled": true,
		"a":   map[string]any{"inbound_methods": []string{"GET", "POST"}},
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "[].sku", "b": "[].product_code"}, {"a": "[].shipped", "b": "[].shipped_epoch", "transform": date}},
	})
	tok := inboundToken(acct, "a")

	// A asks for a list; B answers bare in its own words, A reads its own.
	up.respond(200, "application/json", `[{"product_code":"s1","shipped_epoch":1709283600},{"product_code":"s2","shipped_epoch":1709370000}]`)
	st, hdr, body := do(t, "GET", in.base+"/t/rl/a2b", tok, nil, nil)
	if st != 200 {
		t.Fatalf("GET list: %d %s", st, body)
	}
	mtSameJSON(t, string(body), `[{"sku":"s1","shipped":"2024-03-01T09:00:00Z"},{"sku":"s2","shipped":"2024-03-02T09:00:00Z"}]`)
	if h := hdr.Get("X-Xlate-Applied"); h != "4" {
		t.Errorf("X-Xlate-Applied %q, want 4", h)
	}

	// A sends a bare list; B must receive it in its words, bare.
	up.respond(200, "application/json", `[{"product_code":"s1"}]`)
	st, _, body = do(t, "POST", in.base+"/t/rl/a2b", tok, `[{"sku":"s1","shipped":"2024-03-01T09:00:00Z"}]`, nil)
	if st != 200 {
		t.Fatalf("POST list: %d %s", st, body)
	}
	if sent, _ := upstreamSaw(up); !strings.HasPrefix(sent, "[") {
		t.Errorf("B did not receive a bare list: %s", sent)
	} else {
		mtSameJSON(t, sent, `[{"product_code":"s1","shipped_epoch":1709283600}]`)
	}
	mtSameJSON(t, string(body), `[{"sku":"s1"}]`)

	// A list that cannot be translated is refused and never forwarded.
	_, before := upstreamSaw(up)
	for _, bad := range []string{`[{"sku":"a"},"stray"]`, `[1,2]`, `[` + strings.Repeat(`{"sku":"x"},`, maxArrayLen) + `{"sku":"y"}]`} {
		st, _, body = do(t, "POST", in.base+"/t/rl/a2b", tok, bad, nil)
		if st != 422 || decode(t, body)["code"] != "array_invalid" {
			t.Errorf("%.40s...: want 422 array_invalid, got %d %.200s", bad, st, body)
		}
	}
	if _, after := upstreamSaw(up); after != before {
		t.Errorf("a refused list reached the destination: %d hits, had %d", after, before)
	}
	// And an answer that cannot be translated never reaches the caller.
	up.respond(200, "application/json", `[{"product_code":"s1"},"stray"]`)
	st, _, body = do(t, "GET", in.base+"/t/rl/a2b", tok, nil, nil)
	if st != 502 || decode(t, body)["code"] != "upstream_invalid" || strings.Contains(string(body), "stray") {
		t.Errorf("want 502 upstream_invalid, got %d %s", st, body)
	}
	trail, err := os.ReadFile(in.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trail), `"reason":"array"`) || !strings.Contains(string(trail), `"reason":"response_array"`) {
		t.Errorf("refusals are missing from the trail: %s", trail)
	}
	if strings.Contains(string(trail), "stray") || strings.Contains(string(trail), "�") || strings.Contains(string(trail), `�`) {
		t.Error("a value, or the engine's own name for the array, reached the audit trail")
	}

	// One side wraps its lists and the other does not.
	rw := mkAccount(t, in, map[string]any{
		"id": "rw", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "[].sku", "b": "data[].code"}},
	})
	up.respond(200, "application/json", `{"data":[{"code":"s1"}]}`)
	st, _, body = do(t, "POST", in.base+"/t/rw/a2b", inboundToken(rw, "a"), `[{"sku":"s1"}]`, nil)
	if sent, _ := upstreamSaw(up); st != 200 {
		t.Fatalf("wrap: %d %s", st, body)
	} else {
		mtSameJSON(t, sent, `{"data":[{"code":"s1"}]}`)
	}
	mtSameJSON(t, string(body), `[{"sku":"s1"}]`)
	up.respond(200, "application/json", `{"data":[{"code":"s1"}],"total":3}`)
	if st, _, body = do(t, "POST", in.base+"/t/rw/a2b", inboundToken(rw, "a"), `[{"sku":"s1"}]`, nil); st != 502 || strings.Contains(string(body), "total") {
		t.Errorf("an envelope that cannot unwrap: want 502 without its content, got %d %s", st, body)
	}

	// An account with no row for a top-level array is as it always was.
	nr := mkAccount(t, in, map[string]any{
		"id": "nr", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "lines[].sku", "b": "items[].code"}},
	})
	st, _, body = do(t, "POST", in.base+"/t/nr/a2b", inboundToken(nr, "a"), `[{"sku":"s1"}]`, nil)
	if st != 400 || decode(t, body)["code"] != "bad_json" {
		t.Errorf("a bare body without a row for it: want 400 bad_json, got %d %s", st, body)
	}
}
