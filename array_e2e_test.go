//go:build e2e

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Array addressing against the shipped binary: rows saved over HTTP, a real
// destination, both legs, and what a refusal leaves behind.

func TestArraysEndToEnd(t *testing.T) {
	up := newUpstream()
	defer up.Close()
	in := start(t)

	// Rows that cannot be honoured are refused when saved, over the wire.
	st, _, body := do(t, "POST", in.base+"/api/admin/accounts", adminTok,
		`{"id":"bad","map":[{"a":"lines[0].sku","b":"items[].code"}]}`, nil)
	if st != 400 || !strings.Contains(string(body), "map[0].a") || !strings.Contains(string(body), "positional") {
		t.Fatalf("a positional index must be refused with its row named: %d %s", st, body)
	}

	acct := mkAccount(t, in, map[string]any{
		"id": "arrs", "enabled": true,
		"b": map[string]any{"target_url": up.URL},
		"map": []map[string]any{
			{"a": "lines[].sku", "b": "items[].product_code"},
			{"a": "lines[].shipped", "b": "items[].shipped_epoch", "transform": map[string]any{
				"kind": "date", "a_format": "rfc3339", "b_format": "unix"}},
		},
	})
	tok := inboundToken(acct, "a")
	up.respond(200, "application/json", `{"items":[{"product_code":"s1","shipped_epoch":1709283600}],"status":"ok"}`)

	st, hdr, body := do(t, "POST", in.base+"/t/arrs/a2b", tok,
		`{"lines":[{"sku":"s1","shipped":"2024-03-01T09:00:00Z"},{"sku":"s2","shipped":"2024-03-02T09:00:00Z"}]}`, nil)
	if st != 200 {
		t.Fatalf("want 200, got %d: %s", st, body)
	}
	sent, _, hits := up.got()
	items, _ := sent["items"].([]any)
	if _, leaked := sent["lines"]; leaked || len(items) != 2 {
		t.Fatalf("the destination must see only its own vocabulary: %v", sent)
	}
	for i, want := range []struct{ sku, epoch string }{{"s1", "1709283600"}, {"s2", "1709370000"}} {
		el := items[i].(map[string]any)
		if el["product_code"] != want.sku || fmt.Sprint(el["shipped_epoch"]) != want.epoch || len(el) != 2 {
			t.Errorf("element %d reached the destination as %v", i, el)
		}
	}
	// The destination's answer comes back in the caller's own words.
	got := decode(t, body)
	lines, _ := got["lines"].([]any)
	if _, leaked := got["items"]; leaked || len(lines) != 1 || got["status"] != "ok" {
		t.Fatalf("the response must come back in the caller's vocabulary: %s", body)
	}
	if el := lines[0].(map[string]any); el["sku"] != "s1" || el["shipped"] != "2024-03-01T09:00:00Z" {
		t.Errorf("element came back as %v", el)
	}
	// Four fields on the way out, two on the way back.
	if h := hdr.Get("X-Xlate-Applied"); h != "6" {
		t.Errorf("X-Xlate-Applied %q, want 6", h)
	}

	// An array the map cannot translate is refused and never forwarded.
	for _, bad := range []string{
		`{"lines":{"sku":"s1"}}`,
		`{"lines":[{"sku":"s1"},"stray"]}`,
		// One element more than the cap.
		`{"lines":[` + strings.Repeat(`{"sku":"x"},`, maxArrayLen) + `{"sku":"y"}]}`,
	} {
		st, _, body = do(t, "POST", in.base+"/t/arrs/a2b", tok, bad, nil)
		if st != 422 || decode(t, body)["code"] != "array_invalid" {
			t.Errorf("%.60s... -> want 422 array_invalid, got %d %.200s", bad, st, body)
		}
	}
	if _, _, after := up.got(); after != hits {
		t.Errorf("a refused message reached the destination: %d hits, had %d", after, hits)
	}

	// The refusals are on the trail by name, with no value.
	trail, err := os.ReadFile(in.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trail), `"reason":"array"`) || !strings.Contains(string(trail), `lines[1]`) {
		t.Errorf("refusals are missing from the trail: %s", trail)
	}
	if strings.Contains(string(trail), "stray") {
		t.Error("a value reached the audit trail")
	}

	// A destination that answers with something the map cannot translate.
	up.respond(200, "application/json", `{"items":"none"}`)
	st, _, body = do(t, "POST", in.base+"/t/arrs/a2b", tok, `{"lines":[{"sku":"s1"}]}`, nil)
	if st != 502 || decode(t, body)["code"] != "upstream_invalid" {
		t.Errorf("want 502 upstream_invalid, got %d %s", st, body)
	}
}
