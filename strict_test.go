package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// Strict transform mode: a value that cannot be converted refuses the
// request (or the destination's response) instead of travelling unconverted.

const (
	strictGoodBody = `{"created_at":"2026-08-06T12:00:00Z","ref":"r1"}`
	strictBadBody  = `{"created_at":"not-a-date","ref":"r2"}`
)

// strictUpstream counts what reaches it and answers with a fixed body.
func strictUpstream(t *testing.T, reply string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(up.Close)
	return up, &n
}

func strictAccountDoc(id, upURL string, strict bool) map[string]any {
	return map[string]any{
		"id": id, "enabled": true, "strict_transforms": strict,
		"b": map[string]any{"target_url": upURL},
		"map": []map[string]any{
			{"a": "created_at", "b": "created_epoch", "transform": map[string]any{
				"kind": "date", "a_format": "rfc3339", "b_format": "unix"}},
			{"a": "ref", "b": "reference"},
		},
	}
}

func strictTrail(t *testing.T, srv *Server) string {
	t.Helper()
	b, err := os.ReadFile(srv.audit.f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTranslateStrictRecordsFailedPaths(t *testing.T) {
	pairs := []FieldPair{
		{A: "when.created", B: "created_epoch", Transform: &Transform{Kind: "date", AFormat: "rfc3339", BFormat: "unix"}},
		{A: "when.closed", B: "closed_epoch", Transform: &Transform{Kind: "date", AFormat: "rfc3339", BFormat: "unix"}},
		{A: "ref", B: "reference"},
	}
	bad := func() map[string]any {
		return map[string]any{"when": map[string]any{"created": "nope", "closed": "also nope"}, "ref": "r"}
	}

	res := Translate(bad(), pairs, AtoB, TranslateOptions{Strict: true})
	if len(res.Failed) != 2 || res.Failed[0] != "when.created" || res.Failed[1] != "when.closed" {
		t.Fatalf("Failed = %v, want both source paths in pair order", res.Failed)
	}
	if len(res.Warnings) != 2 {
		t.Errorf("the warnings must still be recorded: %v", res.Warnings)
	}

	if res := Translate(bad(), pairs, AtoB, TranslateOptions{}); len(res.Failed) != 0 || len(res.Warnings) != 2 {
		t.Errorf("without Strict the failure stays a warning: failed %v, warnings %v", res.Failed, res.Warnings)
	}

	good := map[string]any{"when": map[string]any{"created": "2026-08-06T12:00:00Z"}, "ref": "r"}
	if res := Translate(good, pairs, AtoB, TranslateOptions{Strict: true}); len(res.Failed) != 0 {
		t.Errorf("a convertible value must not fail: %v", res.Failed)
	}
}

func TestBoundedPathsCapsAndCleans(t *testing.T) {
	many := make([]string, 3*maxLoggedFields)
	for i := range many {
		many[i] = "a\nb" + strings.Repeat("x", 2*maxLoggedFieldName)
	}
	got := boundedPaths(many)
	if len(got) != maxLoggedFields {
		t.Fatalf("listed %d paths, want %d", len(got), maxLoggedFields)
	}
	for _, p := range got {
		if strings.ContainsAny(p, "\r\n") || len([]rune(p)) > maxLoggedFieldName+1 {
			t.Fatalf("path not cleaned or bounded: %q", p)
		}
	}
}

func TestStrictRefusesRequestWithUnconvertibleValue(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	up, hits := strictUpstream(t, `{"created_epoch":1786017600}`)
	acct := mustCreate(t, ts, strictAccountDoc("strict", up.URL, true))
	if acct["strict_transforms"] != true {
		t.Fatalf("strict_transforms not stored: %v", acct["strict_transforms"])
	}
	tok := sideToken(acct, "a")

	if r := call(t, ts, "POST", "/t/strict/a2b", tok, strictGoodBody); r.status != 200 {
		t.Fatalf("a convertible request must pass: %d %s", r.status, r.body)
	}
	if hits.Load() != 1 {
		t.Fatalf("destination saw %d requests, want 1", hits.Load())
	}

	r := call(t, ts, "POST", "/t/strict/a2b", tok, strictBadBody)
	if r.status != 422 {
		t.Fatalf("want 422, got %d: %s", r.status, r.body)
	}
	if code := r.json(t)["code"]; code != "transform_failed" {
		t.Errorf("code = %v", code)
	}
	if fe := r.fieldErrors(t); len(fe) != 1 || fe["created_at"] == "" {
		t.Errorf("the sender should be told which of its own fields failed: %v", fe)
	}
	// Vocabulary isolation and no echo of data: neither the destination's
	// names nor the offending value may reach the sender.
	for _, leak := range []string{"created_epoch", "reference", "not-a-date", "unix", "rfc3339"} {
		if strings.Contains(string(r.body), leak) {
			t.Errorf("refusal leaks %q: %s", leak, r.body)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("a refused request reached the destination (%d hits)", hits.Load())
	}

	trail := strictTrail(t, srv)
	if !strings.Contains(trail, `"event":"ingest.rejected"`) || !strings.Contains(trail, `"reason":"transform"`) ||
		!strings.Contains(trail, `"fields":["created_at"]`) {
		t.Errorf("no rejection record naming the field in the trail:\n%s", trail)
	}
	if strings.Contains(trail, "not-a-date") {
		t.Error("the offending value reached the audit trail")
	}

	logs := admin(t, ts, "GET", "/api/admin/logs?account=strict&limit=1", nil).json(t)["entries"].([]any)
	if e := logs[0].(map[string]any); e["status"].(json.Number).String() != "422" || e["err"] != "strict: transform refused" {
		t.Errorf("activity entry = %v", e)
	}

	// A partner sending bad dates is a data problem, not a credential
	// guess: it must never feed the tripwire.
	for i := 0; i < 12; i++ {
		call(t, ts, "POST", "/t/strict/a2b", tok, strictBadBody)
	}
	if r := call(t, ts, "POST", "/t/strict/a2b", tok, strictGoodBody); r.status != 200 {
		t.Errorf("refusals tripped the account: %d %s", r.status, r.body)
	}
}

func TestStrictOffKeepsFailOpen(t *testing.T) {
	ts := newAPI(t)
	up, hits := strictUpstream(t, `{"created_epoch":1786017600}`)
	acct := mustCreate(t, ts, strictAccountDoc("lax", up.URL, false))
	if _, present := acct["strict_transforms"]; present {
		t.Errorf("an off setting should not appear in the document: %v", acct)
	}
	r := call(t, ts, "POST", "/t/lax/a2b", sideToken(acct, "a"), strictBadBody)
	if r.status != 200 || r.hdr.Get("X-Xlate-Warnings") != "1" {
		t.Fatalf("fail-open changed: %d warnings=%q %s", r.status, r.hdr.Get("X-Xlate-Warnings"), r.body)
	}
	if hits.Load() != 1 {
		t.Errorf("the request should still be forwarded, saw %d", hits.Load())
	}
}

func TestStrictRefusesUnconvertibleResponse(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	up, hits := strictUpstream(t, `{"created_epoch":"garbage","reference":"r1"}`)
	strict := mustCreate(t, ts, strictAccountDoc("strict", up.URL, true))
	lax := mustCreate(t, ts, strictAccountDoc("lax", up.URL, false))

	r := call(t, ts, "POST", "/t/strict/a2b", sideToken(strict, "a"), strictGoodBody)
	if r.status != 502 || r.json(t)["code"] != "upstream_invalid" {
		t.Fatalf("want 502 upstream_invalid, got %d: %s", r.status, r.body)
	}
	for _, leak := range []string{"garbage", "created_epoch", "reference"} {
		if strings.Contains(string(r.body), leak) {
			t.Errorf("the destination's response leaked through the refusal: %s", r.body)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("the destination should have been called exactly once, saw %d", hits.Load())
	}
	trail := strictTrail(t, srv)
	if !strings.Contains(trail, `"reason":"response_transform"`) || !strings.Contains(trail, `"upstream":200`) {
		t.Errorf("no response-refusal record in the trail:\n%s", trail)
	}
	if strings.Contains(trail, `"event":"ingest.ok"`) {
		t.Error("a refused response was also recorded as delivered")
	}

	// Without strict mode the same response is relayed with a warning.
	r = call(t, ts, "POST", "/t/lax/a2b", sideToken(lax, "a"), strictGoodBody)
	if r.status != 200 || r.hdr.Get("X-Xlate-Warnings") != "1" || !strings.Contains(string(r.body), "garbage") {
		t.Errorf("fail-open response leg changed: %d warnings=%q %s", r.status, r.hdr.Get("X-Xlate-Warnings"), r.body)
	}
}

func TestStrictDryRunReportsRefusal(t *testing.T) {
	ts := newAPI(t)
	up, _ := strictUpstream(t, `{}`)
	mustCreate(t, ts, strictAccountDoc("strict", up.URL, true))
	mustCreate(t, ts, strictAccountDoc("lax", up.URL, false))
	dry := func(id, payload string) map[string]any {
		r := admin(t, ts, "POST", "/api/admin/accounts/"+id+"/test",
			map[string]any{"direction": "a2b", "payload": json.RawMessage(payload)})
		if r.status != 200 {
			t.Fatalf("dry run: %d %s", r.status, r.body)
		}
		return r.json(t)
	}

	got := dry("strict", strictBadBody)
	if got["rejected"] != true {
		t.Errorf("strict dry run did not report the refusal: %v", got)
	}
	if failed, _ := got["failed"].([]any); len(failed) != 1 || failed[0] != "created_at" {
		t.Errorf("failed = %v", got["failed"])
	}
	if _, present := dry("strict", strictGoodBody)["rejected"]; present {
		t.Error("a convertible payload was reported as refused")
	}
	if _, present := dry("lax", strictBadBody)["rejected"]; present {
		t.Error("an account that is not strict reported a refusal")
	}
}

// A PUT from a client that predates the setting omits it; that must keep
// the stored value, because dropping it would reopen a fail-closed account.
func TestStrictSurvivesAPutThatOmitsIt(t *testing.T) {
	ts := newAPI(t)
	up, _ := strictUpstream(t, `{}`)
	mustCreate(t, ts, strictAccountDoc("strict", up.URL, true))

	doc := admin(t, ts, "GET", "/api/admin/accounts/strict", nil).json(t)
	delete(doc, "strict_transforms")
	doc["name"] = "renamed"
	if r := admin(t, ts, "PUT", "/api/admin/accounts/strict", doc); r.status != 200 {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	got := admin(t, ts, "GET", "/api/admin/accounts/strict", nil).json(t)
	if got["name"] != "renamed" || got["strict_transforms"] != true {
		t.Fatalf("an omitting PUT changed the setting: %v", got)
	}

	doc["strict_transforms"] = false
	if r := admin(t, ts, "PUT", "/api/admin/accounts/strict", doc); r.status != 200 {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	if got := admin(t, ts, "GET", "/api/admin/accounts/strict", nil).json(t); got["strict_transforms"] == true {
		t.Errorf("an explicit false was ignored: %v", got)
	}
}
