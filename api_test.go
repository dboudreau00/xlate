package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testAdminToken = "xadm_test_admin_token_0123456789"

// newAPI wires a Server the way main does, against temp files, and
// serves it in-process. Handlers, middleware, decoding and validation
// are all exercised for real; only the process boundary is skipped.
func newAPI(t *testing.T, tune ...func(*Server)) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	audit, err := OpenAudit(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, NewRing(200), testAdminToken, 2<<20, []byte("<html>admin</html>"))
	srv.audit = audit
	srv.trip = NewTripwire(5, 5*time.Minute, 15*time.Minute, "lock")
	for _, f := range tune {
		f(srv)
	}
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(func() {
		ts.Close()
		_ = audit.Close()
	})
	return ts
}

type apiResp struct {
	status int
	hdr    http.Header
	body   []byte
}

func (r apiResp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(r.body))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("response is not a JSON object (%d): %s", r.status, r.body)
	}
	return m
}

// fieldErrors returns the validation detail keyed by field name.
func (r apiResp) fieldErrors(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	raw, ok := r.json(t)["fields"].([]any)
	if !ok {
		return out
	}
	for _, f := range raw {
		fe := f.(map[string]any)
		out[fmt.Sprint(fe["field"])] = fmt.Sprint(fe["message"])
	}
	return out
}

// call issues a request. A string or []byte body is sent verbatim so
// malformed JSON can be tested; anything else is marshaled.
func call(t *testing.T, ts *httptest.Server, method, path, token string, body any, hdr ...map[string]string) apiResp {
	t.Helper()
	var rdr io.Reader
	setCT := false
	switch v := body.(type) {
	case nil:
	case string:
		rdr, setCT = strings.NewReader(v), true
	case []byte:
		rdr, setCT = bytes.NewReader(v), true
	default:
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		rdr, setCT = bytes.NewReader(b), true
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if setCT {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, h := range hdr {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return apiResp{resp.StatusCode, resp.Header, b}
}

func admin(t *testing.T, ts *httptest.Server, method, path string, body any) apiResp {
	t.Helper()
	return call(t, ts, method, path, testAdminToken, body)
}

// mustCreate creates an account and fails the test if it is rejected.
func mustCreate(t *testing.T, ts *httptest.Server, doc map[string]any) map[string]any {
	t.Helper()
	r := admin(t, ts, "POST", "/api/admin/accounts", doc)
	if r.status != 201 {
		t.Fatalf("create %v: want 201, got %d: %s", doc["id"], r.status, r.body)
	}
	return r.json(t)
}

func sideToken(m map[string]any, side string) string {
	return m[side].(map[string]any)["inbound_token"].(string)
}

// ---------------------------------------------------------------------------
// Envelope + routing

func TestAPIErrorEnvelopeIsAlwaysJSON(t *testing.T) {
	ts := newAPI(t)

	t.Run("unknown route", func(t *testing.T) {
		r := call(t, ts, "GET", "/nope", "", nil)
		if r.status != 404 {
			t.Fatalf("want 404, got %d", r.status)
		}
		if got := r.json(t)["code"]; got != "not_found" {
			t.Errorf("code: want not_found, got %v", got)
		}
	})

	t.Run("wrong method carries Allow", func(t *testing.T) {
		for _, tc := range []struct{ method, path, allow string }{
			{"GET", "/t/x/a2b", "POST"},
			{"DELETE", "/api/admin/accounts", "GET, POST"},
			{"POST", "/api/admin/tripwire", "GET"},
			{"PATCH", "/api/admin/accounts/x", "GET, PUT, DELETE"},
		} {
			r := call(t, ts, tc.method, tc.path, testAdminToken, nil)
			if r.status != 405 {
				t.Errorf("%s %s: want 405, got %d", tc.method, tc.path, r.status)
				continue
			}
			if got := r.hdr.Get("Allow"); got != tc.allow {
				t.Errorf("%s %s: Allow want %q, got %q", tc.method, tc.path, tc.allow, got)
			}
			if got := r.json(t)["code"]; got != "method_not_allowed" {
				t.Errorf("%s %s: code want method_not_allowed, got %v", tc.method, tc.path, got)
			}
		}
	})

	t.Run("every error carries error and code", func(t *testing.T) {
		for _, r := range []apiResp{
			call(t, ts, "GET", "/api/admin/accounts", "", nil),
			call(t, ts, "GET", "/nope", "", nil),
			admin(t, ts, "GET", "/api/admin/accounts/missing", nil),
			admin(t, ts, "POST", "/api/admin/accounts", `{`),
		} {
			m := r.json(t)
			if m["error"] == nil || m["error"] == "" || m["code"] == nil || m["code"] == "" {
				t.Errorf("incomplete envelope (%d): %s", r.status, r.body)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Request decoding

func TestAPIRejectsMalformedRequests(t *testing.T) {
	ts := newAPI(t)

	cases := []struct {
		name, body, wantIn string
	}{
		{"empty body", ``, "empty"},
		{"malformed json", `{"id":`, "malformed JSON"},
		{"trailing garbage", `{"id":"a"} nonsense`, "unexpected data"},
		{"two json values", `{"id":"a"}{"id":"b"}`, "unexpected data"},
		{"array instead of object", `["id"]`, ""},
		{"unknown field", `{"id":"a","target_uri":"http://x/"}`, "unknown field"},
		{"unknown nested field", `{"id":"a","a":{"targetUrl":"http://x/"}}`, "unknown field"},
		{"wrong type", `{"id":"a","timeout_sec":"thirty"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := admin(t, ts, "POST", "/api/admin/accounts", tc.body)
			if r.status != 400 {
				t.Fatalf("want 400, got %d: %s", r.status, r.body)
			}
			if tc.wantIn != "" && !strings.Contains(fmt.Sprint(r.json(t)["error"]), tc.wantIn) {
				t.Errorf("error should mention %q, got %s", tc.wantIn, r.body)
			}
		})
	}

	t.Run("non-json content type", func(t *testing.T) {
		r := call(t, ts, "POST", "/api/admin/accounts", testAdminToken, nil,
			map[string]string{"Content-Type": "text/plain"})
		if r.status != 400 {
			t.Fatalf("want 400, got %d: %s", r.status, r.body)
		}
		if !strings.Contains(fmt.Sprint(r.json(t)["error"]), "application/json") {
			t.Errorf("want a content-type complaint, got %s", r.body)
		}
	})

	t.Run("oversize body", func(t *testing.T) {
		big := `{"id":"a","name":"` + strings.Repeat("x", maxAdminBody+16) + `"}`
		r := admin(t, ts, "POST", "/api/admin/accounts", big)
		if r.status != 400 && r.status != 413 {
			t.Fatalf("want 400 or 413, got %d: %s", r.status, r.body)
		}
	})

	t.Run("unknown field error names the field", func(t *testing.T) {
		r := admin(t, ts, "POST", "/api/admin/accounts", `{"id":"a","target_uri":"http://x/"}`)
		if got, ok := r.fieldErrors(t)["target_uri"]; !ok {
			t.Errorf("want a field error keyed on target_uri, got %v", r.fieldErrors(t))
		} else if !strings.Contains(got, "unknown field") {
			t.Errorf("message should say unknown field, got %q", got)
		}
	})

	t.Run("unknown fields rejected on every write route", func(t *testing.T) {
		mustCreate(t, ts, map[string]any{"id": "known"})
		for _, tc := range []struct{ method, path, body string }{
			{"PUT", "/api/admin/accounts/known", `{"nope":1}`},
			{"POST", "/api/admin/accounts/known/rotate", `{"side":"a","kind":"inbound","extra":1}`},
			{"POST", "/api/admin/accounts/known/test", `{"direction":"a2b","payload":{},"extra":1}`},
		} {
			r := admin(t, ts, tc.method, tc.path, tc.body)
			if r.status != 400 {
				t.Errorf("%s %s: want 400, got %d: %s", tc.method, tc.path, r.status, r.body)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Field validation

func TestAPIAccountFieldValidation(t *testing.T) {
	ts := newAPI(t)

	cases := []struct {
		name      string
		doc       map[string]any
		wantField string
	}{
		{"empty id", map[string]any{"id": ""}, "id"},
		{"uppercase id", map[string]any{"id": "Acme"}, "id"},
		{"id starting with dash", map[string]any{"id": "-acme"}, "id"},
		{"id too long", map[string]any{"id": strings.Repeat("a", 64)}, "id"},
		{"name too long", map[string]any{"id": "a", "name": strings.Repeat("n", maxNameLen+1)}, "name"},
		{"name with newline", map[string]any{"id": "a", "name": "line\nbreak"}, "name"},
		{"label too long", map[string]any{"id": "a",
			"a": map[string]any{"label": strings.Repeat("l", maxLabelLen+1)}}, "a.label"},
		{"negative timeout", map[string]any{"id": "a", "timeout_sec": -5}, "timeout_sec"},
		{"timeout over max", map[string]any{"id": "a", "timeout_sec": maxTimeoutSec + 1}, "timeout_sec"},

		{"non-http target", map[string]any{"id": "a",
			"a": map[string]any{"target_url": "file:///etc/passwd"}}, "a.target_url"},
		{"relative target", map[string]any{"id": "a",
			"a": map[string]any{"target_url": "/hook"}}, "a.target_url"},
		{"target without host", map[string]any{"id": "a",
			"a": map[string]any{"target_url": "http://"}}, "a.target_url"},
		{"target with credentials", map[string]any{"id": "a",
			"b": map[string]any{"target_url": "https://user:pw@example.com/hook"}}, "b.target_url"},
		{"target with fragment", map[string]any{"id": "a",
			"b": map[string]any{"target_url": "https://example.com/hook#frag"}}, "b.target_url"},

		{"short token", map[string]any{"id": "a",
			"a": map[string]any{"inbound_token": "tiny"}}, "a.inbound_token"},
		{"token with crlf", map[string]any{"id": "a",
			"b": map[string]any{"outbound_token": "abcdefghijklmnop\r\nX-Evil: 1"}}, "b.outbound_token"},
		{"token with space", map[string]any{"id": "a",
			"a": map[string]any{"outbound_token": "abcdefghij klmnop"}}, "a.outbound_token"},

		{"incomplete map row", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "x"}}}, "map[0].b"},
		{"leading dot path", map[string]any{"id": "a",
			"map": []map[string]any{{"a": ".x", "b": "y"}}}, "map[0].a"},
		{"trailing dot path", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "x.", "b": "y"}}}, "map[0].a"},
		{"double dot path", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "x..y", "b": "y"}}}, "map[0].a"},
		{"array index path", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "items[0].id", "b": "y"}}}, "map[0].a"},
		{"path too deep", map[string]any{"id": "a",
			"map": []map[string]any{{"a": strings.Repeat("x.", maxPathDepth) + "x", "b": "y"}}}, "map[0].a"},
		{"path too long", map[string]any{"id": "a",
			"map": []map[string]any{{"a": strings.Repeat("x", maxPathLen+1), "b": "y"}}}, "map[0].a"},
		{"duplicate side a", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "x", "b": "y"}, {"a": "x", "b": "z"}}}, "map[1].a"},
		{"duplicate side b", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "x", "b": "y"}, {"a": "z", "b": "y"}}}, "map[1].b"},
		{"parent/child conflict", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "customer", "b": "y"}, {"a": "customer.id", "b": "z"}}}, "map[1].a"},

		{"bad transform kind", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "x", "b": "y",
				"transform": map[string]any{"kind": "enum", "a_format": "p", "b_format": "q"}}}},
			"map[0].transform.kind"},
		{"empty format", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "x", "b": "y",
				"transform": map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": ""}}}},
			"map[0].transform.b_format"},
		{"non-Go layout", map[string]any{"id": "a",
			"map": []map[string]any{{"a": "x", "b": "y",
				"transform": map[string]any{"kind": "date", "a_format": "YYYY-MM-DD", "b_format": "unix"}}}},
			"map[0].transform.a_format"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := admin(t, ts, "POST", "/api/admin/accounts", tc.doc)
			if r.status != 400 {
				t.Fatalf("want 400, got %d: %s", r.status, r.body)
			}
			if got := r.json(t)["code"]; got != "validation_failed" {
				t.Errorf("code: want validation_failed, got %v", got)
			}
			fields := r.fieldErrors(t)
			if _, ok := fields[tc.wantField]; !ok {
				t.Errorf("want a field error on %q, got %v", tc.wantField, fields)
			}
		})
	}
}

func TestAPIValidationIsExhaustive(t *testing.T) {
	ts := newAPI(t)
	// An admin fixing a form should see every problem at once.
	r := admin(t, ts, "POST", "/api/admin/accounts", map[string]any{
		"id":          "BAD ID",
		"timeout_sec": -1,
		"a":           map[string]any{"target_url": "ftp://nope"},
		"b":           map[string]any{"inbound_token": "short"},
		"map":         []map[string]any{{"a": ".bad", "b": "ok"}},
	})
	if r.status != 400 {
		t.Fatalf("want 400, got %d: %s", r.status, r.body)
	}
	fields := r.fieldErrors(t)
	for _, want := range []string{"id", "timeout_sec", "a.target_url", "b.inbound_token", "map[0].a"} {
		if _, ok := fields[want]; !ok {
			t.Errorf("missing field error for %q; got %v", want, fields)
		}
	}
	if len(fields) < 5 {
		t.Errorf("validation stopped early: %v", fields)
	}
}

func TestAPIAcceptsValidDocuments(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{
		"id": "good", "name": "Good", "timeout_sec": maxTimeoutSec,
		"a": map[string]any{"label": "A", "target_url": "https://a.example/hook"},
		"b": map[string]any{"label": "B", "target_url": "http://b.example:8080/hook?q=1"},
		"map": []map[string]any{
			{"a": "payment_id", "b": "payment_proof"},
			{"a": "customer.id", "b": "cust.identifier"},
			{"a": "created_at", "b": "created_epoch",
				"transform": map[string]any{"kind": "date", "a_format": "02/01/2006 15:04", "b_format": "unix_ms"}},
		},
	})
	if got := fmt.Sprint(acct["timeout_sec"]); got != fmt.Sprint(maxTimeoutSec) {
		t.Errorf("timeout_sec: want %d, got %v", maxTimeoutSec, acct["timeout_sec"])
	}

	t.Run("omitted timeout takes the default", func(t *testing.T) {
		a := mustCreate(t, ts, map[string]any{"id": "deftimeout"})
		if got := fmt.Sprint(a["timeout_sec"]); got != fmt.Sprint(defaultTimeoutSec) {
			t.Errorf("want %d, got %v", defaultTimeoutSec, a["timeout_sec"])
		}
	})

	t.Run("an account with no pairs returns an empty list not null", func(t *testing.T) {
		// Creating an account before you know the partner's vocabulary is
		// the normal onboarding order, so this is not an edge case.
		for _, doc := range []map[string]any{
			{"id": "nomap"},
			{"id": "emptymap", "map": []map[string]any{}},
			{"id": "blankonly", "map": []map[string]any{{"a": "", "b": ""}}},
		} {
			a := mustCreate(t, ts, doc)
			m, ok := a["map"].([]any)
			if !ok || m == nil {
				t.Errorf("%v: map should be [], got %#v", doc["id"], a["map"])
			}
			got := admin(t, ts, "GET", "/api/admin/accounts/"+fmt.Sprint(doc["id"]), nil)
			if !strings.Contains(string(got.body), `"map":[]`) {
				t.Errorf("%v: GET should also return [], got %s", doc["id"], got.body)
			}
		}
	})

	t.Run("blank map rows are dropped not rejected", func(t *testing.T) {
		a := mustCreate(t, ts, map[string]any{"id": "blankrows",
			"map": []map[string]any{{"a": "", "b": ""}, {"a": "x", "b": "y"}}})
		if m, _ := a["map"].([]any); len(m) != 1 {
			t.Errorf("want 1 surviving row, got %v", a["map"])
		}
	})
}

func TestAPIDuplicateAccountIsConflict(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, map[string]any{"id": "dupe"})

	r := admin(t, ts, "POST", "/api/admin/accounts", map[string]any{"id": "dupe"})
	if r.status != http.StatusConflict {
		t.Fatalf("want 409, got %d: %s", r.status, r.body)
	}
	if got := r.json(t)["code"]; got != "already_exists" {
		t.Errorf("code: want already_exists, got %v", got)
	}

	// Whitespace must normalise to the same identity, not slip past.
	r = admin(t, ts, "POST", "/api/admin/accounts", map[string]any{"id": "  dupe  "})
	if r.status != http.StatusConflict {
		t.Errorf("padded duplicate id: want 409, got %d: %s", r.status, r.body)
	}
}

// ---------------------------------------------------------------------------
// enabled semantics

func TestAPIEnabledOmissionSemantics(t *testing.T) {
	ts := newAPI(t)

	t.Run("omitted on create enables", func(t *testing.T) {
		a := mustCreate(t, ts, map[string]any{"id": "e1"})
		if a["enabled"] != true {
			t.Errorf("want enabled=true, got %v", a["enabled"])
		}
	})

	t.Run("explicit false on create is honoured", func(t *testing.T) {
		a := mustCreate(t, ts, map[string]any{"id": "e2", "enabled": false})
		if a["enabled"] != false {
			t.Errorf("want enabled=false, got %v", a["enabled"])
		}
	})

	t.Run("omitted on update retains", func(t *testing.T) {
		mustCreate(t, ts, map[string]any{"id": "e3", "enabled": false})
		r := admin(t, ts, "PUT", "/api/admin/accounts/e3", map[string]any{"name": "renamed"})
		if r.status != 200 {
			t.Fatalf("want 200, got %d: %s", r.status, r.body)
		}
		if got := r.json(t)["enabled"]; got != false {
			t.Errorf("omission must not flip enabled: want false, got %v", got)
		}
	})

	t.Run("explicit true on update enables", func(t *testing.T) {
		r := admin(t, ts, "PUT", "/api/admin/accounts/e3", map[string]any{"enabled": true})
		if got := r.json(t)["enabled"]; got != true {
			t.Errorf("want true, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Data plane validation

func TestAPIIngestValidation(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()

	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{
		"id": "ing", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "x", "b": "y"}},
	})
	tok := sideToken(acct, "a")

	t.Run("body must be one JSON object", func(t *testing.T) {
		for _, body := range []string{`[1,2]`, `"str"`, `null`, `{`, `{"a":1} extra`, `{"a":1}{"b":2}`, ``} {
			r := call(t, ts, "POST", "/t/ing/a2b", tok, body)
			if r.status != 400 {
				t.Errorf("body %q: want 400, got %d: %s", body, r.status, r.body)
				continue
			}
			if got := r.json(t)["code"]; got != "bad_json" {
				t.Errorf("body %q: code want bad_json, got %v", body, got)
			}
		}
	})

	t.Run("correlation headers must be header-safe", func(t *testing.T) {
		for _, tc := range []struct{ name, header, value string }{
			{"idempotency crlf", "Idempotency-Key", "abc\r\nX-Evil: 1"},
			{"request id control", "X-Request-Id", "abc\x00def"},
			{"request id oversize", "X-Request-Id", strings.Repeat("k", maxCorrelationLen+1)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// Go's client refuses to transmit raw CR/LF, so build the
				// header value through the map to bypass Set's checks where
				// possible; oversize values always transmit.
				req, err := http.NewRequest("POST", ts.URL+"/t/ing/a2b", strings.NewReader(`{"x":1}`))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("Content-Type", "application/json")
				req.Header[tc.header] = []string{tc.value}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					// net/http refused to write it; the value never reaches
					// any upstream, which is the outcome we want.
					t.Skipf("client refused to transmit: %v", err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 400 {
					t.Errorf("want 400, got %d: %s", resp.StatusCode, b)
				}
			})
		}
	})

	t.Run("valid request still succeeds", func(t *testing.T) {
		r := call(t, ts, "POST", "/t/ing/a2b", tok, map[string]any{"x": 1},
			map[string]string{"Idempotency-Key": "idem-1", "X-Request-Id": "req-1"})
		if r.status != 200 {
			t.Fatalf("want 200, got %d: %s", r.status, r.body)
		}
	})

	t.Run("direction must be a2b or b2a", func(t *testing.T) {
		r := call(t, ts, "POST", "/t/ing/sideways", tok, map[string]any{"x": 1})
		if r.status != 404 || r.json(t)["code"] != "bad_direction" {
			t.Errorf("want 404/bad_direction, got %d: %s", r.status, r.body)
		}
	})
}

func TestAPIDryRunValidation(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, map[string]any{"id": "dry",
		"map": []map[string]any{{"a": "x", "b": "y"}}})

	t.Run("bad direction and missing payload reported together", func(t *testing.T) {
		r := admin(t, ts, "POST", "/api/admin/accounts/dry/test", map[string]any{"direction": "nope"})
		if r.status != 400 {
			t.Fatalf("want 400, got %d: %s", r.status, r.body)
		}
		fields := r.fieldErrors(t)
		if _, ok := fields["direction"]; !ok {
			t.Errorf("missing direction error: %v", fields)
		}
		if _, ok := fields["payload"]; !ok {
			t.Errorf("missing payload error: %v", fields)
		}
	})

	t.Run("unknown account is 404 not 400", func(t *testing.T) {
		r := admin(t, ts, "POST", "/api/admin/accounts/ghost/test",
			map[string]any{"direction": "a2b", "payload": map[string]any{}})
		if r.status != 404 {
			t.Errorf("want 404, got %d: %s", r.status, r.body)
		}
	})
}

func TestAPIRotateValidation(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, map[string]any{"id": "rot"})

	for _, tc := range []struct {
		body      map[string]any
		wantField string
	}{
		{map[string]any{"side": "c", "kind": "inbound"}, "side"},
		{map[string]any{"side": "a", "kind": "sideways"}, "kind"},
		{map[string]any{}, "side"},
	} {
		r := admin(t, ts, "POST", "/api/admin/accounts/rot/rotate", tc.body)
		if r.status != 400 {
			t.Errorf("%v: want 400, got %d: %s", tc.body, r.status, r.body)
			continue
		}
		if _, ok := r.fieldErrors(t)[tc.wantField]; !ok {
			t.Errorf("%v: want field error on %q, got %v", tc.body, tc.wantField, r.fieldErrors(t))
		}
	}

	t.Run("unknown account is 404", func(t *testing.T) {
		r := admin(t, ts, "POST", "/api/admin/accounts/ghost/rotate",
			map[string]any{"side": "a", "kind": "inbound"})
		if r.status != 404 {
			t.Errorf("want 404, got %d: %s", r.status, r.body)
		}
	})
}

func TestAPIUpdateUnknownAccountIs404(t *testing.T) {
	ts := newAPI(t)
	r := admin(t, ts, "PUT", "/api/admin/accounts/ghost", map[string]any{"name": "x"})
	if r.status != 404 {
		t.Fatalf("want 404, got %d: %s", r.status, r.body)
	}
	if got := r.json(t)["code"]; got != "not_found" {
		t.Errorf("code: want not_found, got %v", got)
	}
}

func TestAPIAdminAuthGuardsEveryControlRoute(t *testing.T) {
	ts := newAPI(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/admin/accounts"},
		{"POST", "/api/admin/accounts"},
		{"GET", "/api/admin/accounts/x"},
		{"PUT", "/api/admin/accounts/x"},
		{"DELETE", "/api/admin/accounts/x"},
		{"POST", "/api/admin/accounts/x/rotate"},
		{"POST", "/api/admin/accounts/x/test"},
		{"POST", "/api/admin/accounts/x/tripwire/reset"},
		{"GET", "/api/admin/tripwire"},
		{"GET", "/api/admin/logs"},
	} {
		r := call(t, ts, tc.method, tc.path, "", nil)
		if r.status != 401 {
			t.Errorf("%s %s: want 401 without a token, got %d", tc.method, tc.path, r.status)
		}
		r = call(t, ts, tc.method, tc.path, "wrong-token", nil)
		if r.status != 401 {
			t.Errorf("%s %s: want 401 with a bad token, got %d", tc.method, tc.path, r.status)
		}
	}
}

func TestAPILogsQueryValidation(t *testing.T) {
	ts := newAPI(t)
	for _, q := range []string{"", "?limit=0", "?limit=-1", "?limit=999999", "?limit=abc", "?account=" + strings.Repeat("a", 300)} {
		r := admin(t, ts, "GET", "/api/admin/logs"+q, nil)
		if r.status != 200 {
			t.Errorf("logs%s: want 200, got %d: %s", q, r.status, r.body)
			continue
		}
		if _, ok := r.json(t)["entries"]; !ok {
			t.Errorf("logs%s: missing entries key: %s", q, r.body)
		}
	}
}
