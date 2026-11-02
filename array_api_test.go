package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Array addressing through the gateway, the admin API and field discovery.

const (
	arrSenderMsg = `{"ref":"r-1","lines":[{"sku":"s1","qty":2,"shipped":"2024-03-01T09:00:00Z","note":"gift"},` +
		`{"sku":"s2","qty":1,"shipped":"2024-03-02T09:00:00Z"}],"free":"text"}`
	arrDestMsg = `{"reference":"r-1","items":[{"product_code":"s1","quantity":2,"shipped_epoch":1709283600,"note":"gift"},` +
		`{"product_code":"s2","quantity":1,"shipped_epoch":1709370000}],"free":"text"}`
	// One leg: ref, and three mapped fields in each of the two elements.
	arrAppliedPerLeg = 7
)

// arrUp is a destination that records what reached it. It echoes the request
// unless it has been told what to answer.
type arrUp struct {
	*httptest.Server
	mu    sync.Mutex
	n     int
	body  []byte
	reply string
}

func newArrUp(t *testing.T) *arrUp {
	t.Helper()
	u := &arrUp{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.n++
		u.body = b
		reply := u.reply
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if reply != "" {
			_, _ = io.WriteString(w, reply)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *arrUp) got() (int, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.n, string(u.body)
}

func (u *arrUp) answer(s string) {
	u.mu.Lock()
	u.reply = s
	u.mu.Unlock()
}

func arrAccountDoc(id, upURL string, extra map[string]any) map[string]any {
	doc := map[string]any{
		"id": id, "enabled": true,
		"a": map[string]any{"target_url": upURL},
		"b": map[string]any{"target_url": upURL},
		"map": []map[string]any{
			{"a": "ref", "b": "reference"},
			{"a": "lines[].sku", "b": "items[].product_code"},
			{"a": "lines[].qty", "b": "items[].quantity"},
			{"a": "lines[].shipped", "b": "items[].shipped_epoch", "transform": map[string]any{
				"kind": "date", "a_format": "rfc3339", "b_format": "unix"}},
		},
	}
	for k, v := range extra {
		doc[k] = v
	}
	return doc
}

func arrBody(key, field string, n int) string {
	var b strings.Builder
	b.WriteString(`{"` + key + `":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"%s":"s%d","qty":%d}`, field, i, i)
	}
	b.WriteString(`]}`)
	return b.String()
}

func sameJSON(t *testing.T, got, want string) bool {
	t.Helper()
	return canon(t, mustObj(t, got)) == canon(t, mustObj(t, want))
}

// ---------------------------------------------------------------------------
// Both directions, both legs

func TestArrayRowsTranslateBothWaysThroughTheGateway(t *testing.T) {
	ts := newAPI(t)
	up := newArrUp(t)
	acct := mustCreate(t, ts, arrAccountDoc("arr", up.URL, nil))

	// Stored and returned exactly as written.
	rows, _ := acct["map"].([]any)
	if len(rows) != 4 || rows[1].(map[string]any)["a"] != "lines[].sku" || rows[1].(map[string]any)["b"] != "items[].product_code" {
		t.Fatalf("rows not stored as written: %v", acct["map"])
	}

	// A speaks: the destination must see B's vocabulary, and A must read its
	// own back (the destination echoes, so the return leg is an identity check).
	r := call(t, ts, "POST", "/t/arr/a2b", sideToken(acct, "a"), arrSenderMsg)
	if r.status != 200 {
		t.Fatalf("a2b: %d %s", r.status, r.body)
	}
	if n, body := up.got(); n != 1 || !sameJSON(t, body, arrDestMsg) {
		t.Errorf("destination received %d request(s): %s\nwant %s", n, body, arrDestMsg)
	}
	if !sameJSON(t, string(r.body), arrSenderMsg) {
		t.Errorf("A did not get its own message back: %s", r.body)
	}
	if got, want := r.hdr.Get("X-Xlate-Applied"), fmt.Sprint(2*arrAppliedPerLeg); got != want {
		t.Errorf("X-Xlate-Applied %s, want %s", got, want)
	}
	if w := r.hdr.Get("X-Xlate-Warnings"); w != "" {
		t.Errorf("unexpected warnings: %s", w)
	}

	// B speaks: mirrored.
	r = call(t, ts, "POST", "/t/arr/b2a", sideToken(acct, "b"), arrDestMsg)
	if r.status != 200 {
		t.Fatalf("b2a: %d %s", r.status, r.body)
	}
	if _, body := up.got(); !sameJSON(t, body, arrSenderMsg) {
		t.Errorf("destination received %s\nwant %s", body, arrSenderMsg)
	}
	if !sameJSON(t, string(r.body), arrDestMsg) {
		t.Errorf("B did not get its own message back: %s", r.body)
	}
	if got, want := r.hdr.Get("X-Xlate-Applied"), fmt.Sprint(2*arrAppliedPerLeg); got != want {
		t.Errorf("b2a X-Xlate-Applied %s, want %s", got, want)
	}
}

func TestArrayRowsHonourDropUnmappedOnRequestsOnly(t *testing.T) {
	ts := newAPI(t)
	up := newArrUp(t)
	acct := mustCreate(t, ts, arrAccountDoc("arrdrop", up.URL, map[string]any{"drop_unmapped": true}))

	r := call(t, ts, "POST", "/t/arrdrop/a2b", sideToken(acct, "a"), arrSenderMsg)
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	// "note" and "free" are unmapped: gone from the request, elements kept.
	const wantDest = `{"reference":"r-1","items":[{"product_code":"s1","quantity":2,"shipped_epoch":1709283600},` +
		`{"product_code":"s2","quantity":1,"shipped_epoch":1709370000}]}`
	if _, body := up.got(); !sameJSON(t, body, wantDest) {
		t.Errorf("destination received %s\nwant %s", body, wantDest)
	}
	// The response is never drop-filtered, so what the destination sent back
	// keeps everything it had.
	const wantBack = `{"ref":"r-1","lines":[{"sku":"s1","qty":2,"shipped":"2024-03-01T09:00:00Z"},` +
		`{"sku":"s2","qty":1,"shipped":"2024-03-02T09:00:00Z"}]}`
	if !sameJSON(t, string(r.body), wantBack) {
		t.Errorf("caller got %s\nwant %s", r.body, wantBack)
	}
}

// ---------------------------------------------------------------------------
// Refusals

func TestArrayRefusalsOverTheWire(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	up := newArrUp(t)
	acct := mustCreate(t, ts, arrAccountDoc("arrbad", up.URL, nil))
	tok := sideToken(acct, "a")

	t.Run("a request is refused whatever the mode, and nothing is forwarded", func(t *testing.T) {
		const secret = "4111-1111-1111-1111"
		r := call(t, ts, "POST", "/t/arrbad/a2b", tok, `{"ref":"r","lines":[{"sku":"a"},"`+secret+`",null]}`)
		if r.status != 422 {
			t.Fatalf("want 422, got %d: %s", r.status, r.body)
		}
		m := r.json(t)
		if m["code"] != "array_invalid" {
			t.Errorf("code %v, want array_invalid", m["code"])
		}
		fe := r.fieldErrors(t)
		if !strings.Contains(fe["lines[1]"], "must be an object, got string") || !strings.Contains(fe["lines[2]"], "got null") || len(fe) != 2 {
			t.Errorf("fields: %v", fe)
		}
		if n, _ := up.got(); n != 0 {
			t.Errorf("the destination saw %d request(s)", n)
		}
		// Not the destination's vocabulary, and no value.
		for _, leak := range []string{"items", "product_code", "reference", secret} {
			if strings.Contains(string(r.body), leak) {
				t.Errorf("response leaks %q: %s", leak, r.body)
			}
		}
		trail := strictTrail(t, srv)
		if !strings.Contains(trail, `"event":"ingest.rejected"`) || !strings.Contains(trail, `"reason":"array"`) ||
			!strings.Contains(trail, `lines[1]`) {
			t.Errorf("the refusal is not on the trail: %s", trail)
		}
		if strings.Contains(trail, secret) {
			t.Error("a value reached the audit trail")
		}
		logs := arrList(admin(t, ts, "GET", "/api/admin/logs?account=arrbad&limit=1", nil).json(t)["entries"])
		if len(logs) == 0 {
			t.Fatal("the refusal is missing from the activity log")
		}
		if e := arrObj(logs[0]); fmt.Sprint(e["status"]) != "422" || e["err"] != "array refused" {
			t.Errorf("activity entry: %v", e)
		}
		if strings.Contains(fmt.Sprint(logs), secret) {
			t.Error("a value reached the activity log")
		}
	})

	t.Run("an array that is not an array", func(t *testing.T) {
		for _, body := range []string{`{"lines":{"sku":"a"}}`, `{"lines":"x"}`, `{"lines":3}`} {
			r := call(t, ts, "POST", "/t/arrbad/a2b", tok, body)
			if r.status != 422 || r.json(t)["code"] != "array_invalid" || r.fieldErrors(t)["lines"] == "" {
				t.Errorf("%s -> %d %s", body, r.status, r.body)
			}
		}
	})

	t.Run("refusals are a data problem, not a credential guess", func(t *testing.T) {
		// More than the tripwire's threshold of 5.
		for i := 0; i < 10; i++ {
			if r := call(t, ts, "POST", "/t/arrbad/a2b", tok, `{"lines":"x"}`); r.status != 422 {
				t.Fatalf("refusal %d: %d %s", i, r.status, r.body)
			}
		}
		if r := call(t, ts, "POST", "/t/arrbad/a2b", tok, arrSenderMsg); r.status != 200 {
			t.Errorf("the account was locked by refused arrays: %d %s", r.status, r.body)
		}
	})

	t.Run("null and an empty array are accepted", func(t *testing.T) {
		for _, body := range []string{`{"lines":null}`, `{"lines":[]}`} {
			if r := call(t, ts, "POST", "/t/arrbad/a2b", tok, body); r.status != 200 {
				t.Errorf("%s -> %d %s", body, r.status, r.body)
			}
		}
	})
}

func TestArrayLengthCapOverTheWire(t *testing.T) {
	ts := newAPI(t)
	up := newArrUp(t)
	acct := mustCreate(t, ts, arrAccountDoc("arrcap", up.URL, nil))

	r := call(t, ts, "POST", "/t/arrcap/a2b", sideToken(acct, "a"), arrBody("lines", "sku", maxArrayLen))
	if r.status != 200 {
		t.Fatalf("%d elements: %d %.200s", maxArrayLen, r.status, r.body)
	}
	if got, want := r.hdr.Get("X-Xlate-Applied"), fmt.Sprint(2*2*maxArrayLen); got != want {
		t.Errorf("X-Xlate-Applied %s, want %s", got, want)
	}

	before, _ := up.got()
	r = call(t, ts, "POST", "/t/arrcap/a2b", sideToken(acct, "a"), arrBody("lines", "sku", maxArrayLen+1))
	if r.status != 422 || r.json(t)["code"] != "array_invalid" {
		t.Fatalf("%d elements: want 422 array_invalid, got %d %.200s", maxArrayLen+1, r.status, r.body)
	}
	if msg := r.fieldErrors(t)["lines"]; !strings.Contains(msg, fmt.Sprintf("at most %d", maxArrayLen)) {
		t.Errorf("reason: %q", msg)
	}
	if after, _ := up.got(); after != before {
		t.Error("an over-long array was forwarded")
	}
}

func TestArrayRefusedResponseNeverReachesTheCaller(t *testing.T) {
	for name, reply := range map[string]string{
		"an object instead of an array": `{"items":{"product_code":"x"}}`,
		"a scalar element":              `{"items":[{"product_code":"x"},"stray"]}`,
		"too many elements":             arrBody("items", "product_code", maxArrayLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			var srv *Server
			ts := newAPI(t, func(s *Server) { srv = s })
			up := newArrUp(t)
			up.answer(reply)
			acct := mustCreate(t, ts, arrAccountDoc("arrresp", up.URL, nil))

			r := call(t, ts, "POST", "/t/arrresp/a2b", sideToken(acct, "a"), arrSenderMsg)
			if r.status != 502 || r.json(t)["code"] != "upstream_invalid" {
				t.Fatalf("want 502 upstream_invalid, got %d %.200s", r.status, r.body)
			}
			if strings.Contains(string(r.body), "product_code") || strings.Contains(string(r.body), "stray") {
				t.Errorf("the destination's content reached the caller: %.200s", r.body)
			}
			if n, _ := up.got(); n != 1 {
				t.Errorf("the destination saw %d requests, want 1", n)
			}
			trail := strictTrail(t, srv)
			if !strings.Contains(trail, `"reason":"response_array"`) {
				t.Errorf("trail: %s", trail)
			}
			if strings.Contains(trail, "stray") {
				t.Error("a value reached the audit trail")
			}
		})
	}
}

// A hostile array cannot make the answer unboundedly long, or the notes
// kept for it unboundedly many, and the counts stay true.
func TestArrayRefusalAndWarningListsAreBounded(t *testing.T) {
	ts := newAPI(t)
	up := newArrUp(t)
	acct := mustCreate(t, ts, map[string]any{
		"id": "arrbound", "enabled": true,
		"a": map[string]any{"target_url": up.URL},
		"b": map[string]any{"target_url": up.URL},
		"map": []map[string]any{
			{"a": "lines[].sku", "b": "items[].code"},
			{"a": "lines[].d1", "b": "items[].e1", "transform": map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"}},
			{"a": "lines[].d2", "b": "items[].e2", "transform": map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"}},
		},
	})
	tok := sideToken(acct, "a")

	// Three hundred elements that are not objects: the refusal names a bounded few.
	r := call(t, ts, "POST", "/t/arrbound/a2b", tok, `{"lines":[`+strings.TrimSuffix(strings.Repeat("1,", 300), ",")+`]}`)
	if r.status != 422 {
		t.Fatalf("want 422, got %d %.200s", r.status, r.body)
	}
	if n := len(r.fieldErrors(t)); n != maxLoggedFields {
		t.Errorf("the refusal lists %d paths, want at most %d", n, maxLoggedFields)
	}

	// 1,000 elements with two unparseable dates each: 2,000 warnings out, and
	// the echoed values fail to convert back, 2,000 more.
	elems := make([]string, maxArrayLen)
	for i := range elems {
		elems[i] = `{"d1":"bad","d2":"bad"}`
	}
	r = call(t, ts, "POST", "/t/arrbound/a2b", tok, `{"lines":[`+strings.Join(elems, ",")+`]}`)
	if r.status != 200 {
		t.Fatalf("fail-open must still forward: %d %.200s", r.status, r.body)
	}
	if got, want := r.hdr.Get("X-Xlate-Warnings"), fmt.Sprint(4*maxArrayLen); got != want {
		t.Errorf("X-Xlate-Warnings %s, want the exact count %s", got, want)
	}

	// The dry run keeps a bounded list and says how many it left out.
	payload := mustObj(t, `{"lines":[`+strings.Join(elems, ",")+`]}`)
	dry := admin(t, ts, "POST", "/api/admin/accounts/arrbound/test", map[string]any{"direction": "a2b", "payload": payload}).json(t)
	warnings, _ := dry["warnings"].([]any)
	if len(warnings) != maxNotes || fmt.Sprint(dry["warnings_omitted"]) != fmt.Sprint(2*maxArrayLen-maxNotes) {
		t.Errorf("dry run kept %d warnings and omitted %v; want %d and %d",
			len(warnings), dry["warnings_omitted"], maxNotes, 2*maxArrayLen-maxNotes)
	}
}

// ---------------------------------------------------------------------------
// Dry run

func TestArrayDryRun(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, arrAccountDoc("arrdry", "http://127.0.0.1:1", map[string]any{"strict_transforms": true}))

	r := admin(t, ts, "POST", "/api/admin/accounts/arrdry/test",
		map[string]any{"direction": "a2b", "payload": mustObj(t, arrSenderMsg)})
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	m := r.json(t)
	if _, rejected := m["rejected"]; rejected {
		t.Errorf("a good payload must not be marked rejected: %s", r.body)
	}
	got, _ := m["translated"].(map[string]any)
	if !sameJSON(t, canon(t, got), arrDestMsg) {
		t.Errorf("translated %v", got)
	}
	if fmt.Sprint(m["applied"]) != fmt.Sprint(arrAppliedPerLeg) {
		t.Errorf("applied %v, want %d", m["applied"], arrAppliedPerLeg)
	}

	// Refused: the payload comes back as sent, with the reasons.
	r = admin(t, ts, "POST", "/api/admin/accounts/arrdry/test",
		map[string]any{"direction": "a2b", "payload": mustObj(t, `{"ref":"r","lines":[{"sku":"a"},"x"]}`)})
	m = r.json(t)
	if m["rejected"] != true {
		t.Fatalf("want rejected: %s", r.body)
	}
	refused, _ := m["refused"].([]any)
	if len(refused) != 1 || refused[0].(map[string]any)["field"] != "lines[1]" {
		t.Errorf("refused: %v", m["refused"])
	}
	if tr, _ := m["translated"].(map[string]any); tr["ref"] != "r" || tr["lines"] == nil {
		t.Errorf("a refused preview must be the payload untouched: %v", m["translated"])
	}

	// Strict mode names the element, and the other refusal list stays absent.
	r = admin(t, ts, "POST", "/api/admin/accounts/arrdry/test", map[string]any{"direction": "a2b",
		"payload": mustObj(t, `{"lines":[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"bad"}]}`)})
	m = r.json(t)
	if failed, _ := m["failed"].([]any); m["rejected"] != true || len(failed) != 1 || failed[0] != "lines[1].shipped" {
		t.Errorf("strict failure inside an array: %s", r.body)
	}
	if _, has := m["refused"]; has {
		t.Errorf("refused must be absent when nothing was refused: %s", r.body)
	}
}

// ---------------------------------------------------------------------------
// Saving

func TestArrayRowsAreValidatedWhenSaved(t *testing.T) {
	ts := newAPI(t)
	for _, tc := range []struct {
		name  string
		rows  []map[string]any
		field string
		why   string
	}{
		{"positional index", []map[string]any{{"a": "items[0].id", "b": "y"}}, "map[0].a", "positional"},
		{"brackets on one side", []map[string]any{{"a": "lines[].sku", "b": "sku"}}, "map[0].b", "side a addresses array elements"},
		{"nothing inside", []map[string]any{{"a": "lines[]", "b": "items[]"}}, "map[0].a", "must name a field inside"},
		{"array in array", []map[string]any{{"a": "a[].b[].c", "b": "x[].y"}}, "map[0].a", "only one []"},
		{"two arrays on one", []map[string]any{{"a": "lines[].a", "b": "items[].a"}, {"a": "lines[].b", "b": "rows[].b"}},
			"map[1].b", "already paired"},
		{"parent beside child", []map[string]any{{"a": "lines", "b": "x"}, {"a": "lines[].sku", "b": "items[].code"}},
			"map[1].a", `addresses "lines" as an array`},
	} {
		r := admin(t, ts, "POST", "/api/admin/accounts", map[string]any{"id": "bad", "map": tc.rows})
		if r.status != 400 || r.json(t)["code"] != "validation_failed" {
			t.Errorf("%s: want 400 validation_failed, got %d %s", tc.name, r.status, r.body)
			continue
		}
		if msg, ok := r.fieldErrors(t)[tc.field]; !ok || !strings.Contains(msg, tc.why) {
			t.Errorf("%s: want %s to say %q, got %v", tc.name, tc.field, tc.why, r.fieldErrors(t))
		}
	}
	if r := admin(t, ts, "GET", "/api/admin/accounts/bad", nil); r.status != 404 {
		t.Errorf("a refused account must not exist: %d", r.status)
	}

	// The same rules on a replacement, and a good replacement is kept.
	mustCreate(t, ts, map[string]any{"id": "good"})
	r := admin(t, ts, "PUT", "/api/admin/accounts/good", map[string]any{"map": []map[string]any{{"a": "lines[0].sku", "b": "y"}}})
	if r.status != 400 {
		t.Errorf("PUT with a positional index: %d %s", r.status, r.body)
	}
	r = admin(t, ts, "PUT", "/api/admin/accounts/good", map[string]any{"map": []map[string]any{{"a": "lines[].sku", "b": "items[].code"}}})
	if r.status != 200 {
		t.Fatalf("PUT with an array row: %d %s", r.status, r.body)
	}
}

func TestArrayRowsSurviveAReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := []FieldPair{
		{A: "lines[].sku", B: "items[].code"},
		{A: "lines[].shipped", B: "items[].epoch", Transform: arrDate},
	}
	if _, err := s.Create(asInput(Account{ID: "arr", Map: rows})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(asInput(Account{ID: "bad", Map: []FieldPair{{A: "lines[]", B: "items[]"}}})); !isRejection(err) {
		t.Errorf("an unusable array row must be refused as a validation error, got %v", err)
	}

	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get("arr")
	if !ok || !reflect.DeepEqual(got.Map, rows) {
		t.Errorf("rows changed across a reload: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Field discovery

// arrList and arrObj read a decoded JSON value without panicking when a
// regression has changed its shape: a test should fail, not take down the
// tests after it.
func arrList(v any) []any {
	l, _ := v.([]any)
	return l
}

func arrObj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// arrFields indexes one direction's report by path.
func arrFields(t *testing.T, report map[string]any, dir string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, f := range arrList(arrObj(report[dir])["fields"]) {
		fe := arrObj(f)
		out[fmt.Sprint(fe["path"])] = fe
	}
	return out
}

func arrTypes(fe map[string]any) string {
	var ts []string
	for _, x := range arrList(fe["types"]) {
		ts = append(ts, fmt.Sprint(x))
	}
	return strings.Join(ts, ",")
}

func TestDiscoveryWalksArrayElements(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "arrdisc", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "arrdisc", 30)

	body := `{"ref":"R","lines":[
		{"sku":"a","qty":1,"price":{"amount":"9"}},
		{"sku":"b","qty":"two","extra":true},
		{}],"tags":["x"]}`
	call(t, ts, "POST", "/t/arrdisc/a2b", tok, body)

	got := arrFields(t, discoverReport(t, ts, "arrdisc"), "a2b")
	for path, want := range map[string]struct {
		types    string
		mappable bool
	}{
		"ref":                  {"string", true},
		"lines":                {"array", false},
		"lines[].sku":          {"string", true},
		"lines[].qty":          {"number,string", true},
		"lines[].extra":        {"bool", true},
		"lines[].price":        {"object", false},
		"lines[].price.amount": {"string", true},
		"tags":                 {"array", false},
		"tags[]":               {"string", false},
	} {
		fe, ok := got[path]
		if !ok {
			t.Errorf("%q was not recorded: %v", path, got)
			continue
		}
		if arrTypes(fe) != want.types || fe["mappable"] != want.mappable {
			t.Errorf("%q: types %s mappable %v; want %s, %v", path, arrTypes(fe), fe["mappable"], want.types, want.mappable)
		}
	}
	// Once per payload, however many elements showed it.
	for _, p := range []string{"lines[].sku", "lines[].qty", "lines"} {
		if c := fmt.Sprint(got[p]["count"]); c != "1" {
			t.Errorf("%q counted %s times after one payload", p, c)
		}
	}
	call(t, ts, "POST", "/t/arrdisc/a2b", tok, body)
	if c := fmt.Sprint(arrFields(t, discoverReport(t, ts, "arrdisc"), "a2b")["lines[].sku"]["count"]); c != "2" {
		t.Errorf("after two payloads lines[].sku counted %s, want 2", c)
	}

	// The starter rows carry the form a map takes.
	sug := arrList(arrObj(arrObj(discoverReport(t, ts, "arrdisc"))["suggest"])["a2b"])
	have := map[string]bool{}
	for _, row := range sug {
		have[fmt.Sprint(arrObj(row)["a"])] = true
	}
	for _, want := range []string{"lines[].sku", "lines[].price.amount", "ref"} {
		if !have[want] {
			t.Errorf("%q should be suggested: %v", want, have)
		}
	}
	for _, not := range []string{"lines", "lines[]", "tags", "tags[]", "lines[].price"} {
		if have[not] {
			t.Errorf("%q must not be suggested: %v", not, have)
		}
	}
}

func TestDiscoveryShowsAMixedArray(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "arrmix", "enabled": true})
	discoverOn(t, ts, "arrmix", 30)
	call(t, ts, "POST", "/t/arrmix/a2b", sideToken(acct, "a"), `{"lines":[{"sku":"a"},"x",null,[1],7]}`)

	got := arrFields(t, discoverReport(t, ts, "arrmix"), "a2b")
	fe, ok := got["lines[]"]
	if !ok || arrTypes(fe) != "array,null,number,string" || fe["mappable"] != false {
		t.Errorf("a mixed array should show its odd elements as lines[]: %v", got)
	}
	if got["lines[].sku"]["mappable"] != true {
		t.Errorf("the object elements are still mappable: %v", got["lines[].sku"])
	}
}

func TestDiscoveryReportsButDoesNotWalkAnArrayInsideAnElement(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "arrnest", "enabled": true})
	discoverOn(t, ts, "arrnest", 30)
	call(t, ts, "POST", "/t/arrnest/a2b", sideToken(acct, "a"), `{"lines":[{"sku":"a","taxes":[{"rate":1}]}]}`)

	got := arrFields(t, discoverReport(t, ts, "arrnest"), "a2b")
	if fe, ok := got["lines[].taxes"]; !ok || arrTypes(fe) != "array" || fe["mappable"] != false {
		t.Errorf("lines[].taxes: %v", got)
	}
	for path := range got {
		if strings.Contains(path, "taxes[]") {
			t.Errorf("one level only, but %q was walked", path)
		}
	}
}

func TestDiscoveryOfALongArrayKeepsThePathBudget(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "arrlong", "enabled": true})
	discoverOn(t, ts, "arrlong", 30)

	var b strings.Builder
	b.WriteString(`{"lines":[`)
	for i := 0; i < maxArrayLen; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"a":1,"b":"x","c":true,"d":null,"e":{"f":1}}`)
	}
	b.WriteString(`]}`)
	call(t, ts, "POST", "/t/arrlong/a2b", sideToken(acct, "a"), b.String())

	rep := discoverReport(t, ts, "arrlong")
	if arrObj(rep["a2b"])["truncated"] == true {
		t.Error("copies of one element's paths used up the budget")
	}
	// lines, lines[].a to .e, and lines[].e.f.
	if got := arrFields(t, rep, "a2b"); len(got) != 7 {
		t.Errorf("want 7 distinct paths, got %d: %v", len(got), got)
	}
}

func TestDiscoveryStopsWalkingAnArrayAtTheCap(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "arrcapdisc", "enabled": true})
	discoverOn(t, ts, "arrcapdisc", 30)

	elems := make([]string, maxArrayLen+2)
	for i := range elems {
		elems[i] = `{}`
	}
	elems[maxArrayLen-1] = `{"last":1}`
	elems[maxArrayLen] = `{"beyond":1}`
	call(t, ts, "POST", "/t/arrcapdisc/a2b", sideToken(acct, "a"), `{"lines":[`+strings.Join(elems, ",")+`]}`)

	got := arrFields(t, discoverReport(t, ts, "arrcapdisc"), "a2b")
	if _, ok := got["lines[].last"]; !ok {
		t.Errorf("the last element within the cap should be walked: %v", got)
	}
	if _, ok := got["lines[].beyond"]; ok {
		t.Errorf("an element past the cap should not be walked: %v", got)
	}
}

func TestDiscoveryDoesNotOfferKeysThatLookLikeArrayPaths(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "arrkeys", "enabled": true})
	discoverOn(t, ts, "arrkeys", 30)
	call(t, ts, "POST", "/t/arrkeys/a2b", sideToken(acct, "a"), `{"a[]":{"b":1},"c[0]":2,"d":3}`)

	got := arrFields(t, discoverReport(t, ts, "arrkeys"), "a2b")
	for _, p := range []string{"a[].b", "c[0]"} {
		if fe, ok := got[p]; !ok || fe["mappable"] != false {
			t.Errorf("%q should be listed and not mappable: %v", p, got[p])
		}
	}
	if got["d"]["mappable"] != true {
		t.Errorf("an ordinary key stays mappable: %v", got["d"])
	}
}

func TestDiscoveryNeverRecordsArrayValues(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "arrpii", "enabled": true})
	discoverOn(t, ts, "arrpii", 30)
	const pan, email = "4111111111111111", "ada@example.com"
	call(t, ts, "POST", "/t/arrpii/a2b", sideToken(acct, "a"),
		fmt.Sprintf(`{"cards":[{"pan":%q,"contact":{"email":%q}},%q]}`, pan, email, pan))

	report := admin(t, ts, "GET", "/api/admin/accounts/arrpii/discover", nil)
	logs := admin(t, ts, "GET", "/api/admin/logs?account=arrpii", nil)
	for _, secret := range []string{pan, email} {
		if strings.Contains(string(report.body), secret) || strings.Contains(string(logs.body), secret) {
			t.Errorf("value %q leaked", secret)
		}
	}
	got := arrFields(t, report.json(t), "a2b")
	for _, p := range []string{"cards[].pan", "cards[].contact.email", "cards[]"} {
		if _, ok := got[p]; !ok {
			t.Errorf("name %q should have been recorded: %v", p, got)
		}
	}
	// And the activity entry carries the shape, deduplicated.
	entries := arrList(admin(t, ts, "GET", "/api/admin/logs?account=arrpii", nil).json(t)["entries"])
	if len(entries) == 0 {
		t.Fatal("the request is missing from the activity log")
	}
	fields := arrList(arrObj(entries[0])["fields"])
	seen := map[string]int{}
	for _, f := range fields {
		seen[fmt.Sprint(f)]++
	}
	if seen["cards[].pan:string"] != 1 {
		t.Errorf("activity shape: %v", fields)
	}
}
