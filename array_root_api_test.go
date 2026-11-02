package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A body that is itself an array, through the gateway, the dry run and field
// discovery. Rows whose paths start with [] address its elements.

const (
	// A list in side A's words and the same list in side B's.
	rootAList = `[{"sku":"s1","qty":2,"shipped":"2024-03-01T09:00:00Z","note":"gift"},` +
		`{"sku":"s2","qty":1,"shipped":"2024-03-02T09:00:00Z"}]`
	rootBList = `[{"product_code":"s1","quantity":2,"shipped_epoch":1709283600,"note":"gift"},` +
		`{"product_code":"s2","quantity":1,"shipped_epoch":1709370000}]`
	// Three mapped fields in each of the two elements.
	rootAppliedPerLeg = 6
)

var (
	rootDate = map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"}

	// Both sides send their lists bare.
	rootListRows = []map[string]any{
		{"a": "[].sku", "b": "[].product_code"},
		{"a": "[].qty", "b": "[].quantity"},
		{"a": "[].shipped", "b": "[].shipped_epoch", "transform": rootDate},
	}
	// Side A sends its lists bare, side B wraps them as {"data": [...]}.
	rootWrapRows = []map[string]any{
		{"a": "[].sku", "b": "data[].code"},
		{"a": "[].qty", "b": "data[].n"},
	}
)

func rootDoc(id string, a, b *mtPartner, rows []map[string]any, extra map[string]any) map[string]any {
	doc := map[string]any{
		"id": id, "enabled": true,
		"a": map[string]any{"label": "Acme", "target_url": a.URL, "inbound_token": mtAIn,
			"outbound_token": mtAOut, "inbound_methods": mtAllMethods},
		"b": map[string]any{"label": "Globex", "target_url": b.URL, "inbound_token": mtBIn,
			"outbound_token": mtBOut, "inbound_methods": mtAllMethods},
		"map": rows,
	}
	for k, v := range extra {
		doc[k] = v
	}
	return doc
}

// rootElements is a JSON array of n small objects, each carrying a sku.
func rootElements(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"sku":"s%d"}`, i)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// ---------------------------------------------------------------------------
// Responses and bodies, both directions

func TestTopLevelArrayResponseOfAGetListIsTranslated(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, rootDoc("lists", a, b, rootListRows, nil))

	// A asks B for a list; B answers in its own words, A reads its own.
	b.answer(200, "application/json", rootBList)
	r := call(t, ts, "GET", "/t/lists/a2b", mtAIn, nil)
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	mtSameJSON(t, string(r.body), rootAList)
	if ct := r.hdr.Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("Content-Type %q", ct)
	}
	if got, want := r.hdr.Get("X-Xlate-Applied"), strconv.Itoa(rootAppliedPerLeg); got != want {
		t.Errorf("X-Xlate-Applied %s, want %s", got, want)
	}
	if w := r.hdr.Get("X-Xlate-Warnings"); w != "" {
		t.Errorf("unexpected warnings: %s", w)
	}
	if seen := b.take(t); seen.method != "GET" || seen.body != "" {
		t.Errorf("B saw %s with a body %q", seen.method, seen.body)
	}

	// An empty list is an empty list.
	b.answer(200, "application/json", `[]`)
	if r := call(t, ts, "GET", "/t/lists/a2b", mtAIn, nil); r.status != 200 || strings.TrimSpace(string(r.body)) != `[]` {
		t.Errorf("empty list: %d %s", r.status, r.body)
	}
	b.take(t)

	// An error answer is an object, and is relayed as one.
	b.answer(500, "application/json", `{"error":"nope","product_code":"p"}`)
	r = call(t, ts, "GET", "/t/lists/a2b", mtAIn, nil)
	if r.status != 500 {
		t.Fatalf("%d", r.status)
	}
	mtSameJSON(t, string(r.body), `{"error":"nope","product_code":"p"}`)
	b.take(t)

	// B asks A: mirrored.
	a.answer(200, "application/json", rootAList)
	r = call(t, ts, "GET", "/t/lists/b2a", mtBIn, nil)
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	mtSameJSON(t, string(r.body), rootBList)
	a.take(t)
}

func TestTopLevelArrayBodiesAreTranslatedBothWays(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, rootDoc("lists", a, b, rootListRows, nil))

	for _, method := range []string{"POST", "PUT", "PATCH"} {
		// A sends a bare list, B must receive it in its words, bare.
		b.answer(200, "application/json", rootBList)
		r := call(t, ts, method, "/t/lists/a2b", mtAIn, rootAList)
		if r.status != 200 {
			t.Fatalf("%s a2b: %d %s", method, r.status, r.body)
		}
		seen := b.take(t)
		if seen.method != method || seen.hdr.Get("Content-Type") != "application/json" {
			t.Errorf("%s: B saw %s with %q", method, seen.method, seen.hdr.Get("Content-Type"))
		}
		mtSameJSON(t, seen.body, rootBList)
		mtSameJSON(t, string(r.body), rootAList)
		if got, want := r.hdr.Get("X-Xlate-Applied"), strconv.Itoa(2*rootAppliedPerLeg); got != want {
			t.Errorf("%s: X-Xlate-Applied %s, want %s", method, got, want)
		}

		// And B to A.
		a.answer(200, "application/json", rootAList)
		r = call(t, ts, method, "/t/lists/b2a", mtBIn, rootBList)
		if r.status != 200 {
			t.Fatalf("%s b2a: %d %s", method, r.status, r.body)
		}
		mtSameJSON(t, a.take(t).body, rootAList)
		mtSameJSON(t, string(r.body), rootBList)
	}

	// Numbers stay numbers, at any size.
	b.answer(200, "application/json", `[{"quantity":9007199254740993}]`)
	r := call(t, ts, "POST", "/t/lists/a2b", mtAIn, `[{"qty":9007199254740993}]`)
	if r.status != 200 || !strings.Contains(b.take(t).body, `"quantity":9007199254740993`) || !strings.Contains(string(r.body), `"qty":9007199254740993`) {
		t.Errorf("a number lost its precision: %d %s", r.status, r.body)
	}
}

func TestTopLevelArrayWrapAndUnwrap(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, rootDoc("wrap", a, b, rootWrapRows, nil))

	t.Run("a bare list is wrapped for the side that wraps, and its answer comes back bare", func(t *testing.T) {
		b.answer(200, "application/json", `{"data":[{"code":"s1","n":2}]}`)
		r := call(t, ts, "POST", "/t/wrap/a2b", mtAIn, `[{"sku":"s1","qty":2}]`)
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		mtSameJSON(t, b.take(t).body, `{"data":[{"code":"s1","n":2}]}`)
		mtSameJSON(t, string(r.body), `[{"sku":"s1","qty":2}]`)
	})

	t.Run("a list answered as an envelope cannot be unwrapped without losing the rest", func(t *testing.T) {
		b.answer(200, "application/json", `{"data":[{"code":"s1","n":2}],"total":3,"next":"p2"}`)
		r := call(t, ts, "POST", "/t/wrap/a2b", mtAIn, `[{"sku":"s1","qty":2}]`)
		if r.status != 502 || r.json(t)["code"] != "upstream_invalid" {
			t.Fatalf("want 502 upstream_invalid, got %d %s", r.status, r.body)
		}
		for _, leak := range []string{"total", "next", "s1", "data"} {
			if strings.Contains(string(r.body), leak) {
				t.Errorf("the destination's content reached the caller: %s", r.body)
			}
		}
		b.take(t)
		var found bool
		for _, rec := range mtTrail(t, srv, "ingest.rejected") {
			if rec["reason"] == "response_array" && fmt.Sprint(rec["fields"]) == "[next total]" {
				found = true
			}
		}
		if !found {
			t.Errorf("the refusal is not on the trail by field name: %s", strictTrail(t, srv))
		}
	})

	t.Run("an envelope sent to the side that wants a bare list is refused by name", func(t *testing.T) {
		before := a.hits()
		r := call(t, ts, "POST", "/t/wrap/b2a", mtBIn, `{"data":[{"code":"s1"}],"ref":"secret-ref"}`)
		if r.status != 422 || r.json(t)["code"] != "array_invalid" {
			t.Fatalf("want 422 array_invalid, got %d %s", r.status, r.body)
		}
		if msg := r.fieldErrors(t)["ref"]; !strings.Contains(msg, "cannot sit beside a top-level array") || len(r.fieldErrors(t)) != 1 {
			t.Errorf("fields: %v", r.fieldErrors(t))
		}
		if a.hits() != before {
			t.Error("a refused message was forwarded")
		}
		if strings.Contains(string(r.body), "secret-ref") || strings.Contains(strictTrail(t, srv), "secret-ref") {
			t.Error("a value was reported")
		}
	})

	t.Run("a list answered in wrapped form to a bare asker is wrapped for them", func(t *testing.T) {
		// B posts a wrapped list; A answers with its bare one; B reads its wrapper.
		a.answer(200, "application/json", `[{"sku":"s1","qty":2}]`)
		r := call(t, ts, "POST", "/t/wrap/b2a", mtBIn, `{"data":[{"code":"s1","n":2}]}`)
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		mtSameJSON(t, a.take(t).body, `[{"sku":"s1","qty":2}]`)
		mtSameJSON(t, string(r.body), `{"data":[{"code":"s1","n":2}]}`)
	})

	t.Run("drop_unmapped lets an envelope through as a bare list, dropping what was beside it", func(t *testing.T) {
		ts := newAPI(t)
		a, b := newMtPartner(t), newMtPartner(t)
		mustCreate(t, ts, rootDoc("wrapdrop", a, b, rootWrapRows, map[string]any{"drop_unmapped": true}))
		a.answer(200, "application/json", `{}`)
		r := call(t, ts, "POST", "/t/wrapdrop/b2a", mtBIn, `{"data":[{"code":"s1","n":2}],"ref":"r"}`)
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		mtSameJSON(t, a.take(t).body, `[{"sku":"s1","qty":2}]`)
	})
}

// ---------------------------------------------------------------------------
// Opt-in: nothing changes without a row that addresses the top level

func TestBareArraysStayAsTheyWereWithoutARootRow(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, rootDoc("named", a, b, []map[string]any{{"a": "lines[].sku", "b": "items[].code"}}, nil))
	mustCreate(t, ts, rootDoc("half", a, b, []map[string]any{{"a": "data[].x", "b": "[].y"}}, nil))

	t.Run("a bare body is still 400 bad_json", func(t *testing.T) {
		for _, id := range []string{"named", "half"} {
			r := call(t, ts, "POST", "/t/"+id+"/a2b", mtAIn, `[{"sku":"a"}]`)
			if r.status != 400 || r.json(t)["code"] != "bad_json" {
				t.Errorf("%s: want 400 bad_json, got %d %s", id, r.status, r.body)
			}
			if msg := fmt.Sprint(r.json(t)["error"]); msg != "body must be a single JSON object" {
				t.Errorf("%s: the message changed: %q", id, msg)
			}
		}
		if a.hits()+b.hits() != 0 {
			t.Error("a refused body was forwarded")
		}
	})

	t.Run("a bare answer is still relayed raw, byte for byte", func(t *testing.T) {
		const raw = `[ {"product_code" : "p"} ]`
		b.answer(200, "application/json", raw)
		r := call(t, ts, "GET", "/t/named/a2b", mtAIn, nil)
		if r.status != 200 || string(r.body) != raw {
			t.Errorf("%d %q", r.status, r.body)
		}
		b.take(t)
		// A list from the side that has no top-level array in the rows is raw too:
		// here B is the side that does, so the list is asked of A.
		a.answer(200, "application/json", raw)
		if r := call(t, ts, "GET", "/t/half/b2a", mtBIn, nil); r.status != 200 || string(r.body) != raw {
			t.Errorf("half: %d %q", r.status, r.body)
		}
		a.take(t)
	})

	t.Run("the side that does have a top-level array still gets one", func(t *testing.T) {
		a.answer(200, "application/json", `{}`)
		r := call(t, ts, "POST", "/t/half/b2a", mtBIn, `[{"y":1}]`)
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		mtSameJSON(t, a.take(t).body, `{"data":[{"x":1}]}`)
	})

	t.Run("the other shapes of a bad body are refused with the old message", func(t *testing.T) {
		for _, body := range []string{`null`, `"s"`, `1`, `{`, `{"a":1} x`, ``} {
			r := call(t, ts, "POST", "/t/named/a2b", mtAIn, body)
			if r.status != 400 || r.json(t)["code"] != "bad_json" {
				t.Errorf("%q: %d %s", body, r.status, r.body)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Refusals

func TestTopLevelArrayRefusalsOverTheWire(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, rootDoc("lists", a, b, rootListRows, nil))

	t.Run("a request that is not a list of objects is refused, and nothing is forwarded", func(t *testing.T) {
		const secret = "4111-1111-1111-1111"
		r := call(t, ts, "POST", "/t/lists/a2b", mtAIn, `[{"sku":"a"},"`+secret+`",7]`)
		if r.status != 422 || r.json(t)["code"] != "array_invalid" {
			t.Fatalf("want 422 array_invalid, got %d %s", r.status, r.body)
		}
		fe := r.fieldErrors(t)
		if !strings.Contains(fe["[1]"], "must be an object, got string") || !strings.Contains(fe["[2]"], "got number") || len(fe) != 2 {
			t.Errorf("fields: %v", fe)
		}
		if b.hits() != 0 {
			t.Error("a refused body was forwarded")
		}
		trail := strictTrail(t, srv)
		if !strings.Contains(trail, `"reason":"array"`) || !strings.Contains(trail, `[1]`) {
			t.Errorf("the refusal is not on the trail: %s", trail)
		}
		for _, text := range []string{string(r.body), trail, fmt.Sprint(admin(t, ts, "GET", "/api/admin/logs?account=lists", nil).body)} {
			if strings.Contains(text, secret) {
				t.Error("a value was reported")
			}
			noEngineName(t, "a response, the trail or the log", text)
		}
	})

	t.Run("the length cap", func(t *testing.T) {
		b.answer(200, "application/json", `[]`)
		if r := call(t, ts, "POST", "/t/lists/a2b", mtAIn, rootElements(maxArrayLen)); r.status != 200 {
			t.Fatalf("%d elements: %d %.200s", maxArrayLen, r.status, r.body)
		}
		b.take(t)
		r := call(t, ts, "POST", "/t/lists/a2b", mtAIn, rootElements(maxArrayLen+1))
		if r.status != 422 || !strings.Contains(r.fieldErrors(t)["[]"], fmt.Sprintf("at most %d", maxArrayLen)) {
			t.Fatalf("%d elements: %d %.200s", maxArrayLen+1, r.status, r.body)
		}
		if b.hits() != 0 {
			t.Error("an over-long list was forwarded")
		}
	})

	t.Run("refused lists are a data problem, not a credential guess", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			if r := call(t, ts, "POST", "/t/lists/a2b", mtAIn, `[1]`); r.status != 422 {
				t.Fatalf("refusal %d: %d %s", i, r.status, r.body)
			}
		}
		b.answer(200, "application/json", `[]`)
		if r := call(t, ts, "POST", "/t/lists/a2b", mtAIn, rootAList); r.status != 200 {
			t.Errorf("the account was locked by refused lists: %d %s", r.status, r.body)
		}
		b.take(t)
	})

	t.Run("an answer that is not a list of objects never reaches the caller", func(t *testing.T) {
		for name, reply := range map[string]string{
			"a scalar element":  `[{"product_code":"p"},"stray"]`,
			"a list of numbers": `[1,2]`,
			"too long":          strings.ReplaceAll(rootElements(maxArrayLen+1), `"sku"`, `"product_code"`),
		} {
			b.answer(200, "application/json", reply)
			r := call(t, ts, "GET", "/t/lists/a2b", mtAIn, nil)
			if r.status != 502 || r.json(t)["code"] != "upstream_invalid" {
				t.Errorf("%s: want 502 upstream_invalid, got %d %.200s", name, r.status, r.body)
			}
			if strings.Contains(string(r.body), "stray") || strings.Contains(string(r.body), "product_code") {
				t.Errorf("%s: the destination's content reached the caller", name)
			}
			b.take(t)
		}
		var reasons int
		for _, rec := range mtTrail(t, srv, "ingest.rejected") {
			if rec["reason"] == "response_array" {
				reasons++
			}
		}
		if reasons != 3 {
			t.Errorf("%d response refusals on the trail, want 3", reasons)
		}
	})

	t.Run("what is neither an object nor an array is still 400, with a message that says both", func(t *testing.T) {
		for _, body := range []string{`null`, `"s"`, `1`, `[`, `[1] x`} {
			r := call(t, ts, "POST", "/t/lists/a2b", mtAIn, body)
			if r.status != 400 || r.json(t)["code"] != "bad_json" || fmt.Sprint(r.json(t)["error"]) != "body must be a single JSON object or array" {
				t.Errorf("%q: %d %s", body, r.status, r.body)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Dry run

func TestTopLevelArrayDryRun(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, rootDoc("lists", a, b, rootListRows, nil))
	mustCreate(t, ts, rootDoc("wrap", a, b, rootWrapRows, nil))
	mustCreate(t, ts, rootDoc("strict", a, b, rootListRows, map[string]any{"strict_transforms": true}))
	mustCreate(t, ts, rootDoc("named", a, b, []map[string]any{{"a": "lines[].sku", "b": "items[].code"}, {"a": "ref", "b": "reference"}}, nil))

	dry := func(id, dir string, payload any) apiResp {
		return admin(t, ts, "POST", "/api/admin/accounts/"+id+"/test", map[string]any{"direction": dir, "payload": payload})
	}
	jsonOf := func(s string) any { return mtJSON(t, s) }

	t.Run("a bare list previews as it would be sent", func(t *testing.T) {
		r := dry("lists", "a2b", jsonOf(rootAList))
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		m := r.json(t)
		mtSameJSON(t, mustMarshalAny(t, m["translated"]), rootBList)
		if fmt.Sprint(m["applied"]) != strconv.Itoa(rootAppliedPerLeg) {
			t.Errorf("applied %v", m["applied"])
		}
		if _, rejected := m["rejected"]; rejected {
			t.Errorf("a good list must not be marked rejected: %s", r.body)
		}
		r = dry("lists", "b2a", jsonOf(rootBList))
		mtSameJSON(t, mustMarshalAny(t, r.json(t)["translated"]), rootAList)
		r = dry("wrap", "a2b", jsonOf(`[{"sku":"s1","qty":2}]`))
		mtSameJSON(t, mustMarshalAny(t, r.json(t)["translated"]), `{"data":[{"code":"s1","n":2}]}`)
		r = dry("wrap", "b2a", jsonOf(`{"data":[{"code":"s1","n":2}]}`))
		mtSameJSON(t, mustMarshalAny(t, r.json(t)["translated"]), `[{"sku":"s1","qty":2}]`)
	})

	t.Run("an envelope that cannot unwrap shows why, with the list under []", func(t *testing.T) {
		r := dry("wrap", "b2a", jsonOf(`{"data":[{"code":"s1","n":2}],"total":3}`))
		m := r.json(t)
		if m["rejected"] != true {
			t.Fatalf("want rejected: %s", r.body)
		}
		refused, _ := m["refused"].([]any)
		if len(refused) != 1 || arrObj(refused[0])["field"] != "total" {
			t.Errorf("refused: %v", m["refused"])
		}
		mtSameJSON(t, mustMarshalAny(t, m["translated"]), `{"[]":[{"sku":"s1","qty":2}],"total":3}`)
		noEngineName(t, "the dry run", string(r.body))
	})

	t.Run("elements that are not objects are named", func(t *testing.T) {
		m := dry("lists", "a2b", jsonOf(`[{"sku":"a"},"x"]`)).json(t)
		refused, _ := m["refused"].([]any)
		if m["rejected"] != true || len(refused) != 1 || arrObj(refused[0])["field"] != "[1]" {
			t.Errorf("%v", m)
		}
		mtSameJSON(t, mustMarshalAny(t, m["translated"]), `[{"sku":"a"},"x"]`)
	})

	t.Run("strict mode names the element", func(t *testing.T) {
		m := dry("strict", "a2b", jsonOf(`[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"bad"}]`)).json(t)
		if failed := arrList(m["failed"]); m["rejected"] != true || len(failed) != 1 || failed[0] != "[1].shipped" {
			t.Errorf("%v", m)
		}
	})

	t.Run("the rule is the data plane's: a bare list needs a row that addresses one", func(t *testing.T) {
		r := dry("named", "a2b", jsonOf(`[{"sku":"a"}]`))
		if r.status != 400 || r.fieldErrors(t)["payload"] != "must be a JSON object" {
			t.Errorf("%d %s", r.status, r.body)
		}
		for _, bad := range []any{nil, "s", 1, true} {
			r := dry("lists", "a2b", bad)
			if r.status != 400 || r.fieldErrors(t)["payload"] == "" {
				t.Errorf("payload %v: %d %s", bad, r.status, r.body)
			}
		}
		if r := admin(t, ts, "POST", "/api/admin/accounts/lists/test", map[string]any{"direction": "a2b"}); r.status != 400 {
			t.Errorf("no payload: %d %s", r.status, r.body)
		}
	})

	t.Run("an object payload is previewed as before", func(t *testing.T) {
		m := dry("named", "a2b", jsonOf(`{"ref":"r","lines":[{"sku":"a"}]}`)).json(t)
		mtSameJSON(t, mustMarshalAny(t, m["translated"]), `{"reference":"r","items":[{"code":"a"}]}`)
	})
}

// sameJSONBytes compares two JSON documents by value, array order included.
func sameJSONBytes(t *testing.T, got, want []byte) bool {
	t.Helper()
	dec := func(b []byte) any {
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			return "not JSON: " + string(b)
		}
		return v
	}
	return reflect.DeepEqual(dec(got), dec(want))
}

func mustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustMarshalAny(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Field discovery

func TestDiscoveryReadsABareArrayBody(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{
		"id": "rootdisc", "enabled": true,
		"map": []map[string]any{{"a": "[].sku", "b": "[].code"}},
	})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "rootdisc", 30)

	// No target yet: the forward fails, the shape is captured.
	body := `[{"sku":"a","qty":1,"price":{"amount":"9"}},{"sku":"b","qty":"two"},"stray-value"]`
	if r := call(t, ts, "POST", "/t/rootdisc/a2b", tok, body); r.status != 502 {
		t.Fatalf("want 502 no_target, got %d %s", r.status, r.body)
	}

	report := discoverReport(t, ts, "rootdisc")
	got := arrFields(t, report, "a2b")
	for path, want := range map[string]struct {
		types    string
		mappable bool
	}{
		"[].sku":          {"string", true},
		"[].qty":          {"number,string", true},
		"[].price":        {"object", false},
		"[].price.amount": {"string", true},
		"[]":              {"string", false},
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
	for path := range got {
		if path == "" {
			t.Error("the array itself must have no path of its own")
		}
	}
	if c := fmt.Sprint(got["[].sku"]["count"]); c != "1" {
		t.Errorf("[].sku counted %s times after one body", c)
	}

	have := map[string]bool{}
	for _, row := range arrList(arrObj(arrObj(report)["suggest"])["a2b"]) {
		have[fmt.Sprint(arrObj(row)["a"])] = true
	}
	for _, want := range []string{"[].sku", "[].qty", "[].price.amount"} {
		if !have[want] {
			t.Errorf("%q should be suggested: %v", want, have)
		}
	}
	for _, not := range []string{"[]", "[].price"} {
		if have[not] {
			t.Errorf("%q must not be suggested: %v", not, have)
		}
	}

	logs := admin(t, ts, "GET", "/api/admin/logs?account=rootdisc", nil)
	for _, text := range []string{string(mustJSONBytes(t, report)), string(logs.body)} {
		if strings.Contains(text, "stray-value") {
			t.Error("a value was recorded")
		}
		noEngineName(t, "discovery or the log", text)
	}
	entries := arrList(arrObj(logs.json(t))["entries"])
	if len(entries) == 0 {
		t.Fatal("the request is missing from the activity log")
	}
	seen := map[string]bool{}
	for _, f := range arrList(arrObj(entries[0])["fields"]) {
		seen[fmt.Sprint(f)] = true
	}
	if !seen["[].sku:string"] || !seen["[]:string"] {
		t.Errorf("activity shape: %v", seen)
	}
}

// ---------------------------------------------------------------------------
// Many accounts, both ways, at once

// rootPost is safe to call from any goroutine: it reports rather than fails.
func rootPost(c *http.Client, url, token, reqID string, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", reqID)
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, out, err
}

const rootScaleFields = 24 // mapped fields per element, and a date besides

// rootScaleRows are the rows of one account of the scenario: side A's list is
// bare; side B's is bare too, or wrapped as {"data": [...]}.
func rootScaleRows(wrapped bool) []map[string]any {
	b := "[]."
	if wrapped {
		b = "data[]."
	}
	rows := make([]map[string]any, 0, rootScaleFields+1)
	for f := 0; f < rootScaleFields; f++ {
		rows = append(rows, map[string]any{"a": fmt.Sprintf("[].fld%02d", f), "b": b + fmt.Sprintf("col%02d", f)})
	}
	return append(rows, map[string]any{"a": "[].placed", "b": b + "placed_epoch", "transform": rootDate})
}

// rootScaleMessage builds one list in each side's words, as JSON. Every value
// is unique to the message, so one landing in the wrong element, request or
// account cannot go unnoticed.
func rootScaleMessage(tag string, n int, wrapped bool) (aJSON, bJSON []byte, mapped int) {
	count := n % 5 // including none
	ea, eb := make([]string, count), make([]string, count)
	for k := 0; k < count; k++ {
		var a, b []string
		for i := 0; i < rootScaleFields; i++ {
			var av, bv string
			if i%9 == 0 { // past 2^53: must cross verbatim, as a number
				av = strconv.FormatInt(9007199254740993+int64(n)*100000+int64(k)*100+int64(i), 10)
				bv = av
			} else {
				av = strconv.Quote(fmt.Sprintf("%s/%d.%d", tag, k, i))
				bv = av
			}
			a = append(a, fmt.Sprintf(`"fld%02d":%s`, i, av))
			b = append(b, fmt.Sprintf(`"col%02d":%s`, i, bv))
		}
		ts := 1786017600 + int64(n)*10 + int64(k)
		a = append(a, fmt.Sprintf(`"placed":%q`, time.Unix(ts, 0).UTC().Format(time.RFC3339)),
			fmt.Sprintf(`"memo":%q`, "memo "+tag))
		b = append(b, fmt.Sprintf(`"placed_epoch":%d`, ts), fmt.Sprintf(`"memo":%q`, "memo "+tag))
		ea[k], eb[k] = "{"+strings.Join(a, ",")+"}", "{"+strings.Join(b, ",")+"}"
	}
	aJSON = []byte("[" + strings.Join(ea, ",") + "]")
	bJSON = []byte("[" + strings.Join(eb, ",") + "]")
	if wrapped {
		bJSON = []byte(`{"data":` + string(bJSON) + `}`)
	}
	return aJSON, bJSON, count * (rootScaleFields + 1)
}

func TestTopLevelArraysManyAccountsBothDirections(t *testing.T) {
	const (
		accounts  = 6
		workers   = 4 // per account and direction
		perWorker = 8
	)
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	up := newScaleUpstream(t)

	type acct struct {
		id, tokA, tokB string
		wrapped        bool
	}
	var accts []acct
	for i := 0; i < accounts; i++ {
		id, wrapped := fmt.Sprintf("rscale%d", i), i%2 == 1
		doc := mustCreate(t, ts, map[string]any{
			"id": id, "enabled": true, "map": rootScaleRows(wrapped),
			"a": map[string]any{"target_url": up.URL + "/" + id + "/a", "outbound_token": scaleOut("A", id)},
			"b": map[string]any{"target_url": up.URL + "/" + id + "/b", "outbound_token": scaleOut("B", id)},
		})
		accts = append(accts, acct{id, sideToken(doc, "a"), sideToken(doc, "b"), wrapped})
	}

	type result struct {
		acct, dir, id string
		sent          []byte // what the caller wrote
		want          []byte // what the destination must have received
		mapped        int
		status        int
		hdr           http.Header
		body          []byte
		err           error
	}
	var (
		mu      sync.Mutex
		results []result
		wg      sync.WaitGroup
	)
	tr := &http.Transport{MaxIdleConnsPerHost: 64}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}
	for _, a := range accts {
		for _, dir := range []string{"a2b", "b2a"} {
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(a acct, dir string, w int) {
					defer wg.Done()
					for k := 0; k < perWorker; k++ {
						n := w*perWorker + k
						reqID := fmt.Sprintf("%s-%s-%d", a.id, dir, n)
						aj, bj, mapped := rootScaleMessage(reqID, n, a.wrapped)
						sent, want, tok := aj, bj, a.tokA
						if dir == "b2a" {
							sent, want, tok = bj, aj, a.tokB
						}
						st, hdr, body, err := rootPost(client, ts.URL+"/t/"+a.id+"/"+dir, tok, reqID, sent)
						mu.Lock()
						results = append(results, result{a.id, dir, reqID, sent, want, mapped, st, hdr, body, err})
						mu.Unlock()
					}
				}(a, dir, w)
			}
		}
	}
	wg.Wait()
	if want := accounts * 2 * workers * perWorker; len(results) != want {
		t.Fatalf("ran %d requests, want %d", len(results), want)
	}

	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }
	for _, r := range results {
		if r.err != nil || r.status != 200 {
			fail("%s: status %d err %v: %.120s", r.id, r.status, r.err, r.body)
			continue
		}
		destPath, destAuth := "/"+r.acct+"/b", "Bearer "+scaleOut("B", r.acct)
		if r.dir == "b2a" {
			destPath, destAuth = "/"+r.acct+"/a", "Bearer "+scaleOut("A", r.acct)
		}
		hit, ok := up.hit(r.id)
		if !ok {
			fail("%s: never reached the destination", r.id)
			continue
		}
		if hit.path != destPath || hit.auth != destAuth {
			fail("%s: reached %s with %q, want %s with %q", r.id, hit.path, hit.auth, destPath, destAuth)
		}
		// What the destination received is the other side's list, in its words
		// and its shape; what the caller got back is what it sent.
		if !sameJSONBytes(t, hit.body, r.want) {
			fail("%s: the destination received %.200s, want %.200s", r.id, hit.body, r.want)
		}
		if !sameJSONBytes(t, r.body, r.sent) {
			fail("%s: the caller got back %.200s, want %.200s", r.id, r.body, r.sent)
		}
		if got, want := r.hdr.Get("X-Xlate-Applied"), strconv.Itoa(2*r.mapped); got != want {
			fail("%s: X-Xlate-Applied %s, want %s", r.id, got, want)
		}
		if w := r.hdr.Get("X-Xlate-Warnings"); w != "" {
			fail("%s: unexpected warnings: %s", r.id, w)
		}
	}
	if len(failures) > 0 {
		if len(failures) > 8 {
			failures = append(failures[:8], "...")
		}
		t.Fatalf("%d requests failed verification:\n%s", len(failures), strings.Join(failures, "\n"))
	}
	if err := VerifyAudit(srv.audit.f.Name(), discardWriter{}); err != nil {
		t.Fatalf("audit chain broke under concurrent traffic: %v", err)
	}
}
