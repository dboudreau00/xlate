package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The query string of a GET or DELETE is translated by the same engine as a
// body: it becomes the same kind of object, goes through Translate, and is
// flattened back into parameters.

func TestQueryPayloadExpandsDottedNamesAndKeepsLists(t *testing.T) {
	got, err := queryPayload("payment_id=123&customer.id=9&tag=a&tag=b&empty=")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"payment_id": "123",
		"customer":   map[string]any{"id": "9"},
		"tag":        []any{"a", "b"},
		"empty":      "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload = %#v\nwant      %#v", got, want)
	}

	none, err := queryPayload("")
	if err != nil || none == nil || len(none) != 0 {
		t.Errorf("an empty query is an empty object, got %#v, %v", none, err)
	}
}

// A name no map could address stays a flat key. No pair can match it, so it is
// passed through or dropped with the other unmapped input, and never reshaped.
func TestQueryPayloadLeavesUnaddressableNamesFlat(t *testing.T) {
	names := []string{
		"filter[status]", "items[0]", "a..b", ".lead", "trail.", "",
		"ctl%01x", strings.Repeat("k", maxPathLen+1), strings.Repeat("a.", maxPathDepth) + "z",
	}
	raw := make([]string, len(names))
	for i, n := range names {
		raw[i] = n + "=v"
	}
	got, err := queryPayload(strings.Join(raw, "&"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(names) {
		t.Fatalf("%d names became %d keys: %v", len(names), len(got), got)
	}
	for k, v := range got {
		if _, nested := v.(map[string]any); nested {
			t.Errorf("%q was expanded", k)
		}
	}
	if got["filter[status]"] != "v" || got["a..b"] != "v" {
		t.Errorf("flat keys lost: %v", got)
	}
}

func TestQueryPayloadRefusals(t *testing.T) {
	tooMany := make([]string, maxQueryParams+1)
	for i := range tooMany {
		tooMany[i] = "p" + strconv.Itoa(i) + "=1"
	}
	atLimit := strings.Join(tooMany[:maxQueryParams], "&")

	for name, tc := range map[string]struct{ raw, field string }{
		"too long":          {"k=" + strings.Repeat("x", maxQueryBytes), "query"},
		"too many":          {strings.Join(tooMany, "&"), "query"},
		"repeats count":     {strings.Repeat("a=1&", maxQueryParams) + "a=2", "query"},
		"bad escape":        {"a=%zz", "query"},
		"semicolon":         {"a=1;b=2", "query"},
		"value and parent":  {"a=1&a.b=2", "query.a.b"},
		"parent after leaf": {"a.b=2&a=1", "query.a.b"},
		"deeper clash":      {"a.b=1&a.b.c=2", "query.a.b.c"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := queryPayload(tc.raw)
			var ve ValidationErrors
			if !errors.As(err, &ve) || len(ve) == 0 {
				t.Fatalf("want a validation refusal, got %v", err)
			}
			if ve[0].Field != tc.field {
				t.Errorf("field = %q, want %q (%v)", ve[0].Field, tc.field, ve)
			}
			if strings.Contains(ve.Error(), "%zz") {
				t.Errorf("the refusal echoes the caller's fragment: %v", ve)
			}
		})
	}

	if _, err := queryPayload(atLimit); err != nil {
		t.Errorf("exactly %d parameters must pass: %v", maxQueryParams, err)
	}
}

// A clash is found the same way whatever order the caller used, and the name
// in the refusal is bounded and cleaned like every other client-chosen name.
func TestQueryPayloadClashNameIsCleaned(t *testing.T) {
	_, err := queryPayload("a=1&a." + strings.Repeat("b", 3*maxLoggedFieldName) + "=2")
	var ve ValidationErrors
	if !errors.As(err, &ve) || len(ve) != 1 {
		t.Fatalf("want one refusal, got %v", err)
	}
	if len([]rune(ve[0].Field)) > len("query.")+maxLoggedFieldName+1 {
		t.Errorf("name not bounded: %d runes", len([]rune(ve[0].Field)))
	}
}

func TestQueryValuesFlattensAndRefusesForeignTypes(t *testing.T) {
	got, err := queryValues(map[string]any{
		"party":   map[string]any{"ref": "c-7", "deep": map[string]any{"x": "1"}},
		"tag":     []any{"a", "b"},
		"epoch":   json.Number("1786017600"),
		"nums":    []any{json.Number("1"), "two"},
		"emptied": map[string]any{},
		"flat.k":  "kept",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "epoch=1786017600&flat.k=kept&nums=1&nums=two&party.deep.x=1&party.ref=c-7&tag=a&tag=b"
	if got.Encode() != want {
		t.Errorf("encoded = %s\nwant      %s", got.Encode(), want)
	}
	if _, present := got["emptied"]; present {
		t.Error("an emptied container must not cross as a parameter")
	}

	for name, in := range map[string]map[string]any{
		"bool":         {"a": true},
		"null":         {"a": nil},
		"float":        {"a": 1.5},
		"object list":  {"a": []any{map[string]any{"x": "1"}}},
		"nested other": {"a": map[string]any{"b": false}},
	} {
		if _, err := queryValues(in); err == nil {
			t.Errorf("%s: a value that cannot have come from a query was accepted", name)
		}
	}
}

// One pair means the same thing in a body and in a query: the same engine, so
// nesting, swapped pairs, collisions and date transforms behave alike, and the
// other direction returns what went in.
func TestQueryTranslatesThroughThePairsBothWays(t *testing.T) {
	pairs := []FieldPair{
		{A: "payment_id", B: "payment_proof"},
		{A: "customer.id", B: "party.ref"},
		{A: "created_at", B: "created_epoch", Transform: &Transform{Kind: "date", AFormat: "rfc3339", BFormat: "unix"}},
		{A: "x", B: "y"},
		{A: "y", B: "x"},
	}
	epoch := strconv.FormatInt(time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC).Unix(), 10)
	in := "payment_id=1&customer.id=2&created_at=2026-08-06T12%3A00%3A00Z&x=ex&y=why&other=o&tag=a&tag=b"

	translate := func(raw string, dir Direction) (string, TranslateResult) {
		t.Helper()
		payload, err := queryPayload(raw)
		if err != nil {
			t.Fatal(err)
		}
		res := Translate(payload, pairs, dir, TranslateOptions{Strict: true})
		vals, err := queryValues(res.Out)
		if err != nil {
			t.Fatal(err)
		}
		return vals.Encode(), res
	}

	out, res := translate(in, AtoB)
	want := url.Values{
		"payment_proof": {"1"}, "party.ref": {"2"}, "created_epoch": {epoch},
		"y": {"ex"}, "x": {"why"}, "other": {"o"}, "tag": {"a", "b"},
	}.Encode()
	if out != want {
		t.Errorf("a2b = %s\nwant  %s", out, want)
	}
	if res.Applied != 5 || len(res.Failed) != 0 {
		t.Errorf("applied %d failed %v", res.Applied, res.Failed)
	}

	back, _ := translate(out, BtoA)
	wantBack := url.Values{
		"payment_id": {"1"}, "customer.id": {"2"}, "created_at": {"2026-08-06T12:00:00Z"},
		"x": {"ex"}, "y": {"why"}, "other": {"o"}, "tag": {"a", "b"},
	}.Encode()
	if back != wantBack {
		t.Errorf("b2a = %s\nwant  %s", back, wantBack)
	}
}

func TestQueryDateThatCannotBeConvertedIsReportedInTheSendersName(t *testing.T) {
	pairs := []FieldPair{{A: "when.created", B: "created_epoch",
		Transform: &Transform{Kind: "date", AFormat: "rfc3339", BFormat: "unix"}}}
	payload, err := queryPayload("when.created=yesterday")
	if err != nil {
		t.Fatal(err)
	}
	res := Translate(payload, pairs, AtoB, TranslateOptions{Strict: true})
	if len(res.Failed) != 1 || res.Failed[0] != "when.created" {
		t.Errorf("Failed = %v, want the caller's own name", res.Failed)
	}

	// A repeated name is a list, and a transform needs one value.
	payload, err = queryPayload("when.created=2026-08-06T12%3A00%3A00Z&when.created=2026-08-07T12%3A00%3A00Z")
	if err != nil {
		t.Fatal(err)
	}
	res = Translate(payload, pairs, AtoB, TranslateOptions{Strict: true})
	if len(res.Failed) != 1 {
		t.Errorf("a list cannot be converted as one date: %v", res.Failed)
	}
}

func TestQueryPathRule(t *testing.T) {
	for k, want := range map[string]bool{
		"a": true, "customer.id": true, "a.b.c": true, "has space": true, "ünï.côde": true,
		"": false, ".a": false, "a.": false, "a..b": false, "a[0]": false, "a[]": false, "a.b]": false,
		"tab\tname": false, "del\x7fx": false, "bad\xffutf8": false,
		strings.Repeat("a.", maxPathDepth-1) + "z":    true,
		strings.Repeat("a.", maxPathDepth) + "z":      false,
		strings.Repeat("k", maxPathLen):               true,
		strings.Repeat("k", maxPathLen+1):             false,
		strings.Repeat("a", maxPathLen-2) + ".b":      true,
		strings.Repeat("a", maxPathLen-1) + ".bc":     false,
		strings.Repeat("seg.", maxPathDepth-1) + "e1": true,
	} {
		if got := queryPath(k); got != want {
			t.Errorf("queryPath(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestWithQueryKeepsWhatTheTargetFixes(t *testing.T) {
	add := url.Values{"payment_proof": {"1"}, "tag": {"a", "b"}}

	got, err := withQuery("https://b.example/api/v1?key=SECRET&mode=x", add)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://b.example/api/v1?key=SECRET&mode=x&" + add.Encode(); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}

	got, err = withQuery("https://b.example/api/v1", add)
	if err != nil || got != "https://b.example/api/v1?"+add.Encode() {
		t.Errorf("no fixed query: %s, %v", got, err)
	}

	// Nothing to add leaves the configured string exactly as it was.
	for _, target := range []string{"https://b.example/x?k=%7Ev", "https://b.example/", "http://h:8080/p?"} {
		if got, err := withQuery(target, nil); err != nil || got != target {
			t.Errorf("withQuery(%q, nil) = %q, %v", target, got, err)
		}
	}
}

func TestWithQueryRefusesWhatTheTargetFixes(t *testing.T) {
	for _, tc := range []struct{ target, name string }{
		{"https://b.example/api?key=SECRET", "key"},
		{"https://b.example/api?key=SECRET", "KEY"},
		{"https://b.example/api?Key=SECRET", "kEY"},
		{"https://b.example/api?%6bey=SECRET", "key"},
		{"https://b.example/api?a=1&key=SECRET&b=2", "key"},
		{"https://b.example/api?key=", "key"},
	} {
		_, err := withQuery(tc.target, url.Values{tc.name: {"evil"}, "other": {"fine"}})
		if !errors.Is(err, errQueryClash) {
			t.Errorf("%s with %q: want a clash, got %v", tc.target, tc.name, err)
		}
	}

	// A fixed query that cannot be read is a broken target, not a clash, and
	// is never guessed at.
	_, err := withQuery("https://b.example/api?a=1;b=2", url.Values{"x": {"1"}})
	if err == nil || errors.Is(err, errQueryClash) {
		t.Errorf("an unreadable fixed query should fail as a bad target, got %v", err)
	}
	if _, err := withQuery("http://[::1", url.Values{"x": {"1"}}); err == nil {
		t.Error("an unparseable target was accepted")
	}
}

// The caller contributes encoded parameters and nothing else: no value can
// change the scheme, host, path, userinfo or fragment the operator set.
func TestWithQueryCannotMoveTheDestination(t *testing.T) {
	hostile := []string{
		"https://evil.example/#frag?y=1", "@evil.example", "../../admin", "/..%2f..", "\r\nHost: evil",
		"x#y", "x?y=1&z=2", "//evil.example", "a b", "%00", "ünï",
	}
	for _, v := range hostile {
		got, err := withQuery("https://b.example:8443/api/v1?k=1", url.Values{"x": {v}, v: {"n"}})
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("%q: result does not parse: %v", v, err)
		}
		if u.Scheme != "https" || u.Host != "b.example:8443" || u.Path != "/api/v1" || u.User != nil || u.Fragment != "" {
			t.Errorf("%q moved the destination: %s", v, got)
		}
		q := u.Query()
		if q.Get("k") != "1" || q.Get("x") != v || q.Get(v) != "n" {
			t.Errorf("%q did not survive as data: %v", v, q)
		}
		if strings.ContainsAny(u.RawQuery, " \r\n#") {
			t.Errorf("%q left a raw delimiter in the query: %s", v, u.RawQuery)
		}
	}
}

// closedPort returns the base URL of a port nothing is listening on, so a
// forward to it fails at once.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr
}

func TestRedactTargetErrKeepsNoQuery(t *testing.T) {
	srv := closedPort(t)
	cl := &http.Client{Timeout: 2 * time.Second}

	for _, tc := range []struct {
		name, method, target, query string
	}{
		{"GET with a fixed query", http.MethodGet, srv + "/api?key=SECRET", "&payment_proof=PII-123"},
		{"DELETE with no fixed query", http.MethodDelete, srv + "/api", "?payment_proof=PII-123"},
		{"POST, request URL equals the configured one", http.MethodPost, srv + "/api?key=SECRET", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.target+tc.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = cl.Do(req)
			if err == nil {
				t.Fatal("the connection was expected to fail")
			}
			got := redactTargetErr(err, tc.target)
			for _, leak := range []string{"PII-123", "SECRET", "payment_proof", "key=", "/api"} {
				if strings.Contains(got, leak) {
					t.Errorf("redacted error still carries %q: %s", leak, got)
				}
			}
			if !strings.Contains(got, strings.TrimPrefix(srv, "http://")) {
				t.Errorf("the host should survive for diagnosis: %s", got)
			}
		})
	}

	if got := redactTargetErr(nil, "http://x"); got != "" {
		t.Errorf("nil error = %q", got)
	}
	if got := redactTargetErr(errors.New("plain"), ""); got != "plain" {
		t.Errorf("an empty configured URL must not rewrite the text: %q", got)
	}
}
