package main

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Array addressing: a [] after a name addresses every element of the array
// there, so "lines[].sku" can be renamed in each element of "lines".

var arrDate = &Transform{Kind: "date", AFormat: "rfc3339", BFormat: "unix"}

func arrPair(a, b string) FieldPair { return FieldPair{A: a, B: b} }

func arrNames(fes []FieldError) []string {
	out := make([]string, len(fes))
	for i, fe := range fes {
		out[i] = fe.Field
	}
	return out
}

// ---------------------------------------------------------------------------
// Path syntax

func TestArrayPathSyntax(t *testing.T) {
	valid := []struct{ path, array, inner string }{
		{"lines[].sku", "lines", "sku"},
		{"a[].b", "a", "b"},
		{"order.lines[].tax.rate", "order.lines", "tax.rate"},
		{"with space[].and-dash", "with space", "and-dash"},
		// A path that starts with [] addresses a body that is itself an array.
		{"[].sku", rootKey, "sku"},
		{"[].tax.rate", rootKey, "tax.rate"},
	}
	for _, tc := range valid {
		if err := validateDotPath(tc.path); err != nil {
			t.Errorf("%q should be a valid path: %v", tc.path, err)
		}
		array, inner, ok := splitArrayPath(tc.path)
		if !ok || array != tc.array || inner != tc.inner {
			t.Errorf("splitArrayPath(%q) = %q, %q, %v; want %q, %q", tc.path, array, inner, ok, tc.array, tc.inner)
		}
	}

	invalid := []struct{ path, why string }{
		{"items[0].id", "positional"},
		{"items[0]", "positional"},
		{"a[", "positional"},
		{"a]", "positional"},
		{"a[x].b", "positional"},
		{"lines[]", "must name a field inside"},
		{"order.lines[]", "must name a field inside"},
		{"[]", "elements of the top-level array"},
		{"a.[].b", "directly follow a field name"},
		{"a[]b", "followed by a dot"},
		{"[]x", "followed by a dot"},
		{"a[].b[].c", "only one []"},
		{"[].a[].b", "only one []"},
		{"[][].b", "only one []"},
		{"a[][].b", "only one []"},
		{"a[].b[0]", "only allowed as the pair"},
		{"a[].[b", "only allowed as the pair"},
	}
	for _, tc := range invalid {
		err := validateDotPath(tc.path)
		if err == nil {
			t.Errorf("%q should have been rejected", tc.path)
			continue
		}
		if !strings.Contains(err.Error(), tc.why) {
			t.Errorf("%q: error %q does not say %q", tc.path, err, tc.why)
		}
	}

	// Brackets are no excuse for the other path rules.
	for _, p := range []string{".a[].b", "a[].b.", "a[]..b", " a[].b", strings.Repeat("a.", maxPathDepth) + "b[].c"} {
		if err := validateDotPath(p); err == nil {
			t.Errorf("%q should have been rejected", p)
		}
	}
}

// ---------------------------------------------------------------------------
// The engine

func TestTranslateArrays(t *testing.T) {
	sku := arrPair("lines[].sku", "items[].product_code")
	shipped := FieldPair{A: "lines[].shipped", B: "items[].shipped_epoch", Transform: arrDate}

	cases := []struct {
		name     string
		payload  string
		pairs    []FieldPair
		dir      Direction
		opt      TranslateOptions
		want     string
		applied  int
		warnings int
	}{
		{
			name:    "renames the field in every element",
			payload: `{"lines":[{"sku":"s1"},{"sku":"s2"},{"sku":"s3"}]}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"items":[{"product_code":"s1"},{"product_code":"s2"},{"product_code":"s3"}]}`,
			applied: 3,
		},
		{
			name:    "the return leg runs the same row backwards",
			payload: `{"items":[{"product_code":"s1"},{"product_code":"s2"}]}`,
			pairs:   []FieldPair{sku},
			dir:     BtoA,
			want:    `{"lines":[{"sku":"s1"},{"sku":"s2"}]}`,
			applied: 2,
		},
		{
			name:    "an element's unmapped fields stay in it",
			payload: `{"lines":[{"sku":"s1","note":"keep","n":7}]}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"items":[{"product_code":"s1","note":"keep","n":7}]}`,
			applied: 1,
		},
		{
			name:    "the array is renamed even when no element has a mapped field",
			payload: `{"lines":[{"other":1},{"other":2}]}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"items":[{"other":1},{"other":2}]}`,
		},
		{
			name:    "ragged elements are translated one by one",
			payload: `{"lines":[{"sku":"a","qty":1},{"qty":2},{"sku":"c"},{}]}`,
			pairs:   []FieldPair{arrPair("lines[].sku", "items[].code"), arrPair("lines[].qty", "items[].n")},
			dir:     AtoB,
			want:    `{"items":[{"code":"a","n":1},{"n":2},{"code":"c"},{}]}`,
			applied: 4,
		},
		{
			name:    "an empty array crosses as an empty array under the new name",
			payload: `{"lines":[]}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"items":[]}`,
		},
		{
			name:    "null crosses as null under the new name",
			payload: `{"lines":null}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"items":null}`,
		},
		{
			name:    "a missing array is a no-op",
			payload: `{"other":1}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"other":1}`,
		},
		{
			name:    "dot paths on both sides of the brackets",
			payload: `{"order":{"id":"o1","lines":[{"tax":{"rate":"5"}},{"tax":{"rate":"7"}}]}}`,
			pairs:   []FieldPair{arrPair("order.lines[].tax.rate", "invoice.rows[].vat")},
			dir:     AtoB,
			// The emptied tax object stays in each element, as it does in any object.
			want:    `{"order":{"id":"o1"},"invoice":{"rows":[{"tax":{},"vat":"5"},{"tax":{},"vat":"7"}]}}`,
			applied: 2,
		},
		{
			name:    "a date transform runs in every element, a2b",
			payload: `{"lines":[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"2024-03-02T09:00:00Z"}]}`,
			pairs:   []FieldPair{shipped},
			dir:     AtoB,
			want:    `{"items":[{"shipped_epoch":1709283600},{"shipped_epoch":1709370000}]}`,
			applied: 2,
		},
		{
			name:    "and un-converts on the return leg",
			payload: `{"items":[{"shipped_epoch":1709283600},{"shipped_epoch":1709370000}]}`,
			pairs:   []FieldPair{shipped},
			dir:     BtoA,
			want:    `{"lines":[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"2024-03-02T09:00:00Z"}]}`,
			applied: 2,
		},
		{
			name:     "a bad date in one element fails open for that element only",
			payload:  `{"lines":[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"not a date"}]}`,
			pairs:    []FieldPair{shipped},
			dir:      AtoB,
			want:     `{"items":[{"shipped_epoch":1709283600},{"shipped_epoch":"not a date"}]}`,
			applied:  2,
			warnings: 1,
		},
		{
			name:    "drop_unmapped keeps only the mapped fields of each element, and every element",
			payload: `{"lines":[{"sku":"s1","note":"n"},{"note":"x"}],"other":1}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			opt:     TranslateOptions{DropUnmapped: true},
			want:    `{"items":[{"product_code":"s1"},{}]}`,
			applied: 1,
		},
		{
			name:    "drop_unmapped drops an array no row addresses",
			payload: `{"lines":[{"sku":"s1"}],"tags":[1,2]}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			opt:     TranslateOptions{DropUnmapped: true},
			want:    `{"items":[{"product_code":"s1"}]}`,
			applied: 1,
		},
		{
			name:    "drop_unmapped still carries null and an empty array",
			payload: `{"lines":null,"parts":[],"x":1}`,
			pairs:   []FieldPair{sku, arrPair("parts[].id", "pieces[].ref")},
			dir:     AtoB,
			opt:     TranslateOptions{DropUnmapped: true},
			want:    `{"items":null,"pieces":[]}`,
		},
		{
			name:    "an array no row addresses crosses whole and untouched",
			payload: `{"lines":[{"sku":"s1"}],"tags":[{"sku":"t"},"x",null]}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"items":[{"product_code":"s1"}],"tags":[{"sku":"t"},"x",null]}`,
			applied: 1,
		},
		{
			name:    "an array inside an element that no row addresses crosses whole",
			payload: `{"lines":[{"sku":"s1","taxes":[{"sku":"t"}]}]}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"items":[{"product_code":"s1","taxes":[{"sku":"t"}]}]}`,
			applied: 1,
		},
		{
			name:    "plain rows and array rows in one map",
			payload: `{"ref":"r","lines":[{"sku":"a"}],"free":true}`,
			pairs:   []FieldPair{arrPair("ref", "reference"), arrPair("lines[].sku", "items[].code")},
			dir:     AtoB,
			want:    `{"reference":"r","items":[{"code":"a"}],"free":true}`,
			applied: 2,
		},
		{
			name:    "two arrays in one map",
			payload: `{"lines":[{"sku":"a"}],"notes":[{"text":"t"},{"text":"u"}]}`,
			pairs:   []FieldPair{arrPair("lines[].sku", "items[].code"), arrPair("notes[].text", "remarks[].body")},
			dir:     AtoB,
			want:    `{"items":[{"code":"a"}],"remarks":[{"body":"t"},{"body":"u"}]}`,
			applied: 3,
		},
		{
			name:    "swapped array names do not clobber each other",
			payload: `{"a":[{"x":1}],"b":[{"p":2}]}`,
			pairs:   []FieldPair{arrPair("a[].x", "b[].y"), arrPair("b[].p", "a[].q")},
			dir:     AtoB,
			want:    `{"b":[{"y":1}],"a":[{"q":2}]}`,
			applied: 2,
		},
		{
			name:    "fields swapped inside an element do not clobber each other",
			payload: `{"lines":[{"x":1,"y":2}]}`,
			pairs:   []FieldPair{arrPair("lines[].x", "items[].y"), arrPair("lines[].y", "items[].x")},
			dir:     AtoB,
			want:    `{"items":[{"y":1,"x":2}]}`,
			applied: 2,
		},
		{
			name:    "the array may keep its name while its fields change",
			payload: `{"lines":[{"sku":"s"}]}`,
			pairs:   []FieldPair{arrPair("lines[].sku", "lines[].code")},
			dir:     AtoB,
			want:    `{"lines":[{"code":"s"}]}`,
			applied: 1,
		},
		{
			name:     "an existing destination is overwritten, with a warning",
			payload:  `{"lines":[{"sku":"s"}],"items":"x"}`,
			pairs:    []FieldPair{sku},
			dir:      AtoB,
			want:     `{"items":[{"product_code":"s"}]}`,
			applied:  1,
			warnings: 1,
		},
		{
			name:     "a field colliding inside an element warns for that element",
			payload:  `{"lines":[{"a":1,"b":9}]}`,
			pairs:    []FieldPair{arrPair("lines[].a", "items[].b")},
			dir:      AtoB,
			want:     `{"items":[{"b":1}]}`,
			applied:  1,
			warnings: 1,
		},
		{
			// The array cannot land (inv is a scalar), so it stays at its
			// source, untranslated, and nothing is lost.
			name:     "a blocked destination restores the array untouched",
			payload:  `{"lines":[{"sku":"s"}],"inv":"scalar"}`,
			pairs:    []FieldPair{arrPair("lines[].sku", "inv.rows[].code")},
			dir:      AtoB,
			want:     `{"lines":[{"sku":"s"}],"inv":"scalar"}`,
			warnings: 2,
		},
		{
			name:    "brackets on one side only make an ordinary row, as before arrays existed",
			payload: `{"items[0]":5,"a[]":{"b":6}}`,
			pairs:   []FieldPair{arrPair("items[0]", "x"), arrPair("a[].b", "c")},
			dir:     AtoB,
			want:    `{"x":5,"a[]":{},"c":6}`,
			applied: 2,
		},
		{
			name:    "so does a bracket path the engine does not understand",
			payload: `{"a[]":1}`,
			pairs:   []FieldPair{arrPair("a[]", "b[]")},
			dir:     AtoB,
			want:    `{"b[]":1}`,
			applied: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Translate(mustObj(t, tc.payload), tc.pairs, tc.dir, tc.opt)
			if len(res.Refused) > 0 {
				t.Fatalf("refused: %v", res.Refused)
			}
			if got, want := canon(t, res.Out), canon(t, mustObj(t, tc.want)); got != want {
				t.Errorf("out = %s, want %s", got, want)
			}
			if res.Applied != tc.applied {
				t.Errorf("applied = %d, want %d", res.Applied, tc.applied)
			}
			if len(res.Warnings) != tc.warnings || res.Warned != tc.warnings {
				t.Errorf("warnings = %v (counted %d), want %d", res.Warnings, res.Warned, tc.warnings)
			}
		})
	}
}

// Whatever the array holds, the sender's own message is what comes back
// round the loop.
func TestTranslateArraysRoundTrip(t *testing.T) {
	pairs := []FieldPair{
		arrPair("ref", "reference"),
		arrPair("lines[].sku", "items[].product_code"),
		{A: "lines[].shipped", B: "items[].shipped_epoch", Transform: arrDate},
		arrPair("lines[].price.amount", "items[].cost"),
		arrPair("order.parts[].id", "invoice.pieces[].ref"),
	}
	in := `{"ref":"r1","lines":[{"sku":"a","shipped":"2024-03-01T09:00:00Z","price":{"amount":"9.50"},"keep":1},
	  {"sku":"b","price":{"amount":"1.00"}},{}],"order":{"id":"o","parts":[{"id":"p1"},{"id":"p2"}]},"extra":[1,2]}`

	res := Translate(mustObj(t, in), pairs, AtoB, TranslateOptions{})
	if len(res.Warnings) != 0 || len(res.Refused) != 0 {
		t.Fatalf("a2b: warnings %v refused %v", res.Warnings, res.Refused)
	}
	forward := canon(t, res.Out)
	for _, leaked := range []string{`"lines"`, `"sku"`, `"shipped"`, `"parts"`} {
		if strings.Contains(forward, leaked) {
			t.Errorf("sender's name %s crossed to the other side: %s", leaked, forward)
		}
	}
	back := Translate(res.Out, pairs, BtoA, TranslateOptions{})
	if len(back.Warnings) != 0 || len(back.Refused) != 0 {
		t.Fatalf("b2a: warnings %v refused %v", back.Warnings, back.Refused)
	}
	// A container emptied by moving its last field out is left behind on
	// purpose (see delPath), and "invoice" was made only to receive the array.
	// Take that one husk away; everything else must be what the sender wrote.
	if husk, ok := back.Out["invoice"].(map[string]any); !ok || len(husk) != 0 {
		t.Errorf("the destination's container should be the only thing left behind: %v", back.Out["invoice"])
	}
	delete(back.Out, "invoice")
	want := mustObj(t, in)
	if got, w := canon(t, back.Out), canon(t, want); got != w {
		t.Errorf("round trip changed the message:\n got %s\nwant %s", got, w)
	}
}

// ---------------------------------------------------------------------------
// Refusals

func arrRows() []FieldPair {
	return []FieldPair{arrPair("ref", "reference"), arrPair("lines[].sku", "items[].code")}
}

func TestTranslateRefusesWhatItCannotTranslate(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		dir     Direction
		fields  []string
		why     string
	}{
		{"an object where an array should be", `{"ref":"r","lines":{"sku":"a"}}`, AtoB, []string{"lines"}, "must be an array or null, got object"},
		{"a string", `{"lines":"text"}`, AtoB, []string{"lines"}, "got string"},
		{"a number", `{"lines":7}`, AtoB, []string{"lines"}, "got number"},
		{"a bool", `{"lines":true}`, AtoB, []string{"lines"}, "got bool"},
		{"the other side's name on the return leg", `{"items":"x"}`, BtoA, []string{"items"}, "must be an array or null, got string"},
		{
			"every element that is not an object, by position",
			`{"lines":[{"sku":"a"},"x",null,[1],7,true,{"sku":"b"}]}`, AtoB,
			[]string{"lines[1]", "lines[2]", "lines[3]", "lines[4]", "lines[5]"}, "must be an object, got string",
		},
	}
	for _, tc := range cases {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/strict=%v", tc.name, strict), func(t *testing.T) {
				payload := mustObj(t, tc.payload)
				before := canon(t, payload)
				res := Translate(payload, arrRows(), tc.dir, TranslateOptions{Strict: strict})
				if got := arrNames(res.Refused); !reflect.DeepEqual(got, tc.fields) {
					t.Fatalf("refused %v, want %v", got, tc.fields)
				}
				if !strings.Contains(res.Refused[0].Message, tc.why) {
					t.Errorf("reason %q does not say %q", res.Refused[0].Message, tc.why)
				}
				// Nothing is half done: not the array, and not the plain row either.
				if got := canon(t, res.Out); got != before {
					t.Errorf("a refused payload was changed:\n got %s\nwant %s", got, before)
				}
				if res.Applied != 0 {
					t.Errorf("applied = %d, want 0", res.Applied)
				}
			})
		}
	}
}

func TestTranslateArrayLengthCap(t *testing.T) {
	build := func(n int) map[string]any {
		elems := make([]any, n)
		for i := range elems {
			elems[i] = map[string]any{"sku": fmt.Sprintf("s%d", i)}
		}
		return map[string]any{"lines": elems}
	}

	res := Translate(build(maxArrayLen), arrRows(), AtoB, TranslateOptions{})
	if len(res.Refused) != 0 {
		t.Fatalf("exactly %d elements must be accepted: %v", maxArrayLen, res.Refused)
	}
	if res.Applied != maxArrayLen {
		t.Errorf("applied = %d, want %d", res.Applied, maxArrayLen)
	}

	payload := build(maxArrayLen + 1)
	res = Translate(payload, arrRows(), AtoB, TranslateOptions{})
	if got := arrNames(res.Refused); !reflect.DeepEqual(got, []string{"lines"}) {
		t.Fatalf("refused %v, want [lines]", got)
	}
	if want := fmt.Sprintf("has %d elements; at most %d are accepted", maxArrayLen+1, maxArrayLen); res.Refused[0].Message != want {
		t.Errorf("reason %q, want %q", res.Refused[0].Message, want)
	}
	if _, kept := res.Out["lines"]; !kept || res.Applied != 0 {
		t.Errorf("an over-long array must be left as it came: %v applied %d", kept, res.Applied)
	}
	for _, e := range payload["lines"].([]any) {
		if _, renamed := e.(map[string]any)["code"]; renamed {
			t.Fatal("an element of a refused array was translated")
		}
	}

	// Only an array a row addresses is held to it.
	long := make([]any, 5*maxArrayLen)
	if res := Translate(map[string]any{"tags": long, "lines": []any{}}, arrRows(), AtoB, TranslateOptions{}); len(res.Refused) != 0 {
		t.Errorf("an unaddressed array of %d elements was refused: %v", len(long), res.Refused)
	}
}

func TestTranslateListsEveryRefusalAcrossArrays(t *testing.T) {
	pairs := []FieldPair{arrPair("lines[].sku", "items[].code"), arrPair("notes[].text", "remarks[].body")}
	res := Translate(mustObj(t, `{"lines":["x"],"notes":3}`), pairs, AtoB, TranslateOptions{})
	if got, want := arrNames(res.Refused), []string{"lines[0]", "notes"}; !reflect.DeepEqual(got, want) {
		t.Errorf("refused %v, want %v", got, want)
	}
}

// Two arrays of nothing but scalars: more refusals than any list keeps.
func TestTranslateBoundsTheRefusalsItKeeps(t *testing.T) {
	pairs := []FieldPair{arrPair("lines[].sku", "items[].code"), arrPair("notes[].text", "remarks[].body")}
	scalars := func() []any {
		s := make([]any, maxArrayLen)
		for i := range s {
			s[i] = float64(i)
		}
		return s
	}
	res := Translate(map[string]any{"lines": scalars(), "notes": scalars()}, pairs, AtoB, TranslateOptions{})
	if len(res.Refused) != maxNotes {
		t.Fatalf("kept %d refusals, want %d", len(res.Refused), maxNotes)
	}
	if res.Refused[0].Field != "lines[0]" || res.Refused[maxArrayLen].Field != "notes[0]" {
		t.Errorf("refusals are kept in order: %q then %q", res.Refused[0].Field, res.Refused[maxArrayLen].Field)
	}
}

func TestTranslateRefusalNamesNoValue(t *testing.T) {
	const secret = "4111111111111111"
	res := Translate(mustObj(t, `{"lines":["`+secret+`", {"sku":"x"}, "`+secret+`"]}`), arrRows(), AtoB, TranslateOptions{})
	if len(res.Refused) != 2 {
		t.Fatalf("refused %v", res.Refused)
	}
	if b := fmt.Sprint(res.Refused); strings.Contains(b, secret) {
		t.Errorf("a refusal carries a value: %s", b)
	}
}

// ---------------------------------------------------------------------------
// Strict mode and what a hostile array can make the engine keep

func TestTranslateStrictInsideArrays(t *testing.T) {
	pairs := []FieldPair{{A: "lines[].shipped", B: "items[].shipped_epoch", Transform: arrDate}}
	payload := func() map[string]any {
		return mustObj(t, `{"lines":[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"bad"},{"shipped":"2024-03-02T09:00:00Z"},{"shipped":"worse"}]}`)
	}

	res := Translate(payload(), pairs, AtoB, TranslateOptions{Strict: true})
	if want := []string{"lines[1].shipped", "lines[3].shipped"}; !reflect.DeepEqual(res.Failed, want) {
		t.Errorf("Failed = %v, want the sender's own concrete paths %v", res.Failed, want)
	}
	if res.Warned != 2 || len(res.Warnings) != 2 || !strings.HasPrefix(res.Warnings[0], "lines[1]: ") {
		t.Errorf("warnings must stay and name the element: %v (%d)", res.Warnings, res.Warned)
	}

	res = Translate(payload(), pairs, AtoB, TranslateOptions{})
	if len(res.Failed) != 0 || res.Warned != 2 {
		t.Errorf("without Strict the failures are only warnings: failed %v, warned %d", res.Failed, res.Warned)
	}

	// The good elements convert in either mode.
	if got := canon(t, res.Out); !strings.Contains(got, `"shipped_epoch":1709283600`) || !strings.Contains(got, `"shipped_epoch":1709370000`) {
		t.Errorf("convertible elements were not converted: %s", got)
	}
}

func TestTranslateBoundsTheNotesAHostileArrayCanMake(t *testing.T) {
	pairs := []FieldPair{
		{A: "lines[].d1", B: "items[].e1", Transform: arrDate},
		{A: "lines[].d2", B: "items[].e2", Transform: arrDate},
		{A: "lines[].d3", B: "items[].e3", Transform: arrDate},
	}
	elems := make([]any, maxArrayLen)
	for i := range elems {
		elems[i] = map[string]any{"d1": "bad", "d2": "bad", "d3": "bad"}
	}
	res := Translate(map[string]any{"lines": elems}, pairs, AtoB, TranslateOptions{Strict: true})

	if want := 3 * maxArrayLen; res.Warned != want {
		t.Errorf("Warned = %d, want the exact count %d", res.Warned, want)
	}
	if len(res.Warnings) != maxNotes {
		t.Errorf("kept %d warnings, want the first %d", len(res.Warnings), maxNotes)
	}
	if len(res.Failed) != maxNotes {
		t.Errorf("kept %d failed paths, want the first %d", len(res.Failed), maxNotes)
	}
	if len(res.Failed) >= 2 && (res.Failed[0] != "lines[0].d1" || res.Failed[1] != "lines[0].d2") {
		t.Errorf("the first failures are the ones kept, in order: %v", res.Failed[:2])
	}
	if res.Applied != 3*maxArrayLen {
		t.Errorf("applied = %d, want %d: the values still cross", res.Applied, 3*maxArrayLen)
	}
}

// Outside arrays no map reaches the cap, so it must never change what an
// ordinary account sees.
func TestNoteCapIsOutOfReachWithoutArrays(t *testing.T) {
	if maxNotes < 3*maxMapPairs {
		t.Fatalf("maxNotes %d would truncate the notes of an ordinary %d-row map", maxNotes, maxMapPairs)
	}
}

// ---------------------------------------------------------------------------
// Concurrency: rows are shared by every request of an account.

func TestTranslateArraysSharedRowsAreRaceFree(t *testing.T) {
	pairs := []FieldPair{
		arrPair("ref", "reference"),
		arrPair("lines[].sku", "items[].code"),
		{A: "lines[].shipped", B: "items[].shipped_epoch", Transform: arrDate},
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				ref := fmt.Sprintf("r%d-%d", g, i)
				res := Translate(map[string]any{
					"ref": ref,
					"lines": []any{
						map[string]any{"sku": ref + "/a", "shipped": "2024-03-01T09:00:00Z"},
						map[string]any{"sku": ref + "/b"},
					},
				}, pairs, AtoB, TranslateOptions{})
				items, _ := res.Out["items"].([]any)
				if res.Out["reference"] != ref || len(items) != 2 ||
					items[0].(map[string]any)["code"] != ref+"/a" || items[1].(map[string]any)["code"] != ref+"/b" {
					errs <- fmt.Sprintf("goroutine %d: wrong output %v", g, res.Out)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// ---------------------------------------------------------------------------
// Save-time rules

func arrValidate(rows ...FieldPair) ValidationErrors {
	return validateAccountDoc(&Account{ID: "arr", Map: rows})
}

func hasFieldError(ve ValidationErrors, field, contains string) bool {
	for _, fe := range ve {
		if fe.Field == field && strings.Contains(fe.Message, contains) {
			return true
		}
	}
	return false
}

func TestValidateAcceptsArrayRows(t *testing.T) {
	for name, rows := range map[string][]FieldPair{
		"one row":                {arrPair("lines[].sku", "items[].code")},
		"rows sharing an array":  {arrPair("lines[].sku", "items[].code"), arrPair("lines[].qty", "items[].n")},
		"nested paths":           {arrPair("order.lines[].tax.rate", "invoice.rows[].vat")},
		"plain and array rows":   {arrPair("ref", "reference"), arrPair("lines[].sku", "items[].code")},
		"two arrays":             {arrPair("lines[].sku", "items[].code"), arrPair("notes[].t", "remarks[].b")},
		"a date transform":       {{A: "lines[].d", B: "items[].e", Transform: arrDate}},
		"same name on both":      {arrPair("lines[].sku", "lines[].code")},
		"fields below a sibling": {arrPair("lines[].a.b", "items[].x"), arrPair("lines[].c", "items[].y")},
		"a plain name that is another side's array": {
			arrPair("lines[].sku", "items[].code"), arrPair("x", "lines"),
		},
		"swapped arrays": {arrPair("a[].x", "b[].y"), arrPair("b[].p", "a[].q")},
	} {
		if ve := arrValidate(rows...); len(ve) > 0 {
			t.Errorf("%s: %v", name, ve)
		}
	}
}

func TestValidateRefusesBadArrayRows(t *testing.T) {
	cases := []struct {
		name  string
		rows  []FieldPair
		field string
		why   string
	}{
		{"positional index", []FieldPair{arrPair("lines[0].sku", "items[].code")}, "map[0].a", "positional"},
		{"nothing inside the elements", []FieldPair{arrPair("lines[]", "items[]")}, "map[0].a", "must name a field inside"},
		{"an array inside an array", []FieldPair{arrPair("a[].b[].c", "x[].y")}, "map[0].a", "only one []"},
		{"brackets on side a only", []FieldPair{arrPair("lines[].sku", "sku")}, "map[0].b", "side a addresses array elements"},
		{"brackets on side b only", []FieldPair{arrPair("sku", "items[].code")}, "map[0].a", "side b addresses array elements"},
		{
			"one a array paired with two b arrays",
			[]FieldPair{arrPair("lines[].a", "items[].a"), arrPair("lines[].b", "rows[].b")},
			"map[1].b", `array "lines" on side a is already paired with array "items" on side b by map[0]`,
		},
		{
			"one b array paired with two a arrays",
			[]FieldPair{arrPair("lines[].a", "items[].a"), arrPair("other[].b", "items[].b")},
			"map[1].a", `array "items" on side b is already paired with array "lines" on side a by map[0]`,
		},
		{
			"the array's plain name beside its elements",
			[]FieldPair{arrPair("lines[].sku", "items[].code"), arrPair("lines", "whole")},
			"map[1].a", `addresses "lines" as an array`,
		},
		{
			"the array's plain name first",
			[]FieldPair{arrPair("lines", "whole"), arrPair("lines[].sku", "items[].code")},
			"map[1].a", `addresses "lines" as an array`,
		},
		{
			"one name as an object and as an array",
			[]FieldPair{arrPair("lines.sku", "x"), arrPair("lines[].sku", "items[].code")},
			"map[1].a", "plain field or object",
		},
		{
			"a field and its own child inside the elements",
			[]FieldPair{arrPair("lines[].a", "items[].x"), arrPair("lines[].a.b", "items[].y")},
			"map[1].a", "one path is a parent of the other",
		},
		{
			"the same field twice",
			[]FieldPair{arrPair("lines[].sku", "items[].a"), arrPair("lines[].sku", "items[].b")},
			"map[1].a", "duplicates side a field",
		},
		{
			"an array on b under an object on b",
			[]FieldPair{arrPair("x", "items.code"), arrPair("lines[].sku", "items[].code")},
			"map[1].b", "plain field or object",
		},
	}
	for _, tc := range cases {
		ve := arrValidate(tc.rows...)
		if !hasFieldError(ve, tc.field, tc.why) {
			t.Errorf("%s: want %s to say %q, got %v", tc.name, tc.field, tc.why, ve)
		}
	}
}

// A path that clashes with several rows names the lowest, every time, so the
// message an operator reads does not change from one save to the next.
func TestPathConflictNamesTheLowestRow(t *testing.T) {
	rows := []FieldPair{
		arrPair("other", "o"),
		arrPair("lines[].a", "items[].a"),
		arrPair("lines[].b", "items[].b"),
		arrPair("lines[].c", "items[].c"),
		arrPair("lines", "whole"),
	}
	for i := 0; i < 100; i++ {
		ve := arrValidate(rows...)
		if !hasFieldError(ve, "map[4].a", `conflicts with "lines[].a" on side a (map[1])`) {
			t.Fatalf("run %d: %v", i, ve)
		}
	}
}

// The existing parent/child rule reads exactly as it did.
func TestParentChildConflictMessageIsUnchanged(t *testing.T) {
	ve := arrValidate(arrPair("customer", "x"), arrPair("customer.id", "y"))
	if !hasFieldError(ve, "map[1].a", `conflicts with "customer" on side a (map[0]): one path is a parent of the other`) {
		t.Errorf("got %v", ve)
	}
}

func TestAnArrayRowWithABadPathIsReportedOnceAtThatPath(t *testing.T) {
	ve := arrValidate(arrPair("lines[0].sku", "items[].code"))
	if len(ve) != 1 || ve[0].Field != "map[0].a" {
		t.Errorf("want one error at map[0].a, got %v", ve)
	}
}
