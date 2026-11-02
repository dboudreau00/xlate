package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// A body that is itself an array: rows whose paths start with [] ("[].sku")
// address its elements, and the engine sees the array under rootKey.

// rootPayload decodes a body for the engine the way the data plane does when a
// row addresses the top-level array.
func rootPayload(t *testing.T, body string) map[string]any {
	t.Helper()
	m, err := decodeBody([]byte(body), true)
	if err != nil {
		t.Fatalf("bad fixture %q: %v", body, err)
	}
	return m
}

// rootJSON is a translation result as it would be sent, canonical enough to
// compare: encoding/json sorts map keys and keeps array order.
func rootJSON(t *testing.T, res TranslateResult) string {
	t.Helper()
	b, err := json.Marshal(bodyOf(res.Out))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func rootWant(t *testing.T, want string) string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(want))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("bad expectation %q: %v", want, err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// noEngineName fails if the engine's private name for the top-level array
// reached anything a person or a log could read.
func noEngineName(t *testing.T, what string, texts ...string) {
	t.Helper()
	for _, s := range texts {
		if strings.Contains(s, rootKey) || strings.Contains(s, "�") || strings.Contains(s, `�`) || strings.Contains(s, `\xff`) {
			t.Errorf("%s shows the engine's name for the top-level array: %q", what, s)
		}
	}
}

func TestTranslateTopLevelArrays(t *testing.T) {
	sku := arrPair("[].sku", "[].product_code")
	shipped := FieldPair{A: "[].shipped", B: "[].shipped_epoch", Transform: arrDate}
	wrapSku := arrPair("[].sku", "data[].code")

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
			payload: `[{"sku":"s1"},{"sku":"s2"},{"sku":"s3"}]`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `[{"product_code":"s1"},{"product_code":"s2"},{"product_code":"s3"}]`,
			applied: 3,
		},
		{
			name:    "the other way",
			payload: `[{"product_code":"s1"},{"product_code":"s2"}]`,
			pairs:   []FieldPair{sku},
			dir:     BtoA,
			want:    `[{"sku":"s1"},{"sku":"s2"}]`,
			applied: 2,
		},
		{
			name:    "an element's unmapped fields stay in it",
			payload: `[{"sku":"s1","note":"keep","n":7}]`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `[{"product_code":"s1","note":"keep","n":7}]`,
			applied: 1,
		},
		{
			name:    "an empty array crosses as an empty array",
			payload: `[]`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `[]`,
		},
		{
			name:    "ragged elements are translated one by one",
			payload: `[{"sku":"a","qty":1},{"qty":2},{"sku":"c"},{}]`,
			pairs:   []FieldPair{arrPair("[].sku", "[].code"), arrPair("[].qty", "[].n")},
			dir:     AtoB,
			want:    `[{"code":"a","n":1},{"n":2},{"code":"c"},{}]`,
			applied: 4,
		},
		{
			name:    "dot paths inside the elements",
			payload: `[{"tax":{"rate":"5"}},{"tax":{"rate":"7"}}]`,
			pairs:   []FieldPair{arrPair("[].tax.rate", "[].vat")},
			dir:     AtoB,
			want:    `[{"tax":{},"vat":"5"},{"tax":{},"vat":"7"}]`,
			applied: 2,
		},
		{
			name:    "a date transform runs in every element",
			payload: `[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"2024-03-02T09:00:00Z"}]`,
			pairs:   []FieldPair{shipped},
			dir:     AtoB,
			want:    `[{"shipped_epoch":1709283600},{"shipped_epoch":1709370000}]`,
			applied: 2,
		},
		{
			name:    "and un-converts on the way back",
			payload: `[{"shipped_epoch":1709283600},{"shipped_epoch":1709370000}]`,
			pairs:   []FieldPair{shipped},
			dir:     BtoA,
			want:    `[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"2024-03-02T09:00:00Z"}]`,
			applied: 2,
		},
		{
			name:    "numbers survive verbatim",
			payload: `[{"sku":9007199254740993}]`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `[{"product_code":9007199254740993}]`,
			applied: 1,
		},
		{
			name:    "drop_unmapped keeps only the mapped fields, and every element",
			payload: `[{"sku":"s1","note":"n"},{"note":"x"}]`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			opt:     TranslateOptions{DropUnmapped: true},
			want:    `[{"product_code":"s1"},{}]`,
			applied: 1,
		},
		{
			name:    "an array wraps where the other side wraps its lists",
			payload: `[{"sku":"s1"},{"sku":"s2"}]`,
			pairs:   []FieldPair{wrapSku},
			dir:     AtoB,
			want:    `{"data":[{"code":"s1"},{"code":"s2"}]}`,
			applied: 2,
		},
		{
			name:    "an object unwraps when its array is all it holds",
			payload: `{"data":[{"code":"s1"},{"code":"s2"}]}`,
			pairs:   []FieldPair{wrapSku},
			dir:     BtoA,
			want:    `[{"sku":"s1"},{"sku":"s2"}]`,
			applied: 2,
		},
		{
			name:    "an unwrapped empty array",
			payload: `{"data":[]}`,
			pairs:   []FieldPair{wrapSku},
			dir:     BtoA,
			want:    `[]`,
		},
		{
			name:    "drop_unmapped lets an object unwrap by dropping what is beside the array",
			payload: `{"data":[{"code":"s1"}],"total":3}`,
			pairs:   []FieldPair{wrapSku},
			dir:     BtoA,
			opt:     TranslateOptions{DropUnmapped: true},
			want:    `[{"sku":"s1"}]`,
			applied: 1,
		},
		{
			name:    "an object payload leaves the rows for a top-level array alone",
			payload: `{"sku":"x","note":1}`,
			pairs:   []FieldPair{sku},
			dir:     AtoB,
			want:    `{"sku":"x","note":1}`,
		},
		{
			name:    "a bare array leaves rows for named fields alone",
			payload: `[{"sku":"x"}]`,
			pairs:   []FieldPair{arrPair("lines[].sku", "items[].code"), arrPair("ref", "reference")},
			dir:     AtoB,
			want:    `[{"sku":"x"}]`,
		},
		{
			name:    "rows for objects and rows for a bare array share a map",
			payload: `[{"sku":"x"}]`,
			pairs:   []FieldPair{arrPair("ref", "reference"), arrPair("lines[].sku", "items[].code"), sku},
			dir:     AtoB,
			want:    `[{"product_code":"x"}]`,
			applied: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var payload map[string]any
			if strings.HasPrefix(tc.payload, "[") {
				payload = rootPayload(t, tc.payload)
			} else {
				payload = mustObj(t, tc.payload)
			}
			res := Translate(payload, tc.pairs, tc.dir, tc.opt)
			if len(res.Refused) > 0 {
				t.Fatalf("refused: %v", res.Refused)
			}
			if got, want := rootJSON(t, res), rootWant(t, tc.want); got != want {
				t.Errorf("out = %s, want %s", got, want)
			}
			if res.Applied != tc.applied {
				t.Errorf("applied = %d, want %d", res.Applied, tc.applied)
			}
			if len(res.Warnings) != tc.warnings {
				t.Errorf("warnings = %v, want %d", res.Warnings, tc.warnings)
			}
			noEngineName(t, "the result", rootJSON(t, res))
		})
	}
}

func TestTranslateTopLevelArrayRefusals(t *testing.T) {
	sku := arrPair("[].sku", "[].product_code")
	wrapSku := arrPair("[].sku", "data[].code")

	cases := []struct {
		name    string
		payload string
		pairs   []FieldPair
		dir     Direction
		fields  []string
		why     string
	}{
		{
			"elements that are not objects, by position", `[{"sku":"a"},"x",null,[1],7,true]`, []FieldPair{sku}, AtoB,
			[]string{"[1]", "[2]", "[3]", "[4]", "[5]"}, "must be an object, got string",
		},
		{"a list of scalars", `[1,2]`, []FieldPair{sku}, AtoB, []string{"[0]", "[1]"}, "must be an object, got number"},
		{
			"fields that would be lost beside an unwrapped array", `{"data":[{"code":"s"}],"total":3,"next":"p2"}`, []FieldPair{wrapSku}, BtoA,
			[]string{"next", "total"}, "cannot sit beside a top-level array",
		},
	}
	for _, tc := range cases {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/strict=%v", tc.name, strict), func(t *testing.T) {
				var payload map[string]any
				if strings.HasPrefix(tc.payload, "[") {
					payload = rootPayload(t, tc.payload)
				} else {
					payload = mustObj(t, tc.payload)
				}
				res := Translate(payload, tc.pairs, tc.dir, TranslateOptions{Strict: strict})
				if got := arrNames(res.Refused); !reflect.DeepEqual(got, tc.fields) {
					t.Fatalf("refused %v, want %v", got, tc.fields)
				}
				if !strings.Contains(res.Refused[0].Message, tc.why) {
					t.Errorf("reason %q does not say %q", res.Refused[0].Message, tc.why)
				}
				var texts []string
				for _, fe := range res.Refused {
					texts = append(texts, fe.Field, fe.Message)
				}
				noEngineName(t, "a refusal", texts...)
				noEngineName(t, "the preview", rootJSON(t, res))
			})
		}
	}

	t.Run("the array too long is named []", func(t *testing.T) {
		elems := make([]any, maxArrayLen+1)
		for i := range elems {
			elems[i] = map[string]any{"sku": "s"}
		}
		res := Translate(map[string]any{rootKey: elems}, []FieldPair{sku}, AtoB, TranslateOptions{})
		if got := arrNames(res.Refused); !reflect.DeepEqual(got, []string{"[]"}) {
			t.Fatalf("refused %v, want []", got)
		}
		if want := fmt.Sprintf("has %d elements; at most %d are accepted", maxArrayLen+1, maxArrayLen); res.Refused[0].Message != want {
			t.Errorf("reason %q, want %q", res.Refused[0].Message, want)
		}
		if _, kept := res.Out[rootKey]; !kept || res.Applied != 0 {
			t.Errorf("an over-long array must be left as it came")
		}
		elems = elems[:maxArrayLen]
		if res := Translate(map[string]any{rootKey: elems}, []FieldPair{sku}, AtoB, TranslateOptions{}); len(res.Refused) != 0 {
			t.Errorf("exactly %d elements must be accepted: %v", maxArrayLen, res.Refused)
		}
	})

	t.Run("a refused array is left as the sender wrote it", func(t *testing.T) {
		payload := rootPayload(t, `[{"sku":"a"},"x"]`)
		res := Translate(payload, []FieldPair{sku}, AtoB, TranslateOptions{})
		if got, want := rootJSON(t, res), `[{"sku":"a"},"x"]`; got != want {
			t.Errorf("a refused body was changed: %s", got)
		}
	})

	t.Run("a preview of an object that cannot unwrap shows the array under []", func(t *testing.T) {
		res := Translate(mustObj(t, `{"data":[{"code":"s"}],"total":3}`), []FieldPair{wrapSku}, BtoA, TranslateOptions{})
		got := rootJSON(t, res)
		if got != `{"[]":[{"sku":"s"}],"total":3}` {
			t.Errorf("preview %s", got)
		}
	})
}

// The fields refused beside an unwrapped array are listed in one order, however
// the map happened to iterate, so an answer does not change from run to run.
func TestStrayFieldsAreNamedInOrder(t *testing.T) {
	pairs := []FieldPair{arrPair("[].sku", "data[].code")}
	for i := 0; i < 60; i++ {
		res := Translate(mustObj(t, `{"data":[{"code":"s"}],"d":1,"b":2,"c":3,"a":4}`), pairs, BtoA, TranslateOptions{})
		if got := arrNames(res.Refused); !reflect.DeepEqual(got, []string{"a", "b", "c", "d"}) {
			t.Fatalf("run %d: refused %v", i, got)
		}
	}
	// One stray is enough to refuse: a bare array has room for nothing beside it.
	res := Translate(mustObj(t, `{"data":[{"code":"s"}],"only":1}`), pairs, BtoA, TranslateOptions{})
	if got := arrNames(res.Refused); !reflect.DeepEqual(got, []string{"only"}) {
		t.Errorf("refused %v", got)
	}
}

func TestTranslateStrictInsideATopLevelArray(t *testing.T) {
	pairs := []FieldPair{{A: "[].shipped", B: "[].shipped_epoch", Transform: arrDate}}
	payload := func() map[string]any {
		return rootPayload(t, `[{"shipped":"2024-03-01T09:00:00Z"},{"shipped":"bad"},{"shipped":"worse"}]`)
	}
	res := Translate(payload(), pairs, AtoB, TranslateOptions{Strict: true})
	if want := []string{"[1].shipped", "[2].shipped"}; !reflect.DeepEqual(res.Failed, want) {
		t.Errorf("Failed = %v, want %v", res.Failed, want)
	}
	if len(res.Warnings) != 2 || !strings.HasPrefix(res.Warnings[0], "[1]: ") {
		t.Errorf("warnings must name the element: %v", res.Warnings)
	}
	noEngineName(t, "a warning", res.Warnings...)
	noEngineName(t, "a failed path", res.Failed...)
	if res := Translate(payload(), pairs, AtoB, TranslateOptions{}); len(res.Failed) != 0 || res.Warned != 2 {
		t.Errorf("without Strict the failures are only warnings: %v %d", res.Failed, res.Warned)
	}
}

func TestAddressesRoot(t *testing.T) {
	rows := []FieldPair{arrPair("ref", "reference"), arrPair("[].sku", "data[].code")}
	for _, tc := range []struct {
		name  string
		pairs []FieldPair
		dir   Direction
		want  bool
	}{
		{"the side with the top-level array sends it", rows, AtoB, true},
		{"the other side wraps its list", rows, BtoA, false},
		{"both sides", []FieldPair{arrPair("[].a", "[].b")}, BtoA, true},
		{"named arrays are not the top level", []FieldPair{arrPair("lines[].a", "items[].b")}, AtoB, false},
		{"no rows", nil, AtoB, false},
		{"a path that is not an array row on both sides", []FieldPair{arrPair("[].a", "b")}, AtoB, false},
		{"a malformed path", []FieldPair{arrPair("[]a", "[]b")}, AtoB, false},
	} {
		if got := addressesRoot(tc.pairs, tc.dir); got != tc.want {
			t.Errorf("%s: addressesRoot = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDecodeBody(t *testing.T) {
	t.Run("a bare array, only where a row addresses one", func(t *testing.T) {
		m, err := decodeBody([]byte(" \n\t[ {\"a\":1} ,{\"a\":2}] \n"), true)
		if err != nil || len(m) != 1 {
			t.Fatalf("%v %v", m, err)
		}
		if arr, ok := m[rootKey].([]any); !ok || len(arr) != 2 {
			t.Errorf("not wrapped under rootKey: %v", m)
		}
		if _, err := decodeBody([]byte(`[{"a":1}]`), false); err == nil {
			t.Error("a bare array must still be refused where no row addresses one")
		}
	})
	t.Run("the empty array is an empty array", func(t *testing.T) {
		m, err := decodeBody([]byte(`[]`), true)
		arr, ok := m[rootKey].([]any)
		if err != nil || !ok || arr == nil || len(arr) != 0 {
			t.Errorf("%v %v", m, err)
		}
	})
	t.Run("numbers survive verbatim", func(t *testing.T) {
		m, _ := decodeBody([]byte(`[{"id":9007199254740993}]`), true)
		if n := m[rootKey].([]any)[0].(map[string]any)["id"]; n != json.Number("9007199254740993") {
			t.Errorf("got %v (%T)", n, n)
		}
	})
	t.Run("an object is still an object", func(t *testing.T) {
		m, err := decodeBody([]byte(`{"a":1}`), true)
		if err != nil || len(m) != 1 || m["a"] == nil {
			t.Errorf("%v %v", m, err)
		}
	})
	t.Run("what is neither is refused as before", func(t *testing.T) {
		for _, body := range []string{``, `null`, `"s"`, `1`, `[1] x`, `[1][2]`, `[`, `[1,`, `{"a":1} x`} {
			for _, rooted := range []bool{true, false} {
				if _, err := decodeBody([]byte(body), rooted); err == nil {
					t.Errorf("rooted=%v body %q should be refused", rooted, body)
				}
			}
		}
	})
	t.Run("depth is bounded by the decoder as for objects", func(t *testing.T) {
		deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
		if _, err := decodeBody([]byte(deep), true); err == nil {
			t.Error("a 20000-deep array must be refused")
		}
	})
}

// The engine's name for the top-level array must be impossible to produce from
// either side: from a message, or from a saved path.
func TestRootKeyCannotBeForged(t *testing.T) {
	for _, body := range []string{"{\"\xff\":[{\"sku\":\"x\"}]}", `{"\ud800":[{"sku":"x"}]}`, "{\"\xc3\":[1]}"} {
		m, err := decodeObjectStrict([]byte(body))
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if _, forged := m[rootKey]; forged {
			t.Errorf("%q decoded to the engine's name for the top-level array", body)
		}
	}
	// NUL is the name that would have been forgeable: JSON can say it.
	if m, _ := decodeObjectStrict([]byte(`{"\u0000":1}`)); m["\x00"] == nil {
		t.Fatal("the premise changed: a NUL key no longer decodes")
	}

	for _, p := range []string{rootKey, rootKey + "[].x", "a." + rootKey, "[]." + rootKey} {
		if err := validateDotPath(p); err == nil {
			t.Errorf("path %q must not be saveable", p)
		}
	}
	if ve := arrValidate(arrPair(rootKey+"[].x", "[].y")); len(ve) == 0 {
		t.Error("a row naming the engine's array must be refused when saved")
	}

	// A message that carries a NUL key is just an object.
	res := Translate(mustObj(t, `{"\u0000":[{"sku":"x"}]}`), []FieldPair{arrPair("[].sku", "[].code")}, AtoB, TranslateOptions{})
	if got, want := rootJSON(t, res), `{"\u0000":[{"sku":"x"}]}`; got != want {
		t.Errorf("an object with a NUL key was treated as a bare array: %s", got)
	}
}

// ---------------------------------------------------------------------------
// Save-time rules

func TestValidateAcceptsTopLevelArrayRows(t *testing.T) {
	for name, rows := range map[string][]FieldPair{
		"one row":                   {arrPair("[].sku", "[].code")},
		"rows sharing the array":    {arrPair("[].sku", "[].code"), arrPair("[].qty", "[].n")},
		"nested paths":              {arrPair("[].tax.rate", "[].vat")},
		"a date transform":          {{A: "[].d", B: "[].e", Transform: arrDate}},
		"wrapped on side b":         {arrPair("[].sku", "data[].code"), arrPair("[].qty", "data[].n")},
		"wrapped on side a":         {arrPair("data[].sku", "[].code")},
		"beside rows for objects":   {arrPair("ref", "reference"), arrPair("[].sku", "[].code")},
		"beside named arrays":       {arrPair("lines[].sku", "items[].code"), arrPair("[].sku", "[].code")},
		"beside a whole-array row":  {arrPair("lines", "items"), arrPair("[].sku", "[].code")},
		"a plain field named like":  {arrPair("sku", "code"), arrPair("[].sku", "[].code")},
		"root paired with a name":   {arrPair("[].a", "data[].a"), arrPair("lines[].b", "items[].b")},
		"two roots do not collide":  {arrPair("[].a", "x[].a"), arrPair("y[].b", "[].b")},
		"siblings inside elements":  {arrPair("[].a", "[].x"), arrPair("[].b", "[].y")},
		"fields below a sibling":    {arrPair("[].a.b", "[].x"), arrPair("[].c", "[].y")},
		"swapped inside the array":  {arrPair("[].x", "[].y"), arrPair("[].y", "[].x")},
		"a name that contains dots": {arrPair("a.b.c", "d.e.f"), arrPair("[].k", "[].l")},
	} {
		if ve := arrValidate(rows...); len(ve) > 0 {
			t.Errorf("%s: %v", name, ve)
		}
	}
}

func TestValidateRefusesBadTopLevelArrayRows(t *testing.T) {
	cases := []struct {
		name  string
		rows  []FieldPair
		field string
		why   string
	}{
		{"nothing inside", []FieldPair{arrPair("[]", "[]")}, "map[0].a", "elements of the top-level array"},
		{"an array inside the top-level array", []FieldPair{arrPair("[].lines[].sku", "[].x")}, "map[0].a", "only one []"},
		{"brackets on side a only", []FieldPair{arrPair("[].sku", "sku")}, "map[0].b", "side a addresses array elements"},
		{"brackets on side b only", []FieldPair{arrPair("sku", "[].code")}, "map[0].a", "side b addresses array elements"},
		{
			"the top-level array paired with two arrays",
			[]FieldPair{arrPair("[].a", "items[].a"), arrPair("[].b", "rows[].b")},
			"map[1].b", `array "[]" on side a is already paired with array "items" on side b by map[0]`,
		},
		{
			"two arrays paired with the top-level array",
			[]FieldPair{arrPair("lines[].a", "[].a"), arrPair("other[].b", "[].b")},
			"map[1].a", `array "[]" on side b is already paired with array "lines" on side a by map[0]`,
		},
		{
			"a named array paired with the top-level array after a named one",
			[]FieldPair{arrPair("[].a", "[].a"), arrPair("[].b", "rows[].b")},
			"map[1].b", `array "[]" on side a is already paired with array "[]" on side b by map[0]`,
		},
		{"a field and its own child inside the elements", []FieldPair{arrPair("[].a", "[].x"), arrPair("[].a.b", "[].y")}, "map[1].a", "one path is a parent of the other"},
		{"the same field twice", []FieldPair{arrPair("[].sku", "[].a"), arrPair("[].sku", "[].b")}, "map[1].a", "duplicates side a field"},
		{"a bad path is reported at its row", []FieldPair{arrPair("a.[].b", "[].x")}, "map[0].a", "directly follow a field name"},
	}
	for _, tc := range cases {
		ve := arrValidate(tc.rows...)
		if !hasFieldError(ve, tc.field, tc.why) {
			t.Errorf("%s: want %s to say %q, got %v", tc.name, tc.field, tc.why, ve)
		}
		for _, fe := range ve {
			noEngineName(t, "an error", fe.Field, fe.Message)
		}
	}
}

// Both orientations of the same mistake read the same.
func TestTopLevelArrayPairingErrorsNameTheArraysByWhatWasWritten(t *testing.T) {
	ve := arrValidate(arrPair("[].a", "data[].a"), arrPair("[].b", "other[].b"))
	var buf bytes.Buffer
	for _, fe := range ve {
		buf.WriteString(fe.Field + ": " + fe.Message + "\n")
	}
	if !strings.Contains(buf.String(), `array "[]" on side a is already paired with array "data" on side b`) {
		t.Errorf("got %s", buf.String())
	}
}
