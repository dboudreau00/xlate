package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func mustObj(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("bad fixture %q: %v", s, err)
	}
	return m
}

func canon(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m) // map keys marshal sorted; canonical enough
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestTranslate(t *testing.T) {
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
			name:    "simple a2b rename",
			payload: `{"payment_id":"p_123","amount":42}`,
			pairs:   []FieldPair{{A: "payment_id", B: "payment_proof"}},
			dir:     AtoB,
			want:    `{"payment_proof":"p_123","amount":42}`,
			applied: 1,
		},
		{
			name:    "return path b2a",
			payload: `{"payment_proof":"p_123"}`,
			pairs:   []FieldPair{{A: "payment_id", B: "payment_proof"}},
			dir:     BtoA,
			want:    `{"payment_id":"p_123"}`,
			applied: 1,
		},
		{
			name:    "swapped pair in one payload does not clobber",
			payload: `{"x":1,"y":2}`,
			pairs:   []FieldPair{{A: "x", B: "y"}, {A: "y", B: "x"}},
			dir:     AtoB,
			want:    `{"y":1,"x":2}`,
			applied: 2,
		},
		{
			name:    "nested dot-path source",
			payload: `{"customer":{"id":"c9","tier":"gold"}}`,
			pairs:   []FieldPair{{A: "customer.id", B: "buyer_ref"}},
			dir:     AtoB,
			want:    `{"customer":{"tier":"gold"},"buyer_ref":"c9"}`,
			applied: 1,
		},
		{
			name:    "nested destination is created",
			payload: `{"ref":"r1"}`,
			pairs:   []FieldPair{{A: "ref", B: "meta.trace.id"}},
			dir:     AtoB,
			want:    `{"meta":{"trace":{"id":"r1"}}}`,
			applied: 1,
		},
		{
			name:    "missing source is a no-op",
			payload: `{"other":true}`,
			pairs:   []FieldPair{{A: "payment_id", B: "payment_proof"}},
			dir:     AtoB,
			want:    `{"other":true}`,
			applied: 0,
		},
		{
			name:    "drop_unmapped keeps only mapped fields",
			payload: `{"payment_id":"p1","internal_debug":"x"}`,
			pairs:   []FieldPair{{A: "payment_id", B: "payment_proof"}},
			dir:     AtoB,
			opt:     TranslateOptions{DropUnmapped: true},
			want:    `{"payment_proof":"p1"}`,
			applied: 1,
		},
		{
			name:     "destination collision overwrites with warning",
			payload:  `{"a":1,"b":9}`,
			pairs:    []FieldPair{{A: "a", B: "b"}},
			dir:      AtoB,
			want:     `{"b":1}`,
			applied:  1,
			warnings: 1,
		},
		{
			// The rename cannot land (b is a scalar, so b.c is
			// unreachable) but the value must never vanish from the
			// forwarded body — it stays at its source path untranslated.
			name:     "non-object intermediate on destination falls back to pass-through",
			payload:  `{"a":1,"b":"scalar"}`,
			pairs:    []FieldPair{{A: "a", B: "b.c"}},
			dir:      AtoB,
			want:     `{"a":1,"b":"scalar"}`,
			applied:  0,
			warnings: 2,
		},
		{
			name:    "identity mapping survives two-phase",
			payload: `{"v":3}`,
			pairs:   []FieldPair{{A: "v", B: "v"}},
			dir:     AtoB,
			want:    `{"v":3}`,
			applied: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Translate(mustObj(t, tc.payload), tc.pairs, tc.dir, tc.opt)
			if got, want := canon(t, res.Out), canon(t, mustObj(t, tc.want)); got != want {
				t.Errorf("out = %s, want %s", got, want)
			}
			if res.Applied != tc.applied {
				t.Errorf("applied = %d, want %d", res.Applied, tc.applied)
			}
			if len(res.Warnings) != tc.warnings {
				t.Errorf("warnings = %v, want %d", res.Warnings, tc.warnings)
			}
		})
	}
}

func TestNumericFidelity(t *testing.T) {
	in := mustObj(t, `{"payment_id":9007199254740993}`) // > 2^53
	res := Translate(in, []FieldPair{{A: "payment_id", B: "payment_proof"}}, AtoB, TranslateOptions{})
	b, _ := json.Marshal(res.Out)
	if want := `{"payment_proof":9007199254740993}`; string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
}

func TestTokenEqual(t *testing.T) {
	if !tokenEqual("abc", "abc") {
		t.Error("equal tokens rejected")
	}
	if tokenEqual("abc", "abd") || tokenEqual("", "abc") || tokenEqual("abc", "") {
		t.Error("unequal tokens accepted")
	}
}

// asInput wraps a stored document as create/update input, mirroring what
// a client that sent every field explicitly would produce.
func asInput(a Account) *accountInput {
	enabled := a.Enabled
	return &accountInput{Account: a, Enabled: &enabled}
}

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.Create(asInput(Account{
		ID:      "acme",
		Name:    "Acme <-> PSP",
		Enabled: true,
		A:       Endpoint{Label: "Acme", TargetURL: "https://a.example/hook"},
		B:       Endpoint{Label: "PSP", TargetURL: "https://b.example/hook"},
		Map:     []FieldPair{{A: "payment_id", B: "payment_proof"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if created.A.InboundToken == "" || created.B.InboundToken == "" {
		t.Error("inbound tokens were not generated")
	}
	if _, err := s.Create(asInput(Account{ID: "acme"})); err == nil {
		t.Error("duplicate id accepted")
	}
	if _, err := s.Create(asInput(Account{ID: "Bad ID!"})); err == nil {
		t.Error("invalid id accepted")
	}
	if _, err := s.Create(asInput(Account{ID: "dup", Map: []FieldPair{{A: "x", B: "y"}, {A: "x", B: "z"}}})); err == nil {
		t.Error("duplicate side-A field accepted")
	}

	// Blank tokens on update must retain stored values.
	upd := created.clone()
	upd.A.InboundToken = ""
	upd.Name = "renamed"
	after, err := s.Update(asInput(*upd))
	if err != nil {
		t.Fatal(err)
	}
	if after.A.InboundToken != created.A.InboundToken {
		t.Error("blank token on update wiped stored credential")
	}

	// Reload from disk.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get("acme")
	if !ok {
		t.Fatal("account lost across reload")
	}
	if got.Name != "renamed" || len(got.Map) != 1 {
		t.Errorf("reloaded account mismatch: %+v", got)
	}

	tok, err := s2.Rotate("acme", "b", "outbound")
	if err != nil {
		t.Fatal(err)
	}
	got2, _ := s2.Get("acme")
	if got2.B.OutboundToken != tok {
		t.Error("rotate did not persist")
	}
}
