package main

import (
	"strings"
	"testing"
	"time"
)

func TestValidateDateFormatAcceptsDocumentedFormats(t *testing.T) {
	for _, f := range documentedFormats() {
		if err := validateDateFormat(f); err != nil {
			t.Errorf("documented format %q rejected: %v", f, err)
		}
	}
}

func TestValidateDateFormatAcceptsRawGoLayouts(t *testing.T) {
	// Including the layout the README uses as its example.
	for _, f := range []string{
		"02/01/2006 15:04",
		"2006-01-02",
		"2006-01-02T15:04:05Z07:00",
		"Mon Jan _2 15:04:05 2006",
		"January 2, 2006",
	} {
		if err := validateDateFormat(f); err != nil {
			t.Errorf("valid Go layout %q rejected: %v", f, err)
		}
	}
}

func TestValidateDateFormatRejectsNonLayouts(t *testing.T) {
	// These are the shapes people actually type: strptime and the
	// moment.js/ISO conventions. Each would be accepted as a literal by
	// time.Format and then fail open on every single request.
	for _, f := range []string{
		"YYYY-MM-DD",
		"DD/MM/YYYY",
		"yyyy-mm-dd hh:mm:ss",
		"%Y-%m-%d",
		"epoch",
		"",
		strings.Repeat("x", maxFormatLen+1),
		"bad\nlayout",
	} {
		if err := validateDateFormat(f); err == nil {
			t.Errorf("format %q should have been rejected", f)
		}
	}
}

// Layouts that Go will happily format and parse but that do not encode a
// whole date. "iso8601" is the trap: Go reads its "1" as a month, so a
// substitution-only check accepts it while it encodes nothing.
func TestValidateDateFormatRejectsPartialDates(t *testing.T) {
	for _, f := range []string{
		"iso8601",
		"2006",         // year only
		"01-02",        // no year
		"15:04:05.000", // time only
		"Monday",       // weekday only
	} {
		if err := validateDateFormat(f); err == nil {
			t.Errorf("partial-date layout %q should have been rejected", f)
		}
	}
}

// A layout must survive a format/parse round trip, or the reverse leg
// silently fails open for every response.
func TestValidateDateFormatRequiresRoundTrip(t *testing.T) {
	for _, f := range documentedFormats() {
		if f == epochSec || f == epochMS {
			continue
		}
		layout := f
		if l, named := namedLayouts[f]; named {
			layout = l
		}
		rendered := probeMoment.Format(layout)
		if _, err := time.Parse(layout, rendered); err != nil {
			t.Errorf("format %q does not round trip: %v", f, err)
		}
	}
}

func TestHeaderSafeRejectsInjection(t *testing.T) {
	for _, s := range []string{"a\r\nX-Evil: 1", "a\nb", "a\tb", "a b", "a\x00b", "café"} {
		if headerSafe(s) {
			t.Errorf("%q should not be considered header-safe", s)
		}
	}
	for _, s := range []string{"xk_deadbeef", "Bearer-ish_token.1", "~!@#$%^&*()"} {
		if !headerSafe(s) {
			t.Errorf("%q should be header-safe", s)
		}
	}
}

func TestValidateDotPath(t *testing.T) {
	for _, p := range []string{"x", "customer.id", "a.b.c.d", "with_underscore", "dash-ok"} {
		if err := validateDotPath(p); err != nil {
			t.Errorf("path %q rejected: %v", p, err)
		}
	}
	for _, p := range []string{
		"", ".x", "x.", "x..y", "items[0]", " padded",
		strings.Repeat("x", maxPathLen+1),
		strings.Repeat("a.", maxPathDepth) + "a",
		"bad\npath",
	} {
		if err := validateDotPath(p); err == nil {
			t.Errorf("path %q should have been rejected", p)
		}
	}
}

func TestPrefixConflictIsSymmetric(t *testing.T) {
	set := map[string]int{"customer": 0}
	if _, _, clash := prefixConflict(set, "customer.id"); !clash {
		t.Error("child added after parent should conflict")
	}
	set = map[string]int{"customer.id": 0}
	if _, _, clash := prefixConflict(set, "customer"); !clash {
		t.Error("parent added after child should conflict")
	}
	// Shared prefix that is not a path boundary is fine.
	set = map[string]int{"customer_id": 0}
	if _, _, clash := prefixConflict(set, "customer_identifier"); clash {
		t.Error("string prefix that is not a path parent must not conflict")
	}
	set = map[string]int{"a.b": 0}
	if _, _, clash := prefixConflict(set, "a.c"); clash {
		t.Error("siblings must not conflict")
	}
}

// Validation must run over the normalised document, so trimming and
// defaulting cannot smuggle a value past a rule.
func TestValidateAccountDocRunsAfterDefaults(t *testing.T) {
	a := &Account{ID: "  spaced  ", Map: []FieldPair{{A: " x ", B: " y "}}}
	applyDefaults(a)
	if ve := validateAccountDoc(a); len(ve) > 0 {
		t.Fatalf("normalised document should validate, got %v", ve)
	}
	if a.ID != "spaced" {
		t.Errorf("id not trimmed: %q", a.ID)
	}
	if a.Map[0].A != "x" || a.Map[0].B != "y" {
		t.Errorf("map fields not trimmed: %+v", a.Map[0])
	}
}

func TestValidateAccountDocReportsDeterministically(t *testing.T) {
	// Both sides invalid: the reported order must not depend on map
	// iteration order.
	var first string
	for i := 0; i < 200; i++ {
		a := &Account{ID: "x",
			A: Endpoint{TargetURL: "ftp://a.invalid"},
			B: Endpoint{TargetURL: "ftp://b.invalid"},
		}
		ve := validateAccountDoc(a)
		if len(ve) != 2 {
			t.Fatalf("want 2 errors, got %v", ve)
		}
		got := ve[0].Field + "," + ve[1].Field
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("field order varies between runs: %q then %q", first, got)
		}
	}
	if first != "a.target_url,b.target_url" {
		t.Errorf("want side a reported first, got %q", first)
	}
}

func TestValidateMapSizeCap(t *testing.T) {
	a := &Account{ID: "big"}
	for i := 0; i <= maxMapPairs; i++ {
		a.Map = append(a.Map, FieldPair{A: "a" + itoa(i), B: "b" + itoa(i)})
	}
	ve := validateAccountDoc(a)
	if len(ve) == 0 {
		t.Fatal("oversized map accepted")
	}
	if ve[0].Field != "map" {
		t.Errorf("want a map-level error, got %v", ve)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestDecodeObjectStrictRejectsTrailingData(t *testing.T) {
	if _, err := decodeObjectStrict([]byte(`{"a":1}`)); err != nil {
		t.Fatalf("valid object rejected: %v", err)
	}
	for _, body := range []string{
		`{"a":1} trailing`,
		`{"a":1}{"b":2}`,
		`{"a":1}]`,
		`null`,
		`[1]`,
		`"str"`,
	} {
		if _, err := decodeObjectStrict([]byte(body)); err == nil {
			t.Errorf("body %q should have been rejected", body)
		}
	}
}

// Numeric fidelity must survive the strict decoder too.
func TestDecodeObjectStrictKeepsBigIntegers(t *testing.T) {
	m, err := decodeObjectStrict([]byte(`{"id":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := m["id"]; got == nil || got.(interface{ String() string }).String() != "9007199254740993" {
		t.Errorf("64-bit id lost precision: %v", got)
	}
}
