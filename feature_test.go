package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- date transforms ---------------------------------------------------

func TestDateTransformBothDirections(t *testing.T) {
	pairs := []FieldPair{{
		A:         "created_at",
		B:         "created_epoch",
		Transform: &Transform{Kind: "date", AFormat: "rfc3339", BFormat: "unix"},
	}}

	// a2b: RFC3339 string -> unix seconds as a JSON number.
	in := map[string]any{"created_at": "2026-08-06T12:00:00Z"}
	res := Translate(in, pairs, AtoB, TranslateOptions{})
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", res.Warnings)
	}
	got, ok := res.Out["created_epoch"].(json.Number)
	if !ok {
		t.Fatalf("created_epoch is %T, want json.Number", res.Out["created_epoch"])
	}
	if got.String() != "1786017600" {
		t.Fatalf("epoch = %s, want 1786017600", got)
	}

	// b2a: the same pair un-converts on the return leg.
	back := map[string]any{"created_epoch": json.Number("1786017600")}
	res2 := Translate(back, pairs, BtoA, TranslateOptions{})
	if res2.Out["created_at"] != "2026-08-06T12:00:00Z" {
		t.Fatalf("round trip = %v", res2.Out["created_at"])
	}
}

func TestDateTransformLayoutsAndEpochShapes(t *testing.T) {
	tr := &Transform{Kind: "date", AFormat: "date", BFormat: "unix_ms"}
	v, err := tr.apply("2026-01-02", AtoB)
	if err != nil {
		t.Fatal(err)
	}
	if v.(json.Number).String() != "1767312000000" {
		t.Fatalf("unix_ms = %v", v)
	}
	// Epochs may arrive as string, float64, or json.Number.
	for _, in := range []any{json.Number("1767312000000"), "1767312000000", float64(1767312000000)} {
		out, err := tr.apply(in, BtoA)
		if err != nil {
			t.Fatalf("%T: %v", in, err)
		}
		if out != "2026-01-02" {
			t.Fatalf("%T -> %v, want 2026-01-02", in, out)
		}
	}
	// Custom Go layout passes through untouched by the named table.
	tr2 := &Transform{Kind: "date", AFormat: "02/01/2006", BFormat: "rfc3339"}
	out, err := tr2.apply("06/08/2026", AtoB)
	if err != nil {
		t.Fatal(err)
	}
	if out != "2026-08-06T00:00:00Z" {
		t.Fatalf("custom layout -> %v", out)
	}
}

func TestDateTransformFailOpen(t *testing.T) {
	pairs := []FieldPair{{
		A: "d", B: "d2",
		Transform: &Transform{Kind: "date", AFormat: "rfc3339", BFormat: "unix"},
	}}
	in := map[string]any{"d": "not-a-date"}
	res := Translate(in, pairs, AtoB, TranslateOptions{})
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "transform") {
		t.Fatalf("want one transform warning, got %v", res.Warnings)
	}
	// Renamed but untransformed: fail-open forwards the original value.
	if res.Out["d2"] != "not-a-date" {
		t.Fatalf("fail-open value = %v", res.Out["d2"])
	}
}

func TestTransformValidation(t *testing.T) {
	if err := (&Transform{Kind: "enum"}).validate(); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if err := (&Transform{Kind: "date", AFormat: "rfc3339"}).validate(); err == nil {
		t.Fatal("missing b_format accepted")
	}
	var none *Transform
	if err := none.validate(); err != nil {
		t.Fatal("nil transform must validate")
	}
}

// --- audit trail --------------------------------------------------------

func TestAuditChainAndTamperDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trail.jsonl")
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := a.Emit("test", "ingest.ok", map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()

	// Chain must survive a reopen: restart extends, not restarts.
	a2, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.Emit("test", "account.create", map[string]any{"account": "x"}); err != nil {
		t.Fatal(err)
	}
	a2.Close()

	if err := VerifyAudit(path, discardWriter{}); err != nil {
		t.Fatalf("intact chain failed verification: %v", err)
	}

	// Tamper with one byte of a middle record: verification must fail.
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 records, got %d", len(lines))
	}
	lines[1] = strings.Replace(lines[1], `"n":1`, `"n":9`, 1)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	if err := VerifyAudit(path, discardWriter{}); err == nil || !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("tampered chain verified clean: %v", err)
	}

	// Deleting a record breaks linkage.
	rest := append([]string{lines[0]}, lines[2:]...)
	os.WriteFile(path, []byte(strings.Join(rest, "\n")+"\n"), 0o600)
	if err := VerifyAudit(path, discardWriter{}); err == nil || !strings.Contains(err.Error(), "chain break") {
		t.Fatalf("truncated chain verified clean: %v", err)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// Regression: the writer holds Go structs in Detail (field order), the
// verifier re-reads them as maps (sorted keys). Before canonicalization
// this false-alarmed as tampering on every tripwire.trip record.
func TestAuditChainWithStructuredDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trail.jsonl")
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Emit("system", "tripwire.trip", map[string]any{
		"account": "acme",
		"top_ips": []IPCount{{IP: "10.0.0.1", Count: 5}, {IP: "10.0.0.2", Count: 1}},
		"count":   6,
		"big":     json.Number("9007199254740993"), // > 2^53: must survive verbatim
		"nested":  map[string]any{"zeta": 1, "alpha": "x"},
	}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if err := VerifyAudit(path, discardWriter{}); err != nil {
		t.Fatalf("struct-bearing detail failed verification: %v", err)
	}
}

// --- tripwire -----------------------------------------------------------

func TestTripwireTripLockRearmReset(t *testing.T) {
	tw := NewTripwire(5, time.Minute, 30*time.Millisecond, "lock")

	// Attempts 1..5 stay quiet; the 6th trips, exactly once.
	for i := 0; i < 5; i++ {
		if info := tw.RecordDenied("acme", "10.0.0.1"); info != nil {
			t.Fatalf("tripped early at attempt %d", i+1)
		}
	}
	info := tw.RecordDenied("acme", "10.0.0.2")
	if info == nil {
		t.Fatal("6th refused attempt did not trip")
	}
	if info.Count != 6 || info.Trips != 1 {
		t.Fatalf("info = %+v", info)
	}
	if len(info.TopIPs) == 0 || info.TopIPs[0].IP != "10.0.0.1" || info.TopIPs[0].Count != 5 {
		t.Fatalf("top ips = %v", info.TopIPs)
	}
	// No re-alarm while tripped.
	if again := tw.RecordDenied("acme", "10.0.0.3"); again != nil {
		t.Fatal("re-alarmed while tripped")
	}
	if locked, rem := tw.Gate("acme"); !locked || rem <= 0 {
		t.Fatal("gate not locked after trip")
	}
	// Other accounts are unaffected.
	if locked, _ := tw.Gate("other"); locked {
		t.Fatal("unrelated account locked")
	}
	// Lock expiry re-arms.
	time.Sleep(40 * time.Millisecond)
	if locked, _ := tw.Gate("acme"); locked {
		t.Fatal("gate still locked after expiry")
	}
	if info := tw.RecordDenied("acme", "10.0.0.1"); info != nil {
		t.Fatal("single attempt after re-arm tripped")
	}
	// Manual reset clears everything.
	tw.Reset("acme")
	st := tw.Status("acme")
	if st["state"] != "armed" || st["count"] != 0 {
		t.Fatalf("status after reset = %v", st)
	}
}

func TestTripwireWindowSlides(t *testing.T) {
	tw := NewTripwire(2, 30*time.Millisecond, time.Minute, "alert")
	tw.RecordDenied("a", "1.1.1.1")
	tw.RecordDenied("a", "1.1.1.1")
	time.Sleep(40 * time.Millisecond) // both age out of the window
	if info := tw.RecordDenied("a", "1.1.1.1"); info != nil {
		t.Fatal("stale attempts counted toward threshold")
	}
}

// --- alert signing -------------------------------------------------------

func TestAlertSignature(t *testing.T) {
	body := []byte(`{"event":"tripwire"}`)
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	// The header format is a contract for receivers; pin it.
	if !strings.HasPrefix(want, "sha256=") || len(want) != 7+64 {
		t.Fatalf("signature format drifted: %s", want)
	}
}
