package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Each test here pins a defect that was found by review and fixed. They
// are cheap; they exist so the behaviour cannot quietly regress.

// The tripwire kept one timestamp per refused attempt inside the window
// and re-scanned the whole slice on every call, so the cost of a flood
// grew quadratically with the flood — while holding a mutex shared by
// every account. Retention is now capped at the only samples that can
// change the verdict.
func TestTripwireRetentionIsBounded(t *testing.T) {
	const threshold = 5
	tw := NewTripwire(threshold, 5*time.Minute, 15*time.Minute, "alert")

	for i := 0; i < 50_000; i++ {
		tw.RecordDenied("victim", fmt.Sprintf("2001:db8::%x", i))
	}
	st := tw.m["victim"]
	if got, want := len(st.times), threshold+1; got > want {
		t.Errorf("timestamps retained: got %d, want at most %d", got, want)
	}
	if len(st.ips) > maxTrackedIPs {
		t.Errorf("tracked IPs: got %d, want at most %d", len(st.ips), maxTrackedIPs)
	}
}

// Cost per denial must not grow with the size of the flood.
//
// Asserted as an absolute per-operation ceiling rather than a ratio
// between two runs. A ratio needs a trustworthy baseline, and the
// baseline here is a few milliseconds — below the clock granularity on
// some platforms, where it rounds to zero and the ratio becomes noise
// divided by noise.
//
// The bounded implementation scans at most Threshold+1 samples, so a
// denial costs tens of nanoseconds. The quadratic version cost ~340µs at
// this depth. Anything under the ceiling below is comfortably the former
// even on a slow or contended machine.
func TestTripwireRecordDeniedCostDoesNotGrowWithFloodSize(t *testing.T) {
	if testing.Short() {
		t.Skip("timing sensitive")
	}
	const n = 200_000
	const ceiling = 10 * time.Microsecond

	tw := NewTripwire(5, 10*time.Minute, time.Minute, "alert")
	for i := 0; i < 1000; i++ { // warm up
		tw.RecordDenied("warmup", "203.0.113.7")
	}
	start := time.Now()
	for i := 0; i < n; i++ {
		tw.RecordDenied("victim", "203.0.113.7")
	}
	perOp := time.Since(start) / n

	t.Logf("%d denials at %v each (ceiling %v)", n, perOp, ceiling)
	if perOp > ceiling {
		t.Errorf("RecordDenied costs %v per call at depth %d; the bounded prune should be "+
			"tens of nanoseconds, so this is the quadratic scan returning", perOp, n)
	}
	// And the retention bound is what makes that possible.
	if got := len(tw.m["victim"].times); got > 6 {
		t.Errorf("window retained %d samples, want at most 6", got)
	}
}

// An expiring lock re-armed by zeroing the whole state, which threw away
// the cumulative trip count operators escalate on.
func TestTripwireKeepsCumulativeTripCountAcrossReArm(t *testing.T) {
	tw := NewTripwire(0, time.Minute, 40*time.Millisecond, "lock")

	first := tw.RecordDenied("acct", "10.0.0.1")
	if first == nil || first.Trips != 1 {
		t.Fatalf("first trip: %+v", first)
	}
	if locked, _ := tw.Gate("acct"); !locked {
		t.Fatal("expected a lock")
	}
	time.Sleep(80 * time.Millisecond)
	if locked, _ := tw.Gate("acct"); locked { // performs the re-arm
		t.Fatal("lock should have expired")
	}

	second := tw.RecordDenied("acct", "10.0.0.1")
	if second == nil {
		t.Fatal("expected a second trip")
	}
	if second.Trips != 2 {
		t.Errorf("trip_number: want 2, got %d", second.Trips)
	}
}

// In "alert" mode nothing ever blocks, so the tripped flag used to stick
// for the life of the process: one alert per account, ever. A drained
// window now re-arms so a later campaign alerts again.
func TestTripwireAlertModeReArmsAfterWindowDrains(t *testing.T) {
	tw := NewTripwire(0, 40*time.Millisecond, time.Hour, "alert")

	if tw.RecordDenied("acct", "10.0.0.1") == nil {
		t.Fatal("expected a first trip")
	}
	if tw.RecordDenied("acct", "10.0.0.1") != nil {
		t.Fatal("a second trip must not fire inside the same window")
	}
	time.Sleep(80 * time.Millisecond) // window drains

	second := tw.RecordDenied("acct", "10.0.0.1")
	if second == nil {
		t.Fatal("a new campaign after the window drained must alert again")
	}
	if second.Trips != 2 {
		t.Errorf("trip_number: want 2, got %d", second.Trips)
	}
}

// "freeze" disables the account, but authentication is checked before
// the enabled flag, so a bad token still yields 401. The tripped state
// must persist there — an admin has to intervene.
func TestTripwireFreezeModeStaysTripped(t *testing.T) {
	tw := NewTripwire(0, 40*time.Millisecond, time.Hour, "freeze")
	if tw.RecordDenied("acct", "10.0.0.1") == nil {
		t.Fatal("expected a trip")
	}
	time.Sleep(80 * time.Millisecond)
	if info := tw.RecordDenied("acct", "10.0.0.1"); info != nil {
		t.Errorf("freeze mode must stay tripped until reset, got a new trip %+v", info)
	}
}

// Return-leg transform failures were counted as applied but their
// warnings were dropped, so a permanently broken response format was
// invisible to both parties and to the activity log.
func TestReturnLegWarningsAreCounted(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"created_epoch":"not-an-epoch"}`)
	}))
	defer up.Close()

	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{
		"id": "warn", "enabled": true,
		"b": map[string]any{"target_url": up.URL},
		"map": []map[string]any{{
			"a": "created_at", "b": "created_epoch",
			"transform": map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"},
		}},
	})

	r := call(t, ts, "POST", "/t/warn/a2b", sideToken(acct, "a"),
		map[string]any{"created_at": "2023-11-14T22:13:20Z"})
	if r.status != 200 {
		t.Fatalf("want 200, got %d: %s", r.status, r.body)
	}
	if got := r.hdr.Get("X-Xlate-Warnings"); got != "1" {
		t.Errorf("X-Xlate-Warnings: want 1, got %q", got)
	}
	// The value must still fail open.
	if got := r.json(t)["created_at"]; got != "not-an-epoch" {
		t.Errorf("value should forward untransformed, got %v", got)
	}

	t.Run("activity log records the warning", func(t *testing.T) {
		lr := admin(t, ts, "GET", "/api/admin/logs?account=warn", nil)
		entries, _ := lr.json(t)["entries"].([]any)
		if len(entries) != 1 {
			t.Fatalf("want 1 entry, got %d: %s", len(entries), lr.body)
		}
		if got := fmt.Sprint(entries[0].(map[string]any)["warnings"]); got != "1" {
			t.Errorf("log warnings: want 1, got %v", got)
		}
	})
}

// A transform format with stray whitespace ("unix ", " rfc3339") used to
// pass validation (which checked the trimmed value) but execute raw —
// renderDate matched epoch keywords by exact string, so every date value
// was replaced by the literal format string with zero warnings. The
// stored value must be the same string validation approved.
func TestRegressionTransformFormatWhitespaceTrimmed(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir + "/s.json")
	if err != nil {
		t.Fatal(err)
	}
	in := &accountInput{Account: Account{
		ID: "trim-check",
		A:  Endpoint{InboundToken: "xk_aaaaaaaaaaaaaaaa", OutboundToken: "xk_aaaaaaaaaaaaaaaa"},
		B:  Endpoint{InboundToken: "xk_bbbbbbbbbbbbbbbb", OutboundToken: "xk_bbbbbbbbbbbbbbbb"},
		Map: []FieldPair{{A: "ts", B: "ts_epoch", Transform: &Transform{
			Kind: "date", AFormat: " rfc3339", BFormat: "unix ",
		}}},
	}}
	acct, err := st.Create(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tr := acct.Map[0].Transform
	if tr.AFormat != "rfc3339" || tr.BFormat != "unix" {
		t.Fatalf("formats not normalised: %q / %q", tr.AFormat, tr.BFormat)
	}
	res := Translate(map[string]any{"ts": "2026-08-06T12:00:00Z"}, acct.Map, AtoB, TranslateOptions{})
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", res.Warnings)
	}
	got := fmt.Sprint(res.Out["ts_epoch"])
	if got != "1786017600" {
		t.Fatalf("epoch conversion wrong: got %v", got)
	}
}
