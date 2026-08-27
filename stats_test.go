package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStatsCountsByOutcome(t *testing.T) {
	s := NewStats()
	now := time.Now()
	for _, e := range []LogEntry{
		{Account: "a", Direction: "a2b", Status: 200, ReqBytes: 100, RespBytes: 50, Applied: 4, LatencyMs: 10, Time: now},
		{Account: "a", Direction: "a2b", Status: 200, ReqBytes: 100, RespBytes: 50, Applied: 4, Warnings: 1, LatencyMs: 20, Time: now},
		{Account: "a", Direction: "b2a", Status: 401, LatencyMs: 1, Time: now},
		{Account: "b", Direction: "a2b", Status: 429, LatencyMs: 2, Time: now},
		{Account: "b", Direction: "a2b", Status: 502, LatencyMs: 30, Time: now},
	} {
		s.Record(e)
	}
	got := s.Snapshot()

	if got.Total != 5 {
		t.Errorf("total: want 5, got %d", got.Total)
	}
	if got.OK != 2 || got.Denied != 1 || got.Blocked != 1 || got.Upstream != 1 {
		t.Errorf("outcome split wrong: %+v", got)
	}
	if got.ClientErr != 2 || got.ServerErr != 1 {
		t.Errorf("class split: want 4xx=2 5xx=1, got %d/%d", got.ClientErr, got.ServerErr)
	}
	if got.ReqBytes != 200 || got.RespBytes != 100 {
		t.Errorf("bytes: got %d/%d", got.ReqBytes, got.RespBytes)
	}
	if got.Applied != 8 || got.Warnings != 1 {
		t.Errorf("fields: got applied=%d warnings=%d", got.Applied, got.Warnings)
	}
	if got.MaxMs != 30 {
		t.Errorf("max latency: want 30, got %d", got.MaxMs)
	}
	if want := 63.0 / 5; got.AvgMs != want {
		t.Errorf("avg latency: want %.2f, got %.2f", want, got.AvgMs)
	}
	if want := 40.0; got.SuccessPct != want {
		t.Errorf("success pct: want %.1f, got %.1f", want, got.SuccessPct)
	}
}

// Tripwire bookkeeping is written to the same ring as real requests, but
// counting it would inflate the node's totals with our own writes.
func TestStatsIgnoresNonRequestEntries(t *testing.T) {
	s := NewStats()
	s.Record(LogEntry{Account: "a", AccountKnown: true, Direction: "a2b", Status: 200, Time: time.Now()})
	s.Record(LogEntry{Account: "a", Direction: "trip", Status: 429, Time: time.Now()})
	s.Record(LogEntry{Account: "a", Direction: "", Status: 500, Time: time.Now()})

	if got := s.Snapshot().Total; got != 1 {
		t.Errorf("want 1 counted request, got %d", got)
	}
}

func TestStatsPerAccountRollup(t *testing.T) {
	s := NewStats()
	now := time.Now()
	for i := 0; i < 5; i++ {
		s.Record(LogEntry{Account: "busy", AccountKnown: true, Direction: "a2b", Status: 200, Applied: 2, LatencyMs: 4, Time: now})
	}
	s.Record(LogEntry{Account: "busy", AccountKnown: true, Direction: "a2b", Status: 401, LatencyMs: 1, Time: now})
	s.Record(LogEntry{Account: "quiet", AccountKnown: true, Direction: "a2b", Status: 200, LatencyMs: 9, Time: now})

	rows := s.Snapshot().Accounts
	if len(rows) != 2 {
		t.Fatalf("want 2 accounts, got %d", len(rows))
	}
	// Sorted by volume, busiest first.
	if rows[0].Account != "busy" || rows[1].Account != "quiet" {
		t.Errorf("wrong order: %s then %s", rows[0].Account, rows[1].Account)
	}
	if rows[0].Total != 6 || rows[0].OK != 5 || rows[0].Denied != 1 {
		t.Errorf("busy rollup wrong: %+v", rows[0])
	}
	if rows[0].Applied != 10 {
		t.Errorf("applied: want 10, got %d", rows[0].Applied)
	}
	if want := 21.0 / 6; rows[0].AvgMs != want {
		t.Errorf("avg ms: want %.3f, got %.3f", want, rows[0].AvgMs)
	}
}

func TestStatsForgetDropsAccount(t *testing.T) {
	s := NewStats()
	s.Record(LogEntry{Account: "gone", AccountKnown: true, Direction: "a2b", Status: 200, Time: time.Now()})
	s.Forget("gone")
	if rows := s.Snapshot().Accounts; len(rows) != 0 {
		t.Errorf("forgotten account still listed: %+v", rows)
	}
	// Node totals are lifetime figures and deliberately survive.
	if got := s.Snapshot().Total; got != 1 {
		t.Errorf("node total should not be rewritten by a delete, got %d", got)
	}
}

// The chart needs an even time axis: 60 slots, oldest first, gaps filled.
func TestStatsSeriesIsAFullHour(t *testing.T) {
	s := NewStats()
	now := time.Now()
	s.Record(LogEntry{Account: "a", AccountKnown: true, Direction: "a2b", Status: 200, Time: now})
	s.Record(LogEntry{Account: "a", AccountKnown: true, Direction: "a2b", Status: 500, Time: now})

	series := s.Snapshot().Series
	if len(series) != statsMinutes {
		t.Fatalf("want %d points, got %d", statsMinutes, len(series))
	}
	for i := 1; i < len(series); i++ {
		if !series[i].At.After(series[i-1].At) {
			t.Fatalf("series not ascending at %d: %v then %v", i, series[i-1].At, series[i].At)
		}
	}
	last := series[len(series)-1]
	if last.Total != 2 || last.OK != 1 || last.Bad != 1 {
		t.Errorf("current minute: want 2/1/1, got %d/%d/%d", last.Total, last.OK, last.Bad)
	}
	var earlier uint64
	for _, p := range series[:len(series)-1] {
		earlier += p.Total
	}
	if earlier != 0 {
		t.Errorf("earlier minutes should be empty, got %d", earlier)
	}
}

// A slot from the previous hour must be recycled, not read as current.
func TestStatsSeriesRecyclesStaleMinuteSlots(t *testing.T) {
	s := NewStats()
	now := time.Now()
	s.Record(LogEntry{Account: "a", AccountKnown: true, Direction: "a2b", Status: 200, Time: now.Add(-90 * time.Minute)})

	for _, p := range s.Snapshot().Series {
		if p.Total != 0 {
			t.Errorf("90-minute-old traffic leaked into the last hour at %v: %d", p.At, p.Total)
		}
	}
}

func TestStatsNilIsSafe(t *testing.T) {
	var s *Stats
	s.Record(LogEntry{Account: "a", AccountKnown: true, Direction: "a2b", Status: 200})
	s.Forget("a")
	got := s.Snapshot()
	if got.Total != 0 || got.Series == nil || got.Accounts == nil {
		t.Errorf("nil Stats should produce an empty snapshot, got %+v", got)
	}
}

func TestStatsConcurrentRecord(t *testing.T) {
	s := NewStats()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				s.Record(LogEntry{Account: fmt.Sprintf("acct-%d", i%5),
					Direction: "a2b", Status: 200, Applied: 1, LatencyMs: 1, Time: time.Now()})
			}
			s.Snapshot()
		}(i)
	}
	wg.Wait()
	if got := s.Snapshot().Total; got != 1000 {
		t.Errorf("want 1000, got %d", got)
	}
}

// End to end through the HTTP surface the dashboard actually calls.
func TestStatsEndpoint(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"y":1}`)
	}))
	defer up.Close()

	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "metered", "enabled": true,
		"b":   map[string]any{"target_url": up.URL},
		"map": []map[string]any{{"a": "x", "b": "y"}}})
	tok := sideToken(acct, "a")

	for i := 0; i < 3; i++ {
		call(t, ts, "POST", "/t/metered/a2b", tok, map[string]any{"x": i})
	}
	call(t, ts, "POST", "/t/metered/a2b", "wrong", map[string]any{"x": 1})

	r := admin(t, ts, "GET", "/api/admin/stats", nil)
	if r.status != 200 {
		t.Fatalf("want 200, got %d: %s", r.status, r.body)
	}
	m := r.json(t)
	if m["version"] != version {
		t.Errorf("version: got %v", m["version"])
	}
	st, _ := m["stats"].(map[string]any)
	if st == nil {
		t.Fatalf("no stats object: %s", r.body)
	}
	if fmt.Sprint(st["total"]) != "4" {
		t.Errorf("total: want 4, got %v", st["total"])
	}
	if fmt.Sprint(st["ok"]) != "3" {
		t.Errorf("ok: want 3, got %v", st["ok"])
	}
	if fmt.Sprint(st["denied"]) != "1" {
		t.Errorf("denied: want 1, got %v", st["denied"])
	}
	if series, _ := st["series"].([]any); len(series) != statsMinutes {
		t.Errorf("series: want %d points, got %d", statsMinutes, len(series))
	}
	rows, _ := st["accounts"].([]any)
	if len(rows) != 1 || fmt.Sprint(rows[0].(map[string]any)["account"]) != "metered" {
		t.Errorf("per-account rollup missing: %v", rows)
	}

	t.Run("requires the admin token", func(t *testing.T) {
		if got := call(t, ts, "GET", "/api/admin/stats", "", nil); got.status != 401 {
			t.Errorf("want 401, got %d", got.status)
		}
	})

	t.Run("no payload or credential material", func(t *testing.T) {
		if strings.Contains(string(r.body), tok) {
			t.Error("a token reached the stats response")
		}
	})

	t.Run("deleting an account clears its row", func(t *testing.T) {
		if got := admin(t, ts, "DELETE", "/api/admin/accounts/metered", nil); got.status != 204 {
			t.Fatalf("delete: %d", got.status)
		}
		after := admin(t, ts, "GET", "/api/admin/stats", nil).json(t)["stats"].(map[string]any)
		if rows, _ := after["accounts"].([]any); len(rows) != 0 {
			t.Errorf("deleted account still on the dashboard: %v", rows)
		}
	})
}

// Unauthenticated probes of nonexistent account ids must not create
// per-account rows: the id is attacker-chosen, and a row per unique
// probe grows the map without bound. The global counters still see the
// request; only the keyed state is gated.
func TestStatsUnknownAccountCreatesNoRow(t *testing.T) {
	s := NewStats()
	for i := 0; i < 50; i++ {
		s.Record(LogEntry{Account: fmt.Sprintf("probe-%d", i), Direction: "a2b", Status: 404, Time: time.Now()})
	}
	snap := s.Snapshot()
	if len(snap.Accounts) != 0 {
		t.Fatalf("404 probes created %d account rows; want 0", len(snap.Accounts))
	}
	if snap.Total != 50 {
		t.Errorf("global total should still count probes: want 50, got %d", snap.Total)
	}
}

// A 401 or 429 that the DESTINATION returned and xlate merely relayed is
// not a security event on this gateway; the denied/blocked counters must
// only count refusals xlate itself produced (which never reach upstream,
// so Upstream stays 0).
func TestStatsPassthroughAuthStatusNotCountedAsDenied(t *testing.T) {
	s := NewStats()
	// Gateway's own refusal.
	s.Record(LogEntry{Account: "a", AccountKnown: true, Direction: "a2b", Status: 401, Time: time.Now()})
	// Upstream's 401, relayed.
	s.Record(LogEntry{Account: "a", AccountKnown: true, Direction: "a2b", Status: 401, Upstream: 401, Time: time.Now()})
	// Upstream's 429, relayed.
	s.Record(LogEntry{Account: "a", AccountKnown: true, Direction: "a2b", Status: 429, Upstream: 429, Time: time.Now()})
	snap := s.Snapshot()
	if snap.Denied != 1 {
		t.Errorf("want denied=1 (gateway's own only), got %d", snap.Denied)
	}
	if snap.Blocked != 0 {
		t.Errorf("want blocked=0 (relayed 429 is not a tripwire event), got %d", snap.Blocked)
	}
}
