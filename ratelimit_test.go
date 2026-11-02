package main

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Per-account rate limit: a token bucket per side, applied after
// authentication, counted apart from the tripwire.

func fakeClockLimiter() (*RateLimiter, *time.Time) {
	l := NewRateLimiter()
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	return l, &now
}

// drain counts how many requests pass before the first refusal.
func drain(l *RateLimiter, account string, dir Direction, perMin int) int {
	n := 0
	for n < 10*perMin && l.Allow(account, dir, perMin) == nil {
		n++
	}
	return n
}

func TestRateLimiterBurstsThenRefills(t *testing.T) {
	l, now := fakeClockLimiter()

	if got := drain(l, "a", AtoB, 60); got != 60 {
		t.Fatalf("an idle side may burst a full minute's allowance: %d passed, want 60", got)
	}
	r := l.Allow("a", AtoB, 60)
	if r == nil || r.RetryAfter != time.Second {
		t.Fatalf("the 61st request should wait one refill interval, got %+v", r)
	}

	*now = now.Add(time.Second)
	if got := drain(l, "a", AtoB, 60); got != 1 {
		t.Errorf("one second at 60 a minute refills one request, %d passed", got)
	}
	*now = now.Add(30 * time.Second)
	if got := drain(l, "a", AtoB, 60); got != 30 {
		t.Errorf("30 seconds refill 30 requests, %d passed", got)
	}
	*now = now.Add(time.Hour)
	if got := drain(l, "a", AtoB, 60); got != 60 {
		t.Errorf("idling must not bank more than a minute's allowance: %d passed, want 60", got)
	}
}

func TestRateLimiterSidesAndAccountsAreIndependent(t *testing.T) {
	l, _ := fakeClockLimiter()
	drain(l, "acme", AtoB, 2)
	if l.Allow("acme", AtoB, 2) == nil {
		t.Fatal("side A should be out of requests")
	}
	if l.Allow("acme", BtoA, 2) != nil {
		t.Error("one side flooding used up the other side's allowance")
	}
	if l.Allow("globex", AtoB, 2) != nil {
		t.Error("one account flooding used up another account's allowance")
	}
}

func TestRateLimiterNewLimitStartsAFreshBucket(t *testing.T) {
	l, _ := fakeClockLimiter()
	drain(l, "acme", AtoB, 5)
	if l.Allow("acme", AtoB, 5) == nil {
		t.Fatal("bucket should be empty")
	}
	if got := drain(l, "acme", AtoB, 8); got != 8 {
		t.Errorf("a changed limit should start full: %d passed, want 8", got)
	}
}

func TestRateLimiterNoLimitAndNilAreOpen(t *testing.T) {
	l, _ := fakeClockLimiter()
	for i := 0; i < 1000; i++ {
		if l.Allow("acme", AtoB, 0) != nil || l.Allow("acme", AtoB, -3) != nil {
			t.Fatal("a limit of zero or less must mean no limit")
		}
	}
	if len(l.m) != 0 {
		t.Errorf("an unlimited account must not allocate state: %d buckets", len(l.m))
	}
	var none *RateLimiter
	if none.Allow("acme", AtoB, 1) != nil {
		t.Error("a nil limiter must let everything through")
	}
	none.Forget("acme")
}

func TestRateLimiterForgetClearsAnAccount(t *testing.T) {
	l, _ := fakeClockLimiter()
	drain(l, "acme", AtoB, 3)
	drain(l, "acme", BtoA, 3)
	l.Forget("acme")
	if got := drain(l, "acme", AtoB, 3) + drain(l, "acme", BtoA, 3); got != 6 {
		t.Errorf("a forgotten account should start full on both sides, %d passed", got)
	}
}

// A record per refusal would let a flood grow the trail.
func TestRateLimiterReportsOncePerWindow(t *testing.T) {
	l, now := fakeClockLimiter()
	if l.Allow("acme", AtoB, 1) != nil {
		t.Fatal("the one allowed request was refused")
	}

	first := l.Allow("acme", AtoB, 1)
	if first == nil || !first.Report || first.Suppressed != 1 {
		t.Fatalf("the first refusal opens a window and is reported: %+v", first)
	}
	for i := 0; i < 3; i++ {
		if r := l.Allow("acme", AtoB, 1); r == nil || r.Report {
			t.Fatalf("refusal %d inside the window must not be reported: %+v", i+2, r)
		}
	}
	*now = now.Add(rateReportEvery)
	next := l.Allow("acme", AtoB, 1)
	if next == nil || !next.Report || next.Suppressed != 4 {
		t.Errorf("the next window reports the refusals held back, this one included: %+v", next)
	}
}

func TestRateLimiterNeverPassesMoreThanItsAllowanceConcurrently(t *testing.T) {
	l := NewRateLimiter()
	var passed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("acme", AtoB, 100) == nil {
				passed.Add(1)
			}
		}()
	}
	wg.Wait()
	// 100 tokens, plus whatever refilled while the goroutines ran.
	if n := passed.Load(); n < 100 || n > 102 {
		t.Errorf("%d requests passed a limit of 100", n)
	}
}

func limitedAccountDoc(id, upURL string, perMin int) map[string]any {
	return map[string]any{
		"id": id, "enabled": true, "rate_limit_per_min": perMin,
		"a":   map[string]any{"target_url": upURL},
		"b":   map[string]any{"target_url": upURL},
		"map": []map[string]any{{"a": "x", "b": "y"}},
	}
}

func TestRateLimitRefusesPastTheLimit(t *testing.T) {
	ts := newAPI(t)
	up, hits := strictUpstream(t, `{"y":1}`)
	acct := mustCreate(t, ts, limitedAccountDoc("limited", up.URL, 3))
	tokA, tokB := sideToken(acct, "a"), sideToken(acct, "b")

	for i := 0; i < 3; i++ {
		if r := call(t, ts, "POST", "/t/limited/a2b", tokA, `{"x":1}`); r.status != 200 {
			t.Fatalf("request %d inside the limit: %d %s", i+1, r.status, r.body)
		}
	}
	r := call(t, ts, "POST", "/t/limited/a2b", tokA, `{"x":1}`)
	if r.status != 429 || r.json(t)["code"] != "rate_limited" {
		t.Fatalf("want 429 rate_limited, got %d: %s", r.status, r.body)
	}
	if ra := r.hdr.Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("Retry-After = %q, want a number of seconds", ra)
	}
	if hits.Load() != 3 {
		t.Errorf("a refused request reached the destination (%d hits)", hits.Load())
	}

	// The other side has an allowance of its own.
	if r := call(t, ts, "POST", "/t/limited/b2a", tokB, `{"y":1}`); r.status != 200 {
		t.Errorf("side B was refused because side A was flooding: %d %s", r.status, r.body)
	}

	// A refusal is not a credential guess: it must not feed the tripwire.
	tw := admin(t, ts, "GET", "/api/admin/tripwire", nil).json(t)["limited"].(map[string]any)
	if tw["state"] != "armed" || tw["count"].(json.Number).String() != "0" {
		t.Errorf("tripwire = %v, want armed and untouched", tw)
	}
}

// Account ids are not secrets. Anonymous traffic must not be able to spend
// the partner's allowance.
func TestRateLimitIsNotSpentByAnonymousCallers(t *testing.T) {
	ts := newAPI(t, func(s *Server) { s.trip = NewTripwire(1000, time.Minute, time.Minute, "alert") })
	up, _ := strictUpstream(t, `{"y":1}`)
	acct := mustCreate(t, ts, limitedAccountDoc("limited", up.URL, 2))

	for i := 0; i < 20; i++ {
		if r := call(t, ts, "POST", "/t/limited/a2b", "not-the-token", `{"x":1}`); r.status != 401 {
			t.Fatalf("a bad token should be refused as 401, got %d", r.status)
		}
	}
	tok := sideToken(acct, "a")
	for i := 0; i < 2; i++ {
		if r := call(t, ts, "POST", "/t/limited/a2b", tok, `{"x":1}`); r.status != 200 {
			t.Fatalf("request %d: junk traffic spent the allowance: %d %s", i+1, r.status, r.body)
		}
	}
	if r := call(t, ts, "POST", "/t/limited/a2b", tok, `{"x":1}`); r.status != 429 {
		t.Errorf("the third request should be over the limit, got %d", r.status)
	}
}

func TestRateLimitIsAuditedOncePerWindowAndCountedApart(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	up, _ := strictUpstream(t, `{"y":1}`)
	acct := mustCreate(t, ts, limitedAccountDoc("limited", up.URL, 2))
	tok := sideToken(acct, "a")

	const total = 32
	for i := 0; i < total; i++ {
		call(t, ts, "POST", "/t/limited/a2b", tok, `{"x":1}`)
	}
	refused := total - 2

	trail := strictTrail(t, srv)
	if n := strings.Count(trail, `"event":"ingest.limited"`); n != 1 {
		t.Errorf("%d refusals wrote %d trail records, want 1 per window", refused, n)
	}
	if !strings.Contains(trail, `"limit_per_min":2`) || !strings.Contains(trail, `"refused":1`) {
		t.Errorf("the record should carry the limit and the count:\n%s", trail)
	}

	st := admin(t, ts, "GET", "/api/admin/stats", nil).json(t)["stats"].(map[string]any)
	if got, _ := st["limited"].(json.Number).Int64(); got != int64(refused) {
		t.Errorf("stats count %d rate-limited requests, want %d", got, refused)
	}
	for _, k := range []string{"blocked", "denied"} {
		if got, _ := st[k].(json.Number).Int64(); got != 0 {
			t.Errorf("a rate-limited request was also counted as %s (%d)", k, got)
		}
	}
	row := st["accounts"].([]any)[0].(map[string]any)
	if got, _ := row["limited"].(json.Number).Int64(); got != int64(refused) {
		t.Errorf("the account row counts %d, want %d", got, refused)
	}
	logs := admin(t, ts, "GET", "/api/admin/logs?account=limited&limit=1", nil).json(t)["entries"].([]any)
	if e := logs[0].(map[string]any); e["status"].(json.Number).String() != "429" || e["err"] != "rate limited" {
		t.Errorf("activity entry = %v", e)
	}
}

func TestRateLimitSettingValidationAndPutRetention(t *testing.T) {
	ts := newAPI(t)
	up, _ := strictUpstream(t, `{}`)

	for _, bad := range []any{-1, maxRatePerMin + 1, 1.5, "many"} {
		doc := limitedAccountDoc("bad", up.URL, 0)
		doc["rate_limit_per_min"] = bad
		r := admin(t, ts, "POST", "/api/admin/accounts", doc)
		if r.status != 400 {
			t.Errorf("rate_limit_per_min %v: want 400, got %d: %s", bad, r.status, r.body)
		}
	}
	if r := admin(t, ts, "POST", "/api/admin/accounts", limitedAccountDoc("edge", up.URL, maxRatePerMin)); r.status != 201 {
		t.Errorf("the ceiling itself should be accepted: %d %s", r.status, r.body)
	}

	acct := mustCreate(t, ts, limitedAccountDoc("kept", up.URL, 5))
	if acct["rate_limit_per_min"].(json.Number).String() != "5" {
		t.Fatalf("setting not stored: %v", acct["rate_limit_per_min"])
	}
	// A PUT from a client that predates the setting omits it; that must not
	// lift the limit.
	doc := admin(t, ts, "GET", "/api/admin/accounts/kept", nil).json(t)
	delete(doc, "rate_limit_per_min")
	if r := admin(t, ts, "PUT", "/api/admin/accounts/kept", doc); r.status != 200 {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	got := admin(t, ts, "GET", "/api/admin/accounts/kept", nil).json(t)
	if v, _ := got["rate_limit_per_min"].(json.Number); v.String() != "5" {
		t.Fatalf("an omitting PUT changed the limit: %v", got["rate_limit_per_min"])
	}
	doc["rate_limit_per_min"] = 0
	if r := admin(t, ts, "PUT", "/api/admin/accounts/kept", doc); r.status != 200 {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	if got := admin(t, ts, "GET", "/api/admin/accounts/kept", nil).json(t); got["rate_limit_per_min"] != nil {
		t.Errorf("an explicit 0 should remove the limit: %v", got["rate_limit_per_min"])
	}
}

func TestRateLimitStartsCleanWhenAnAccountIsRecreated(t *testing.T) {
	ts := newAPI(t)
	up, _ := strictUpstream(t, `{"y":1}`)
	acct := mustCreate(t, ts, limitedAccountDoc("again", up.URL, 1))
	call(t, ts, "POST", "/t/again/a2b", sideToken(acct, "a"), `{"x":1}`)
	if r := call(t, ts, "POST", "/t/again/a2b", sideToken(acct, "a"), `{"x":1}`); r.status != 429 {
		t.Fatalf("setup: want 429, got %d", r.status)
	}
	if r := admin(t, ts, "DELETE", "/api/admin/accounts/again", nil); r.status != 204 {
		t.Fatalf("delete: %d", r.status)
	}
	acct = mustCreate(t, ts, limitedAccountDoc("again", up.URL, 1))
	if r := call(t, ts, "POST", "/t/again/a2b", sideToken(acct, "a"), `{"x":1}`); r.status != 200 {
		t.Errorf("a recreated account inherited the old bucket: %d %s", r.status, r.body)
	}
}
