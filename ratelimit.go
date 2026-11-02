package main

import (
	"sync"
	"time"
)

// RateLimiter enforces Account.RateLimitPerMin: a token bucket per side of
// an account. The bucket holds one minute's allowance and refills
// continuously, so a partner that sends in bursts is not punished for it,
// and the long-run rate still cannot pass the limit. Each side has its own
// bucket, so one party flooding cannot use up the other's callbacks.
//
// State is in memory and per instance, and starts full after a restart or a
// change of limit. Buckets are made only for authenticated callers of
// accounts that have a limit, so the map is bounded by the configured
// accounts and cannot be grown by anyone guessing identifiers.
type RateLimiter struct {
	mu  sync.Mutex
	m   map[rateKey]*bucket
	now func() time.Time
}

type rateKey struct {
	account string
	dir     Direction
}

type bucket struct {
	perMin int
	tokens float64
	last   time.Time

	// Refusals are reported to the audit trail at most once per
	// rateReportEvery, with a count of the ones held back, for the same
	// reason admin-plane denials are coalesced: a record per refusal would
	// make the limiter a way to grow the trail.
	held     int
	reportAt time.Time
}

const rateReportEvery = 10 * time.Second

// RateRefusal describes a request that was over its limit.
type RateRefusal struct {
	// RetryAfter is how long until one more request would pass.
	RetryAfter time.Duration
	// Report is true when this refusal should reach the audit trail, and
	// Suppressed is then the number refused since the last record, this one
	// included.
	Report     bool
	Suppressed int
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{m: map[rateKey]*bucket{}, now: time.Now}
}

// Allow takes one token from the (account, side) bucket. It returns nil when
// the request may go on and a refusal when it may not. A limit of zero or
// less means no limit.
func (l *RateLimiter) Allow(account string, dir Direction, perMin int) *RateRefusal {
	if l == nil || perMin <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	k := rateKey{account, dir}
	b := l.m[k]
	switch {
	case b == nil || b.perMin != perMin:
		b = &bucket{perMin: perMin, tokens: float64(perMin), last: now}
		l.m[k] = b
	case now.After(b.last):
		b.tokens = min(float64(perMin), b.tokens+now.Sub(b.last).Seconds()*float64(perMin)/60)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return nil
	}
	r := &RateRefusal{RetryAfter: time.Duration((1 - b.tokens) * 60 / float64(perMin) * float64(time.Second))}
	b.held++
	if !now.Before(b.reportAt) {
		r.Report, r.Suppressed = true, b.held
		b.held, b.reportAt = 0, now.Add(rateReportEvery)
	}
	return r
}

// Forget drops an account's buckets, so a deleted account's state does not
// linger and a recreated id starts clean.
func (l *RateLimiter) Forget(account string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, rateKey{account, AtoB})
	delete(l.m, rateKey{account, BtoA})
}
