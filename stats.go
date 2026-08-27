package main

import (
	"sort"
	"sync"
	"time"
)

// Stats are lifetime counters for this node, plus a rolling per-minute
// series for the dashboard.
//
// The activity ring answers "what just happened" and holds only the last
// -log-size requests. These counters answer "what has this node done",
// which the ring cannot: it forgets. They are in-memory and reset on
// restart — deliberately, because durable metrics belong in whatever
// scrapes the node, not in a gateway that is trying to stay a single
// dependency-free binary.
//
// Like everything else here, counters only. No payloads, no identifiers.
const statsMinutes = 60

type Stats struct {
	mu        sync.Mutex
	startedAt time.Time

	total    uint64
	c2xx     uint64
	c4xx     uint64
	c5xx     uint64
	denied   uint64 // 401
	blocked  uint64 // 429 (tripwire)
	upstream uint64 // 502 and friends

	reqBytes  uint64
	respBytes uint64
	applied   uint64
	warnings  uint64

	latSumMs uint64
	latMaxMs int64

	accounts map[string]*accountStat
	minutes  [statsMinutes]minuteBucket
}

type accountStat struct {
	Total     uint64 `json:"total"`
	OK        uint64 `json:"ok"`
	Denied    uint64 `json:"denied"`
	Blocked   uint64 `json:"blocked"`
	Failed    uint64 `json:"failed"`
	ReqBytes  uint64 `json:"req_bytes"`
	RespBytes uint64 `json:"resp_bytes"`
	Applied   uint64 `json:"applied"`
	Warnings  uint64 `json:"warnings"`
	latSumMs  uint64
	AvgMs     float64   `json:"avg_ms"`
	LastSeen  time.Time `json:"last_seen"`
}

type minuteBucket struct {
	at    time.Time
	total uint64
	ok    uint64
	bad   uint64
}

// MinutePoint is one column of the dashboard chart.
type MinutePoint struct {
	At    time.Time `json:"at"`
	Total uint64    `json:"total"`
	OK    uint64    `json:"ok"`
	Bad   uint64    `json:"bad"`
}

type AccountStatRow struct {
	accountStat
	Account string `json:"account"`
}

// StatsSnapshot is the shape returned by GET /api/admin/stats.
type StatsSnapshot struct {
	UptimeSec  int              `json:"uptime_sec"`
	Total      uint64           `json:"total"`
	OK         uint64           `json:"ok"`
	ClientErr  uint64           `json:"client_err"`
	ServerErr  uint64           `json:"server_err"`
	Denied     uint64           `json:"denied"`
	Blocked    uint64           `json:"blocked"`
	Upstream   uint64           `json:"upstream_err"`
	SuccessPct float64          `json:"success_pct"`
	ReqBytes   uint64           `json:"req_bytes"`
	RespBytes  uint64           `json:"resp_bytes"`
	Applied    uint64           `json:"applied"`
	Warnings   uint64           `json:"warnings"`
	AvgMs      float64          `json:"avg_ms"`
	MaxMs      int64            `json:"max_ms"`
	PerMin     float64          `json:"per_min"`
	Series     []MinutePoint    `json:"series"`
	Accounts   []AccountStatRow `json:"accounts"`
}

func NewStats() *Stats {
	return &Stats{startedAt: time.Now(), accounts: map[string]*accountStat{}}
}

// Record folds one finished ingest into the counters. Tripwire pseudo
// entries (Direction "trip") are bookkeeping, not requests, so they are
// skipped — counting them would inflate the totals with our own writes.
func (s *Stats) Record(e LogEntry) {
	if s == nil || (e.Direction != "a2b" && e.Direction != "b2a") {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.total++
	s.reqBytes += uint64(e.ReqBytes)
	s.respBytes += uint64(e.RespBytes)
	s.applied += uint64(e.Applied)
	s.warnings += uint64(e.Warnings)
	if e.LatencyMs > 0 {
		s.latSumMs += uint64(e.LatencyMs)
	}
	if e.LatencyMs > s.latMaxMs {
		s.latMaxMs = e.LatencyMs
	}

	good := e.Status >= 200 && e.Status < 400
	switch {
	case good:
		s.c2xx++
	case e.Status >= 500:
		s.c5xx++
	case e.Status >= 400:
		s.c4xx++
	}
	// denied/blocked are security signals about THIS gateway's decisions.
	// A 401 or 429 the destination returned and we merely relayed is an
	// upstream outcome, not a credential guess against us — and it is
	// distinguishable because relays carry the upstream status while
	// gateway refusals never reached upstream (e.Upstream == 0).
	gatewayOwn := e.Upstream == 0
	switch {
	case e.Status == 401 && gatewayOwn:
		s.denied++
	case e.Status == 429 && gatewayOwn:
		s.blocked++
	case e.Status == 502:
		s.upstream++
	}

	// Per-account rows are keyed by attacker-typed ids on 404 probes;
	// only ids that resolved to a real account may create or touch a row.
	if e.AccountKnown {
		as := s.accounts[e.Account]
		if as == nil {
			as = &accountStat{}
			s.accounts[e.Account] = as
		}
		as.Total++
		as.ReqBytes += uint64(e.ReqBytes)
		as.RespBytes += uint64(e.RespBytes)
		as.Applied += uint64(e.Applied)
		as.Warnings += uint64(e.Warnings)
		as.latSumMs += uint64(max64s(e.LatencyMs, 0))
		as.LastSeen = e.Time
		switch {
		case good:
			as.OK++
		case e.Status == 401 && gatewayOwn:
			as.Denied++
		case e.Status == 429 && gatewayOwn:
			as.Blocked++
		default:
			as.Failed++
		}
	}

	// Rolling per-minute series: one slot per minute of the hour, stamped
	// so a stale slot from the previous hour is recycled rather than read.
	//
	// Slot arithmetic must use one clock family on both write and read:
	// entries arrive stamped UTC while Snapshot runs on the host clock,
	// and in a half- or 45-minute-offset zone (IST, Newfoundland) the
	// local minute is shifted from the UTC minute — indexing one side
	// local left the dashboard series permanently empty there.
	now := e.Time
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	slot := now.Minute() % statsMinutes
	b := &s.minutes[slot]
	if !b.at.Equal(now.Truncate(time.Minute)) {
		*b = minuteBucket{at: now.Truncate(time.Minute)}
	}
	b.total++
	if good {
		b.ok++
	} else {
		b.bad++
	}
}

// Snapshot renders the counters for the dashboard.
func (s *Stats) Snapshot() StatsSnapshot {
	out := StatsSnapshot{Series: []MinutePoint{}, Accounts: []AccountStatRow{}}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	uptime := time.Since(s.startedAt)
	out.UptimeSec = int(uptime.Seconds())
	out.Total, out.OK = s.total, s.c2xx
	out.ClientErr, out.ServerErr = s.c4xx, s.c5xx
	out.Denied, out.Blocked, out.Upstream = s.denied, s.blocked, s.upstream
	out.ReqBytes, out.RespBytes = s.reqBytes, s.respBytes
	out.Applied, out.Warnings = s.applied, s.warnings
	out.MaxMs = s.latMaxMs
	if s.total > 0 {
		out.SuccessPct = float64(s.c2xx) * 100 / float64(s.total)
		out.AvgMs = float64(s.latSumMs) / float64(s.total)
	}
	if m := uptime.Minutes(); m > 0 {
		out.PerMin = float64(s.total) / m
	}

	// Emit the last hour oldest-first, filling gaps so the chart has an
	// even time axis instead of only the minutes that saw traffic.
	nowMin := time.Now().UTC().Truncate(time.Minute)
	for i := statsMinutes - 1; i >= 0; i-- {
		at := nowMin.Add(-time.Duration(i) * time.Minute)
		p := MinutePoint{At: at}
		if b := s.minutes[at.Minute()%statsMinutes]; b.at.Equal(at) {
			p.Total, p.OK, p.Bad = b.total, b.ok, b.bad
		}
		out.Series = append(out.Series, p)
	}

	for id, as := range s.accounts {
		row := AccountStatRow{accountStat: *as, Account: id}
		if as.Total > 0 {
			row.AvgMs = float64(as.latSumMs) / float64(as.Total)
		}
		out.Accounts = append(out.Accounts, row)
	}
	sort.Slice(out.Accounts, func(i, j int) bool {
		if out.Accounts[i].Total != out.Accounts[j].Total {
			return out.Accounts[i].Total > out.Accounts[j].Total
		}
		return out.Accounts[i].Account < out.Accounts[j].Account
	})
	return out
}

// Forget drops an account's counters, so a deleted account does not
// linger on the dashboard.
func (s *Stats) Forget(account string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accounts, account)
}

func max64s(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
