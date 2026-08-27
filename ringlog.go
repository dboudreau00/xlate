package main

import (
	"sync"
	"time"
)

// LogEntry records request metadata only. Payload bodies are never
// captured: translated traffic routinely carries payment identifiers
// and PII, and the log is readable by anyone holding the admin token.
type LogEntry struct {
	Seq       int64     `json:"seq"`
	Time      time.Time `json:"time"`
	Account   string    `json:"account"`
	Direction string    `json:"direction"`
	Status    int       `json:"status"`             // status returned to caller
	Upstream  int       `json:"upstream,omitempty"` // status from destination, if reached
	LatencyMs int64     `json:"latency_ms"`
	ReqBytes  int       `json:"req_bytes"`
	RespBytes int       `json:"resp_bytes"`
	Applied   int       `json:"applied"`
	Warnings  int       `json:"warnings,omitempty"`
	Err       string    `json:"err,omitempty"`
	// AccountKnown marks entries whose account id resolved to a real
	// account. Stats keying trusts only marked entries — the id in an
	// unauthenticated 404 probe is attacker-chosen, and creating a
	// counter row per unique probe would grow memory without bound.
	AccountKnown bool `json:"-"`
	// Fields carries "path:type" entries when the account is inside a
	// discovery window. Shape only — never a value — and only ever in
	// this in-memory ring, never on the durable audit trail.
	Fields []string `json:"fields,omitempty"`
}

// Ring is a fixed-size circular log. Overwrites oldest when full.
type Ring struct {
	mu    sync.Mutex
	buf   []LogEntry
	head  int // next write position
	count int
	seq   int64
}

func NewRing(n int) *Ring {
	if n < 1 {
		n = 1
	}
	return &Ring{buf: make([]LogEntry, n)}
}

func (r *Ring) Add(e LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	e.Seq = r.seq
	r.buf[r.head] = e
	r.head = (r.head + 1) % len(r.buf)
	if r.count < len(r.buf) {
		r.count++
	}
}

// List returns entries newest-first, optionally filtered by account.
func (r *Ring) List(account string, limit int) []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit < 1 || limit > r.count {
		limit = r.count
	}
	out := make([]LogEntry, 0, limit)
	n := len(r.buf)
	for i := 0; i < r.count && len(out) < limit; i++ {
		e := r.buf[((r.head-1-i)%n+n)%n]
		if account != "" && e.Account != account {
			continue
		}
		out = append(out, e)
	}
	return out
}
