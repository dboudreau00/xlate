package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Benchmarks for capacity planning. Run:
//
//	go test -bench . -benchtime 2s -run '^$' ./...
//
// The end-to-end numbers include a real loopback HTTP call to a mock
// upstream, because xlate always makes one — a figure that excluded it
// would not describe anything you can deploy.

var benchPairs = []FieldPair{
	{A: "payment_id", B: "payment_proof"},
	{A: "customer.id", B: "cust_id"},
	{A: "amount", B: "value"},
	{A: "currency", B: "ccy"},
	{A: "created_at", B: "created_epoch",
		Transform: &Transform{Kind: "date", AFormat: "rfc3339", BFormat: "unix"}},
}

const benchPayload = `{"payment_id":"P-12345","customer":{"id":"C-9","name":"Acme"},` +
	`"amount":1999,"currency":"USD","created_at":"2023-11-14T22:13:20Z",` +
	`"note":"unmapped passthrough","ref":"R-1"}`

func BenchmarkTranslate(b *testing.B) {
	src, _ := decodeObjectStrict([]byte(benchPayload))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := make(map[string]any, len(src))
		for k, v := range src {
			m[k] = v
		}
		Translate(m, benchPairs, AtoB, TranslateOptions{})
	}
}

func BenchmarkDecodeObjectStrict(b *testing.B) {
	body := []byte(benchPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := decodeObjectStrict(body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenEqual(b *testing.B) {
	tok := newToken()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tokenEqual(tok, tok)
	}
}

func BenchmarkTripwireGate(b *testing.B) {
	tw := NewTripwire(5, 5*time.Minute, 15*time.Minute, "lock")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tw.Gate("acct")
	}
}

func BenchmarkTripwireRecordDenied(b *testing.B) {
	tw := NewTripwire(5, 5*time.Minute, 15*time.Minute, "alert")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tw.RecordDenied("acct", "203.0.113.7")
	}
}

// Audit writes happen once per ingest. ingest.ok is buffered+flushed;
// account.* and denials are fsynced. The gap between these two is the
// single largest per-request cost in the pipeline.
func BenchmarkAuditEmitBuffered(b *testing.B) {
	benchAudit(b, "ingest.ok")
}

func BenchmarkAuditEmitFsynced(b *testing.B) {
	benchAudit(b, "ingest.denied")
}

func benchAudit(b *testing.B, event string) {
	b.Helper()
	a, err := OpenAudit(filepath.Join(b.TempDir(), "trail.jsonl"))
	if err != nil {
		b.Fatal(err)
	}
	defer a.Close()
	detail := map[string]any{"account": "acme", "dir": "a2b", "upstream": 200,
		"req_bytes": 210, "resp_bytes": 64, "applied": 5, "warnings": 0}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.Emit("account:acme", event, detail); err != nil {
			b.Fatal(err)
		}
	}
}

// benchGateway wires a full server against a mock upstream and returns
// the ingest URL plus the inbound token.
func benchGateway(tb testing.TB, auditPath string) (*httptest.Server, string, func()) {
	tb.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"payment_proof":"P-12345","cust_id":"C-9","value":1999,"ccy":"USD","created_epoch":1700000000}`)
	}))

	dir := tb.TempDir()
	store, err := OpenStore(filepath.Join(dir, "state.json"))
	if err != nil {
		tb.Fatal(err)
	}
	srv := NewServer(store, NewRing(500), testAdminToken, 2<<20, []byte("<html>ui</html>"))
	srv.trip = NewTripwire(5, 5*time.Minute, 15*time.Minute, "lock")

	var audit *AuditLog
	if auditPath != "" {
		audit, err = OpenAudit(filepath.Join(dir, auditPath))
		if err != nil {
			tb.Fatal(err)
		}
		srv.audit = audit
	}

	acct, err := store.Create(asInput(Account{
		ID: "bench", Enabled: true,
		A:   Endpoint{Label: "A"},
		B:   Endpoint{Label: "B", TargetURL: up.URL},
		Map: benchPairs,
	}))
	if err != nil {
		tb.Fatal(err)
	}
	ts := httptest.NewServer(srv.routes())
	return ts, acct.A.InboundToken, func() {
		ts.Close()
		up.Close()
		_ = audit.Close()
	}
}

// BenchmarkIngest measures one full a2b round trip: auth, decode,
// translate, forward over loopback, reverse-map the response, audit.
func BenchmarkIngest(b *testing.B) {
	for _, tc := range []struct{ name, audit string }{
		{"AuditOn", "trail.jsonl"},
		{"AuditOff", ""},
	} {
		b.Run(tc.name, func(b *testing.B) {
			ts, tok, done := benchGateway(b, tc.audit)
			defer done()
			url := ts.URL + "/t/bench/a2b"
			client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256}}

			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req, _ := http.NewRequest("POST", url, strings.NewReader(benchPayload))
					req.Header.Set("Authorization", "Bearer "+tok)
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err != nil {
						b.Error(err)
						return
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != 200 {
						b.Errorf("status %d", resp.StatusCode)
						return
					}
				}
			})
		})
	}
}

// BenchmarkIngestRejected measures the cheap paths: a request that never
// reaches the upstream.
func BenchmarkIngestRejected(b *testing.B) {
	ts, _, done := benchGateway(b, "trail.jsonl")
	defer done()
	url := ts.URL + "/t/bench/a2b"
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256}}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("POST", url, strings.NewReader(benchPayload))
			req.Header.Set("Authorization", "Bearer wrong-token")
			resp, err := client.Do(req)
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// BenchmarkIngestBlocked measures a request to a locked-out account.
// This is the path an attacker drives during a credential-guessing
// burst, and it emits ingest.blocked — a critical event, so every one
// costs an fsync under the audit mutex.
func BenchmarkIngestBlocked(b *testing.B) {
	ts, tok, done := benchGateway(b, "trail.jsonl")
	defer done()
	url := ts.URL + "/t/bench/a2b"
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256}}

	// Drive the account into lockout first.
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequest("POST", url, strings.NewReader(benchPayload))
		req.Header.Set("Authorization", "Bearer nope")
		if resp, err := client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
	req, _ := http.NewRequest("POST", url, strings.NewReader(benchPayload))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 429 {
		b.Fatalf("setup: expected a lockout, got %d", resp.StatusCode)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("POST", url, strings.NewReader(benchPayload))
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := client.Do(req)
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// TestLoadProfile is a throughput probe rather than an assertion: it
// reports sustained requests/sec and the latency spread at a few
// concurrency levels. Skipped unless XLATE_LOAD=1 so it never slows CI.
func TestLoadProfile(t *testing.T) {
	if os.Getenv("XLATE_LOAD") == "" {
		t.Skip("set XLATE_LOAD=1 to run the throughput probe")
	}
	ts, tok, done := benchGateway(t, "trail.jsonl")
	defer done()
	url := ts.URL + "/t/bench/a2b"

	for _, workers := range []int{1, 8, 32, 128} {
		const perWorker = 400
		client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: workers + 8}}
		lat := make([]time.Duration, 0, workers*perWorker)
		var mu sync.Mutex
		var failed atomic.Int64

		var wg sync.WaitGroup
		start := time.Now()
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				local := make([]time.Duration, 0, perWorker)
				for i := 0; i < perWorker; i++ {
					t0 := time.Now()
					req, _ := http.NewRequest("POST", url, strings.NewReader(benchPayload))
					req.Header.Set("Authorization", "Bearer "+tok)
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err != nil {
						failed.Add(1)
						continue
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != 200 {
						failed.Add(1)
					}
					local = append(local, time.Since(t0))
				}
				mu.Lock()
				lat = append(lat, local...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)

		total := workers * perWorker
		rps := float64(total) / elapsed.Seconds()
		p50, p95, p99 := percentiles(lat)
		t.Logf("workers=%-4d %7.0f req/s   p50=%-9v p95=%-9v p99=%-9v failed=%d",
			workers, rps, p50.Round(time.Microsecond), p95.Round(time.Microsecond),
			p99.Round(time.Microsecond), failed.Load())
	}
}

func percentiles(d []time.Duration) (p50, p95, p99 time.Duration) {
	if len(d) == 0 {
		return
	}
	// Insertion into a sorted copy is fine at these sizes.
	s := append([]time.Duration(nil), d...)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	at := func(q float64) time.Duration {
		i := int(q * float64(len(s)-1))
		return s[i]
	}
	return at(0.50), at(0.95), at(0.99)
}

// Guard against the benchmark payload drifting out of sync with the map.
func TestBenchFixtureTranslatesCleanly(t *testing.T) {
	m, err := decodeObjectStrict([]byte(benchPayload))
	if err != nil {
		t.Fatal(err)
	}
	res := Translate(m, benchPairs, AtoB, TranslateOptions{})
	if len(res.Warnings) != 0 {
		t.Errorf("benchmark fixture produces warnings: %v", res.Warnings)
	}
	if res.Applied != len(benchPairs) {
		t.Errorf("applied %d of %d pairs", res.Applied, len(benchPairs))
	}
	if _, err := json.Marshal(res.Out); err != nil {
		t.Fatal(err)
	}
	_ = fmt.Sprint(res.Out)
}
