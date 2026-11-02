package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Group commit: security-relevant records are durable before Emit returns,
// but callers that arrive together share fsyncs, and routine records never
// queue behind one.

func openGroupAudit(t *testing.T) *AuditLog {
	t.Helper()
	a, err := OpenAudit(filepath.Join(t.TempDir(), "trail.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// blockSyncs makes every fsync wait until release is called, and closes
// entered when the first one starts. onSync, if set, runs as each begins.
// Release also runs at cleanup, ahead of the log's Close, so a failing test
// reports instead of hanging on an fsync that never ends.
func blockSyncs(t *testing.T, a *AuditLog, onSync func()) (entered <-chan struct{}, release func()) {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	var inOnce, outOnce sync.Once
	a.syncFn = func() error {
		if onSync != nil {
			onSync()
		}
		inOnce.Do(func() { close(in) })
		<-out
		return nil
	}
	release = func() { outOnce.Do(func() { close(out) }) }
	t.Cleanup(release)
	return in, release
}

func TestAuditConcurrentCallersShareFsyncs(t *testing.T) {
	a := openGroupAudit(t)
	var syncs atomic.Int32
	a.syncFn = func() error {
		syncs.Add(1)
		time.Sleep(20 * time.Millisecond) // a slow disk, so callers pile up behind it
		return a.syncF.Sync()
	}

	const callers = 64
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs <- a.Emit("account:x", "ingest.denied", map[string]any{"n": i})
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("emit failed: %v", err)
		}
	}

	n := syncs.Load()
	t.Logf("%d callers shared %d fsyncs", callers, n)
	if n < 1 || n > 8 {
		t.Errorf("%d callers took %d fsyncs; they should share them (at most 8)", callers, n)
	}
	if err := VerifyAudit(a.f.Name(), discardWriter{}); err != nil {
		t.Fatalf("chain broke: %v", err)
	}
	raw, err := os.ReadFile(a.f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(raw, []byte("\n")); got != callers {
		t.Errorf("%d records on disk, want %d", got, callers)
	}
}

func TestAuditCriticalEmitWaitsForItsFsync(t *testing.T) {
	a := openGroupAudit(t)
	var sizeAtSync atomic.Int64
	entered, release := blockSyncs(t, a, func() {
		st, _ := a.f.Stat()
		sizeAtSync.Store(st.Size())
	})

	done := make(chan error, 1)
	go func() { done <- a.Emit("account:x", "ingest.denied", nil) }()
	<-entered
	select {
	case err := <-done:
		t.Fatalf("Emit returned (%v) while its fsync was still running", err)
	case <-time.After(100 * time.Millisecond):
	}
	if sizeAtSync.Load() == 0 {
		t.Error("the fsync began before the record had been written")
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The old design held the one lock across the fsync, so every routine
// ingest.ok queued behind a denial's fsync.
func TestAuditRoutineRecordsDoNotWaitBehindAnFsync(t *testing.T) {
	a := openGroupAudit(t)
	var syncs atomic.Int32
	entered, release := blockSyncs(t, a, func() { syncs.Add(1) })

	done := make(chan error, 1)
	go func() { done <- a.Emit("account:x", "ingest.denied", nil) }()
	<-entered

	routine := make(chan error, 1)
	go func() { routine <- a.Emit("account:x", "ingest.ok", nil) }()
	select {
	case err := <-routine:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a routine record waited behind an fsync")
	}
	if syncs.Load() != 1 {
		t.Errorf("a routine record triggered an fsync (%d calls)", syncs.Load())
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// After a failed fsync the kernel may have dropped the dirty pages, so a
// later success proves nothing about the records it covered.
func TestAuditFailedFsyncFailsEveryRecordItCovered(t *testing.T) {
	a := openGroupAudit(t)
	boom := errors.New("disk on fire")
	var calls atomic.Int32
	a.syncFn = func() error {
		if calls.Add(1) == 1 {
			return boom
		}
		return nil
	}

	// Holding the sync lock lets both callers write before either looks, so
	// the one fsync covers both records.
	a.syncMu.Lock()
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { errs <- a.Emit("account:x", "ingest.denied", nil) }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.mu.Lock()
		n := a.seq
		a.mu.Unlock()
		if n == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	a.syncMu.Unlock()

	for i := 0; i < 2; i++ {
		if err := <-errs; !errors.Is(err, boom) {
			t.Errorf("caller %d was told %v, want the fsync failure", i, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("the covered records were retried after the failure (%d fsyncs)", calls.Load())
	}

	// A record written afterwards is a new question and gets its own fsync.
	if err := a.Emit("account:x", "ingest.denied", nil); err != nil {
		t.Errorf("a later record failed too: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("a later record should have been synced separately (%d fsyncs)", calls.Load())
	}
}

func TestAuditChainHoldsUnderMixedConcurrentEmits(t *testing.T) {
	a := openGroupAudit(t)
	events := []string{"ingest.ok", "ingest.denied", "account.update", "ingest.ok", "tripwire.trip"}
	const goroutines, each = 16, 25

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				ev := events[(g+i)%len(events)]
				if err := a.Emit(fmt.Sprintf("account:g%d", g), ev, map[string]any{"g": g, "i": i}); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if err := VerifyAudit(a.f.Name(), discardWriter{}); err != nil {
		t.Fatalf("chain broke under concurrent writers: %v", err)
	}
	raw, err := os.ReadFile(a.f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(raw, []byte("\n")); got != goroutines*each {
		t.Errorf("%d records on disk, want %d", got, goroutines*each)
	}
}

func TestAuditCloseWaitsForAnFsyncInFlight(t *testing.T) {
	a := openGroupAudit(t)
	entered, release := blockSyncs(t, a, nil)

	emitted := make(chan error, 1)
	go func() { emitted <- a.Emit("account:x", "ingest.denied", nil) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- a.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) while an fsync was in flight", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if err := <-emitted; err != nil {
		t.Errorf("the record being synced was reported failed: %v", err)
	}
	if err := <-closed; err != nil {
		t.Errorf("close: %v", err)
	}
}
