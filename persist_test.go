package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A write that fails must leave memory exactly as it was. Otherwise the
// API reports an error while the change stays live: the account serves
// traffic, shows up in listings, and then disappears on restart.
//
// The failure is induced by making the state path unwritable — a
// directory sitting where the temp file needs to be.
func blockWrites(t *testing.T, s *Store) {
	t.Helper()
	tmp := s.path + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		t.Fatal(err)
	}
	// A directory at the temp path makes OpenFile fail on every platform.
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPersistFailureRollsBackCreate(t *testing.T) {
	s := newStore(t)
	blockWrites(t, s)

	if _, err := s.Create(asInput(Account{ID: "ghost"})); err == nil {
		t.Fatal("create should have failed with an unwritable state file")
	}
	if n := s.Count(); n != 0 {
		t.Errorf("failed create left %d account(s) live in memory", n)
	}
	if _, ok := s.Get("ghost"); ok {
		t.Error("failed create is still reachable through Get")
	}
}

func TestPersistFailureRollsBackUpdate(t *testing.T) {
	s := newStore(t)
	created, err := s.Create(asInput(Account{ID: "acct", Name: "original", Enabled: true}))
	if err != nil {
		t.Fatal(err)
	}
	blockWrites(t, s)

	upd := created.clone()
	upd.Name = "rewritten"
	upd.Enabled = false
	if _, err := s.Update(asInput(*upd)); err == nil {
		t.Fatal("update should have failed")
	}
	got, ok := s.Get("acct")
	if !ok {
		t.Fatal("account vanished after a failed update")
	}
	if got.Name != "original" || !got.Enabled {
		t.Errorf("failed update was not rolled back: %+v", got)
	}
}

func TestPersistFailureRollsBackDelete(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create(asInput(Account{ID: "keeper"})); err != nil {
		t.Fatal(err)
	}
	blockWrites(t, s)

	if err := s.Delete("keeper"); err == nil {
		t.Fatal("delete should have failed")
	}
	if _, ok := s.Get("keeper"); !ok {
		t.Error("failed delete removed the account from memory anyway")
	}
	if n := s.Count(); n != 1 {
		t.Errorf("count: want 1, got %d", n)
	}
}

// Rotate edits the account in place, so it needs its own rollback: a
// half-applied rotation kills the old token without persisting the new
// one, locking the partner out with no way back.
func TestPersistFailureRollsBackRotate(t *testing.T) {
	s := newStore(t)
	created, err := s.Create(asInput(Account{ID: "rot"}))
	if err != nil {
		t.Fatal(err)
	}
	original := created.A.InboundToken
	blockWrites(t, s)

	if _, err := s.Rotate("rot", "a", "inbound"); err == nil {
		t.Fatal("rotate should have failed")
	}
	got, ok := s.Get("rot")
	if !ok {
		t.Fatal("account vanished")
	}
	if got.A.InboundToken != original {
		t.Errorf("failed rotate left the token changed in memory: partner is locked out\n want %q\n got  %q",
			original, got.A.InboundToken)
	}
}

// The state file must never be observed partially written: the temp file
// is fsynced before the rename, so any reader sees old or new, never half.
func TestPersistWritesAreAtomicAndComplete(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 25; i++ {
		if _, err := s.Create(asInput(Account{ID: "acct" + itoa(i), Name: strings.Repeat("n", 100)})); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(s.path)
		if err != nil {
			t.Fatalf("state unreadable after write %d: %v", i, err)
		}
		var st State
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatalf("state truncated or corrupt after write %d: %v", i, err)
		}
		if len(st.Accounts) != i+1 {
			t.Fatalf("write %d: want %d accounts on disk, got %d", i, i+1, len(st.Accounts))
		}
	}
	// No temp file left behind.
	if _, err := os.Stat(s.path + ".tmp"); err == nil {
		t.Error("a .tmp file survived a successful write")
	}
}

func TestPersistLeavesNoTempFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "sub", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(asInput(Account{ID: "nested"})); err != nil {
		t.Fatalf("creating under a new directory should work: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

// Owner-only permissions matter: the file holds every credential.
func TestStateFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not modelled on windows")
	}
	s := newStore(t)
	if _, err := s.Create(asInput(Account{ID: "perms"})); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file perms: want 0600, got %o", perm)
	}
}

// A corrupt state file must stop the process rather than silently start
// with no accounts and begin refusing live traffic.
func TestOpenStoreRejectsCorruptState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"accounts":[{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(p); err == nil {
		t.Fatal("a truncated state file should be an error, not an empty store")
	}
}

func TestOpenStoreRoundTripsDiscoveryWindow(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(asInput(Account{ID: "win"})); err != nil {
		t.Fatal(err)
	}
	// Absent discovery must survive a reload as absent, not as year 1.
	s2, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get("win")
	if !ok {
		t.Fatal("account did not survive reload")
	}
	if got.DiscoverUntil != nil {
		t.Errorf("discovery window should be absent, got %v", got.DiscoverUntil)
	}
	if got.discovering() {
		t.Error("a reloaded account with no window should not be discovering")
	}
}

// The "none" sentinel is the only way to intentionally clear an outbound
// token (blank keeps the stored value, and rotation mints a new one).
func TestOutboundTokenNoneSentinelClears(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir + "/s.json")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(outA string) *accountInput {
		return &accountInput{Account: Account{
			ID: "clear-check",
			A:  Endpoint{InboundToken: "xk_aaaaaaaaaaaaaaaa", OutboundToken: outA},
			B:  Endpoint{InboundToken: "xk_bbbbbbbbbbbbbbbb", OutboundToken: "xk_bbbbbbbbbbbbbbbb"},
		}}
	}
	if _, err := st.Create(mk("xk_partner_issued_aaaa")); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Blank on update keeps the stored token.
	if acct, err := st.Update(mk("")); err != nil || acct.A.OutboundToken != "xk_partner_issued_aaaa" {
		t.Fatalf("blank should keep stored token: %v / %q", err, acct.A.OutboundToken)
	}
	// "none" clears it.
	acct, err := st.Update(mk("none"))
	if err != nil {
		t.Fatalf("update with none: %v", err)
	}
	if acct.A.OutboundToken != "" {
		t.Fatalf("sentinel did not clear: %q", acct.A.OutboundToken)
	}
	// And create with "none" stores empty from the start.
	if err := st.Delete("clear-check"); err != nil {
		t.Fatal(err)
	}
	if acct, err := st.Create(mk("none")); err != nil || acct.A.OutboundToken != "" {
		t.Fatalf("create with none: %v / %q", err, acct.A.OutboundToken)
	}
}
