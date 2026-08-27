package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeoutSec = 15
	maxTimeoutSec     = 300
)

var accountIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// errAccountNotFound lets handlers map a miss to 404 without matching on
// error prose.
var errAccountNotFound = errors.New("account not found")

// errAccountExists marks a create that collides with an existing id.
var errAccountExists = errors.New("account already exists")

// Endpoint describes one side of a translation pairing.
type Endpoint struct {
	Label     string `json:"label"`
	TargetURL string `json:"target_url"`
	// InboundToken is what this side must present when POSTing to xlate.
	InboundToken string `json:"inbound_token"`
	// OutboundToken is what xlate presents (Bearer) when POSTing to
	// this side's TargetURL.
	OutboundToken string `json:"outbound_token"`
}

// Account binds two endpoints to a shared bidirectional field map.
type Account struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Enabled      bool        `json:"enabled"`
	A            Endpoint    `json:"a"`
	B            Endpoint    `json:"b"`
	Map          []FieldPair `json:"map"`
	DropUnmapped bool        `json:"drop_unmapped"`
	TimeoutSec   int         `json:"timeout_sec"`
	// DiscoverUntil time-boxes field discovery. While it is in the
	// future, the shape of inbound payloads (paths and types, never
	// values) is recorded so an operator can wire a map from what a
	// partner actually sends.
	//
	// A pointer so "off" is absent rather than a zero timestamp:
	// omitempty does not apply to structs, so a time.Time here would put
	// a meaningless year-1 date in every response.
	DiscoverUntil *time.Time `json:"discover_until,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (a *Account) clone() *Account {
	c := *a
	// make+copy rather than append(nil, ...): appending zero elements to a
	// nil slice yields nil, which would turn an empty map back into JSON
	// null on the way out.
	c.Map = make([]FieldPair, len(a.Map))
	copy(c.Map, a.Map)
	return &c
}

// accountInput is the wire shape for create and update. It shadows
// Enabled with a pointer so an omitted field can be told apart from an
// explicit false: omission must never silently flip a live account,
// which is the same rule blank token fields already follow.
type accountInput struct {
	Account
	Enabled *bool `json:"enabled"`
}

// resolve folds the input onto the stored document. On create an
// unspecified account is enabled — you create one in order to use it,
// and it cannot forward anything until a target_url is set anyway. On
// update an unspecified value is retained.
func (in *accountInput) resolve(current *Account, creating bool) *Account {
	a := in.Account
	switch {
	case in.Enabled != nil:
		a.Enabled = *in.Enabled
	case creating:
		a.Enabled = true
	case current != nil:
		a.Enabled = current.Enabled
	}
	return &a
}

func (a *Account) timeout() time.Duration {
	t := a.TimeoutSec
	if t <= 0 {
		t = defaultTimeoutSec
	}
	if t > maxTimeoutSec {
		t = maxTimeoutSec
	}
	return time.Duration(t) * time.Second
}

// State is the on-disk document. Versioned so future migrations have a
// hook to key off.
type State struct {
	Version  int        `json:"version"`
	Accounts []*Account `json:"accounts"`
}

// Store owns the state and its persistence. All mutations are
// serialized and flushed atomically (write temp + rename, 0600).
type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, state: State{Version: 1}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil // first run; file materializes on first write
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.state); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	return s, nil
}

// persistLocked writes the state durably: temp file, fsync, rename,
// then fsync the directory.
//
// The rename is what makes the swap atomic, but rename alone is not
// durable — without the fsync a crash can leave the new name pointing at
// a file whose contents never reached the disk, and this file holds every
// account and every credential. Losing it is losing the deployment.
func (s *Store) persistLocked() error {
	b, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	// Fsync the directory so the rename itself survives a crash. Best
	// effort: Windows does not support syncing a directory handle.
	if dir == "" {
		dir = "."
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// snapshotLocked copies the account list so a failed write can be undone.
// Elements are pointers, so a caller that mutates an account in place
// must snapshot that account separately.
func (s *Store) snapshotLocked() []*Account {
	return append([]*Account(nil), s.state.Accounts...)
}

// persistOrRollbackLocked keeps memory and disk in step. Without it a
// failed write (full disk, read-only mount) returns an error to the
// caller while the change stays live in memory: the account would serve
// traffic, appear in the API, and then vanish on restart.
func (s *Store) persistOrRollbackLocked(prev []*Account) error {
	if err := s.persistLocked(); err != nil {
		s.state.Accounts = prev
		return err
	}
	return nil
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.state.Accounts)
}

// MaxTimeout reports the largest effective upstream timeout across all
// accounts, so shutdown can size its drain window to the slowest request
// it may actually be holding.
func (s *Store) MaxTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := time.Duration(defaultTimeoutSec) * time.Second
	for _, a := range s.state.Accounts {
		if t := a.timeout(); t > m {
			m = t
		}
	}
	return m
}

func (s *Store) List() []*Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Account, 0, len(s.state.Accounts))
	for _, a := range s.state.Accounts {
		out = append(out, a.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) Get(id string) (*Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.state.Accounts {
		if a.ID == id {
			return a.clone(), true
		}
	}
	return nil, false
}

func (s *Store) findLocked(id string) (int, *Account) {
	for i, a := range s.state.Accounts {
		if a.ID == id {
			return i, a
		}
	}
	return -1, nil
}

// Create validates and inserts a new account, filling defaults and
// generating any tokens the caller left blank.
func (s *Store) Create(input *accountInput) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	in := input.resolve(nil, true)
	// Normalise before the collision check: " acme" and "acme" are the
	// same account once trimmed, so checking first would let the second
	// one through and then fail on validation for the wrong reason.
	applyDefaults(in)
	if err := validateAccount(in); err != nil {
		return nil, err
	}
	if _, existing := s.findLocked(in.ID); existing != nil {
		return nil, fmt.Errorf("%w: %q", errAccountExists, in.ID)
	}
	now := time.Now().UTC()
	in.CreatedAt, in.UpdatedAt = now, now
	prev := s.snapshotLocked()
	s.state.Accounts = append(s.state.Accounts, in.clone())
	if err := s.persistOrRollbackLocked(prev); err != nil {
		return nil, err
	}
	return in.clone(), nil
}

// Update replaces an existing account. Blank token fields in the
// incoming document retain the stored value, so a client can never
// wipe credentials by omission.
func (s *Store) Update(input *accountInput) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	i, cur := s.findLocked(input.ID)
	if cur == nil {
		return nil, fmt.Errorf("%w: %q", errAccountNotFound, input.ID)
	}
	in := input.resolve(cur, false)
	mergeTokens(&in.A, cur.A)
	mergeTokens(&in.B, cur.B)
	applyDefaults(in)
	if err := validateAccount(in); err != nil {
		return nil, err
	}
	in.CreatedAt = cur.CreatedAt
	in.UpdatedAt = time.Now().UTC()
	prev := s.snapshotLocked()
	s.state.Accounts[i] = in.clone()
	if err := s.persistOrRollbackLocked(prev); err != nil {
		return nil, err
	}
	return in.clone(), nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, cur := s.findLocked(id)
	if cur == nil {
		return fmt.Errorf("%w: %q", errAccountNotFound, id)
	}
	prev := s.snapshotLocked()
	s.state.Accounts = append(s.state.Accounts[:i], s.state.Accounts[i+1:]...)
	return s.persistOrRollbackLocked(prev)
}

// Rotate replaces one token (side "a"|"b", kind "inbound"|"outbound")
// and persists immediately.
func (s *Store) Rotate(id, side, kind string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, cur := s.findLocked(id)
	if cur == nil {
		return "", fmt.Errorf("%w: %q", errAccountNotFound, id)
	}
	before := cur.clone()
	ep := &cur.A
	if side == "b" {
		ep = &cur.B
	} else if side != "a" {
		return "", errors.New(`side must be "a" or "b"`)
	}
	tok := newToken()
	switch kind {
	case "inbound":
		ep.InboundToken = tok
	case "outbound":
		ep.OutboundToken = tok
	default:
		return "", errors.New(`kind must be "inbound" or "outbound"`)
	}
	cur.UpdatedAt = time.Now().UTC()
	// Rotate edits the stored account in place, so the slice snapshot is
	// not enough to undo it: a failed write would otherwise leave the old
	// token dead and the new one unpersisted, locking the partner out.
	if err := s.persistLocked(); err != nil {
		*cur = *before
		return "", err
	}
	return tok, nil
}

func mergeTokens(in *Endpoint, cur Endpoint) {
	if strings.TrimSpace(in.InboundToken) == "" {
		in.InboundToken = cur.InboundToken
	}
	// Blank keeps the stored credential (omission must never wipe), which
	// left no way to intentionally remove an outbound token. The literal
	// "none" clears it — an explicit act, unambiguous because real tokens
	// have a 16-character minimum, and matching the UI's wording for the
	// cleared state ("none — sent without Authorization").
	switch strings.TrimSpace(in.OutboundToken) {
	case "":
		in.OutboundToken = cur.OutboundToken
	case outboundTokenNone:
		in.OutboundToken = ""
	}
}

// outboundTokenNone is the explicit-clear sentinel for outbound tokens.
const outboundTokenNone = "none"

func applyDefaults(a *Account) {
	a.ID = strings.TrimSpace(a.ID)
	a.Name = strings.TrimSpace(a.Name)
	if a.Name == "" {
		a.Name = a.ID
	}
	if a.A.Label == "" {
		a.A.Label = "System A"
	}
	if a.B.Label == "" {
		a.B.Label = "System B"
	}
	if a.A.InboundToken == "" {
		a.A.InboundToken = newToken()
	}
	if a.B.InboundToken == "" {
		a.B.InboundToken = newToken()
	}
	// On create there is nothing to merge against, so map the explicit
	// "no outbound auth" sentinel to the empty stored form here.
	if strings.TrimSpace(a.A.OutboundToken) == outboundTokenNone {
		a.A.OutboundToken = ""
	}
	if strings.TrimSpace(a.B.OutboundToken) == outboundTokenNone {
		a.B.OutboundToken = ""
	}
	// Only an omitted timeout takes the default; an out-of-range one is
	// rejected by validation rather than silently clamped, so the stored
	// document always matches what the caller asked for.
	if a.TimeoutSec == 0 {
		a.TimeoutSec = defaultTimeoutSec
	}
	// Drop rows that are blank on both sides (empty grid rows in the UI).
	kept := a.Map[:0]
	for _, p := range a.Map {
		p.A, p.B = strings.TrimSpace(p.A), strings.TrimSpace(p.B)
		if p.A == "" && p.B == "" {
			continue
		}
		// Transform formats are matched by exact string at runtime (named
		// layouts, epoch keywords) while validation checks the trimmed
		// value — so the stored value must BE the trimmed value, or
		// "unix " passes validation and then renders every date as the
		// literal string "unix ".
		if p.Transform != nil {
			t := *p.Transform
			t.Kind = strings.TrimSpace(t.Kind)
			t.AFormat = strings.TrimSpace(t.AFormat)
			t.BFormat = strings.TrimSpace(t.BFormat)
			p.Transform = &t
		}
		kept = append(kept, p)
	}
	a.Map = kept
	if a.Map == nil {
		// A list field must serialise as [], never null: an account with
		// no pairs is a normal state (you create one before you know the
		// partner's vocabulary) and every client would have to special-case
		// it otherwise.
		a.Map = []FieldPair{}
	}
}

// validateAccount reports every structural problem with a normalised
// account document. See validate.go for the individual rules.
func validateAccount(a *Account) error {
	if ve := validateAccountDoc(a); len(ve) > 0 {
		return ve
	}
	return nil
}

// newToken returns a 192-bit random token, hex encoded, with a short
// prefix so leaked credentials are attributable in scans.
func newToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "xk_" + hex.EncodeToString(b)
}

func newAdminToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "xadm_" + hex.EncodeToString(b)
}
