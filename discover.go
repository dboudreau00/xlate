package main

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Field discovery answers the onboarding question: a partner is POSTing
// to us, we do not yet know their vocabulary, and we need to build a map
// from what they actually send.
//
// It records the SHAPE of a payload — dot-paths and JSON types — and
// never a value. That distinction is the whole design. Field names are
// schema; field values are the payment identifiers and PII this gateway
// exists to pass through without reading. "Bodies are never captured"
// stays true.
//
// Three further guards, because the input is partner-controlled:
//
//   - Discovery is off by default and time-boxed. It expires on its own,
//     so nobody can leave it on and forget.
//   - Observations live in memory only. They are never written to the
//     audit trail or the state file, so they cannot outlive the process
//     or end up in a backup.
//   - An object with more sibling keys than any real record has is
//     recorded as a map rather than enumerated. JSON keyed by identifier
//     — {"balances":{"cust-91@example.com":…}} — puts data in the key
//     position, and enumerating it would capture exactly what this
//     feature promises not to.
//
// That last guard is a heuristic, and the threshold is the trade-off: set
// it low and a legitimately wide record (which is common — 40-field
// payment objects are ordinary) collapses to nothing useful; set it high
// and a small identifier-keyed object is enumerated. It sits above real
// record widths, and the residual case is covered by the other two
// guards: such payloads blow the total path cap fast and report
// truncated, and nothing survives the window closing.
const (
	maxDiscoveredPaths = 200
	maxDiscoverDepth   = 16
	maxDiscoverKeyLen  = 64
	maxSiblingKeys     = 64
	maxDiscoverWindow  = 24 * time.Hour
	mapKeyPlaceholder  = "{*}"
)

// FieldObservation is one path seen in a partner's payloads.
type FieldObservation struct {
	Path     string    `json:"path"`
	Types    []string  `json:"types"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
	// Mappable is false for paths a field map cannot address: containers,
	// arrays themselves and anything that is not an object inside one, arrays
	// inside arrays, and the contents of identifier-keyed objects. A field of
	// an array's elements is mappable, as "lines[].sku".
	Mappable bool `json:"mappable"`
}

// DiscoveryReport is what the admin API returns for one direction.
type DiscoveryReport struct {
	Requests  int                `json:"requests"`
	FirstSeen time.Time          `json:"first_seen,omitempty"`
	LastSeen  time.Time          `json:"last_seen,omitempty"`
	Truncated bool               `json:"truncated"`
	Fields    []FieldObservation `json:"fields"`
}

type directionSchema struct {
	paths     map[string]*FieldObservation
	requests  int
	firstSeen time.Time
	lastSeen  time.Time
	truncated bool
}

// SchemaStore accumulates observations per account and direction. A2B
// and B2A are kept apart on purpose: they are two different vocabularies
// and mixing them would produce a map that is wrong in one direction.
type SchemaStore struct {
	mu sync.Mutex
	m  map[string]*directionSchema
}

func NewSchemaStore() *SchemaStore {
	return &SchemaStore{m: map[string]*directionSchema{}}
}

func schemaKey(account string, dir Direction) string {
	return account + "|" + dir.String()
}

// Observe records the shape of one payload and returns the paths seen in
// it, newest-request-first ordering being the caller's concern. It must
// run before Translate, which mutates the payload in place.
func (s *SchemaStore) Observe(account string, dir Direction, payload map[string]any) []string {
	if s == nil {
		return nil
	}
	// Walk first, then apply under a single lock. Taking the mutex once
	// per path would mean up to maxDiscoveredPaths acquisitions per
	// request on the data path, contending with every other account's
	// observations — the same shape of bug the tripwire had.
	//
	// A path repeats within one payload when it lies inside an array, once
	// per element. It is recorded once, with every type it showed, so a count
	// stays the number of payloads it appeared in and a long array cannot use
	// up the path budget on copies of itself.
	type observed struct {
		path     string
		types    []string
		mappable bool
	}
	found := make([]observed, 0, 16)
	at := make(map[string]int, 16)
	seen := make([]string, 0, 16)
	truncated := false
	// A body that is itself an array is walked as one, so its fields read
	// "[].sku" and not the engine's name for it.
	var root any = payload
	if arr, bare := payload[rootKey]; bare {
		root = arr
	}
	walkShape("", root, 0, false, func(path, typ string, mappable bool) {
		if i, dup := at[path]; dup {
			if !containsString(found[i].types, typ) {
				found[i].types = append(found[i].types, typ)
				seen = append(seen, path+":"+typ)
			}
			return
		}
		if len(found) >= maxDiscoveredPaths {
			truncated = true
			return
		}
		at[path] = len(found)
		found = append(found, observed{path, []string{typ}, mappable})
		seen = append(seen, path+":"+typ)
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	ds := s.schemaLocked(account, dir)
	now := time.Now().UTC()
	for _, o := range found {
		obs := ds.paths[o.path]
		if obs == nil {
			if len(ds.paths) >= maxDiscoveredPaths {
				ds.truncated = true
				continue
			}
			obs = &FieldObservation{Path: o.path, Mappable: o.mappable}
			ds.paths[o.path] = obs
		}
		obs.Count++
		obs.LastSeen = now
		for _, typ := range o.types {
			if !containsString(obs.Types, typ) {
				obs.Types = append(obs.Types, typ)
				sort.Strings(obs.Types)
			}
		}
	}
	ds.requests++
	if ds.firstSeen.IsZero() {
		ds.firstSeen = now
	}
	ds.lastSeen = now
	if truncated {
		ds.truncated = true
	}
	sort.Strings(seen)
	return seen
}

func (s *SchemaStore) schemaLocked(account string, dir Direction) *directionSchema {
	k := schemaKey(account, dir)
	ds := s.m[k]
	if ds == nil {
		ds = &directionSchema{paths: map[string]*FieldObservation{}}
		s.m[k] = ds
	}
	return ds
}

// Report returns the accumulated schema for one direction.
func (s *SchemaStore) Report(account string, dir Direction) DiscoveryReport {
	out := DiscoveryReport{Fields: []FieldObservation{}}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ds := s.m[schemaKey(account, dir)]
	if ds == nil {
		return out
	}
	out.Requests, out.FirstSeen, out.LastSeen, out.Truncated = ds.requests, ds.firstSeen, ds.lastSeen, ds.truncated
	for _, obs := range ds.paths {
		out.Fields = append(out.Fields, *obs)
	}
	sort.Slice(out.Fields, func(i, j int) bool { return out.Fields[i].Path < out.Fields[j].Path })
	return out
}

// Forget drops everything recorded for an account, in both directions.
// Called when discovery is switched off and when an account is deleted.
func (s *SchemaStore) Forget(account string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, dir := range []Direction{AtoB, BtoA} {
		delete(s.m, schemaKey(account, dir))
	}
}

// walkShape emits (path, jsonType, mappable) for every addressable
// position in a decoded payload. Values are read only to determine their
// type; none is retained.
//
// The elements of an array are walked the way a map addresses them: the
// fields of its object elements as "lines[].sku", at most maxArrayLen of
// them, and any other element as "lines[]" with its type, which is how a
// mixed array shows. Only one level can be addressed, so an array inside an
// element (inElem) is reported and not walked. A body that is itself an array
// is walked from an empty prefix and reads "[].sku" and "[]".
func walkShape(prefix string, v any, depth int, inElem bool, emit func(path, typ string, mappable bool)) {
	switch t := v.(type) {
	case map[string]any:
		if depth >= maxDiscoverDepth {
			emit(prefix, "object", false)
			return
		}
		// Identifier-keyed objects: record the shape, not the keys.
		if len(t) > maxSiblingKeys {
			emit(joinPath(prefix, mapKeyPlaceholder), "object", false)
			return
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := joinPath(prefix, safeKey(k))
			// A key that itself holds brackets would read as an array path
			// below it, and a map cannot address it: nothing under it is mappable.
			emitChild := emit
			if strings.ContainsAny(k, "[]") {
				emitChild = func(path, typ string, _ bool) { emit(path, typ, false) }
			}
			switch t[k].(type) {
			case map[string]any:
				emitChild(child, "object", false)
				walkShape(child, t[k], depth+1, inElem, emitChild)
			default:
				walkShape(child, t[k], depth+1, inElem, emitChild)
			}
		}
	case []any:
		// An empty prefix is a body that is itself an array: it has no path of
		// its own, only elements ("[]").
		if prefix != "" {
			emit(prefix, "array", false)
		}
		if inElem {
			return
		}
		for i, el := range t {
			if i == maxArrayLen {
				break
			}
			if _, isObj := el.(map[string]any); isObj {
				walkShape(prefix+"[]", el, depth+1, true, emit)
			} else {
				emit(prefix+"[]", jsonType(el), false)
			}
		}
	case string:
		emit(prefix, "string", true)
	case bool:
		emit(prefix, "bool", true)
	case nil:
		emit(prefix, "null", true)
	default:
		// json.Number and any other scalar.
		emit(prefix, "number", true)
	}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// safeKey bounds and sanitises a partner-supplied JSON key before it can
// reach a log line or an API response.
func safeKey(k string) string {
	k = safeLogValue(k, maxDiscoverKeyLen)
	if k == "" {
		return strconv.Quote("")
	}
	return k
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// discovering reports whether the account is inside its discovery window.
func (a *Account) discovering() bool {
	return a.DiscoverUntil != nil && time.Now().Before(*a.DiscoverUntil)
}

// suggestPairs turns an observed schema into starter mapping rows, so
// the operator can wire a partner from what they actually sent instead
// of retyping it. Only mappable scalar paths are offered.
func suggestPairs(rep DiscoveryReport, dir Direction) []FieldPair {
	out := make([]FieldPair, 0, len(rep.Fields))
	for _, f := range rep.Fields {
		if !f.Mappable || strings.Contains(f.Path, mapKeyPlaceholder) {
			continue
		}
		if dir == AtoB {
			out = append(out, FieldPair{A: f.Path})
		} else {
			out = append(out, FieldPair{B: f.Path})
		}
	}
	return out
}
