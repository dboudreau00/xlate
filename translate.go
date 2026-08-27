package main

import (
	"strconv"
	"strings"
)

// Direction selects which column of a FieldPair is the source.
type Direction int

const (
	AtoB Direction = iota
	BtoA
)

func (d Direction) Reverse() Direction {
	if d == AtoB {
		return BtoA
	}
	return AtoB
}

func (d Direction) String() string {
	if d == AtoB {
		return "a2b"
	}
	return "b2a"
}

// ParseDirection maps the wire form ("a2b"/"b2a") to a Direction.
func ParseDirection(s string) (Direction, bool) {
	switch s {
	case "a2b":
		return AtoB, true
	case "b2a":
		return BtoA, true
	}
	return AtoB, false
}

// FieldPair is one bidirectional vocabulary entry: field name on side A,
// field name on side B. Names are dot-paths ("customer.id"); plain names
// address top-level keys. Array indexing is out of scope for v0.1.
type FieldPair struct {
	A string `json:"a"`
	B string `json:"b"`
	// Transform, when set, converts the value in flight (not just the
	// name). "date" is the only supported kind.
	Transform *Transform `json:"transform,omitempty"`
}

type TranslateOptions struct {
	// DropUnmapped, when true, builds the output only from mapped fields.
	// When false (default) unmapped fields pass through untouched.
	DropUnmapped bool
}

type TranslateResult struct {
	Out      map[string]any
	Applied  int
	Warnings []string
}

// Translate renames fields in payload according to pairs and direction.
//
// It runs in two phases: every source value is extracted (and removed)
// first, then every destination is assigned. This makes swapped pairs
// within one map (x->y and y->x) safe — a single-pass rename would
// clobber. payload is mutated in place unless DropUnmapped is set.
//
// Semantics:
//   - missing source: no-op for that pair
//   - destination already exists: overwritten, recorded as a warning
//   - destination path crosses a non-object value: the value stays at its
//     source path untranslated, warning — never dropped
//   - intermediate objects on the destination path are created as needed
func Translate(payload map[string]any, pairs []FieldPair, dir Direction, opt TranslateOptions) TranslateResult {
	res := TranslateResult{}

	type hit struct {
		src string
		dst string
		val any
		tr  *Transform
	}
	hits := make([]hit, 0, len(pairs))

	// Phase 1: extract.
	for _, p := range pairs {
		src, dst := p.A, p.B
		if dir == BtoA {
			src, dst = p.B, p.A
		}
		if src == "" || dst == "" {
			continue
		}
		if v, ok := getPath(payload, src); ok {
			delPath(payload, src)
			hits = append(hits, hit{src: src, dst: dst, val: v, tr: p.Transform})
		}
	}

	out := payload
	if opt.DropUnmapped {
		out = map[string]any{}
	}

	// Phase 2: transform + assign.
	for _, h := range hits {
		if h.tr != nil {
			v, err := h.tr.apply(h.val, dir)
			if err != nil {
				// Fail-open: the untransformed value is forwarded and the
				// failure surfaces as a warning (header + logs). Rejecting
				// the whole request over one bad date is the worse default
				// for a pass-through gateway; strict mode is a roadmap knob.
				res.Warnings = append(res.Warnings, "transform "+strconv.Quote(h.dst)+": "+err.Error())
			} else {
				h.val = v
			}
		}
		ok, warn := setPath(out, h.dst, h.val)
		if warn != "" {
			res.Warnings = append(res.Warnings, warn)
		}
		if ok {
			res.Applied++
		} else {
			// The destination was unreachable (an intermediate segment is
			// not an object), but the value was already extracted in phase
			// 1. Dropping it would silently delete a field this gateway
			// exists to pass through — restore it at its source path
			// instead, matching the transform fail-open rule: on any
			// per-field failure the original data still flows.
			if rok, _ := setPath(out, h.src, h.val); !rok {
				// The source path is blocked too (its parent was consumed
				// by another pair). Last resort: park the value under its
				// full source path as a flat key so it survives the trip.
				out[h.src] = h.val
			}
			res.Warnings = append(res.Warnings, "value for "+strconv.Quote(h.dst)+" left at source "+strconv.Quote(h.src))
		}
	}

	res.Out = out
	return res
}

// getPath resolves a dot-path against nested map[string]any values.
func getPath(m map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	cur := m
	for i, p := range parts {
		v, ok := cur[p]
		if !ok {
			return nil, false
		}
		if i == len(parts)-1 {
			return v, true
		}
		next, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return nil, false
}

// delPath removes the value at a dot-path. Empty parent objects left
// behind are preserved deliberately: silently pruning containers the
// caller may rely on is more surprising than an empty object.
func delPath(m map[string]any, path string) {
	parts := strings.Split(path, ".")
	cur := m
	for i, p := range parts {
		if i == len(parts)-1 {
			delete(cur, p)
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
}

// setPath assigns val at a dot-path, creating intermediate objects.
// Returns ok=false when an intermediate segment exists but is not an
// object. A non-empty warn is returned both for that case and for a
// successful overwrite of an existing destination.
func setPath(m map[string]any, path string, val any) (ok bool, warn string) {
	parts := strings.Split(path, ".")
	cur := m
	for i, p := range parts {
		if i == len(parts)-1 {
			if _, exists := cur[p]; exists {
				warn = "overwrote existing field " + strconv.Quote(path)
			}
			cur[p] = val
			return true, warn
		}
		v, exists := cur[p]
		if !exists {
			next := map[string]any{}
			cur[p] = next
			cur = next
			continue
		}
		next, isMap := v.(map[string]any)
		if !isMap {
			return false, "cannot set " + strconv.Quote(path) + ": segment " + strconv.Quote(p) + " is not an object"
		}
		cur = next
	}
	return false, ""
}
