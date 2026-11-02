package main

import (
	"fmt"
	"strconv"
	"strings"
)

// What a partner-controlled array may cost. Unlike the path rules in
// validate.go, an array's length belongs to the payload, so it cannot be
// checked when the account is saved: it is checked on every message, and a
// message over the limit is refused, never truncated or passed on.
const (
	maxArrayLen = 1000
	// maxNotes bounds the warnings and failed paths one Translate keeps. A row
	// outside an array yields at most three, so no ordinary map reaches it;
	// without it a hostile array would yield a few per element. Counts stay
	// exact.
	maxNotes = 3 * maxMapPairs
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
// address top-level keys. A [] after a name addresses every element of the
// array there ("lines[].sku"); see Translate.
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
	// Strict makes a failed value transform fatal. The warning is still
	// recorded, and the field's source path is added to Failed.
	Strict bool
}

type TranslateResult struct {
	Out     map[string]any
	Applied int
	// Warnings holds the first maxNotes warnings; Warned counts all of them.
	Warnings []string
	Warned   int
	// Failed lists the source paths whose transform failed under Strict.
	// When it is not empty Out must be refused, not forwarded: it carries
	// the unconverted values the caller asked to be kept out.
	Failed []string
	// Refused names the arrays a row addresses that cannot be translated as
	// mapped: too long, not an array, or holding something that is not an
	// object. Like Failed it means Out must be refused, not forwarded; unlike
	// Failed it holds whatever the mode, and Out is then the payload untouched.
	Refused []FieldError
}

func (r *TranslateResult) warn(msg string) {
	r.Warned++
	if len(r.Warnings) < maxNotes {
		r.Warnings = append(r.Warnings, msg)
	}
}

func (r *TranslateResult) fail(path string) {
	if len(r.Failed) < maxNotes {
		r.Failed = append(r.Failed, path)
	}
}

func (r *TranslateResult) refuse(path, why string) {
	if len(r.Refused) < maxNotes {
		r.Refused = append(r.Refused, FieldError{Field: path, Message: why})
	}
}

// absorb folds in the result of translating one array element, naming the
// element in everything it reports.
func (r *TranslateResult) absorb(elem string, er TranslateResult) {
	r.Applied += er.Applied
	r.Warned += er.Warned
	for _, w := range er.Warnings {
		if len(r.Warnings) >= maxNotes {
			break
		}
		r.Warnings = append(r.Warnings, elem+": "+w)
	}
	for _, f := range er.Failed {
		r.fail(elem + "." + f)
	}
}

// arrayHit is every row under one array, and the array itself once read.
type arrayHit struct {
	src, dst string      // where the array is in the payload, and where it goes
	rows     []FieldPair // the rows under it, relative to one element; A and B as in the map
	val      any
	found    bool
}

// mentionsArray is the cheap test that keeps rows without brackets, which is
// nearly every row, out of the array code altogether.
func mentionsArray(a, b string) bool {
	return strings.IndexByte(a, '[') >= 0 && strings.IndexByte(b, '[') >= 0
}

// isArrayRow reports whether p addresses an array on both sides.
func isArrayRow(p FieldPair) bool {
	_, _, aok := splitArrayPath(p.A)
	_, _, bok := splitArrayPath(p.B)
	return aok && bok
}

// addArrayRow files p under its array. It reports false for a row that does
// not address an array on both sides, which the caller then treats as an
// ordinary row.
func addArrayRow(arrays *[]*arrayHit, p FieldPair, dir Direction) bool {
	aArr, aIn, aok := splitArrayPath(p.A)
	bArr, bIn, bok := splitArrayPath(p.B)
	if !aok || !bok {
		return false
	}
	src, dst := aArr, bArr
	if dir == BtoA {
		src, dst = bArr, aArr
	}
	var ah *arrayHit
	for _, c := range *arrays {
		if c.src == src && c.dst == dst {
			ah = c
			break
		}
	}
	if ah == nil {
		ah = &arrayHit{src: src, dst: dst}
		*arrays = append(*arrays, ah)
	}
	ah.rows = append(ah.rows, FieldPair{A: aIn, B: bIn, Transform: p.Transform})
	return true
}

// checkArray records why the value at an addressed array cannot be translated.
func (r *TranslateResult) checkArray(path string, v any) {
	switch t := v.(type) {
	case nil:
		// null is how a nil list is usually sent; it crosses as null.
	case []any:
		if len(t) > maxArrayLen {
			r.refuse(path, fmt.Sprintf("has %d elements; at most %d are accepted", len(t), maxArrayLen))
			return
		}
		for i, el := range t {
			if _, ok := el.(map[string]any); !ok {
				r.refuse(path+"["+strconv.Itoa(i)+"]", "must be an object, got "+jsonType(el))
			}
		}
	default:
		r.refuse(path, "must be an array or null, got "+jsonType(v))
	}
}

// jsonType names the JSON type of a decoded value, never the value.
func jsonType(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "bool"
	case nil:
		return "null"
	}
	return "number"
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
//   - transform fails: the value passes untransformed with a warning; under
//     Strict its source path is also recorded in Failed
//   - a [] in a path addresses every element of an array: the rows under
//     "lines[]" ("lines[].sku") are grouped by their array. The array moves
//     from one side's name to the other's as a unit, and each element is
//     translated by the rows under it as an object of its own, with the same
//     options, so an element's unmapped fields stay in it (or go, under
//     DropUnmapped, leaving {} so no element is ever removed). null crosses as
//     null and a missing array is a no-op. An array of more than maxArrayLen
//     elements, a value that is not an array, and an element that is not an
//     object cannot be translated as mapped: Refused names them, nothing is
//     changed, and Out is the payload as it came.
func Translate(payload map[string]any, pairs []FieldPair, dir Direction, opt TranslateOptions) TranslateResult {
	return translate(payload, pairs, dir, opt, true)
}

// translate is Translate. Rows are searched for arrays only when addressable
// is set: the rows under an array have had their [] taken off already, and an
// element is not searched again, which keeps a long array of small elements
// down to the rows that apply to them.
func translate(payload map[string]any, pairs []FieldPair, dir Direction, opt TranslateOptions, addressable bool) TranslateResult {
	res := TranslateResult{}

	type hit struct {
		src string
		dst string
		val any
		tr  *Transform
	}
	// An element rarely holds every field the map knows; do not size for them all.
	size := len(pairs)
	if !addressable && size > len(payload) {
		size = len(payload)
	}
	hits := make([]hit, 0, size)

	// Arrays are read and checked before anything is changed, so a refusal
	// leaves the payload as the sender wrote it. A row with a bracket on both
	// sides addresses an array; one that does not parse as such is an
	// ordinary row, as it was before arrays existed.
	var arrays []*arrayHit
	if addressable {
		for _, p := range pairs {
			if mentionsArray(p.A, p.B) {
				addArrayRow(&arrays, p, dir)
			}
		}
		for _, ah := range arrays {
			if ah.val, ah.found = getPath(payload, ah.src); ah.found {
				res.checkArray(ah.src, ah.val)
			}
		}
		if len(res.Refused) > 0 {
			res.Out = payload
			return res
		}
	}

	// Phase 1: extract.
	for _, p := range pairs {
		src, dst := p.A, p.B
		if dir == BtoA {
			src, dst = p.B, p.A
		}
		if src == "" || dst == "" {
			continue
		}
		if addressable && mentionsArray(src, dst) && isArrayRow(p) {
			continue
		}
		if v, ok := getPath(payload, src); ok {
			delPath(payload, src)
			hits = append(hits, hit{src: src, dst: dst, val: v, tr: p.Transform})
		}
	}
	for _, ah := range arrays {
		if ah.found {
			delPath(payload, ah.src)
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
				// for a pass-through gateway, so strict mode is opt-in per
				// account: the caller refuses whatever carries a Failed path.
				res.warn("transform " + strconv.Quote(h.dst) + ": " + err.Error())
				if opt.Strict {
					res.fail(h.src)
				}
			} else {
				h.val = v
			}
		}
		ok, warn := setPath(out, h.dst, h.val)
		if warn != "" {
			res.warn(warn)
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
			res.warn("value for " + strconv.Quote(h.dst) + " left at source " + strconv.Quote(h.src))
		}
	}

	// Arrays move like any other value; what differs is that the elements are
	// translated once the array has somewhere to go. A blocked destination
	// restores the array untouched, so nothing is half translated.
	for _, ah := range arrays {
		if !ah.found {
			continue
		}
		ok, warn := setPath(out, ah.dst, ah.val)
		if warn != "" {
			res.warn(warn)
		}
		if !ok {
			if rok, _ := setPath(out, ah.src, ah.val); !rok {
				out[ah.src] = ah.val
			}
			res.warn("value for " + strconv.Quote(ah.dst) + " left at source " + strconv.Quote(ah.src))
			continue
		}
		elems, _ := ah.val.([]any)
		for i, el := range elems {
			// checkArray vouched for every element being an object.
			if em, isObj := el.(map[string]any); isObj {
				er := translate(em, ah.rows, dir, opt, false)
				elems[i] = er.Out
				res.absorb(ah.src+"["+strconv.Itoa(i)+"]", er)
			}
		}
	}

	res.Out = out
	return res
}

// splitArrayPath splits "order.lines[].sku" at its [] into the path of the
// array ("order.lines") and the path inside each of its elements ("sku").
// validateDotPath is the strict judge of what an array path may look like;
// this reads only what a validated path holds, and reports false for anything
// that is not of that shape.
func splitArrayPath(p string) (array, inner string, ok bool) {
	i := strings.Index(p, "[]")
	if i <= 0 || len(p) < i+4 || p[i+2] != '.' {
		return "", "", false
	}
	return p[:i], p[i+3:], true
}

// getPath resolves a dot-path against nested map[string]any values.
func getPath(m map[string]any, path string) (any, bool) {
	// A single name is by far the commonest path and needs no splitting. It
	// matters most for a field missing from every element of a long array.
	if strings.IndexByte(path, '.') < 0 {
		v, ok := m[path]
		return v, ok
	}
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
