package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// GET and DELETE carry no body, so their input is the query string. It is
// turned into the shape a JSON body decodes to and goes through Translate, so
// a pair means the same thing in a body and in a query, and the collision,
// drop-unmapped, transform and strict rules are the ones bodies already have.
// On the way out the translated object is flattened back into parameters.
//
// A name that is a dot-path expands to nested objects ("customer.id" is
// customer, then id) and is flattened again afterwards; that is what lets a
// pair written for a body address a query. Values stay strings, because that
// is all a query carries, and a repeated name crosses as a list. A name that
// is not a path the map could address (an empty segment, brackets, too long)
// stays a flat key that no pair can match, so it passes through or is dropped
// together with the rest of the unmapped input.
const (
	maxQueryBytes  = 8 << 10
	maxQueryParams = 100
)

// errQueryClash means a translated parameter has the name of one the target
// URL fixes. The fixed one always wins, so the request is refused rather than
// merged: a partner must not be able to replace a credential the operator put
// in the target's query.
var errQueryClash = errors.New("a query parameter collides with one the destination fixes")

// queryPayload parses the query string of a bodyless request into the object
// the translation engine works on. Every refusal is a ValidationErrors.
func queryPayload(raw string) (map[string]any, error) {
	var ve ValidationErrors
	if len(raw) > maxQueryBytes {
		ve.add("query", "must be at most %d bytes", maxQueryBytes)
		return nil, ve
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		// The parser's message quotes the bad fragment; the caller already
		// knows what it sent, so the generic wording is enough.
		ve.add("query", "is not a valid query string (check percent-encoding and separators)")
		return nil, ve
	}
	n := 0
	for _, v := range vals {
		n += len(v)
	}
	if n > maxQueryParams {
		ve.add("query", "must carry at most %d parameters", maxQueryParams)
		return nil, ve
	}

	// Sorted, so a parent name is stored before the names beneath it and a
	// clash is found the same way whatever order the caller used.
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]any, len(keys))
	for _, k := range keys {
		var v any = vals[k][0]
		if len(vals[k]) > 1 {
			list := make([]any, len(vals[k]))
			for i, s := range vals[k] {
				list[i] = s
			}
			v = list
		}
		if !queryPath(k) {
			out[k] = v
			continue
		}
		if !setNested(out, strings.Split(k, "."), v) {
			ve.add("query."+safeLogValue(k, maxLoggedFieldName),
				"conflicts with another parameter: one name is a parent of the other")
		}
	}
	if len(ve) > 0 {
		return nil, ve
	}
	return out, nil
}

// queryPath reports whether a parameter name is a path the engine can
// address. Every path a map may contain is one; the rule is kept here, not
// borrowed from the map validator, so a change to what a map may contain does
// not silently change which query names expand.
func queryPath(k string) bool {
	if k == "" || len(k) > maxPathLen || !utf8.ValidString(k) {
		return false
	}
	segments := strings.Split(k, ".")
	if len(segments) > maxPathDepth {
		return false
	}
	for _, s := range segments {
		if s == "" || strings.ContainsAny(s, "[]") {
			return false
		}
	}
	for _, r := range k {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// setNested stores v at path, creating the objects on the way. It reports
// false when the path runs through a value that is not an object or ends on a
// name that is already taken.
func setNested(m map[string]any, path []string, v any) bool {
	cur := m
	for _, p := range path[:len(path)-1] {
		next, exists := cur[p]
		if !exists {
			child := map[string]any{}
			cur[p] = child
			cur = child
			continue
		}
		child, isObject := next.(map[string]any)
		if !isObject {
			return false
		}
		cur = child
	}
	last := path[len(path)-1]
	if _, taken := cur[last]; taken {
		return false
	}
	cur[last] = v
	return true
}

// queryValues flattens a translated object back into query parameters: nested
// objects become dotted names and a list becomes a repeated parameter. An
// emptied container produces nothing, so no container name crosses. Anything
// that is not a string, a number or a list of those cannot have come from a
// query and is refused rather than guessed at.
func queryValues(m map[string]any) (url.Values, error) {
	out := url.Values{}
	var add func(name string, v any) error
	add = func(name string, v any) error {
		switch t := v.(type) {
		case string:
			out.Add(name, t)
		case json.Number:
			out.Add(name, t.String())
		case []any:
			for _, e := range t {
				switch ev := e.(type) {
				case string:
					out.Add(name, ev)
				case json.Number:
					out.Add(name, ev.String())
				default:
					return fmt.Errorf("unsupported list element %T", e)
				}
			}
		case map[string]any:
			for k, c := range t {
				if err := add(joinPath(name, k), c); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unsupported value %T", v)
		}
		return nil
	}
	for k, v := range m {
		if err := add(k, v); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// withQuery appends the translated parameters to the target URL's own query.
// What the target fixes is kept byte for byte and always wins: a parameter of
// the same name, in any letter case since some servers fold it, is refused.
// Host, path and scheme are the operator's and are never touched.
func withQuery(target string, add url.Values) (string, error) {
	if len(add) == 0 {
		return target, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	fixed, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", err
	}
	for name := range add {
		for have := range fixed {
			if strings.EqualFold(name, have) {
				return "", errQueryClash
			}
		}
	}
	enc := add.Encode()
	if u.RawQuery == "" {
		u.RawQuery = enc
	} else {
		u.RawQuery += "&" + enc
	}
	return u.String(), nil
}
