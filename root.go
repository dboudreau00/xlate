package main

import (
	"bytes"
	"encoding/json"
)

// A body can be an object or, where the map says so, an array: rows whose
// paths start with [] ("[].sku") address its elements. The engine only knows
// objects, so a bare array travels through it wrapped as {rootKey: [...]} and
// is unwrapped again on the way out; see rootKey in translate.go.

// leadingByte returns the first byte of b that is not JSON whitespace, or 0.
func leadingByte(b []byte) byte {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return c
	}
	return 0
}

// decodeBody decodes a data-plane body that may be a top-level array. rooted
// says that some row addresses one on this side of the message; only then is a
// bare array decoded, and it comes back wrapped under rootKey. Anything else
// is decoded as an object, errors included, exactly as it always was.
func decodeBody(b []byte, rooted bool) (map[string]any, error) {
	if rooted && leadingByte(b) == '[' {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var arr []any
		if err := dec.Decode(&arr); err != nil {
			return nil, err
		}
		if err := ensureNoTrailingData(dec); err != nil {
			return nil, err
		}
		return map[string]any{rootKey: arr}, nil
	}
	return decodeObjectStrict(b)
}

// bodyOf is a translation result as JSON: the top-level array alone when that
// is all the engine left, as it is sent. When the array shares its object with
// other fields the message has been refused (see refuseStrays) and this is
// only for showing it, with the array under the [] it was written with.
func bodyOf(out map[string]any) any {
	arr, bare := out[rootKey]
	if !bare {
		return out
	}
	if len(out) == 1 {
		return arr
	}
	shown := make(map[string]any, len(out))
	for k, v := range out {
		if k == rootKey {
			k = "[]"
		}
		shown[k] = v
	}
	return shown
}
