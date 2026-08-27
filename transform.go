package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Transform converts a field's value in flight. Direction-aware: for a2b
// the value is parsed with AFormat and rendered with BFormat; b2a mirrors.
// The same transform therefore also un-converts reverse-mapped responses,
// keeping each side's vocabulary AND representation intact.
type Transform struct {
	Kind    string `json:"kind"`     // "date" is the only supported kind
	AFormat string `json:"a_format"` // representation on side A
	BFormat string `json:"b_format"` // representation on side B
}

// Named formats accepted in addition to raw Go reference layouts.
var namedLayouts = map[string]string{
	"rfc3339":     time.RFC3339,
	"rfc3339nano": time.RFC3339Nano,
	"date":        "2006-01-02",
	"datetime":    "2006-01-02 15:04:05",
	"rfc1123":     time.RFC1123,
}

// epoch formats are numeric, not layout-based.
const (
	epochSec = "unix"
	epochMS  = "unix_ms"
)

// validate reports whether the transform is usable. The rules live in
// validate.go so config-time checking and the REST layer cannot drift.
func (t *Transform) validate() error {
	if t == nil {
		return nil
	}
	var ve ValidationErrors
	validateTransform(t, "transform", &ve)
	if len(ve) > 0 {
		return ve
	}
	return nil
}

func (t *Transform) apply(v any, dir Direction) (any, error) {
	src, dst := t.AFormat, t.BFormat
	if dir == BtoA {
		src, dst = dst, src
	}
	tm, err := parseDate(v, src)
	if err != nil {
		return nil, err
	}
	return renderDate(tm, dst), nil
}

func parseDate(v any, format string) (time.Time, error) {
	switch format {
	case epochSec, epochMS:
		n, err := toInt64(v)
		if err != nil {
			return time.Time{}, fmt.Errorf("cannot read %v as %s epoch: %w", v, format, err)
		}
		if format == epochMS {
			return time.UnixMilli(n).UTC(), nil
		}
		return time.Unix(n, 0).UTC(), nil
	}
	s, ok := v.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("expected string for layout %q, got %T", format, v)
	}
	layout := format
	if l, known := namedLayouts[format]; known {
		layout = l
	}
	tm, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot parse %q as %q", s, format)
	}
	return tm, nil
}

func renderDate(tm time.Time, format string) any {
	switch format {
	case epochSec:
		return json.Number(strconv.FormatInt(tm.Unix(), 10))
	case epochMS:
		return json.Number(strconv.FormatInt(tm.UnixMilli(), 10))
	}
	layout := format
	if l, known := namedLayouts[format]; known {
		layout = l
	}
	return tm.Format(layout)
}

// toInt64 accepts the shapes an epoch can arrive in over JSON.
func toInt64(v any) (int64, error) {
	switch n := v.(type) {
	case json.Number:
		return n.Int64()
	case string:
		return strconv.ParseInt(strings.TrimSpace(n), 10, 64)
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	}
	return 0, fmt.Errorf("unsupported type %T", v)
}
