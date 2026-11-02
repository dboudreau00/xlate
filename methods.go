package main

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// The data plane replays the method it receives, so the methods a side may
// use form a closed list. HEAD and OPTIONS give a translating gateway nothing
// to replay, and TRACE and CONNECT must never be forwarded: none of them can
// be granted.
var dataMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
}

// maxMethodEntries bounds a submitted list before it is checked against the
// closed one, so a document cannot make validation walk through junk.
const maxMethodEntries = 16

// dataMethod returns the table entry equal to s. The outbound request takes
// its method from here, never from the request's own string.
func dataMethod(s string) (string, bool) {
	for _, m := range dataMethods {
		if s == m {
			return m, true
		}
	}
	return "", false
}

// methodHasBody reports whether requests with this method carry a JSON body,
// translated like a POST body, or carry their input in the query string.
func methodHasBody(method string) bool {
	return method != http.MethodGet && method != http.MethodDelete
}

// methodList is what this side may send, in the order of dataMethods. A side
// with no list is POST only, which is what every document written before the
// setting existed means.
func (e Endpoint) methodList() []string {
	if len(e.InboundMethods) == 0 {
		return []string{http.MethodPost}
	}
	out := make([]string, 0, len(e.InboundMethods))
	for _, m := range dataMethods {
		if slices.Contains(e.InboundMethods, m) {
			out = append(out, m)
		}
	}
	return out
}

// allows reports whether this side may send method.
func (e Endpoint) allows(method string) bool {
	if len(e.InboundMethods) == 0 {
		return method == http.MethodPost
	}
	return slices.Contains(e.InboundMethods, method)
}

// normMethods trims and upper-cases a submitted list so "get" and " GET " are
// one entry. Order, duplicates and unknown entries are kept as sent, so
// validation reports them at the position the caller used.
func normMethods(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, m := range in {
		out[i] = strings.ToUpper(strings.TrimSpace(m))
	}
	return out
}

// keepMethods lets a document that leaves the list out, or sends it empty,
// keep the stored one. Omission must never narrow a side that was granted more
// than POST: its partner would start getting 405s with nothing to explain them.
// To narrow a side on purpose, send ["POST"].
func keepMethods(in *Endpoint, cur Endpoint) {
	if len(in.InboundMethods) == 0 {
		in.InboundMethods = slices.Clone(cur.InboundMethods)
	}
}

// validateMethods checks a normalised list. The unknown entry is not echoed:
// it is free text from the caller.
func validateMethods(field string, methods []string, ve *ValidationErrors) {
	if len(methods) > maxMethodEntries {
		ve.add(field, "must list at most %d methods", maxMethodEntries)
		return
	}
	seen := map[string]int{}
	for i, m := range methods {
		entry := fmt.Sprintf("%s[%d]", field, i)
		if !slices.Contains(dataMethods, m) {
			ve.add(entry, "must be one of %s", strings.Join(dataMethods, ", "))
			continue
		}
		if prev, dup := seen[m]; dup {
			ve.add(entry, "duplicates %s already listed at %s[%d]", m, field, prev)
			continue
		}
		seen[m] = i
	}
}
