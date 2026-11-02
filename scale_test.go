package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Wide maps, several accounts, both directions, all at once.
//
// Every message carries ~100 mapped fields spread over four nested groups
// (24 fields each) and is unique, so a value that lands in the wrong field,
// the wrong request or the wrong account cannot go unnoticed. The upstream
// echoes what it received, which makes the return leg an identity check:
// translate, forward, reverse-map must give the caller back its own message.

const (
	scaleGroups = 4
	scaleFields = 24 // plain pairs per group
)

var (
	scaleAGroups = [scaleGroups]string{"customer", "billing", "shipping", "order"}
	scaleBGroups = [scaleGroups]string{"party", "invoice", "delivery", "purchase"}
	scaleMap     = scalePairs()
)

type scalePair struct {
	a, b string
	date bool
}

// scalePairs is the map every account in the scenario uses. Side B renames
// each group and flattens the last one, so renaming and reshaping both run,
// and two pairs carry a date transform.
func scalePairs() []scalePair {
	var ps []scalePair
	for g := 0; g < scaleGroups; g++ {
		for f := 0; f < scaleFields; f++ {
			a := fmt.Sprintf("%s.fld%02d", scaleAGroups[g], f)
			b := fmt.Sprintf("%s.col%02d", scaleBGroups[g], f)
			if g == scaleGroups-1 {
				b = fmt.Sprintf("ord_col%02d", f)
			}
			ps = append(ps, scalePair{a: a, b: b})
		}
	}
	return append(ps,
		scalePair{a: "order.placed", b: "purchase.placed_epoch", date: true},
		scalePair{a: "order.shipped", b: "purchase.shipped_epoch", date: true})
}

func scaleMapDoc() []map[string]any {
	rows := make([]map[string]any, 0, len(scaleMap))
	for _, p := range scaleMap {
		row := map[string]any{"a": p.a, "b": p.b}
		if p.date {
			row["transform"] = map[string]any{"kind": "date", "a_format": "rfc3339", "b_format": "unix"}
		}
		rows = append(rows, row)
	}
	return rows
}

// scaleNest places v at a dot-path. The scenario builds both vocabularies
// with this rather than with the engine under test.
func scaleNest(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = v
}

type scaleMsg struct{ a, b map[string]any } // one message, in each vocabulary

func scaleMessage(tag string, n int) scaleMsg {
	m := scaleMsg{a: map[string]any{}, b: map[string]any{}}
	for i, p := range scaleMap {
		var av, bv any
		switch {
		case p.date:
			ts := 1786017600 + int64(n)*10 + int64(i)
			av = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			bv = json.Number(strconv.FormatInt(ts, 10))
		case i%9 == 0:
			// Past 2^53: must cross verbatim, as a number.
			av = json.Number(strconv.FormatInt(9007199254740993+int64(n)*1000+int64(i), 10))
			bv = av
		default:
			av = tag + "/" + strconv.Itoa(i)
			bv = av
		}
		scaleNest(m.a, p.a, av)
		scaleNest(m.b, p.b, bv)
	}
	// Unmapped fields cross untouched in either direction, and an array is
	// carried whole: its elements are not addressable.
	for _, side := range []map[string]any{m.a, m.b} {
		side["note"] = "free text " + tag
		side["items"] = []any{
			map[string]any{"sku": "s-" + tag, "qty": json.Number("2")},
			map[string]any{"sku": "t-" + tag, "qty": json.Number("1")},
		}
		side["meta"] = map[string]any{"trace": tag}
	}
	return m
}

// scaleLeaves flattens a payload to path -> canonical JSON for every leaf
// (an array is one leaf) and lists the empty objects apart: an emptied
// parent is left behind on purpose, so group names cross as empty objects.
func scaleLeaves(m map[string]any) (leaves map[string]string, empties []string) {
	leaves = map[string]string{}
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, v := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if sub, ok := v.(map[string]any); ok {
				if len(sub) == 0 {
					empties = append(empties, p)
				} else {
					walk(p, sub)
				}
				continue
			}
			b, _ := json.Marshal(v)
			leaves[p] = string(b)
		}
	}
	walk("", m)
	sort.Strings(empties)
	return leaves, empties
}

func scaleDiff(want, got map[string]string) []string {
	var d []string
	for k, w := range want {
		if g, ok := got[k]; !ok {
			d = append(d, "missing "+k)
		} else if g != w {
			d = append(d, fmt.Sprintf("%s: got %s, want %s", k, g, w))
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			d = append(d, "unexpected "+k)
		}
	}
	sort.Strings(d)
	return d
}

type scaleHit struct {
	path, auth string
	body       []byte
}

// scaleUpstream is both partner systems at once: it records what each
// request carried, keyed by X-Request-Id, and answers with the same body.
type scaleUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]scaleHit
}

func newScaleUpstream(t *testing.T) *scaleUpstream {
	t.Helper()
	u := &scaleUpstream{hits: map[string]scaleHit{}}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.hits[r.Header.Get("X-Request-Id")] = scaleHit{r.URL.Path, r.Header.Get("Authorization"), b}
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *scaleUpstream) hit(id string) (scaleHit, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	h, ok := u.hits[id]
	return h, ok
}

// scalePost is safe to call from any goroutine; it reports rather than
// fails, because t.Fatal belongs to the test goroutine.
func scalePost(c *http.Client, url, token, reqID string, payload map[string]any) (int, http.Header, []byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", reqID)
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, body, err
}

func scaleOut(side, id string) string { return "out" + side + "-" + id + "-0123456789ab" }

func TestScaleWideMapsManyAccountsBothDirections(t *testing.T) {
	const (
		accounts  = 6
		workers   = 4 // per account and direction
		perWorker = 8
		perAcct   = 2 * workers * perWorker
		total     = accounts * perAcct
	)
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	up := newScaleUpstream(t)

	type acct struct{ id, tokA, tokB string }
	var accts []acct
	for i := 0; i < accounts; i++ {
		id := fmt.Sprintf("scale%d", i)
		doc := mustCreate(t, ts, map[string]any{
			"id": id, "enabled": true, "map": scaleMapDoc(),
			"a": map[string]any{"target_url": up.URL + "/" + id + "/a", "outbound_token": scaleOut("A", id)},
			"b": map[string]any{"target_url": up.URL + "/" + id + "/b", "outbound_token": scaleOut("B", id)},
		})
		accts = append(accts, acct{id, sideToken(doc, "a"), sideToken(doc, "b")})
	}

	type result struct {
		acct, dir, id string
		msg           scaleMsg
		status        int
		hdr           http.Header
		body          []byte
		err           error
	}
	var (
		mu      sync.Mutex
		results []result
		wg      sync.WaitGroup
	)
	tr := &http.Transport{MaxIdleConnsPerHost: 64}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}
	for _, a := range accts {
		for _, dir := range []string{"a2b", "b2a"} {
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(a acct, dir string, w int) {
					defer wg.Done()
					for k := 0; k < perWorker; k++ {
						n := w*perWorker + k
						reqID := fmt.Sprintf("%s-%s-%d", a.id, dir, n)
						msg := scaleMessage(reqID, n)
						sent, tok := msg.a, a.tokA
						if dir == "b2a" {
							sent, tok = msg.b, a.tokB
						}
						st, hdr, body, err := scalePost(client, ts.URL+"/t/"+a.id+"/"+dir, tok, reqID, sent)
						mu.Lock()
						results = append(results, result{a.id, dir, reqID, msg, st, hdr, body, err})
						mu.Unlock()
					}
				}(a, dir, w)
			}
		}
	}
	wg.Wait()
	if len(results) != total {
		t.Fatalf("ran %d requests, want %d", len(results), total)
	}

	residueA := append([]string(nil), scaleAGroups[:]...)
	residueB := append([]string(nil), scaleBGroups[:]...)
	sort.Strings(residueA)
	sort.Strings(residueB)

	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }
	check := func(what string, got []byte, want map[string]any, wantResidue []string) {
		gl, ge := scaleLeaves(mustObj(t, string(got)))
		wl, _ := scaleLeaves(want)
		if d := scaleDiff(wl, gl); len(d) > 0 {
			fail("%s: %d field differences, first: %s", what, len(d), d[0])
		}
		if !reflect.DeepEqual(ge, wantResidue) {
			fail("%s: empty containers %v, want %v", what, ge, wantResidue)
		}
	}
	for _, r := range results {
		if r.err != nil || r.status != 200 {
			fail("%s: status %d err %v: %.120s", r.id, r.status, r.err, r.body)
			continue
		}
		// What the sender wrote, what the destination must have received,
		// where it must have gone and under whose credential.
		sent, wantDest := r.msg.a, r.msg.b
		destPath, destAuth := "/"+r.acct+"/b", "Bearer "+scaleOut("B", r.acct)
		destResidue, respResidue := residueA, residueB
		if r.dir == "b2a" {
			sent, wantDest = r.msg.b, r.msg.a
			destPath, destAuth = "/"+r.acct+"/a", "Bearer "+scaleOut("A", r.acct)
			destResidue, respResidue = residueB, residueA
		}
		hit, ok := up.hit(r.id)
		if !ok {
			fail("%s: never reached the destination", r.id)
			continue
		}
		if hit.path != destPath || hit.auth != destAuth {
			fail("%s: reached %s with %q, want %s with %q", r.id, hit.path, hit.auth, destPath, destAuth)
		}
		check(r.id+" at the destination", hit.body, wantDest, destResidue)
		check(r.id+" back at the caller", r.body, sent, respResidue)
		if got, want := r.hdr.Get("X-Xlate-Applied"), strconv.Itoa(2*len(scaleMap)); got != want {
			fail("%s: X-Xlate-Applied %s, want %s", r.id, got, want)
		}
		if w := r.hdr.Get("X-Xlate-Warnings"); w != "" {
			fail("%s: unexpected warnings: %s", r.id, w)
		}
	}
	if len(failures) > 0 {
		if len(failures) > 8 {
			failures = append(failures[:8], "...")
		}
		t.Fatalf("%d requests failed verification:\n%s", len(failures), strings.Join(failures, "\n"))
	}

	// The counters and the trail must agree with what actually ran.
	st := admin(t, ts, "GET", "/api/admin/stats", nil).json(t)["stats"].(map[string]any)
	if got, _ := st["total"].(json.Number).Int64(); got != total {
		t.Errorf("stats total %d, want %d", got, total)
	}
	rows, _ := st["accounts"].([]any)
	if len(rows) != accounts {
		t.Errorf("stats has %d account rows, want %d", len(rows), accounts)
	}
	for _, row := range rows {
		m := row.(map[string]any)
		if got, _ := m["ok"].(json.Number).Int64(); got != perAcct {
			t.Errorf("stats for %v: %d delivered, want %d", m["account"], got, perAcct)
		}
	}
	path := srv.audit.f.Name()
	if err := VerifyAudit(path, discardWriter{}); err != nil {
		t.Fatalf("audit chain broke under concurrent traffic: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(raw, []byte(`"event":"ingest.ok"`)); n != total {
		t.Errorf("audit trail has %d ingest.ok records, want %d", n, total)
	}
}

// The documented ceiling, end to end: a 500-pair map is accepted by the
// admin API and translates both ways without loss.
func TestScaleMaxSizeMapEndToEnd(t *testing.T) {
	rows := make([]map[string]any, maxMapPairs)
	msgA, msgB := map[string]any{}, map[string]any{}
	for i := range rows {
		a := fmt.Sprintf("g%d.f%03d", i%10, i)
		b := fmt.Sprintf("h%d.k.c%03d", i%7, i)
		rows[i] = map[string]any{"a": a, "b": b}
		v := fmt.Sprintf("value-%03d", i)
		scaleNest(msgA, a, v)
		scaleNest(msgB, b, v)
	}
	ts := newAPI(t)
	up := newScaleUpstream(t)
	doc := mustCreate(t, ts, map[string]any{
		"id": "maxmap", "enabled": true, "map": rows,
		"a": map[string]any{"target_url": up.URL + "/a"},
		"b": map[string]any{"target_url": up.URL + "/b"},
	})

	st, hdr, body, err := scalePost(http.DefaultClient, ts.URL+"/t/maxmap/a2b", sideToken(doc, "a"), "max-1", msgA)
	if err != nil || st != 200 {
		t.Fatalf("status %d err %v: %.200s", st, err, body)
	}
	hit, _ := up.hit("max-1")
	gotDest, _ := scaleLeaves(mustObj(t, string(hit.body)))
	wantDest, _ := scaleLeaves(msgB)
	if d := scaleDiff(wantDest, gotDest); len(d) > 0 {
		t.Errorf("destination received %d wrong fields, first: %s", len(d), d[0])
	}
	gotBack, _ := scaleLeaves(mustObj(t, string(body)))
	wantBack, _ := scaleLeaves(msgA)
	if d := scaleDiff(wantBack, gotBack); len(d) > 0 {
		t.Errorf("caller got %d wrong fields back, first: %s", len(d), d[0])
	}
	if got, want := hdr.Get("X-Xlate-Applied"), strconv.Itoa(2*maxMapPairs); got != want {
		t.Errorf("X-Xlate-Applied %s, want %s", got, want)
	}
	if w := hdr.Get("X-Xlate-Warnings"); w != "" {
		t.Errorf("unexpected warnings: %s", w)
	}
}
