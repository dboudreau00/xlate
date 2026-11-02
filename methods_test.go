package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Methods on the data plane: GET, PUT, PATCH and DELETE next to POST, in both
// directions, with the translation, credential isolation and audit guarantees
// POST already has. Each side lists the methods it may send; none listed means
// POST only.

const (
	mtAIn  = "xk_a_inbound_0123456789abcdef"
	mtBIn  = "xk_b_inbound_0123456789abcdef"
	mtAOut = "xk_a_outbound_secret_for_a_only"
	mtBOut = "xk_b_outbound_secret_for_b_only"

	mtDate  = "2026-08-06T12:00:00Z" // side A's representation of an instant
	mtEpoch = "1786017600"           // side B's representation of the same one
)

var (
	mtAllMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	mtAllTokens  = []string{mtAIn, mtBIn, mtAOut, mtBOut}
)

// mtSeen is one request exactly as a partner system received it.
type mtSeen struct {
	method, uri, body string
	hdr               http.Header
}

// wire renders the whole request so a leak can be searched for anywhere in it.
func (s mtSeen) wire() string {
	var b strings.Builder
	b.WriteString(s.method + " " + s.uri + "\n")
	for k, v := range s.hdr {
		b.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	b.WriteString(s.body)
	return b.String()
}

// mtPartner stands in for one partner system. It records what xlate sent and
// answers with whatever the test last set.
type mtPartner struct {
	*httptest.Server
	mu                  sync.Mutex
	seen                []mtSeen
	status              int
	ct, reply, location string
}

func newMtPartner(t *testing.T) *mtPartner {
	t.Helper()
	p := &mtPartner{status: 200, ct: "application/json", reply: `{}`}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.seen = append(p.seen, mtSeen{r.Method, r.RequestURI, string(b), r.Header.Clone()})
		status, ct, reply, loc := p.status, p.ct, p.reply, p.location
		p.mu.Unlock()
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *mtPartner) answer(status int, ct, reply string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status, p.ct, p.reply, p.location = status, ct, reply, ""
}

func (p *mtPartner) hits() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

// take returns the one request recorded since the last take.
func (p *mtPartner) take(t *testing.T) mtSeen {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.seen) != 1 {
		t.Fatalf("the partner saw %d requests, want exactly 1: %v", len(p.seen), p.seen)
	}
	s := p.seen[0]
	p.seen = nil
	return s
}

// mtDoc is an account between two recording partners. A nil list leaves that
// side at the default, which is POST only.
func mtDoc(id string, a, b *mtPartner, aMethods, bMethods []string) map[string]any {
	return map[string]any{
		"id": id,
		"a": map[string]any{"label": "Acme", "target_url": a.URL,
			"inbound_token": mtAIn, "outbound_token": mtAOut, "inbound_methods": aMethods},
		"b": map[string]any{"label": "Globex", "target_url": b.URL,
			"inbound_token": mtBIn, "outbound_token": mtBOut, "inbound_methods": bMethods},
		"map": []map[string]any{
			{"a": "payment_id", "b": "payment_proof"},
			{"a": "customer.id", "b": "party.ref"},
			{"a": "created_at", "b": "created_epoch", "transform": map[string]any{
				"kind": "date", "a_format": "rfc3339", "b_format": "unix"}},
		},
	}
}

func mtJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return v
}

func mtSameJSON(t *testing.T, got, want string) {
	t.Helper()
	if g, w := mtJSON(t, got), mtJSON(t, want); !reflect.DeepEqual(g, w) {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// mtTrail returns the audit records of one event, decoded.
func mtTrail(t *testing.T, srv *Server, event string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strictTrail(t, srv), "\n") {
		if line == "" {
			continue
		}
		rec := mtJSON(t, line).(map[string]any)
		if rec["event"] == event {
			out = append(out, rec["detail"].(map[string]any))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Both directions, every method

// mtDir is one direction of the account from mtDoc: who sends, what the
// destination must receive, and what the sender must get back, each in its own
// side's vocabulary.
type mtDir struct {
	name, token, bearer string
	dest                *mtPartner
	body, wantBody      string
	query               string
	wantQuery           url.Values
	reply, wantReply    string
}

func mtDirections(a, b *mtPartner) []mtDir {
	return []mtDir{
		{
			name: "a2b", token: mtAIn, dest: b, bearer: mtBOut,
			body: `{"payment_id":"p-1","customer":{"id":"c-7"},"created_at":"` + mtDate + `","note":"n"}`,
			// The emptied "customer" is left behind in a body, as it always has
			// been (leaf-level isolation). A query has no containers, so none of
			// that crosses there.
			wantBody:  `{"payment_proof":"p-1","party":{"ref":"c-7"},"created_epoch":` + mtEpoch + `,"note":"n","customer":{}}`,
			query:     "payment_id=p-1&customer.id=c-7&created_at=2026-08-06T12%3A00%3A00Z&note=n",
			wantQuery: url.Values{"payment_proof": {"p-1"}, "party.ref": {"c-7"}, "created_epoch": {mtEpoch}, "note": {"n"}},
			reply:     `{"payment_proof":"p-1","created_epoch":` + mtEpoch + `,"result":"ok"}`,
			wantReply: `{"payment_id":"p-1","created_at":"` + mtDate + `","result":"ok"}`,
		},
		{
			name: "b2a", token: mtBIn, dest: a, bearer: mtAOut,
			body:      `{"payment_proof":"p-1","party":{"ref":"c-7"},"created_epoch":` + mtEpoch + `,"note":"n"}`,
			wantBody:  `{"payment_id":"p-1","customer":{"id":"c-7"},"created_at":"` + mtDate + `","note":"n","party":{}}`,
			query:     "payment_proof=p-1&party.ref=c-7&created_epoch=" + mtEpoch + "&note=n",
			wantQuery: url.Values{"payment_id": {"p-1"}, "customer.id": {"c-7"}, "created_at": {mtDate}, "note": {"n"}},
			reply:     `{"payment_id":"p-1","created_at":"` + mtDate + `","result":"ok"}`,
			wantReply: `{"payment_proof":"p-1","created_epoch":` + mtEpoch + `,"result":"ok"}`,
		},
	}
}

// request is what the sender puts on the wire for one method.
func (d mtDir) request(method string) (path string, body any, hdr map[string]string) {
	hdr = map[string]string{"X-Request-Id": "rid-" + d.name + "-" + method, "Idempotency-Key": "idem-" + method}
	path = "/t/duo/" + d.name
	if methodHasBody(method) {
		// A query on a bodied method is not read, as on POST today.
		return path + "?ignored=1", d.body, hdr
	}
	return path + "?" + d.query, nil, hdr
}

// expect checks one crossing: what the destination received, and what the
// sender got back.
func (d mtDir) expect(t *testing.T, method string, status int, respHdr http.Header, respBody []byte) {
	t.Helper()
	if status != 200 {
		t.Fatalf("want 200, got %d: %s", status, respBody)
	}
	got := d.dest.take(t)

	if got.method != method {
		t.Errorf("the destination saw %s, want %s", got.method, method)
	}
	if auth := got.hdr.Get("Authorization"); auth != "Bearer "+d.bearer {
		t.Errorf("the destination saw Authorization %q, want its own outbound token", auth)
	}
	wire := got.wire()
	for _, tok := range mtAllTokens {
		if tok != d.bearer && strings.Contains(wire, tok) {
			t.Errorf("the destination received %s", tok)
		}
	}
	if v := got.hdr.Get("X-Request-Id"); v != "rid-"+d.name+"-"+method {
		t.Errorf("X-Request-Id = %q", v)
	}
	if v := got.hdr.Get("Idempotency-Key"); v != "idem-"+method {
		t.Errorf("Idempotency-Key = %q", v)
	}
	if ua := got.hdr.Get("User-Agent"); ua != "xlate/"+version {
		t.Errorf("User-Agent = %q", ua)
	}

	if methodHasBody(method) {
		if got.uri != "/" {
			t.Errorf("the caller's query was forwarded on %s: %s", method, got.uri)
		}
		if ct := got.hdr.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		mtSameJSON(t, got.body, d.wantBody)
	} else {
		if got.body != "" || got.hdr.Get("Content-Type") != "" {
			t.Errorf("%s forwarded a body or a content type: %q %q", method, got.body, got.hdr.Get("Content-Type"))
		}
		u, err := url.ParseRequestURI(got.uri)
		if err != nil || u.Path != "/" {
			t.Fatalf("destination request = %s (%v)", got.uri, err)
		}
		if !reflect.DeepEqual(u.Query(), d.wantQuery) {
			t.Errorf("destination query = %v\nwant %v", u.Query(), d.wantQuery)
		}
	}

	mtSameJSON(t, string(respBody), d.wantReply)
	if v := respHdr.Get("X-Xlate-Applied"); v != "5" {
		t.Errorf("X-Xlate-Applied = %q, want 5 (three pairs out, two back)", v)
	}
	if v := respHdr.Get("X-Xlate-Warnings"); v != "" {
		t.Errorf("X-Xlate-Warnings = %q on clean traffic", v)
	}
}

func TestEveryMethodCrossesInBothDirections(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, mtAllMethods, mtAllMethods))

	for _, d := range mtDirections(a, b) {
		for _, method := range mtAllMethods {
			t.Run(d.name+" "+method, func(t *testing.T) {
				d.dest.answer(200, "application/json", d.reply)
				path, body, hdr := d.request(method)
				r := call(t, ts, method, path, d.token, body, hdr)
				d.expect(t, method, r.status, r.hdr, r.body)
			})
		}
	}
}

// ---------------------------------------------------------------------------
// The method gate

func TestUnlistedMethodIs405BeforeAuthenticationAndAnythingCounted(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, []string{"GET", "POST"}, nil))

	for _, tc := range []struct{ method, dir, token, allow string }{
		{"PUT", "a2b", mtAIn, "GET, POST"},
		{"PATCH", "a2b", "", "GET, POST"}, // no credentials at all: never a 401
		{"DELETE", "a2b", "wrong-token-entirely", "GET, POST"},
		{"get", "a2b", mtAIn, "GET, POST"}, // methods are case-sensitive
		{"GET", "b2a", mtBIn, "POST"},      // side B was granted nothing
		{"PUT", "b2a", "", "POST"},
		{"DELETE", "b2a", mtBIn, "POST"},
	} {
		for i := 0; i < 8; i++ { // past the tripwire threshold on purpose
			r := call(t, ts, tc.method, "/t/duo/"+tc.dir, tc.token, nil)
			if r.status != 405 || r.hdr.Get("Allow") != tc.allow || r.json(t)["code"] != "method_not_allowed" {
				t.Fatalf("%s %s: want 405 Allow %q, got %d %q %s", tc.method, tc.dir, tc.allow, r.status, r.hdr.Get("Allow"), r.body)
			}
		}
	}
	for _, m := range []string{"HEAD", "OPTIONS", "TRACE"} {
		if r := call(t, ts, m, "/t/duo/a2b", mtAIn, nil); r.status != 405 || r.hdr.Get("Allow") != "GET, POST" {
			t.Errorf("%s: want 405 Allow \"GET, POST\", got %d %q", m, r.status, r.hdr.Get("Allow"))
		}
	}

	if a.hits()+b.hits() != 0 {
		t.Error("a refused method reached a partner")
	}
	tw := admin(t, ts, "GET", "/api/admin/tripwire", nil).json(t)["duo"].(map[string]any)
	if tw["state"] != "armed" || tw["count"].(json.Number).String() != "0" {
		t.Errorf("a wrong method fed the tripwire: %v", tw)
	}
	if r := call(t, ts, "POST", "/t/duo/a2b", mtAIn, `{"payment_id":"p"}`); r.status != 200 {
		t.Errorf("the account was locked by wrong methods: %d %s", r.status, r.body)
	}
	if strings.Contains(strictTrail(t, srv), `"event":"ingest.denied"`) {
		t.Error("a wrong method was audited as a denial")
	}

	// It is visible in the activity log, with the method that was tried.
	logs := admin(t, ts, "GET", "/api/admin/logs?account=duo&limit=500", nil).json(t)["entries"].([]any)
	var refused int
	for _, e := range logs {
		if m := e.(map[string]any); m["status"].(json.Number).String() == "405" {
			refused++
			if m["method"] == nil || m["method"] == "" {
				t.Errorf("a 405 entry does not name the method: %v", m)
			}
		}
	}
	if refused == 0 {
		t.Error("the activity log shows no 405")
	}
}

// The method is the sender's to choose only from its own list; an unknown
// account or direction is still a 404, as for POST.
func TestMethodGateOrderingAgainstUnknownTargetsAndLockouts(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, []string{"GET"}, nil))

	if r := call(t, ts, "GET", "/t/ghost/a2b", mtAIn, nil); r.status != 404 || r.json(t)["code"] != "not_found" {
		t.Errorf("unknown account: %d %s", r.status, r.body)
	}
	if r := call(t, ts, "GET", "/t/duo/sideways", mtAIn, nil); r.status != 404 || r.json(t)["code"] != "bad_direction" {
		t.Errorf("bad direction: %d %s", r.status, r.body)
	}

	// Lock the account with refused credentials on the one method side A has.
	for i := 0; i < 6; i++ {
		if r := call(t, ts, "GET", "/t/duo/a2b", "guess", nil); r.status != 401 {
			t.Fatalf("guess %d: want 401, got %d", i+1, r.status)
		}
	}
	if r := call(t, ts, "GET", "/t/duo/a2b", mtAIn, nil); r.status != 429 || r.json(t)["code"] != "account_locked" {
		t.Errorf("a locked account must answer 429 on a method it allows, valid credentials included: %d %s", r.status, r.body)
	}
	// A method the side was never granted keeps answering 405, locked or not:
	// it says nothing the Allow header did not, and costs no audit record.
	if r := call(t, ts, "DELETE", "/t/duo/a2b", mtAIn, nil); r.status != 405 {
		t.Errorf("a refused method on a locked account: want 405, got %d", r.status)
	}
}

func TestMethodThatIsAllowedFeedsTheTripwireLikePost(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, []string{"GET", "DELETE"}, nil))

	for _, m := range []string{"GET", "DELETE", "GET", "DELETE", "GET", "DELETE"} {
		if r := call(t, ts, m, "/t/duo/a2b", "not-the-token", nil); r.status != 401 {
			t.Fatalf("%s with a bad token: want 401, got %d", m, r.status)
		}
	}
	// The sixth refusal tripped it; it was itself still a 401.
	r := call(t, ts, "GET", "/t/duo/a2b", mtAIn, nil)
	if r.status != 429 || r.json(t)["code"] != "account_locked" {
		t.Fatalf("want 429 account_locked after the trip, got %d %s", r.status, r.body)
	}
	if st := admin(t, ts, "GET", "/api/admin/tripwire", nil).json(t)["duo"].(map[string]any)["state"]; st != "locked" {
		t.Errorf("tripwire state = %v", st)
	}

	trail := mtTrail(t, srv, "ingest.denied")
	if len(trail) != 6 {
		t.Fatalf("%d denial records, want 6", len(trail))
	}
	seen := map[any]bool{}
	for _, d := range trail {
		seen[d["method"]] = true
	}
	if !seen["GET"] || !seen["DELETE"] {
		t.Errorf("denial records do not name the method: %v", trail)
	}
	if blocked := mtTrail(t, srv, "ingest.blocked"); len(blocked) != 1 || blocked[0]["method"] != "GET" {
		t.Errorf("blocked records = %v", blocked)
	}
}

func TestEveryMethodSharesTheSidesRateAllowance(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	doc := mtDoc("lim", a, b, []string{"GET", "PUT", "DELETE"}, mtAllMethods)
	doc["rate_limit_per_min"] = 3
	mustCreate(t, ts, doc)

	// A method the side was not granted spends nothing.
	for i := 0; i < 6; i++ {
		if r := call(t, ts, "PATCH", "/t/lim/a2b", mtAIn, `{"payment_id":"p"}`); r.status != 405 {
			t.Fatalf("want 405, got %d", r.status)
		}
	}
	for _, m := range []string{"GET", "DELETE", "PUT"} {
		var body any
		if methodHasBody(m) {
			body = `{"payment_id":"p"}`
		}
		if r := call(t, ts, m, "/t/lim/a2b", mtAIn, body); r.status != 200 {
			t.Fatalf("%s inside the allowance: %d %s", m, r.status, r.body)
		}
	}
	r := call(t, ts, "GET", "/t/lim/a2b", mtAIn, nil)
	if r.status != 429 || r.json(t)["code"] != "rate_limited" || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("the fourth request of any method is over the limit: %d %s", r.status, r.body)
	}
	if b.hits() != 3 {
		t.Errorf("the destination saw %d requests, want 3", b.hits())
	}
	// Side B has its own allowance, and the refusal is no credential guess.
	if r := call(t, ts, "DELETE", "/t/lim/b2a", mtBIn, nil); r.status != 200 {
		t.Errorf("side B was refused because side A was flooding: %d %s", r.status, r.body)
	}
	tw := admin(t, ts, "GET", "/api/admin/tripwire", nil).json(t)["lim"].(map[string]any)
	if tw["state"] != "armed" || tw["count"].(json.Number).String() != "0" {
		t.Errorf("tripwire = %v", tw)
	}
}

// ---------------------------------------------------------------------------
// Bodyless methods

func TestQueryRequestsAreStrictWhateverTheAccountSays(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("lax", a, b, mtAllMethods, nil)) // strict_transforms off

	for _, m := range []string{"GET", "DELETE"} {
		r := call(t, ts, m, "/t/lax/a2b?payment_id=p&created_at=yesterday", mtAIn, nil)
		if r.status != 422 || r.json(t)["code"] != "transform_failed" {
			t.Fatalf("%s: want 422 transform_failed, got %d %s", m, r.status, r.body)
		}
		if fe := r.fieldErrors(t); len(fe) != 1 || fe["created_at"] == "" {
			t.Errorf("%s: the sender should be told which of its own parameters failed: %v", m, fe)
		}
		for _, leak := range []string{"created_epoch", "payment_proof", "unix", "rfc3339", "yesterday"} {
			if strings.Contains(string(r.body), leak) {
				t.Errorf("%s: the refusal leaks %q: %s", m, leak, r.body)
			}
		}
	}
	if b.hits() != 0 {
		t.Fatalf("a refused query reached the destination (%d hits)", b.hits())
	}
	refused := mtTrail(t, srv, "ingest.rejected")
	if len(refused) != 2 || refused[0]["method"] != "GET" || refused[1]["method"] != "DELETE" || refused[0]["reason"] != "transform" {
		t.Errorf("rejection records = %v", refused)
	}
	if strings.Contains(strictTrail(t, srv), "yesterday") {
		t.Error("the offending value reached the audit trail")
	}

	// A body follows the account's setting, as POST always has: fail open.
	for _, m := range []string{"POST", "PUT", "PATCH"} {
		r := call(t, ts, m, "/t/lax/a2b", mtAIn, `{"created_at":"yesterday"}`)
		if r.status != 200 || r.hdr.Get("X-Xlate-Warnings") != "1" {
			t.Fatalf("%s: a body must keep failing open: %d warnings=%q %s", m, r.status, r.hdr.Get("X-Xlate-Warnings"), r.body)
		}
		if got := b.take(t); !strings.Contains(got.body, `"created_epoch":"yesterday"`) {
			t.Errorf("%s: the value should have travelled unconverted: %s", m, got.body)
		}
	}

	// And strict on refuses bodies as well.
	doc := mtDoc("lax", a, b, mtAllMethods, nil)
	doc["strict_transforms"] = true
	if r := admin(t, ts, "PUT", "/api/admin/accounts/lax", doc); r.status != 200 {
		t.Fatalf("update: %d %s", r.status, r.body)
	}
	for _, m := range []string{"POST", "PUT", "PATCH"} {
		if r := call(t, ts, m, "/t/lax/a2b", mtAIn, `{"created_at":"yesterday"}`); r.status != 422 {
			t.Errorf("%s: strict account should refuse, got %d", m, r.status)
		}
	}
	if b.hits() != 0 {
		t.Errorf("strict refusals reached the destination (%d hits)", b.hits())
	}
}

// The response leg is not a query: it follows the account, for every method.
func TestResponseLegStrictnessFollowsTheAccountForGet(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	b.answer(200, "application/json", `{"created_epoch":"garbage","payment_proof":"p"}`)

	mustCreate(t, ts, mtDoc("lax", a, b, mtAllMethods, nil))
	r := call(t, ts, "GET", "/t/lax/a2b?payment_id=p", mtAIn, nil)
	if r.status != 200 || r.hdr.Get("X-Xlate-Warnings") != "1" || !strings.Contains(string(r.body), "garbage") {
		t.Errorf("fail-open response leg changed: %d warnings=%q %s", r.status, r.hdr.Get("X-Xlate-Warnings"), r.body)
	}

	strict := mtDoc("strict", a, b, mtAllMethods, nil)
	strict["strict_transforms"] = true
	mustCreate(t, ts, strict)
	r = call(t, ts, "GET", "/t/strict/a2b?payment_id=p", mtAIn, nil)
	if r.status != 502 || r.json(t)["code"] != "upstream_invalid" || strings.Contains(string(r.body), "garbage") {
		t.Errorf("strict response leg: want 502 upstream_invalid with no value, got %d %s", r.status, r.body)
	}
}

func TestBodyOnGetOrDeleteIsRefusedAndBodiedMethodsStillNeedAnObject(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, mtAllMethods, mtAllMethods))

	for _, m := range []string{"GET", "DELETE"} {
		r := call(t, ts, m, "/t/duo/a2b?payment_id=p", mtAIn, `{"payment_id":"p"}`)
		if r.status != 400 || r.json(t)["code"] != "validation_failed" {
			t.Fatalf("%s with a body: want 400 validation_failed, got %d %s", m, r.status, r.body)
		}
		if fe := r.fieldErrors(t); fe["body"] == "" {
			t.Errorf("%s: the refusal should name the body: %s", m, r.body)
		}
	}
	if b.hits() != 0 {
		t.Errorf("a body on GET or DELETE reached the destination")
	}
	// An empty body with a JSON content type is just no body.
	if r := call(t, ts, "GET", "/t/duo/a2b?payment_id=p", mtAIn, ""); r.status != 200 {
		t.Errorf("an empty body on GET: %d %s", r.status, r.body)
	}

	for _, m := range []string{"POST", "PUT", "PATCH"} {
		for body, code := range map[string]string{`[1]`: "bad_json", ``: "bad_json", `{"a":1}{"b":2}`: "bad_json", `null`: "bad_json"} {
			r := call(t, ts, m, "/t/duo/a2b", mtAIn, body)
			if r.status != 400 || r.json(t)["code"] != code {
				t.Errorf("%s %q: want 400 %s, got %d %s", m, body, code, r.status, r.body)
			}
		}
	}
}

func TestQueryRefusalsOnTheDataPlane(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, mtAllMethods, mtAllMethods))

	many := make([]string, maxQueryParams+1)
	for i := range many {
		many[i] = fmt.Sprintf("p%d=1", i)
	}
	for name, tc := range map[string]struct{ query, field string }{
		"bad escape":       {"payment_id=%zz", "query"},
		"semicolon":        {"payment_id=1;x=2", "query"},
		"value and parent": {"customer=1&customer.id=2", "query.customer.id"},
		"too long":         {"x=" + strings.Repeat("v", maxQueryBytes), "query"},
		"too many":         {strings.Join(many, "&"), "query"},
	} {
		for _, m := range []string{"GET", "DELETE"} {
			r := call(t, ts, m, "/t/duo/a2b?"+tc.query, mtAIn, nil)
			if r.status != 400 || r.json(t)["code"] != "validation_failed" || r.fieldErrors(t)[tc.field] == "" {
				t.Errorf("%s %s: want 400 on %q, got %d %s", m, name, tc.field, r.status, r.body)
			}
		}
	}
	if b.hits() != 0 {
		t.Errorf("a refused query reached the destination")
	}
}

func TestQueryCannotOverrideWhatTheTargetFixes(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	doc := mtDoc("duo", a, b, mtAllMethods, mtAllMethods)
	doc["b"].(map[string]any)["target_url"] = b.URL + "/api?key=SECRET"
	doc["map"] = append(doc["map"].([]map[string]any), map[string]any{"a": "api", "b": "key"})
	mustCreate(t, ts, doc)

	for _, q := range []string{"key=evil", "KEY=evil", "%6bey=evil", "Key=evil&payment_id=p", "api=evil"} {
		for _, m := range []string{"GET", "DELETE"} {
			r := call(t, ts, m, "/t/duo/a2b?"+q, mtAIn, nil)
			if r.status != 400 || r.json(t)["code"] != "validation_failed" {
				t.Errorf("%s ?%s: want 400, got %d %s", m, q, r.status, r.body)
			}
			// The refusal says nothing about what the destination fixes.
			for _, leak := range []string{"key", "SECRET", "evil"} {
				if strings.Contains(strings.ToLower(string(r.body)), strings.ToLower(leak)) {
					t.Errorf("?%s: the refusal leaks %q: %s", q, leak, r.body)
				}
			}
		}
	}
	if b.hits() != 0 {
		t.Fatalf("a colliding parameter reached the destination (%d hits)", b.hits())
	}

	// The target's own parameters stay first, byte for byte, and are sent once.
	if r := call(t, ts, "GET", "/t/duo/a2b?payment_id=p-1&note=n", mtAIn, nil); r.status != 200 {
		t.Fatalf("a clean query: %d %s", r.status, r.body)
	}
	if got := b.take(t); got.uri != "/api?key=SECRET&note=n&payment_proof=p-1" {
		t.Errorf("destination request = %s", got.uri)
	}
	// A body method goes to the target exactly as configured.
	if r := call(t, ts, "PUT", "/t/duo/a2b", mtAIn, `{"payment_id":"p-1"}`); r.status != 200 {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}
	if got := b.take(t); got.uri != "/api?key=SECRET" {
		t.Errorf("destination request = %s", got.uri)
	}
}

func TestDropUnmappedAppliesToQueriesToo(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	open := mtDoc("open", a, b, mtAllMethods, nil)
	closed := mtDoc("closed", a, b, mtAllMethods, nil)
	closed["drop_unmapped"] = true
	mustCreate(t, ts, open)
	mustCreate(t, ts, closed)

	const q = "?payment_id=p&utm_source=x&admin=true"
	call(t, ts, "GET", "/t/open/a2b"+q, mtAIn, nil)
	got, _ := url.ParseQuery(strings.TrimPrefix(b.take(t).uri, "/?"))
	if !reflect.DeepEqual(got, url.Values{"payment_proof": {"p"}, "utm_source": {"x"}, "admin": {"true"}}) {
		t.Errorf("unmapped parameters should pass through by default: %v", got)
	}
	call(t, ts, "DELETE", "/t/closed/a2b"+q, mtAIn, nil)
	got, _ = url.ParseQuery(strings.TrimPrefix(b.take(t).uri, "/?"))
	if !reflect.DeepEqual(got, url.Values{"payment_proof": {"p"}}) {
		t.Errorf("drop_unmapped should leave only mapped parameters: %v", got)
	}
}

// ---------------------------------------------------------------------------
// Responses

func TestResponsesOfTheNewMethodsArePassedThroughLikePost(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	third := newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, mtAllMethods, mtAllMethods))

	t.Run("204 with no body", func(t *testing.T) {
		b.answer(204, "", "")
		r := call(t, ts, "DELETE", "/t/duo/a2b?payment_id=p", mtAIn, nil)
		if r.status != 204 || len(r.body) != 0 {
			t.Errorf("want an empty 204, got %d %q", r.status, r.body)
		}
		b.take(t)
	})
	t.Run("error body is reverse-mapped and the status relayed", func(t *testing.T) {
		b.answer(404, "application/json", `{"payment_proof":"p","error":"nope"}`)
		r := call(t, ts, "GET", "/t/duo/a2b?payment_id=p", mtAIn, nil)
		if r.status != 404 {
			t.Fatalf("status %d", r.status)
		}
		mtSameJSON(t, string(r.body), `{"payment_id":"p","error":"nope"}`)
		b.take(t)
	})
	t.Run("201 on PUT", func(t *testing.T) {
		b.answer(201, "application/json", `{"payment_proof":"p"}`)
		r := call(t, ts, "PUT", "/t/duo/a2b", mtAIn, `{"payment_id":"p"}`)
		if r.status != 201 {
			t.Fatalf("status %d", r.status)
		}
		mtSameJSON(t, string(r.body), `{"payment_id":"p"}`)
		b.take(t)
	})
	t.Run("a non-JSON body is relayed raw", func(t *testing.T) {
		b.answer(200, "text/plain", "plain payment_proof text")
		r := call(t, ts, "GET", "/t/duo/a2b", mtAIn, nil)
		if r.status != 200 || string(r.body) != "plain payment_proof text" || r.hdr.Get("Content-Type") != "text/plain" {
			t.Errorf("got %d %q %q", r.status, r.body, r.hdr.Get("Content-Type"))
		}
		b.take(t)
	})
	// Known gap, not new: a JSON array is not an object, so it is relayed raw in
	// the destination's vocabulary. Pinned so that closing the gap is a decision.
	t.Run("a JSON array is relayed raw", func(t *testing.T) {
		b.answer(200, "application/json", `[{"payment_proof":"p"}]`)
		r := call(t, ts, "GET", "/t/duo/a2b", mtAIn, nil)
		if r.status != 200 || string(r.body) != `[{"payment_proof":"p"}]` {
			t.Errorf("got %d %s", r.status, r.body)
		}
		b.take(t)
	})
	t.Run("a redirect is relayed, never followed", func(t *testing.T) {
		b.mu.Lock()
		b.status, b.ct, b.reply, b.location = 302, "", "", third.URL+"/elsewhere"
		b.mu.Unlock()
		r := call(t, ts, "GET", "/t/duo/a2b?payment_id=p", mtAIn, nil)
		if r.status != 302 || r.hdr.Get("Location") != third.URL+"/elsewhere" {
			t.Errorf("got %d Location %q", r.status, r.hdr.Get("Location"))
		}
		if third.hits() != 0 {
			t.Error("the redirect was followed")
		}
		b.take(t)
	})
}

// ---------------------------------------------------------------------------
// Credentials and the caller's own choices

func TestACredentialInTheQueryIsNotAuthenticationButAKeyHeaderStillIs(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, mtAllMethods, nil))

	for _, q := range []string{"access_token=" + mtAIn, "api_key=" + mtAIn + "&token=" + mtAIn, "authorization=Bearer+" + mtAIn} {
		if r := call(t, ts, "GET", "/t/duo/a2b?"+q, "", nil); r.status != 401 {
			t.Errorf("?%s: a credential in the query must not authenticate, got %d", q, r.status)
		}
	}
	if b.hits() != 0 {
		t.Error("an unauthenticated request reached the destination")
	}
	if r := call(t, ts, "GET", "/t/duo/a2b", "", nil, map[string]string{"X-Api-Key": mtAIn}); r.status != 200 {
		t.Errorf("X-Api-Key is the documented fallback, got %d %s", r.status, r.body)
	}
	if strings.Contains(b.take(t).wire(), mtAIn) {
		t.Error("the sender's key crossed")
	}
}

func TestOnlyTheRequestLineChoosesTheMethod(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, []string{"GET", "POST"}, nil))
	override := map[string]string{
		"X-HTTP-Method-Override": "DELETE", "X-Method-Override": "PUT", "X-HTTP-Method": "PATCH",
	}

	for _, tc := range []struct{ method, path string }{
		{"POST", "/t/duo/a2b?_method=DELETE&method=PUT"},
		{"GET", "/t/duo/a2b?_method=DELETE"},
	} {
		var body any
		if tc.method == "POST" {
			body = `{"payment_id":"p"}`
		}
		if r := call(t, ts, tc.method, tc.path, mtAIn, body, override); r.status != 200 {
			t.Fatalf("%s: %d %s", tc.method, r.status, r.body)
		}
		got := b.take(t)
		if got.method != tc.method {
			t.Errorf("%s was replayed as %s", tc.method, got.method)
		}
		for h := range override {
			if got.hdr.Get(h) != "" {
				t.Errorf("%s crossed to the destination", h)
			}
		}
	}
	// Asking for an override of a method that is not allowed gains nothing.
	if r := call(t, ts, "PUT", "/t/duo/a2b", mtAIn, `{"payment_id":"p"}`, map[string]string{"X-HTTP-Method-Override": "POST"}); r.status != 405 {
		t.Errorf("an override header must not make PUT acceptable, got %d", r.status)
	}
}

// ---------------------------------------------------------------------------
// What the operator's logs may hold

func TestNeitherTheTrailNorTheActivityLogHoldsAQueryWhenAForwardFails(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	a := newMtPartner(t)
	doc := mtDoc("duo", a, a, mtAllMethods, mtAllMethods)
	doc["b"].(map[string]any)["target_url"] = closedPort(t) + "/api?key=SECRET"
	mustCreate(t, ts, doc)

	for _, m := range []string{"GET", "DELETE"} {
		r := call(t, ts, m, "/t/duo/a2b?payment_id=PII-123&customer.id=PII-456", mtAIn, nil)
		if r.status != 502 || r.json(t)["code"] != "upstream_failed" {
			t.Fatalf("%s: want 502 upstream_failed, got %d %s", m, r.status, r.body)
		}
		if strings.Contains(string(r.body), "PII") || strings.Contains(string(r.body), "127.0.0.1") {
			t.Errorf("%s: the caller was told more than it needs: %s", m, r.body)
		}
	}
	if r := call(t, ts, "PUT", "/t/duo/a2b", mtAIn, `{"payment_id":"PII-123"}`); r.status != 502 {
		t.Fatalf("PUT: %d", r.status)
	}

	logs := string(admin(t, ts, "GET", "/api/admin/logs?limit=100", nil).body)
	for where, text := range map[string]string{"activity log": logs, "audit trail": strictTrail(t, srv)} {
		for _, leak := range []string{"PII-123", "PII-456", "SECRET", "payment_proof", "party.ref", "key="} {
			if strings.Contains(text, leak) {
				t.Errorf("the %s holds %q", where, leak)
			}
		}
	}
	errs := mtTrail(t, srv, "ingest.error")
	if len(errs) != 3 || errs[0]["method"] != "GET" || errs[1]["method"] != "DELETE" || errs[2]["method"] != "PUT" {
		t.Errorf("error records = %v", errs)
	}
}

func TestAuditNamesTheMethodAndTheGrantedLists(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, []string{"get", "DELETE"}, nil))

	created := mtTrail(t, srv, "account.create")
	if len(created) != 1 || !reflect.DeepEqual(created[0]["a_methods"], []any{"GET", "DELETE"}) ||
		!reflect.DeepEqual(created[0]["b_methods"], []any{"POST"}) {
		t.Errorf("account.create = %v", created)
	}

	for _, m := range mtAllMethods {
		if m == "POST" || m == "PUT" || m == "PATCH" {
			continue
		}
		call(t, ts, m, "/t/duo/a2b?payment_id=p", mtAIn, nil)
	}
	call(t, ts, "POST", "/t/duo/b2a", mtBIn, `{"payment_proof":"p"}`)
	got := map[string]int{}
	for _, d := range mtTrail(t, srv, "ingest.ok") {
		got[fmt.Sprint(d["method"])+" "+fmt.Sprint(d["dir"])]++
	}
	if !reflect.DeepEqual(got, map[string]int{"GET a2b": 1, "DELETE a2b": 1, "POST b2a": 1}) {
		t.Errorf("ingest.ok records = %v", got)
	}

	// Widening a side is itself on the trail.
	if r := admin(t, ts, "PUT", "/api/admin/accounts/duo", mtDoc("duo", a, b, []string{"GET", "DELETE"}, []string{"PUT", "PATCH"})); r.status != 200 {
		t.Fatalf("update: %d %s", r.status, r.body)
	}
	updated := mtTrail(t, srv, "account.update")
	if len(updated) != 1 || !reflect.DeepEqual(updated[0]["b_methods"], []any{"PUT", "PATCH"}) {
		t.Errorf("account.update = %v", updated)
	}

	logs := admin(t, ts, "GET", "/api/admin/logs?account=duo&limit=10", nil).json(t)["entries"].([]any)
	var methods []string
	for _, e := range logs {
		methods = append(methods, e.(map[string]any)["method"].(string))
	}
	sort.Strings(methods)
	if !reflect.DeepEqual(methods, []string{"DELETE", "GET", "POST"}) {
		t.Errorf("activity methods = %v", methods)
	}
}

func TestDiscoveryLearnsQueryNamesAndNeverValues(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, mtAllMethods, nil))
	if r := admin(t, ts, "POST", "/api/admin/accounts/duo/discover", map[string]any{"minutes": 5}); r.status != 200 {
		t.Fatalf("discover: %d %s", r.status, r.body)
	}

	call(t, ts, "GET", "/t/duo/a2b?customer.id=VAL-9f3&flag=VAL-2c1&tag=VAL-a&tag=VAL-b", mtAIn, nil)
	logs := admin(t, ts, "GET", "/api/admin/logs?account=duo&limit=1", nil).json(t)["entries"].([]any)
	fields, _ := logs[0].(map[string]any)["fields"].([]any)
	have := map[string]bool{}
	for _, f := range fields {
		have[fmt.Sprint(f)] = true
	}
	for _, want := range []string{"customer.id:string", "flag:string", "tag:array"} {
		if !have[want] {
			t.Errorf("discovery did not record %q: %v", want, fields)
		}
	}
	report := admin(t, ts, "GET", "/api/admin/accounts/duo/discover", nil)
	if strings.Contains(string(report.body), "VAL-") {
		t.Errorf("discovery kept a value: %s", report.body)
	}
}

// ---------------------------------------------------------------------------
// The setting

func TestMethodSettingValidationNormalisationAndPutRetention(t *testing.T) {
	var srv *Server
	ts := newAPI(t, func(s *Server) { srv = s })
	a, b := newMtPartner(t), newMtPartner(t)

	t.Run("default is left out of the document", func(t *testing.T) {
		got := mustCreate(t, ts, mtDoc("plain", a, b, nil, nil))
		for _, side := range []string{"a", "b"} {
			if _, present := got[side].(map[string]any)["inbound_methods"]; present {
				t.Errorf("side %s: a default list should not appear: %v", side, got[side])
			}
		}
		if r := call(t, ts, "GET", "/t/plain/a2b", mtAIn, nil); r.status != 405 || r.hdr.Get("Allow") != "POST" {
			t.Errorf("a default account must stay POST only: %d %q", r.status, r.hdr.Get("Allow"))
		}
	})

	t.Run("lists are trimmed and upper-cased", func(t *testing.T) {
		got := mustCreate(t, ts, mtDoc("norm", a, b, []string{" get ", "Delete"}, []string{"put"}))
		if !reflect.DeepEqual(got["a"].(map[string]any)["inbound_methods"], []any{"GET", "DELETE"}) ||
			!reflect.DeepEqual(got["b"].(map[string]any)["inbound_methods"], []any{"PUT"}) {
			t.Errorf("stored lists = %v / %v", got["a"], got["b"])
		}
		// The Allow header is in the fixed order, whatever order was stored.
		if r := call(t, ts, "PATCH", "/t/norm/a2b", mtAIn, nil); r.hdr.Get("Allow") != "GET, DELETE" {
			t.Errorf("Allow = %q", r.hdr.Get("Allow"))
		}
	})

	t.Run("invalid lists are refused field by field", func(t *testing.T) {
		seventeen := make([]string, maxMethodEntries+1)
		for i := range seventeen {
			seventeen[i] = "GET"
		}
		for name, tc := range map[string]struct {
			a, b  []string
			field string
		}{
			"trace":       {[]string{"TRACE"}, nil, "a.inbound_methods[0]"},
			"head":        {nil, []string{"GET", "HEAD"}, "b.inbound_methods[1]"},
			"options":     {[]string{"OPTIONS"}, nil, "a.inbound_methods[0]"},
			"connect":     {nil, []string{"CONNECT"}, "b.inbound_methods[0]"},
			"blank":       {[]string{""}, nil, "a.inbound_methods[0]"},
			"junk":        {[]string{"G E T"}, nil, "a.inbound_methods[0]"},
			"duplicate":   {[]string{"GET", "get"}, nil, "a.inbound_methods[1]"},
			"too many":    {seventeen, nil, "a.inbound_methods"},
			"both sides":  {[]string{"NOPE"}, []string{"NADA"}, "b.inbound_methods[0]"},
			"long junk":   {[]string{strings.Repeat("x", 5000)}, nil, "a.inbound_methods[0]"},
			"duplicate 3": {nil, []string{"PUT", "GET", "PUT"}, "b.inbound_methods[2]"},
		} {
			r := admin(t, ts, "POST", "/api/admin/accounts", mtDoc("bad-"+strings.ReplaceAll(name, " ", "-"), a, b, tc.a, tc.b))
			if r.status != 400 || r.fieldErrors(t)[tc.field] == "" {
				t.Errorf("%s: want 400 on %s, got %d %s", name, tc.field, r.status, r.body)
			}
			if strings.Contains(string(r.body), "xxxxxxxxxx") {
				t.Errorf("%s: the refusal echoes the caller's junk", name)
			}
		}
		if r := admin(t, ts, "POST", "/api/admin/accounts", `{"id":"typed","a":{"inbound_methods":"GET"}}`); r.status != 400 {
			t.Errorf("a string where a list belongs: want 400, got %d %s", r.status, r.body)
		}
		if !strings.Contains(strictTrail(t, srv), `"event":"account.rejected"`) {
			t.Error("a refused list was not audited")
		}
	})

	t.Run("a PUT that leaves the list out keeps it, and an explicit list replaces it", func(t *testing.T) {
		mustCreate(t, ts, mtDoc("keep", a, b, []string{"GET", "POST"}, []string{"DELETE"}))
		get := func() (any, any) {
			m := admin(t, ts, "GET", "/api/admin/accounts/keep", nil).json(t)
			return m["a"].(map[string]any)["inbound_methods"], m["b"].(map[string]any)["inbound_methods"]
		}

		doc := mtDoc("keep", a, b, nil, nil) // a client that predates the setting
		if r := admin(t, ts, "PUT", "/api/admin/accounts/keep", doc); r.status != 200 {
			t.Fatalf("PUT: %d %s", r.status, r.body)
		}
		if ga, gb := get(); !reflect.DeepEqual(ga, []any{"GET", "POST"}) || !reflect.DeepEqual(gb, []any{"DELETE"}) {
			t.Errorf("an omitted list narrowed the account: %v / %v", ga, gb)
		}
		doc = mtDoc("keep", a, b, []string{}, []string{}) // explicitly empty is the same as omitted
		if r := admin(t, ts, "PUT", "/api/admin/accounts/keep", doc); r.status != 200 {
			t.Fatalf("PUT: %d %s", r.status, r.body)
		}
		if ga, gb := get(); !reflect.DeepEqual(ga, []any{"GET", "POST"}) || !reflect.DeepEqual(gb, []any{"DELETE"}) {
			t.Errorf("an empty list narrowed the account: %v / %v", ga, gb)
		}

		doc = mtDoc("keep", a, b, []string{"POST"}, nil) // narrowing is explicit
		if r := admin(t, ts, "PUT", "/api/admin/accounts/keep", doc); r.status != 200 {
			t.Fatalf("PUT: %d %s", r.status, r.body)
		}
		if ga, gb := get(); !reflect.DeepEqual(ga, []any{"POST"}) || !reflect.DeepEqual(gb, []any{"DELETE"}) {
			t.Errorf("an explicit list should replace the stored one, and leave the other side alone: %v / %v", ga, gb)
		}
		if r := call(t, ts, "GET", "/t/keep/a2b", mtAIn, nil); r.status != 405 {
			t.Errorf("the narrowed side still accepts GET: %d", r.status)
		}
	})

	t.Run("a document read back can be written back", func(t *testing.T) {
		mustCreate(t, ts, mtDoc("round", a, b, mtAllMethods, []string{"GET"}))
		read := admin(t, ts, "GET", "/api/admin/accounts/round", nil)
		if r := call(t, ts, "PUT", "/api/admin/accounts/round", testAdminToken, read.body); r.status != 200 {
			t.Fatalf("PUT of the read document: %d %s", r.status, r.body)
		}
		first, again := read.json(t), admin(t, ts, "GET", "/api/admin/accounts/round", nil).json(t)
		for _, side := range []string{"a", "b"} {
			if !reflect.DeepEqual(first[side], again[side]) {
				t.Errorf("side %s changed on a round trip:\n%v\n%v", side, first[side], again[side])
			}
		}
	})
}

// A list belongs to the account for good: it survives a restart, a document
// written before the setting existed means POST only, and what the store hands
// out is a copy.
func TestMethodListsPersistAndAreNeverAliased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.Create(&accountInput{Account: Account{
		ID: "p",
		A:  Endpoint{InboundMethods: []string{"get"}},
		B:  Endpoint{InboundMethods: []string{"PUT", "DELETE"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(&accountInput{Account: Account{ID: "plain"}}); err != nil {
		t.Fatal(err)
	}

	// The copy returned by Create, Get and List must not alias the stored list.
	created.A.InboundMethods[0] = "DELETE"
	got, _ := s.Get("p")
	got.B.InboundMethods[0] = "PATCH"
	s.List()[0].A.InboundMethods[0] = "DELETE" // "p" sorts before "plain"
	again, _ := s.Get("p")
	if !reflect.DeepEqual(again.A.InboundMethods, []string{"GET"}) || !reflect.DeepEqual(again.B.InboundMethods, []string{"PUT", "DELETE"}) {
		t.Errorf("the store's lists were changed through a copy: %v / %v", again.A.InboundMethods, again.B.InboundMethods)
	}

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reopened.Get("p")
	if !reflect.DeepEqual(p.A.InboundMethods, []string{"GET"}) || !reflect.DeepEqual(p.B.InboundMethods, []string{"PUT", "DELETE"}) {
		t.Errorf("lists after a restart: %v / %v", p.A.InboundMethods, p.B.InboundMethods)
	}
	raw, _ := os.ReadFile(path)
	if n := strings.Count(string(raw), "inbound_methods"); n != 2 {
		t.Errorf("the state file names the setting %d times, want 2 (the default is left out)", n)
	}

	// A document from before the setting.
	old := `{"version":1,"accounts":[{"id":"legacy","name":"legacy","enabled":true,` +
		`"a":{"label":"A","target_url":"","inbound_token":"xk_a_inbound_0123456789abcdef","outbound_token":""},` +
		`"b":{"label":"B","target_url":"","inbound_token":"xk_b_inbound_0123456789abcdef","outbound_token":""},` +
		`"map":[],"drop_unmapped":false,"timeout_sec":15,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}]}`
	legacyPath := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(legacyPath, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	ls, err := OpenStore(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := ls.Get("legacy")
	if !l.A.allows("POST") || l.A.allows("GET") || l.B.allows("DELETE") {
		t.Errorf("an account from before the setting must be POST only: %v %v", l.A.methodList(), l.B.methodList())
	}
}

func TestMethodTable(t *testing.T) {
	for in, want := range map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
		"get": false, "HEAD": false, "OPTIONS": false, "TRACE": false, "CONNECT": false, "": false, "GET ": false} {
		got, ok := dataMethod(in)
		if ok != want || (ok && got != in) {
			t.Errorf("dataMethod(%q) = %q, %v", in, got, ok)
		}
	}
	for m, want := range map[string]bool{"POST": true, "PUT": true, "PATCH": true, "GET": false, "DELETE": false} {
		if methodHasBody(m) != want {
			t.Errorf("methodHasBody(%s) = %v", m, !want)
		}
	}

	var none Endpoint
	if got := none.methodList(); !reflect.DeepEqual(got, []string{"POST"}) || !none.allows("POST") || none.allows("GET") {
		t.Errorf("no list must mean POST only: %v", got)
	}
	ep := Endpoint{InboundMethods: []string{"DELETE", "GET", "PUT"}}
	if got := ep.methodList(); !reflect.DeepEqual(got, []string{"GET", "PUT", "DELETE"}) {
		t.Errorf("the list is reported in the fixed order: %v", got)
	}
	if ep.allows("POST") || !ep.allows("PUT") {
		t.Error("allows disagrees with the list")
	}
}

// The method is the caller's own text: an odd one is refused like any other
// that was not granted, and what reaches the activity log is capped.
func TestAnOddMethodIsRefusedAndBoundedInTheActivityLog(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, nil, nil))

	for _, m := range []string{"PROPFIND", "MKCOL", strings.Repeat("PROPFIND", 40)} {
		r := call(t, ts, m, "/t/duo/a2b", mtAIn, nil)
		if r.status != 405 || r.hdr.Get("Allow") != "POST" {
			t.Errorf("%.20s: want 405 Allow POST, got %d %q", m, r.status, r.hdr.Get("Allow"))
		}
	}
	logs := admin(t, ts, "GET", "/api/admin/logs?account=duo&limit=10", nil).json(t)["entries"].([]any)
	if len(logs) != 3 {
		t.Fatalf("%d activity entries, want 3", len(logs))
	}
	for _, e := range logs {
		if m := e.(map[string]any)["method"].(string); len([]rune(m)) > 17 {
			t.Errorf("the activity log holds a method of %d runes: %.40q", len([]rune(m)), m)
		}
	}
	if a.hits()+b.hits() != 0 {
		t.Error("an odd method reached a partner")
	}
}

// ---------------------------------------------------------------------------
// Concurrency

func TestMixedMethodsInBothDirectionsAreRaceFree(t *testing.T) {
	ts := newAPI(t)
	a, b := newMtPartner(t), newMtPartner(t)
	mustCreate(t, ts, mtDoc("duo", a, b, mtAllMethods, mtAllMethods))

	const workers, each = 12, 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				m := mtAllMethods[(w+i)%len(mtAllMethods)]
				dir, tok, id := "a2b", mtAIn, "payment_id"
				if (w+i)%2 == 1 {
					dir, tok, id = "b2a", mtBIn, "payment_proof"
				}
				var r apiResp
				if methodHasBody(m) {
					r = call(t, ts, m, "/t/duo/"+dir, tok, `{"`+id+`":"p"}`)
				} else {
					r = call(t, ts, m, "/t/duo/"+dir+"?"+id+"=p", tok, nil)
				}
				if r.status != 200 {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("%s %s: %d", m, dir, r.status))
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("%d of %d requests failed: %v", len(failures), workers*each, failures[:min(5, len(failures))])
	}
	if got := a.hits() + b.hits(); got != workers*each {
		t.Errorf("the partners saw %d requests, want %d", got, workers*each)
	}
}
