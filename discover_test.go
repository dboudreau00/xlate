package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func discoverOn(t *testing.T, ts *httptest.Server, id string, minutes int) map[string]any {
	t.Helper()
	r := admin(t, ts, "POST", "/api/admin/accounts/"+id+"/discover",
		map[string]any{"minutes": minutes})
	if r.status != 200 {
		t.Fatalf("discover %d: want 200, got %d: %s", minutes, r.status, r.body)
	}
	return r.json(t)
}

func discoverReport(t *testing.T, ts *httptest.Server, id string) map[string]any {
	t.Helper()
	r := admin(t, ts, "GET", "/api/admin/accounts/"+id+"/discover", nil)
	if r.status != 200 {
		t.Fatalf("discover status: want 200, got %d: %s", r.status, r.body)
	}
	return r.json(t)
}

// paths flattens a direction report into path -> comma-joined types.
func paths(t *testing.T, report map[string]any, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	d, _ := report[dir].(map[string]any)
	if d == nil {
		return out
	}
	fields, _ := d["fields"].([]any)
	for _, f := range fields {
		fe := f.(map[string]any)
		types := []string{}
		if ts, ok := fe["types"].([]any); ok {
			for _, x := range ts {
				types = append(types, fmt.Sprint(x))
			}
		}
		out[fmt.Sprint(fe["path"])] = strings.Join(types, ",")
	}
	return out
}

// The onboarding path: a partner POSTs before the account is wired, and
// we learn their vocabulary from the request instead of guessing.
func TestDiscoveryLearnsSchemaFromUnwiredAccount(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "partner", "enabled": true})
	tok := sideToken(acct, "a")

	discoverOn(t, ts, "partner", 30)

	// No target_url yet: the forward fails, but the shape is captured.
	r := call(t, ts, "POST", "/t/partner/a2b", tok, `{
		"paymentReference": "P-9",
		"customer": {"id": "C-1", "vip": true},
		"amountMinor": 2499,
		"currency": "USD",
		"createdAt": "2024-03-01T09:00:00Z",
		"lineItems": [{"sku": "A"}],
		"note": null
	}`)
	if r.status != 502 || r.json(t)["code"] != "no_target" {
		t.Fatalf("want 502/no_target, got %d: %s", r.status, r.body)
	}

	got := paths(t, discoverReport(t, ts, "partner"), "a2b")
	want := map[string]string{
		"paymentReference": "string",
		"customer":         "object",
		"customer.id":      "string",
		"customer.vip":     "bool",
		"amountMinor":      "number",
		"currency":         "string",
		"createdAt":        "string",
		"lineItems":        "array",
		"note":             "null",
	}
	for path, typ := range want {
		if got[path] != typ {
			t.Errorf("path %q: want type %q, got %q (full: %v)", path, typ, got[path], got)
		}
	}
}

// The rule that makes this feature acceptable at all.
func TestDiscoveryNeverRecordsValues(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "pii", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "pii", 30)

	const (
		pan   = "4111111111111111"
		email = "ada@example.com"
		ssn   = "078-05-1120"
	)
	call(t, ts, "POST", "/t/pii/a2b", tok, fmt.Sprintf(`{
		"card_number": %q,
		"contact": {"email": %q},
		"tax_id": %q,
		"amount": 1999
	}`, pan, email, ssn))

	report := admin(t, ts, "GET", "/api/admin/accounts/pii/discover", nil)
	logs := admin(t, ts, "GET", "/api/admin/logs?account=pii", nil)
	for _, secret := range []string{pan, email, ssn, "1999"} {
		if strings.Contains(string(report.body), secret) {
			t.Errorf("value %q leaked into the discovery report", secret)
		}
		if strings.Contains(string(logs.body), secret) {
			t.Errorf("value %q leaked into the activity log", secret)
		}
	}
	// The field NAMES must be there — that is the point.
	got := paths(t, report.json(t), "a2b")
	for _, name := range []string{"card_number", "contact.email", "tax_id", "amount"} {
		if _, ok := got[name]; !ok {
			t.Errorf("field name %q should have been recorded: %v", name, got)
		}
	}
}

// JSON keyed by identifier puts data in the key position. Enumerating it
// would capture exactly what the feature promises not to.
func TestDiscoveryCollapsesIdentifierKeyedObjects(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "mapshape", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "mapshape", 30)

	var b strings.Builder
	b.WriteString(`{"balances":{`)
	for i := 0; i < maxSiblingKeys+10; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"cust-%d@example.com":%d`, i, i)
	}
	b.WriteString(`},"total":42}`)

	call(t, ts, "POST", "/t/mapshape/a2b", tok, b.String())

	report := admin(t, ts, "GET", "/api/admin/accounts/mapshape/discover", nil)
	if strings.Contains(string(report.body), "cust-3@example.com") {
		t.Error("identifier keys were enumerated into the report")
	}
	got := paths(t, report.json(t), "a2b")
	if _, ok := got["balances."+mapKeyPlaceholder]; !ok {
		t.Errorf("expected a collapsed map placeholder, got %v", got)
	}
	if got["total"] != "number" {
		t.Errorf("sibling scalar should still be recorded: %v", got)
	}
}

func TestDiscoveryIsOffByDefault(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "quiet", "enabled": true})
	call(t, ts, "POST", "/t/quiet/a2b", sideToken(acct, "a"), `{"secret_field":"x"}`)

	report := admin(t, ts, "GET", "/api/admin/accounts/quiet/discover", nil)
	if report.json(t)["active"] != false {
		t.Error("discovery should be off by default")
	}
	if strings.Contains(string(report.body), "secret_field") {
		t.Error("shape was recorded without discovery being enabled")
	}
	logs := admin(t, ts, "GET", "/api/admin/logs?account=quiet", nil)
	if strings.Contains(string(logs.body), "secret_field") {
		t.Error("shape reached the activity log without discovery being enabled")
	}
}

func TestDiscoveryExpires(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "expiring", "enabled": true})
	tok := sideToken(acct, "a")

	// Set a window that has already elapsed by writing the field directly.
	stored := admin(t, ts, "GET", "/api/admin/accounts/expiring", nil).json(t)
	stored["discover_until"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	delete(stored, "created_at")
	delete(stored, "updated_at")
	if r := admin(t, ts, "PUT", "/api/admin/accounts/expiring", stored); r.status != 200 {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}

	call(t, ts, "POST", "/t/expiring/a2b", tok, `{"after_expiry":"x"}`)
	report := admin(t, ts, "GET", "/api/admin/accounts/expiring/discover", nil)
	if report.json(t)["active"] != false {
		t.Error("an elapsed window should not be active")
	}
	if strings.Contains(string(report.body), "after_expiry") {
		t.Error("shape recorded after the window expired")
	}
}

func TestDiscoveryWindowIsBounded(t *testing.T) {
	ts := newAPI(t)
	mustCreate(t, ts, map[string]any{"id": "bounded"})

	tooLong := int(maxDiscoverWindow/time.Minute) + 1
	r := admin(t, ts, "POST", "/api/admin/accounts/bounded/discover", map[string]any{"minutes": tooLong})
	if r.status != 400 {
		t.Fatalf("want 400, got %d: %s", r.status, r.body)
	}
	if _, ok := r.fieldErrors(t)["minutes"]; !ok {
		t.Errorf("want a field error on minutes, got %v", r.fieldErrors(t))
	}

	for _, bad := range []map[string]any{{}, {"minutes": -1}} {
		if r := admin(t, ts, "POST", "/api/admin/accounts/bounded/discover", bad); r.status != 400 {
			t.Errorf("%v: want 400, got %d", bad, r.status)
		}
	}
	// The stored field is validated too, not just the endpoint.
	r = admin(t, ts, "PUT", "/api/admin/accounts/bounded", map[string]any{
		"discover_until": time.Now().UTC().Add(72 * time.Hour).Format(time.RFC3339)})
	if r.status != 400 {
		t.Errorf("an over-long stored window should be rejected, got %d: %s", r.status, r.body)
	}
}

// Turning discovery off must also drop what was collected.
func TestDiscoveryOffForgetsObservations(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "forget", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "forget", 30)
	call(t, ts, "POST", "/t/forget/a2b", tok, `{"learned_field":"x"}`)

	if got := paths(t, discoverReport(t, ts, "forget"), "a2b"); got["learned_field"] == "" {
		t.Fatalf("setup: field was not learned: %v", got)
	}
	discoverOn(t, ts, "forget", 0)

	report := admin(t, ts, "GET", "/api/admin/accounts/forget/discover", nil)
	if report.json(t)["active"] != false {
		t.Error("discovery should be off")
	}
	if strings.Contains(string(report.body), "learned_field") {
		t.Error("observations survived being switched off")
	}
}

func TestDiscoveryResetKeepsWindowOpen(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "reset", "enabled": true})
	tok := sideToken(acct, "a")
	discoverOn(t, ts, "reset", 30)
	call(t, ts, "POST", "/t/reset/a2b", tok, `{"old_field":"x"}`)

	r := admin(t, ts, "DELETE", "/api/admin/accounts/reset/discover", nil)
	if r.status != 200 {
		t.Fatalf("reset: %d %s", r.status, r.body)
	}
	if r.json(t)["active"] != true {
		t.Error("reset should not close the window")
	}
	if strings.Contains(string(r.body), "old_field") {
		t.Error("reset did not forget observations")
	}

	call(t, ts, "POST", "/t/reset/a2b", tok, `{"new_field":"x"}`)
	if got := paths(t, discoverReport(t, ts, "reset"), "a2b"); got["new_field"] == "" {
		t.Errorf("should still be recording after a reset: %v", got)
	}
}

// a2b and b2a are two different vocabularies; mixing them would produce a
// map that is wrong in one direction.
func TestDiscoveryKeepsDirectionsApart(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()

	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "dirs", "enabled": true,
		"a": map[string]any{"target_url": up.URL},
		"b": map[string]any{"target_url": up.URL}})
	discoverOn(t, ts, "dirs", 30)

	call(t, ts, "POST", "/t/dirs/a2b", sideToken(acct, "a"), `{"side_a_field":"x"}`)
	call(t, ts, "POST", "/t/dirs/b2a", sideToken(acct, "b"), `{"side_b_field":"y"}`)

	report := discoverReport(t, ts, "dirs")
	a2b, b2a := paths(t, report, "a2b"), paths(t, report, "b2a")
	if _, ok := a2b["side_a_field"]; !ok {
		t.Errorf("a2b should hold side A's field: %v", a2b)
	}
	if _, ok := a2b["side_b_field"]; ok {
		t.Errorf("a2b must not hold side B's field: %v", a2b)
	}
	if _, ok := b2a["side_b_field"]; !ok {
		t.Errorf("b2a should hold side B's field: %v", b2a)
	}
}

// The payload arrives on the activity log entry too, so "see it in the
// log" works without a second call.
func TestDiscoveryShapeAppearsOnTheActivityLog(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "logged", "enabled": true})
	discoverOn(t, ts, "logged", 30)
	call(t, ts, "POST", "/t/logged/a2b", sideToken(acct, "a"), `{"ref":"R-1","qty":3}`)

	r := admin(t, ts, "GET", "/api/admin/logs?account=logged", nil)
	entries, _ := r.json(t)["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d: %s", len(entries), r.body)
	}
	fields, _ := entries[0].(map[string]any)["fields"].([]any)
	got := map[string]bool{}
	for _, f := range fields {
		got[fmt.Sprint(f)] = true
	}
	for _, want := range []string{"ref:string", "qty:number"} {
		if !got[want] {
			t.Errorf("activity entry should carry %q, got %v", want, fields)
		}
	}
	if strings.Contains(string(r.body), "R-1") {
		t.Error("a value leaked onto the activity log")
	}
}

// The report offers starter mapping rows so the operator can wire from
// what was actually sent.
func TestDiscoverySuggestsMappablePairsOnly(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "suggest", "enabled": true})
	discoverOn(t, ts, "suggest", 30)
	call(t, ts, "POST", "/t/suggest/a2b", sideToken(acct, "a"),
		`{"ref":"R","nested":{"leaf":1},"items":[1,2]}`)

	r := admin(t, ts, "GET", "/api/admin/accounts/suggest/discover", nil)
	sug, _ := r.json(t)["suggest"].(map[string]any)
	rows, _ := sug["a2b"].([]any)
	got := map[string]bool{}
	for _, row := range rows {
		got[fmt.Sprint(row.(map[string]any)["a"])] = true
	}
	if !got["ref"] || !got["nested.leaf"] {
		t.Errorf("scalar leaves should be suggested: %v", got)
	}
	// Containers and arrays are not addressable as mapping sources.
	if got["nested"] || got["items"] {
		t.Errorf("containers and arrays must not be suggested: %v", got)
	}
}

func TestDiscoveryPathCountIsBounded(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "wide", "enabled": true})
	discoverOn(t, ts, "wide", 30)

	// Nested so no single object exceeds the sibling cap, but the total
	// path count does: 20 groups x 20 leaves = 420 paths.
	var b strings.Builder
	b.WriteString("{")
	for g := 0; g < 20; g++ {
		if g > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"g%02d":{`, g)
		for i := 0; i < 20; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"f%02d":%d`, i, i)
		}
		b.WriteString("}")
	}
	b.WriteString("}")
	call(t, ts, "POST", "/t/wide/a2b", sideToken(acct, "a"), b.String())

	report := discoverReport(t, ts, "wide")
	d, _ := report["a2b"].(map[string]any)
	fields, _ := d["fields"].([]any)
	if len(fields) > maxDiscoveredPaths {
		t.Errorf("path count not bounded: got %d, want at most %d", len(fields), maxDiscoveredPaths)
	}
	if d["truncated"] != true {
		t.Error("truncation should be reported so the operator knows the list is partial")
	}
}

// A legitimately wide record must be enumerated, not mistaken for an
// identifier-keyed map — 40-field payment objects are ordinary.
func TestDiscoveryEnumeratesWideRecords(t *testing.T) {
	ts := newAPI(t)
	acct := mustCreate(t, ts, map[string]any{"id": "wide-record", "enabled": true})
	discoverOn(t, ts, "wide-record", 30)

	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 40; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"business_field_%02d":"v"`, i)
	}
	b.WriteString("}")
	call(t, ts, "POST", "/t/wide-record/a2b", sideToken(acct, "a"), b.String())

	got := paths(t, discoverReport(t, ts, "wide-record"), "a2b")
	if len(got) != 40 {
		t.Errorf("a 40-field record should be enumerated, got %d paths: %v", len(got), got)
	}
	if _, collapsed := got[mapKeyPlaceholder]; collapsed {
		t.Error("a wide business record was mistaken for an identifier-keyed map")
	}
}

func TestDiscoveryUnknownAccount(t *testing.T) {
	ts := newAPI(t)
	for _, m := range []string{"GET", "DELETE"} {
		if r := call(t, ts, m, "/api/admin/accounts/ghost/discover", testAdminToken, nil); r.status != 404 {
			t.Errorf("%s: want 404, got %d", m, r.status)
		}
	}
	r := admin(t, ts, "POST", "/api/admin/accounts/ghost/discover", map[string]any{"minutes": 10})
	if r.status != 404 {
		t.Errorf("POST: want 404, got %d: %s", r.status, r.body)
	}
}
