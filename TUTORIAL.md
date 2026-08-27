# xlate tutorial

Zero to two systems talking, in about fifteen minutes. Every command here is runnable as written; nothing is pseudocode.

You will build a working gateway between a fictional billing system (**side A**) and a payment provider (**side B**) that disagree about what to call things:

| Side A says | Side B says |
|---|---|
| `payment_id` | `payment_proof` |
| `customer.id` | `cust_id` |
| `amount` | `value` |
| `created_at` (`2024-03-01T09:00:00Z`) | `created_epoch` (`1709283600`) |

Neither side changes a line of code. Neither side learns the other's vocabulary.

**Contents**

1. [Start the gateway](#1-start-the-gateway)
2. [Create an account](#2-create-an-account)
3. [Try a translation without sending anything](#3-try-a-translation-without-sending-anything)
4. [Stand up a fake System B](#4-stand-up-a-fake-system-b)
5. [Send a real request](#5-send-a-real-request)
6. [Convert a date in flight](#6-convert-a-date-in-flight)
7. [The return leg](#7-the-return-leg)
8. [Hand each side its credentials](#8-hand-each-side-its-credentials)
9. [Watch the tripwire fire](#9-watch-the-tripwire-fire)
10. [Prove the audit trail is intact](#10-prove-the-audit-trail-is-intact)
11. [When things go wrong](#when-things-go-wrong)
12. [Going to production](#going-to-production)

---

## 1. Start the gateway

Build it and pin an admin token so it survives restarts:

```sh
go build -o xlate .
```

```sh
mkdir -p /tmp/xlate-demo
XLATE_ADMIN_TOKEN=demo-admin-token-please-change ./xlate \
  -listen 127.0.0.1:8080 \
  -state /tmp/xlate-demo/state.json \
  -audit /tmp/xlate-demo/trail.jsonl
```

Leave that running and open a second terminal. Save yourself typing:

```sh
export TOK=demo-admin-token-please-change
export XL=http://127.0.0.1:8080
```

Check it's alive:

```sh
curl -s $XL/healthz
```

```json
{"ok":true,"version":"0.4.0","accounts":0,"uptime_sec":3}
```

> Without `XLATE_ADMIN_TOKEN`, xlate generates a token and prints it at startup. That is fine for a first look, but it changes on every restart — pin it once you're doing anything real.

## 2. Create an account

An *account* is one pairing of two systems plus the vocabulary between them.

```sh
curl -s -X POST $XL/api/admin/accounts \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "acme",
    "name": "Acme billing ⇄ PSP",
    "a": {"label": "Acme"},
    "b": {"label": "PSP"},
    "map": [
      {"a": "payment_id",  "b": "payment_proof"},
      {"a": "customer.id", "b": "cust_id"},
      {"a": "amount",      "b": "value"}
    ]
  }'
```

You get the stored document back, with two generated inbound tokens:

```json
{
  "id": "acme",
  "enabled": true,
  "a": {"label":"Acme","target_url":"","inbound_token":"xk_9f2c…","outbound_token":""},
  "b": {"label":"PSP","target_url":"","inbound_token":"xk_41ab…","outbound_token":""},
  "map": [ … ],
  "timeout_sec": 15
}
```

Four things just happened worth understanding:

- **`enabled` defaulted to true.** You create an account in order to use it. (Omitting `enabled` on a later `PUT` *retains* whatever is stored — omission never flips a live account.)
- **Inbound tokens were generated.** These are what each side presents *to xlate*. You never invent them by hand.
- **`target_url` is empty on both sides.** Perfectly legal while you're wiring up; ingest returns `502 no_target` until you set one.
- **`timeout_sec` defaulted to 15.**

Grab side A's inbound token:

```sh
export ATOK=$(curl -s $XL/api/admin/accounts/acme -H "Authorization: Bearer $TOK" \
  | grep -o '"inbound_token":"[^"]*"' | head -1 | cut -d'"' -f4)
echo $ATOK
```

## 3. Try a translation without sending anything

Before wiring up a real destination, use the dry run. It applies the map and shows you the result — and forwards nothing.

```sh
curl -s -X POST $XL/api/admin/accounts/acme/test \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "a2b",
    "payload": {
      "payment_id": "P-777",
      "customer": {"id": "C-1", "name": "Ada"},
      "amount": 1999,
      "internal_note": "not mapped"
    }
  }'
```

```json
{
  "applied": 3,
  "translated": {
    "cust_id": "C-1",
    "customer": {"name": "Ada"},
    "internal_note": "not mapped",
    "payment_proof": "P-777",
    "value": 1999
  },
  "warnings": []
}
```

Read that output carefully — it shows all the mapping rules at once:

- `payment_id` → `payment_proof`, and the old name is **gone**.
- `customer.id` is a **dot-path**: it reached into the nested object and lifted the value out to a top-level `cust_id`.
- `customer` remains, now holding only `name`. Extracting the last key of a nested object leaves the empty parent behind on purpose — silently deleting a container the other side might rely on is more surprising than an empty object.
- `internal_note` was **not** in the map, so it passed straight through. Set `"drop_unmapped": true` on the account if you want only mapped fields to survive.

This endpoint is the fastest way to answer "what will actually arrive?" Use it whenever a map surprises you.

## 4. Stand up a fake System B

Any HTTP server that echoes will do. Python is the shortest path:

```sh
python3 -c '
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        print("PSP received:", body.decode())
        print("PSP saw auth:", self.headers.get("Authorization"))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"payment_proof":"P-777","status":"settled"}).encode())
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 9090), H).serve_forever()
' &
```

Point side B at it, and give xlate a credential to present:

```sh
curl -s -X PUT $XL/api/admin/accounts/acme \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Acme billing ⇄ PSP",
    "a": {"label": "Acme"},
    "b": {"label": "PSP",
          "target_url": "http://127.0.0.1:9090/payments",
          "outbound_token": "psp-secret-credential-value"},
    "map": [
      {"a": "payment_id",  "b": "payment_proof"},
      {"a": "customer.id", "b": "cust_id"},
      {"a": "amount",      "b": "value"}
    ]
  }' > /dev/null
```

> **`PUT` replaces the document.** Send the whole thing, not a patch. Two fields are forgiving: blank token fields keep their stored values (so you can't wipe credentials by omission), and an omitted `enabled` keeps its stored value. Everything else is replaced by what you send.

## 5. Send a real request

Now be System A:

```sh
curl -i -X POST $XL/t/acme/a2b \
  -H "Authorization: Bearer $ATOK" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: order-777' \
  -d '{"payment_id":"P-777","customer":{"id":"C-1"},"amount":1999}'
```

The fake PSP terminal prints:

```
PSP received: {"cust_id":"C-1","customer":{},"payment_proof":"P-777","value":1999}
PSP saw auth: Bearer psp-secret-credential-value
```

and System A gets back:

```
HTTP/1.1 200 OK
Content-Type: application/json
X-Xlate-Applied: 4

{"payment_id":"P-777","status":"settled"}
```

Three things to notice:

- **The PSP never saw System A's token.** xlate authenticated A with A's inbound token, then presented B's *outbound* token. Neither side holds the other's credential.
- **The response came back in A's vocabulary.** The PSP answered `payment_proof`; System A read `payment_id`. The reverse map ran automatically.
- **`X-Xlate-Applied: 4`** counts both legs — three fields on the way out, one on the way back. `Idempotency-Key` was forwarded untouched.

## 6. Convert a date in flight

System A speaks RFC 3339. The PSP wants a Unix epoch. Add a pair with a `transform`:

```sh
curl -s -X PUT $XL/api/admin/accounts/acme \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Acme billing ⇄ PSP",
    "a": {"label": "Acme"},
    "b": {"label": "PSP",
          "target_url": "http://127.0.0.1:9090/payments",
          "outbound_token": "psp-secret-credential-value"},
    "map": [
      {"a": "payment_id",  "b": "payment_proof"},
      {"a": "customer.id", "b": "cust_id"},
      {"a": "amount",      "b": "value"},
      {"a": "created_at",  "b": "created_epoch",
       "transform": {"kind": "date", "a_format": "rfc3339", "b_format": "unix"}}
    ]
  }' > /dev/null
```

```sh
curl -s -X POST $XL/api/admin/accounts/acme/test \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"direction":"a2b","payload":{"created_at":"2024-03-01T09:00:00Z"}}'
```

```json
{"translated":{"created_epoch":1709283600},"applied":1,"warnings":[]}
```

And it is symmetric — the same pair un-converts on the way back:

```sh
curl -s -X POST $XL/api/admin/accounts/acme/test \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"direction":"b2a","payload":{"created_epoch":1709283600}}'
```

```json
{"translated":{"created_at":"2024-03-01T09:00:00Z"},"applied":1,"warnings":[]}
```

**A trap worth walking into on purpose.** Go's date layouts are written as a reference *time*, not as `YYYY-MM-DD`. Try the wrong thing:

```sh
curl -s -X PUT $XL/api/admin/accounts/acme \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"map":[{"a":"created_at","b":"created_epoch",
       "transform":{"kind":"date","a_format":"YYYY-MM-DD","b_format":"unix"}}]}'
```

```json
{
  "code": "validation_failed",
  "error": "map[0].transform.a_format: \"YYYY-MM-DD\" is not a Go reference layout …",
  "fields": [{"field": "map[0].transform.a_format", "message": "…"}]
}
```

Rejected at save time, which is the whole point: an unvalidated typo here would be accepted and then fail open on *every request forever*, silently forwarding unconverted values. Use `rfc3339`, `unix`, `unix_ms`, `date`, `datetime`, `rfc1123`, or a real Go layout like `02/01/2006 15:04`.

## 7. The return leg

For async flows the PSP calls *you*. It POSTs to `/t/acme/b2a` with **side B's** inbound token, and the same pipeline runs mirrored: B's vocabulary in, A's vocabulary out to A's `target_url`. Set `a.target_url` the same way you set `b.target_url`, hand the PSP side B's inbound token, and you have a full duplex integration.

## 8. Hand each side its credentials

Each party needs exactly two things: its URL and its inbound token.

| Party | Sends to | Presents |
|---|---|---|
| System A | `POST /t/acme/a2b` | `a.inbound_token` |
| System B | `POST /t/acme/b2a` | `b.inbound_token` |

The admin console's **Integration** card generates the curl snippet for each side — that's the easiest way to hand this over. If a token leaks, rotate just that one:

```sh
curl -s -X POST $XL/api/admin/accounts/acme/rotate \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"side":"a","kind":"inbound"}'
```

```json
{"token":"xk_new…","side":"a","kind":"inbound"}
```

The old token stops working immediately. The audit trail records *which slot* rotated, never the value.

## 9. Watch the tripwire fire

Send six bad tokens (the default threshold is 5, and it fires when *exceeded*):

```sh
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code} " -X POST $XL/t/acme/a2b \
    -H 'Authorization: Bearer wrong' -H 'Content-Type: application/json' -d '{}'
done; echo
```

```
401 401 401 401 401 401
```

Now try again — **with the correct token**:

```sh
curl -i -X POST $XL/t/acme/a2b -H "Authorization: Bearer $ATOK" \
  -H 'Content-Type: application/json' -d '{"payment_id":"P-1"}'
```

```
HTTP/1.1 429 Too Many Requests
Retry-After: 900

{"error":"account temporarily locked","code":"account_locked"}
```

Valid credentials are locked out too, and that is deliberate: during an active credential-guessing burst against an account, the safe state is closed. Check and clear it:

```sh
curl -s $XL/api/admin/tripwire -H "Authorization: Bearer $TOK"
```

```json
{"acme":{"count":6,"state":"locked","trips":1,"unlock_in_sec":899}}
```

```sh
curl -s -X POST $XL/api/admin/accounts/acme/tripwire/reset -H "Authorization: Bearer $TOK"
```

In production set `-alert-webhook` and `-alert-secret` so a trip pages you, signed with HMAC-SHA256 so the receiver can tell a real alert from a forged one.

## 10. Prove the audit trail is intact

```sh
./xlate -verify-audit /tmp/xlate-demo/trail.jsonl
```

```
audit chain OK: 21 records, tail 5dc072ac0ffb…
```

Now tamper with it — change any character in the middle of the file — and re-run:

```sh
audit verification FAILED: line 7 (seq 7): record tampered — hash mismatch
```

Each record hashes itself plus its predecessor, so an edit, deletion, reorder or insertion breaks the chain from that point on. Restarts extend the same chain rather than starting a new one.

Look at what's in there:

```sh
grep -o '"event":"[^"]*"' /tmp/xlate-demo/trail.jsonl | sort | uniq -c
```

Then satisfy yourself about what is *not* in there — no request bodies, and no token values:

```sh
grep -c 'psp-secret-credential-value' /tmp/xlate-demo/trail.jsonl   # 0
grep -c 'P-777' /tmp/xlate-demo/trail.jsonl                          # 0
```

This matters because translated traffic routinely carries payment identifiers and PII, and the trail is readable by anyone holding the admin token.

## When things go wrong

Every error is `{"error": "...", "code": "..."}`. Branch on `code`, not on prose.

| You see | It means | Do this |
|---|---|---|
| `401 auth_invalid` | wrong inbound token for that side | check you're using A's token on `a2b`, B's on `b2a` |
| `403 account_disabled` | account is off, or a tripwire froze it | re-enable it, then reset the tripwire |
| `404 not_found` | no such account id | check the id in the URL |
| `404 bad_direction` | path wasn't `a2b` or `b2a` | fix the URL |
| `429 account_locked` | tripwire lockout | wait for `Retry-After`, or reset it |
| `502 no_target` | destination side has no `target_url` | set it |
| `502 upstream_failed` | the destination didn't answer | check the destination; detail is in xlate's log, never in the response |
| `400 bad_json` | body wasn't exactly one JSON object | no arrays, no trailing bytes |
| `400 validation_failed` | admin document was rejected | read the `fields` array — it names each bad field |
| `409 already_exists` | that account id is taken | pick another, or `PUT` the existing one |

**"My config change did nothing."** It almost certainly returned `400` with an unknown-field error. xlate rejects fields it does not recognise rather than ignoring them, because a silently dropped `target_url` typo is a data-loss bug wearing a `200 OK`:

```json
{"code":"validation_failed",
 "error":"target_uri: unknown field; check for a typo, or a setting that does not exist",
 "fields":[{"field":"target_uri","message":"unknown field; …"}]}
```

Rejections are also written to the audit trail as `account.rejected` with the offending field **names** — so if a partner's integration script is looping on a typo, you can see it server-side. Values are never recorded: an unknown field is very often a misspelled credential field with a live credential in it.

**"A date isn't converting."** Parse failures at request time fail open — the value forwards unchanged and a warning is counted. Check `X-Xlate-Warnings` on the response and the `warnings` count in `GET /api/admin/logs`. The usual cause is real data not matching the declared format.

**"Which fields actually moved?"** `X-Xlate-Applied` counts both legs. For the full picture use the dry run (§3) — it shows the exact output without sending anything.

## Going to production

Before you point anything real at this:

- **Pin the admin token** (`XLATE_ADMIN_TOKEN`) and put xlate behind TLS — either `-tls-cert`/`-tls-key` or a terminating proxy. Tokens are bearer credentials in plaintext on the wire otherwise.
- **The state file contains credentials in plaintext.** It's written `0600`; keep it on a disk you control and out of version control (the shipped `.gitignore` already excludes it).
- **Enable alerts**: `-alert-webhook` plus `-alert-secret`. An unsigned webhook is spoofable, which defeats the point of a security signal.
- **Ship the audit trail off-host.** It's line-oriented JSONL, so any log shipper works. Tamper-evidence catches edits and truncation, but an attacker with write access and the source can rebuild the chain; comparing tails off-host is what makes it strong.
- **Only turn on `-trust-proxy` if a proxy in front strips client-supplied `X-Forwarded-For`.** That value feeds tripwire forensics, and it's attacker-controlled otherwise.
- **Cap concurrency around 32 in-flight requests per instance** and put a rate limiter in front. Throughput peaks there (~3 500 req/s on an i9; see *Performance* in the README) and degrades beyond it. The tripwire is an anomaly detector, not a rate limiter — refused requests are fsync-bound at roughly 700 req/s.
- **Target URLs are unrestricted by design**, so admin access implies SSRF reach. Egress-filter if untrusted people can reach the control plane.

Clean up the demo:

```sh
kill %1 2>/dev/null; rm -rf /tmp/xlate-demo
```
