# livetest — live end-to-end harness

Black-box end-to-end check that runs the **real `xlate` binary** as a subprocess
and drives it over real HTTP, with both partner systems ("Acme Checkout" = side
A, "Globex Ledger" = side B) running as real servers on real ports.

Unlike `e2e_test.go`, this asserts on **what each partner actually received** —
that Globex sees Globex's field names and Globex's credential, that Acme reads
its own vocabulary back, and that neither ever holds the other's token.

## Run

```bash
go build -o xlate . && cd livetest && XLATE_BIN=../xlate go run .
```

On Windows: `go build -o xlate.exe . && cd livetest && XLATE_BIN=../xlate.exe go run .`

Exit code is 0 only if every assertion passes. Ports used: 18080 (xlate),
19101 (side A), 19102 (side B). Scratch state/audit/log land in `run/`, which
is gitignored and wiped at the start of each run.

## What it covers

| Area | Checks |
|---|---|
| Provisioning | admin auth, create, duplicate 409, invalid id 400 |
| A → B | field rename, nested dot-paths, date transform, unmapped passthrough, outbound credential, correlation headers |
| B → A | the same in reverse, including the transform rendering each side's own date format |
| Response | reverse-mapping of the upstream reply into the caller's vocabulary |
| Credential isolation | neither party ever receives the other's inbound or outbound token |
| Auth | wrong token, wrong side's token, no token, unknown account, bad direction, wrong method |
| Malformed input | bad JSON, non-object body, oversize body, unsafe/oversized correlation headers, raw-socket CRLF smuggling |
| Upstream | 4xx passthrough, unreachable target → 502 without leaking topology |
| Config | `drop_unmapped`, disabled account, token retention on update, rotation |
| Tripwire | boundary at threshold, lockout, fail-closed on valid tokens, `Retry-After`, admin reset, self-expiry |
| Discovery | records paths and types, never values |
| Observability | stats, activity log free of credentials and PII, admin console |
| Durability | kill the process, restart, confirm accounts/map/tokens reload and traffic still flows |
| Audit | hash chain verifies across the restart; contains no credentials |

## Note

This is a **nested module** (its own `go.mod`) on purpose, so `go build ./...`,
`go vet ./...` and `make check` in the parent module ignore it entirely.
