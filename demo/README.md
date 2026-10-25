# xlate demo

A fully populated xlate in one command: the gateway, a mock destination, four dummy accounts, and enough traffic to make the dashboard mean something.

Everything is loopback-only and writes to a scratch directory (`%TEMP%\xlate-demo` / `$TMPDIR/xlate-demo`). Nothing touches your real config.

```powershell
./demo/demo.ps1            # instant
./demo/demo.ps1 -Minutes 5 # spread traffic so the chart has a profile
```

```sh
./demo/demo.sh             # instant
MINUTES=5 ./demo/demo.sh   # same, POSIX
```

Then open `http://localhost:8080/admin/` and sign in with `demo-admin-token-please-change`.

Stop it with `./demo/stop.ps1` (or `./demo/stop.sh`); add `-Purge` / `--purge` to delete the scratch directory too.

> Requires Go and, for the shell version, `curl` and `python3`.

## What you get

Four accounts, each chosen to show a different thing:

| Account | Shows |
|---|---|
| **acme** | The full pipeline — five field pairs including a `rfc3339 ⇄ unix` date transform, both legs translating. Some requests carry a deliberately malformed date, so you also see a fail-open warning. |
| **northwind** | Refused traffic. A slice of requests arrive with a bad token, so the tripwire counter climbs and the account may badge as tripped. |
| **contoso** | Onboarding. It has **no field map at all** and discovery is open — the partner's vocabulary was learned from the requests they sent. Open it and scroll to **Field discovery**: every path they sent, with its JSON type, and an **Add pair** button that drops it straight into the field map. |
| **legacy-crm** | A disabled account, greyed out in the list. |

Worth a look once it's up:

- **Dashboard**: each account as a lane through the gateway (hover one to trace it), lifetime totals, the per-minute chart, and the per-account rollup. Run with `-Minutes 5` for a chart with an actual shape; a one-minute run puts everything in a single bar.
- **contoso → Field discovery** — the field names the partner sent, ready to wire. Click **Add pair** on a few, fill in your own side, Save. Then grep the audit trail and the activity log for any of their *values* (`CON-88421`, `ops@contoso.example`); there are none. Containers and arrays are marked *not mappable* because a field map cannot address them.
- **Activity** — one row per request, metadata only.
- **Theme toggle** — top right. Light is the default and the choice is remembered.

Verify the audit chain is intact (the command is printed when the demo starts):

```sh
<workdir>/xlate -verify-audit <workdir>/trail.jsonl
```

Then edit any character in the middle of that file and run it again.

## The dummy data

All of it lives in [`seed.json`](seed.json) — accounts, field maps, and the payloads used to generate traffic. Change it and re-run; nothing is hard-coded in the scripts.

**Every credential in that file is fake** and exists only for this demo. The admin token is literally `demo-admin-token-please-change`. Do not reuse any of it anywhere, and note that the demo runs xlate over plain HTTP on loopback — real deployments need TLS and a pinned token. See *Going to production* in [TUTORIAL.md](../TUTORIAL.md).

`upstream/` is the mock destination — a ~50-line HTTP server that answers in each partner's own vocabulary so the return leg has something real to reverse-map. It is a separate Go module so it can never become a dependency of the gateway.
