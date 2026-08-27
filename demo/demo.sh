#!/usr/bin/env bash
# Brings up a fully populated xlate demo: gateway, mock destination,
# dummy accounts and shaped traffic. Everything is loopback-only and
# writes to a scratch directory. Stop it with demo/stop.sh.
#
#   ./demo/demo.sh            # instant
#   MINUTES=5 ./demo/demo.sh  # spread traffic so the chart has a profile
set -euo pipefail

PORT="${PORT:-8080}"
UPSTREAM_PORT="${UPSTREAM_PORT:-9090}"
MINUTES="${MINUTES:-1}"

demo="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$demo")"
work="${TMPDIR:-/tmp}/xlate-demo"
base="http://127.0.0.1:${PORT}"

need() { command -v "$1" >/dev/null || { echo "need $1 on PATH" >&2; exit 1; }; }
need go; need curl; need python3

tok="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["admin_token"])' "$demo/seed.json")"
say()  { printf '  %s\n' "$*"; }
head_() { printf '\n%s\n' "$*"; }

head_ "xlate demo"
say "workdir  $work"
say "gateway  $base"

"$demo/stop.sh" --quiet || true
mkdir -p "$work"
rm -f "$work/state.json" "$work/trail.jsonl"

head_ "Building"
( cd "$root" && go build -o "$work/xlate" . )
( cd "$demo/upstream" && go build -o "$work/upstream" . )
say ok

head_ "Starting"
"$work/upstream" -listen "127.0.0.1:${UPSTREAM_PORT}" -quiet \
  >"$work/upstream.out" 2>"$work/upstream.err" & echo $! >"$work/upstream.pid"
"$work/xlate" -listen "127.0.0.1:${PORT}" \
  -state "$work/state.json" -audit "$work/trail.jsonl" -admin-token "$tok" \
  >"$work/xlate.out" 2>"$work/xlate.err" & echo $! >"$work/xlate.pid"

for _ in $(seq 1 100); do
  curl -fsS "$base/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "$base/healthz" >/dev/null || { echo "gateway did not start; see $work/xlate.err" >&2; exit 1; }
say "gateway pid $(cat "$work/xlate.pid"), mock destination pid $(cat "$work/upstream.pid")"

adm() { curl -fsS -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }

head_ "Creating accounts"
python3 - "$demo/seed.json" <<'PY' > "$work/accounts.ndjson"
import json,sys
for a in json.load(open(sys.argv[1]))["accounts"]:
    print(json.dumps(a))
PY
while IFS= read -r acct; do
  id="$(printf '%s' "$acct" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
  code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$base/api/admin/accounts" \
      -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d "$acct")"
  [ "$code" = "201" ] || { echo "creating $id failed ($code)" >&2; exit 1; }
  say "$id"
done < "$work/accounts.ndjson"

# Contoso ships with no map on purpose: it is the onboarding story.
adm -X POST "$base/api/admin/accounts/contoso/discover" -d '{"minutes":60}' >/dev/null
say "contoso: field discovery open for 60 minutes"

head_ "Generating traffic"
payload() { python3 -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))["payloads"][sys.argv[2]]))' "$demo/seed.json" "$1"; }
inbound() { adm "$base/api/admin/accounts/$1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["a"]["inbound_token"])'; }

T_ACME="$(inbound acme)"; T_NW="$(inbound northwind)"; T_CT="$(inbound contoso)"
P_ACME="$(payload acme)"; P_BAD="$(payload acme_bad_date)"
P_NW="$(payload northwind)"; P_CT="$(payload contoso)"

send() { curl -sS -o /dev/null -X POST "$base/t/$1/a2b" \
  -H "Authorization: Bearer $2" -H 'Content-Type: application/json' -d "$3" || true; }

profile=(34 61 22 48 15)
for m in $(seq 0 $((MINUTES-1))); do
  n="${profile[$((m % ${#profile[@]}))]}"
  for i in $(seq 1 "$n"); do
    send acme "$T_ACME" "$P_ACME"
    [ $((i % 2))  -eq 0 ] && send northwind "$T_NW" "$P_NW"
    [ $((i % 3))  -eq 0 ] && send contoso   "$T_CT" "$P_CT"
    [ $((i % 11)) -eq 0 ] && send acme "$T_ACME" "$P_BAD"
  done
  # One credential-guessing burst, in the first minute only, then the
  # operator clears it. Left running, the lockout would 429 every
  # subsequent request and the demo would look like an outage.
  if [ "$m" -eq 0 ]; then
    for _ in $(seq 1 7); do send northwind "wrong-token" '{}'; done
    adm -X POST "$base/api/admin/accounts/northwind/tripwire/reset" >/dev/null
    say "northwind: 7 refused attempts tripped the wire, then reset"
  fi
  say "minute $((m+1))/$MINUTES  ($n batches)"
  [ "$m" -lt $((MINUTES-1)) ] && sleep 62
done

adm "$base/api/admin/stats" | python3 -c '
import json,sys
s=json.load(sys.stdin)["stats"]
print("  %d requests, %d delivered (%.1f%%), %d refused, %d fields translated"
      % (s["total"], s["ok"], s["success_pct"], s["denied"]+s["blocked"], s["applied"]))'

head_ "Ready"
echo "  Console   $base/admin/"
echo "  Token     $tok"
echo
echo "  Try:"
echo "    Dashboard  totals, per-minute chart, per-account rollup"
echo "    contoso    open it -> field discovery learned its vocabulary"
echo "    northwind  refused attempts, tripwire counter"
echo "    Activity   one row per request, metadata only"
echo
echo "  Verify the audit chain:"
echo "    $work/xlate -verify-audit $work/trail.jsonl"
echo "  Stop:"
echo "    ./demo/stop.sh"
echo
