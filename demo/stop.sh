#!/usr/bin/env bash
# Stops the xlate demo. Pass --purge to delete the scratch directory too.
set -uo pipefail
work="${TMPDIR:-/tmp}/xlate-demo"
quiet=0; purge=0
for a in "$@"; do
  case "$a" in --quiet) quiet=1 ;; --purge) purge=1 ;; esac
done
for n in xlate upstream; do
  f="$work/$n.pid"
  if [ -f "$f" ]; then
    pid="$(cat "$f" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill "$pid" 2>/dev/null; then
      [ "$quiet" = 1 ] || echo "stopped $n (pid $pid)"
    fi
    rm -f "$f"
  fi
done
if [ "$purge" = 1 ]; then
  rm -rf "$work"
  [ "$quiet" = 1 ] || echo "removed $work"
fi
