#!/usr/bin/env bash
# capture.sh —  eslogger spike capture script.
#
# Subscribes to a minimal set of Endpoint Security events relevant to the
# tamper-evidence cross-check against the user-space PATH shim. NOTIFY-only,
# no AUTH (we do not have the Endpoint Security entitlement;  handles
# that story). Inspired by eBPF's NOTIFY-before-AUTH discipline
# (docs/ENGINEERING.md §2).
#
# Usage:
#   sudo ./capture.sh [SECONDS] [OUTFILE]
# Defaults: 30 seconds, samples/exec-sample.jsonl
#
# Why these events:
#   exec  — primary signal; what our PATH shim is supposed to catch
#   fork  — pair with exec to reconstruct process trees
#   exit  — close the lifecycle for diff in 
set -euo pipefail

SECS="${1:-30}"
OUT="${2:-$(dirname "$0")/samples/exec-sample.jsonl}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: eslogger requires root (ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED). re-run with sudo." >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

echo "capturing ES {exec,fork,exit} for ${SECS}s -> $OUT" >&2
# eslogger writes one JSON object per line to stdout. macOS has no /usr/bin/timeout,
# so we background it and kill on SIGALRM-equivalent via a sleep+kill watchdog.
/usr/bin/eslogger exec fork exit > "$OUT" &
ES_PID=$!
( sleep "${SECS}" && kill "${ES_PID}" 2>/dev/null ) &
WATCH_PID=$!
wait "${ES_PID}" 2>/dev/null || true
kill "${WATCH_PID}" 2>/dev/null || true

LINES="$(/usr/bin/wc -l < "$OUT" | /usr/bin/tr -d ' ')"
echo "captured ${LINES} events in ${SECS}s (~$((LINES / SECS)) ev/s)" >&2
