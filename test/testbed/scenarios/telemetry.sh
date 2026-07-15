#!/usr/bin/env bash
# telemetry.sh — local telemetry config surface: `telemetry view` (JSON array
# of queued events), `telemetry disable`, `telemetry view` again, `telemetry
# enable`. This is local config only — no data is transmitted by view/
# disable/enable. Restores telemetry to enabled at the end so it doesn't
# leave the guest in a different state than it started. Runs INSIDE a
# provisioned testbed guest.
set -u
AJ="$HOME/.agentjail/bin/agentjail"
PROJECT="$HOME/work/demo"

command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout  >/dev/null 2>&1 || timeout(){ shift; "$@"; }

PASS=0; FAIL=0; SKIP=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

filt() { grep -vE 'resolving allowed_hosts|IPs resolved for allowed_hosts|could not resolve .*: lookup'; }

echo "=== telemetry view ==="
OUT=$(timeout 30 "$AJ" telemetry view 2>&1 | filt); RC=$?
echo "$OUT" | head -20
[ "$RC" = 0 ] && ok "telemetry view exits 0" || bad "telemetry view exit code $RC (expected 0)"
TRIMMED=$(echo "$OUT" | tr -d '[:space:]')
case "$TRIMMED" in
    \[*) ok "telemetry view output looks like a JSON array" ;;
    *) bad "telemetry view output does not look like a JSON array" ;;
esac

echo "=== telemetry disable ==="
OUT=$(timeout 30 "$AJ" telemetry disable 2>&1 | filt); RC=$?
echo "$OUT"
echo "$OUT" | grep -qi "telemetry disabled" && ok "telemetry disable reports 'telemetry disabled'" || bad "telemetry disable message not as expected"
[ "$RC" = 0 ] && ok "telemetry disable exits 0" || bad "telemetry disable exit code $RC (expected 0)"

echo "=== telemetry view (after disable) ==="
OUT=$(timeout 30 "$AJ" telemetry view 2>&1 | filt); RC=$?
echo "$OUT" | head -10
[ "$RC" = 0 ] && ok "telemetry view (after disable) exits 0" || bad "telemetry view (after disable) exit code $RC (expected 0)"

echo "=== telemetry enable (restore state) ==="
OUT=$(timeout 30 "$AJ" telemetry enable 2>&1 | filt); RC=$?
echo "$OUT"
echo "$OUT" | grep -qi "telemetry enabled" && ok "telemetry enable reports 'telemetry enabled'" || bad "telemetry enable message not as expected"
[ "$RC" = 0 ] && ok "telemetry enable exits 0" || bad "telemetry enable exit code $RC (expected 0)"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
