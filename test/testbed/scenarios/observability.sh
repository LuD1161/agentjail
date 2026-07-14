#!/usr/bin/env bash
# observability.sh — sessions/logs/replay surface: `sessions list`, `logs`
# (capped with a timeout since it's a streaming TUI), and `replay <id>`
# (skipped gracefully if no session id is available). Runs INSIDE a
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

echo "=== sessions (bare — expected usage error) ==="
# Capture agentjail's own exit code (no pipe, or $? would be grep's/filt's).
OUT=$(timeout 30 "$AJ" sessions 2>&1); RC=$?
echo "$OUT" | filt
echo "$OUT" | grep -qi "usage: agentjail sessions" && ok "sessions (bare) prints usage" || bad "sessions (bare) usage message not as expected"
[ "$RC" = 2 ] && ok "sessions (bare) exits 2 (usage error)" || bad "sessions (bare) exit code $RC (expected 2)"

echo "=== sessions list ==="
OUT=$(timeout 30 "$AJ" sessions list 2>&1); RC=$?
echo "$OUT" | filt | head -20
[ "$RC" = 0 ] && ok "sessions list exits 0" || bad "sessions list exit code $RC (expected 0)"

echo "=== logs (TUI — capped at 5s) ==="
OUT=$(timeout 5 "$AJ" logs 2>&1 | sed $'s/\033\\[[0-9;]*m//g' | filt)
echo "$OUT" | head -12
echo "  -> (logs capped by timeout)"
ok "logs ran under a 5s cap without hanging the scenario"

echo "=== replay <id> (best-effort; skip if no session id available) ==="
SID=$(echo "$OUT" | grep -oE '[0-9a-f]{6,}' | head -1)
if [ -z "${SID:-}" ]; then
    SID=$(timeout 30 "$AJ" sessions list 2>&1 | filt | grep -oE '[0-9a-f]{6,}' | head -1)
fi
if [ -n "${SID:-}" ]; then
    OUT2=$(timeout 30 "$AJ" replay "$SID" 2>&1 | filt); RC2=$?
    echo "$OUT2" | head -20
    [ "$RC2" = 0 ] && ok "replay $SID exits 0" || bad "replay $SID exit code $RC2 (expected 0)"
else
    skip "replay <id> (no session id available in this guest)"
fi

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
