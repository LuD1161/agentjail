#!/usr/bin/env bash
# egress-grants.sh — runtime egress grant workflow: `grants` (empty),
# `allow host <h>` (creates a pending grant), `grants` (lists the pending
# request). Does NOT approve/deny the grant — that requires the interactive
# daemon-side approval flow. Runs INSIDE a provisioned testbed guest.
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

echo "=== grants (expected empty) ==="
OUT=$(timeout 30 "$AJ" grants 2>&1 | filt)
echo "$OUT" | head -10
echo "$OUT" | grep -qi "no pending grant requests" && ok "grants (empty) reports no pending grant requests" || bad "grants (empty) message not as expected"

echo "=== allow host (creates a pending grant) ==="
HOST="egress-grants-test.example.com"
OUT=$(timeout 30 "$AJ" allow host "$HOST" 2>&1 | filt); RC=$?
echo "$OUT"
echo "$OUT" | grep -qi "requested host $HOST" && ok "allow host reports requested host" || bad "allow host message missing 'requested host $HOST'"
echo "$OUT" | grep -qi "pending human approval" && ok "allow host reports pending human approval" || bad "allow host message missing pending-approval wording"
echo "$OUT" | grep -qiE "grant_id" && ok "allow host reports a grant_id" || bad "allow host message missing grant_id"
[ "$RC" = 0 ] && ok "allow host exits 0" || bad "allow host exit code $RC (expected 0)"

echo "=== grants (should now list the pending request) ==="
OUT=$(timeout 30 "$AJ" grants 2>&1 | filt)
echo "$OUT" | head -20
echo "$OUT" | grep -qF "$HOST" && ok "grants lists the pending host request" || bad "grants does not list the pending host request"

skip "grant approve/deny (requires interactive human-approval flow, not exercised here)"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
