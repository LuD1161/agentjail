#!/usr/bin/env bash
# run-shield.sh — `agentjail run --` shielded execution: allowed exec,
# blocked ~/.ssh read + write, and cwd=project write allowed. Runs INSIDE a
# provisioned testbed guest, against the INSTALLED `agentjail run` (not the
# raw shield binary — see e2e-smoke.sh for the Tier-2 shield-binary tests).
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

mkdir -p "$PROJECT"
cd "$PROJECT" || { bad "no project dir ($PROJECT)"; echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="; exit 1; }

echo "=== run -- echo (allowed exec) ==="
OUT=$(timeout 30 "$AJ" run -- echo hi 2>&1 | filt)
echo "$OUT"
echo "$OUT" | grep -qi "starting shielded session for echo" && ok "run announces shielded session" || bad "run did not announce shielded session"
echo "$OUT" | grep -qx "hi" && ok "run -- echo hi produced 'hi'" || bad "run -- echo hi did not produce 'hi'"

echo "=== run -- cat ~/.ssh/id_rsa (blocked read) ==="
mkdir -p "$HOME/.ssh"
echo ORIG > "$HOME/.ssh/id_rsa" 2>/dev/null || true
OUT=$(timeout 30 "$AJ" run -- cat "$HOME/.ssh/id_rsa" 2>&1 | filt)
echo "$OUT"
echo "$OUT" | grep -q ORIG && bad "shield did NOT block private-key read via run" || ok "shield blocked private-key read via run"

echo "=== run -- write to ~/.ssh (blocked write) ==="
OUT=$(timeout 30 "$AJ" run -- bash -c 'echo PWNED > ~/.ssh/id_rsa' 2>&1 | filt)
echo "$OUT"
grep -q PWNED "$HOME/.ssh/id_rsa" 2>/dev/null && bad "shield did NOT block ~/.ssh write via run" || ok "shield blocked ~/.ssh write via run"

echo "=== run -- write inside project cwd (allowed) ==="
rm -f "$PROJECT/run-shield-ok.txt"
OUT=$(timeout 30 "$AJ" run -- bash -c 'echo ok > ./run-shield-ok.txt' 2>&1 | filt)
echo "$OUT"
[ -f "$PROJECT/run-shield-ok.txt" ] && ok "run allows project-cwd write" || bad "run blocked project-cwd write"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
