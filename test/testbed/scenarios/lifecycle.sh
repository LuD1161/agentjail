#!/usr/bin/env bash
# lifecycle.sh — install-lifecycle surface: version, status, doctor, and
# install idempotency on the INSTALLED agentjail binaries. Runs INSIDE a
# provisioned testbed guest.
#
# Does NOT run uninstall/update — those are destructive/network side effects.
# We only document (echo) what they would do, per the test-catalog spec.
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

echo "=== version ==="
OUT=$(timeout 30 "$AJ" version 2>&1 | filt)
echo "$OUT" | head -5
echo "$OUT" | grep -qi "AgentJail" && ok "version prints AgentJail banner" || bad "version banner missing"

echo "=== status ==="
OUT=$(timeout 30 "$AJ" status 2>&1 | filt)
echo "$OUT" | head -20
echo "$OUT" | grep -qi "Infrastructure" && ok "status shows Infrastructure section" || bad "status missing Infrastructure section"
echo "$OUT" | grep -qi "Agent hooks" && ok "status shows Agent hooks section" || bad "status missing Agent hooks section"
echo "$OUT" | grep -qi "Claude" && ok "status reports Claude hook detection" || bad "status missing Claude hook line"

echo "=== doctor ==="
OUT=$(timeout 30 "$AJ" doctor 2>&1 | filt)
echo "$OUT" | head -30
echo "$OUT" | grep -qi "All checks passed" && ok "doctor: All checks passed" || bad "doctor did not report all checks passed"

echo "=== install idempotency ==="
[ -d "$HOME/.agentjail" ] && ok "install present (~/.agentjail)" || bad "install missing (~/.agentjail)"
[ -x "$AJ" ] && ok "agentjail binary is executable" || bad "agentjail binary missing/non-executable"
[ -d "$PROJECT" ] && ok "seed project present ($PROJECT)" || bad "seed project missing"
# Re-running a read-only diagnostic command twice should be idempotent (no
# state mutation, same exit code both times) — a cheap proxy for "install
# is stable", without re-running the actual installer (network + binary swap).
RC1=0; timeout 30 "$AJ" status >/dev/null 2>&1 || RC1=$?
RC2=0; timeout 30 "$AJ" status >/dev/null 2>&1 || RC2=$?
[ "$RC1" = "$RC2" ] && ok "status exit code stable across repeated invocation ($RC1)" || bad "status exit code changed between runs ($RC1 vs $RC2)"

echo "=== NOT exercised here (destructive / external) ==="
echo "  uninstall : removes ~/.agentjail entirely; owned by cli-tour.sh's finale only."
echo "  update    : replaces installed binaries from the network release channel;"
echo "              would clobber the dev build under test."
skip "uninstall (destructive teardown — belongs to cli-tour.sh finale only)"
skip "update (network side effect; would replace binaries under test)"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
