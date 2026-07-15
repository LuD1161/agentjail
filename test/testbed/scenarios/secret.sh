#!/usr/bin/env bash
# secret.sh — scoped credential vault surface: `secret list` (empty),
# `secret set`/`secret remove`. Also DETECTS whether the `agentjail-secrets`
# vault binary is actually shipped in the install dir/PATH — if it is absent,
# that is recorded as a FINDING (not silently skipped), since `secret set`
# then fails and the happy-path round-trip cannot be exercised. Runs INSIDE a
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
# A genuine environmental/packaging gap — surfaced prominently but kept OUT of
# the pass/fail tally (it is not a scenario defect). Mirrors cli-tour.sh.
finding() { echo "FINDING  $1"; }

filt() { grep -vE 'resolving allowed_hosts|IPs resolved for allowed_hosts|could not resolve .*: lookup'; }

echo "=== secret list (expected empty) ==="
OUT=$(timeout 30 "$AJ" secret list 2>&1 | filt)
echo "$OUT" | head -10
echo "$OUT" | grep -qi "no credentials configured" && ok "secret list (empty) reports no credentials configured" || bad "secret list (empty) message not as expected"

echo "=== vault binary detection ==="
VAULT_BIN="$HOME/.agentjail/bin/agentjail-secrets"
VAULT_PRESENT=0
if [ -x "$VAULT_BIN" ]; then
    VAULT_PRESENT=1
    ok "agentjail-secrets vault binary present at $VAULT_BIN"
elif command -v agentjail-secrets >/dev/null 2>&1; then
    VAULT_PRESENT=1
    ok "agentjail-secrets vault binary present on PATH ($(command -v agentjail-secrets))"
else
    finding "agentjail-secrets vault binary is NOT shipped (checked $VAULT_BIN and PATH) — 'secret set' cannot succeed"
fi

echo "=== secret set (roundtrip, gated on vault binary) ==="
if [ "$VAULT_PRESENT" = 1 ]; then
    OUT=$(timeout 30 "$AJ" secret set testtoken --value REDACTED --hosts api.example.com 2>&1); RC=$?
    echo "$OUT"
    if [ "$RC" = 0 ]; then
        ok "secret set succeeded (vault binary present)"
        OUT2=$(timeout 30 "$AJ" secret list 2>&1 | filt)
        echo "$OUT2" | grep -qi testtoken && ok "secret set persisted (value not shown)" || bad "secret not listed after set"
        timeout 30 "$AJ" secret remove testtoken >/dev/null 2>&1
    else
        bad "secret set failed despite vault binary present (rc=$RC)"
    fi
else
    OUT=$(timeout 30 "$AJ" secret set testtoken --value REDACTED --hosts api.example.com 2>&1); RC=$?
    echo "$OUT"
    [ "$RC" != 0 ] && ok "secret set fails as expected without vault binary (rc=$RC)" || bad "secret set unexpectedly succeeded without vault binary"
    skip "secret set/list roundtrip happy-path (agentjail-secrets vault binary not shipped)"
fi

echo "=== secret remove (reports missing vault binary when absent) ==="
OUT=$(timeout 30 "$AJ" secret remove nonexistent-secret 2>&1)
echo "$OUT"
if [ "$VAULT_PRESENT" = 1 ]; then
    echo "INFO  secret remove output (vault present): $OUT"
else
    echo "$OUT" | grep -qi "agentjail-secrets not found" && ok "secret remove reports vault binary not found in install dir or PATH" || bad "secret remove missing-vault message not as expected"
fi

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
