#!/usr/bin/env bash
# trust.sh — project policy overlay trust workflow: `trust <path>`,
# `trust list`, `untrust <path>`. Runs INSIDE a provisioned testbed guest.
#
# The overlay file must be shaped like the Go `config.PolicyConfig` struct
# (agentpolicy/config/config.go), NOT a bare `rules:` list — a bare list
# still "trusts" (with a parse warning) but we write a schema-correct overlay
# here so the round-trip is warning-free.
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

mkdir -p "$PROJECT/.agentjail"
# config.PolicyConfig-shaped overlay (top-level keys: mcp, file, commands,
# network, web, aws, secrets, credentials, skills, disabled_rules,
# daemon_unreachable). An empty disabled_rules list is a minimal, valid,
# warning-free overlay.
cat > "$PROJECT/.agentjail/policy.yaml" <<'YAML'
disabled_rules: []
YAML

echo "=== trust ==="
OUT=$(timeout 30 "$AJ" trust "$PROJECT" 2>&1 | filt); RC=$?
echo "$OUT"
if echo "$OUT" | grep -qi "overlay does not parse cleanly"; then
    echo "INFO  overlay produced a parse warning (unexpected for a PolicyConfig-shaped file, but non-fatal)"
fi
echo "$OUT" | grep -qi "trusted:" && ok "trust reports trusted: <path> (sha256 ...)" || bad "trust confirmation message not as expected"
[ "$RC" = 0 ] && ok "trust exits 0" || bad "trust exit code $RC (expected 0)"

echo "=== trust list ==="
OUT=$(timeout 30 "$AJ" trust list 2>&1 | filt)
echo "$OUT" | head -10
echo "$OUT" | grep -qF "$PROJECT" && ok "trust list shows the trusted project path" || bad "trust list missing project path"
echo "$OUT" | grep -qi "sha256" && ok "trust list shows sha256 digest" || bad "trust list missing sha256 digest"

echo "=== untrust ==="
OUT=$(timeout 30 "$AJ" untrust "$PROJECT" 2>&1 | filt); RC=$?
echo "$OUT"
echo "$OUT" | grep -qi "untrusted:" && ok "untrust reports untrusted: <path>" || bad "untrust confirmation message not as expected"
[ "$RC" = 0 ] && ok "untrust exits 0" || bad "untrust exit code $RC (expected 0)"

echo "=== trust list (after untrust) ==="
OUT=$(timeout 30 "$AJ" trust list 2>&1 | filt)
echo "$OUT" | head -10
echo "$OUT" | grep -qF "$PROJECT" && bad "trust list still shows project after untrust" || ok "trust list no longer shows project after untrust"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
