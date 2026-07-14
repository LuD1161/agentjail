#!/usr/bin/env bash
# policy-mgmt.sh — policy inspection + mutation guardrails: `policy list`,
# `policy add` rejecting a non-rego file, `policy remove` of a missing rule,
# and `policy disable` of a core rule being refused without an interactive
# TTY. Runs INSIDE a provisioned testbed guest.
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

echo "=== policy list ==="
OUT=$(timeout 30 "$AJ" policy list 2>&1 | filt)
echo "$OUT" | head -30
echo "$OUT" | grep -qi "Core Rules" && ok "policy list shows Core Rules section" || bad "policy list missing Core Rules section"
echo "$OUT" | grep -qE '(✓ on|locked)' && ok "policy list shows rule status rows" || bad "policy list missing rule status rows"

echo "=== policy add (non-rego file rejected) ==="
BADFILE=/tmp/policy-mgmt-bad-rule.yaml
cat > "$BADFILE" <<'YAML'
rules:
  - id: pm/no-touch-tmpsecret
    description: block writes to /tmp/pm-secret
    match:
      tool: Write
      path_glob: "/tmp/pm-secret*"
    action: deny
YAML
OUT=$(timeout 30 "$AJ" policy add "$BADFILE" 2>&1); RC=$?
echo "$OUT"
[ "$RC" != 0 ] && ok "policy add (non-rego) exits non-zero ($RC)" || bad "policy add (non-rego) unexpectedly succeeded"
echo "$OUT" | grep -qi "package agentjail" && ok "policy add rejects file missing 'package agentjail'" || bad "policy add rejection message not as expected"

echo "=== policy remove (missing rule) ==="
OUT=$(timeout 30 "$AJ" policy remove pm-nonexistent-rule-id 2>&1); RC=$?
echo "$OUT"
[ "$RC" != 0 ] && ok "policy remove (missing) exits non-zero ($RC)" || bad "policy remove (missing) unexpectedly succeeded"
echo "$OUT" | grep -qi "not found" && ok "policy remove reports 'not found in ~/.agentjail/rules'" || bad "policy remove missing-rule message not as expected"

echo "=== policy disable (core rule, non-TTY) ==="
OUT=$(timeout 30 "$AJ" policy disable command_policy/no-sudo < /dev/null 2>&1); RC=$?
echo "$OUT"
if echo "$OUT" | grep -qiE 'force|tty|interactive'; then
    ok "core-rule disable refused without --force/TTY"
else
    bad "core-rule disable did not show the expected force/tty/interactive guard (rc=$RC)"
fi
# Never assert success (rc==0) here would mean the guard was bypassed —
# call that out explicitly rather than silently passing.
if [ "$RC" = 0 ]; then
    bad "core-rule disable exited 0 in non-TTY — guard may have been bypassed"
else
    ok "core-rule disable exited non-zero in non-TTY ($RC)"
fi
skip "policy disable happy-path (requires --force + interactive TTY confirmation)"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
