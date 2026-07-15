#!/usr/bin/env bash
# skill.sh — skill inspection (`skill list`) plus the anti-self-approval
# guard: `skill ask`/`skill clear` must be REFUSED with no interactive
# terminal. Runs INSIDE a provisioned testbed guest.
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

echo "=== skill list ==="
OUT=$(timeout 30 "$AJ" skill list 2>&1 | filt)
echo "$OUT" | head -20
echo "$OUT" | grep -qi "Skills" && ok "skill list shows Skills section" || bad "skill list missing Skills section"

echo "=== skill ask / skill clear — anti-self-approval guard (non-TTY) ==="
# Use a placeholder skill name; the guard should fire before any lookup of a
# real skill, since it is a terminal-detection check, not a name-validation
# check.
SK="placeholder-skill"

OUT=$(timeout 30 "$AJ" skill ask "$SK" < /dev/null 2>&1); RC=$?
echo "$OUT"
if echo "$OUT" | grep -qi "REFUSED" && echo "$OUT" | grep -qi "no interactive terminal"; then
    ok "skill ask refused (no interactive terminal detected)"
else
    bad "skill ask did not show expected REFUSED/no-interactive-terminal message"
fi
echo "$OUT" | grep -qi "self-approving a skill" && ok "skill ask refusal names self-approval risk" || bad "skill ask refusal missing self-approval wording"
[ "$RC" = 1 ] && ok "skill ask exits 1 in non-TTY" || bad "skill ask exit code $RC (expected 1)"

OUT=$(timeout 30 "$AJ" skill clear "$SK" < /dev/null 2>&1); RC=$?
echo "$OUT"
if echo "$OUT" | grep -qi "REFUSED" && echo "$OUT" | grep -qi "no interactive terminal"; then
    ok "skill clear refused (no interactive terminal detected)"
else
    bad "skill clear did not show expected REFUSED/no-interactive-terminal message"
fi
echo "$OUT" | grep -qi "self-approving a skill" && ok "skill clear refusal names self-approval risk" || bad "skill clear refusal missing self-approval wording"
[ "$RC" = 1 ] && ok "skill clear exits 1 in non-TTY" || bad "skill clear exit code $RC (expected 1)"

skip "skill ask/clear happy-path (requires interactive TTY confirmation)"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
