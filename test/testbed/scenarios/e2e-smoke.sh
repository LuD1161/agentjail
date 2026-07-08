#!/usr/bin/env bash
# e2e-smoke.sh — the first real testbed scenario (follow-up Stage 3 seed).
#
# Runs INSIDE a provisioned testbed guest. Exercises agentjail exactly as a
# human's Claude Code session would, across both enforcement tiers, and asserts
# on the installed binaries' actual behavior — not on source-tree tests.
#
#   Copy in + run:
#     testbed.sh exec <name> -- 'bash -s' < test/testbed/scenarios/e2e-smoke.sh
#   or from the host:
#     limactl cp test/testbed/scenarios/e2e-smoke.sh <inst>:/tmp/ && \
#       testbed.sh exec <name> -- bash /tmp/e2e-smoke.sh
#
# Tiers:
#   Tier 1 (hook)   — Claude Code invokes agentjail-hook with PreToolUse JSON;
#                     allow = exit 0, deny = exit 2 (+ remediation hint on stderr).
#   Tier 2 (shield) — agentjail-shield wraps a process with a kernel sandbox
#                     (Landlock on Linux). cwd is granted RW, so scenarios run
#                     from a PROJECT dir (~/work/demo), like a real session —
#                     NOT from $HOME (that would grant all of home RW).
#
# Not covered here: the IMDS/cloud-metadata egress guard is shield-tier and only
# fires when a metadata service (169.254.169.254) is actually reachable — a
# plain VM has none, so it is a cloud-only scenario (see ADR 0049).

set -u
HOOK="$HOME/.agentjail/bin/agentjail-hook"
SHIELD="$HOME/.agentjail/bin/agentjail-shield"
PROJECT="$HOME/work/demo"
PASS=0; FAIL=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

hook() { # <label> <expected-exit> <json>
    local rc; echo "$3" | "$HOOK" >/dev/null 2>/tmp/he; rc=$?
    [ "$rc" = "$2" ] && ok "$1 (exit $rc)" || { bad "$1: want exit $2 got $rc"; sed 's/^/      /' /tmp/he | head -2; }
}

echo "=== install wiring ==="
grep -q agentjail-hook "$HOME/.claude/settings.json" && ok "hook wired into ~/.claude/settings.json" || bad "hook not wired"
systemctl --user is-active agentjail-daemon >/dev/null 2>&1 && ok "daemon active (systemd --user)" || bad "daemon not active"

echo "=== Tier 1: hook policy ==="
hook "allow write inside project"      0 '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$PROJECT"'/note.txt","content":"hi"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "deny write ~/.ssh/authorized_keys" 2 '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.ssh/authorized_keys","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "deny write ~/.aws/credentials"   2 '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.aws/credentials","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "deny rm -rf /"                    2 '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'

echo "=== Tier 1: remediation hint on deny ==="
echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.ssh/authorized_keys","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}' \
    | "$HOOK" 2>&1 >/dev/null | grep -qiE "ssh|sensitive|credential|blocked" && ok "deny carries a hint" || bad "deny hint missing"

echo "=== Tier 2: shield kernel sandbox (cwd = project, like a real session) ==="
cd "$PROJECT" || { bad "no project dir"; }
rm -f "$HOME/.ssh/id_rsa"; echo ORIG > "$HOME/.ssh/id_rsa"
"$SHIELD" -- bash -c 'echo PWNED > ~/.ssh/id_rsa' >/dev/null 2>&1
grep -q PWNED "$HOME/.ssh/id_rsa" && bad "shield: ~/.ssh write NOT blocked" || ok "shield blocks ~/.ssh write (Landlock EPERM)"
"$SHIELD" -- bash -c 'cat ~/.ssh/id_rsa' 2>/dev/null | grep -q ORIG && bad "shield: private-key read NOT blocked" || ok "shield blocks ~/.ssh read"
"$SHIELD" -- bash -c 'echo ok > ./shield-ok.txt' >/dev/null 2>&1
[ -f "$PROJECT/shield-ok.txt" ] && ok "shield allows project write" || bad "shield blocks project write"

echo "=== decisions recorded ==="
DB=$(ls "$HOME"/.agentjail/*.db 2>/dev/null | head -1)
[ -n "$DB" ] && { N=$(sqlite3 -readonly "$DB" "select count(*) from decisions;" 2>/dev/null); ok "decisions store has $N rows"; } || bad "no decisions store"

echo "=== RESULT: $PASS pass, $FAIL fail ==="
[ "$FAIL" = 0 ]
