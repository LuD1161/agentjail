#!/usr/bin/env bash
# agent-conformance.sh — exercise the shared hook contract through every
# supported coding-agent adapter without requiring a provider login.
#
# The inputs are the native JSON shapes for Claude Code, Codex, and Cursor.
# This catches adapter drift while keeping the assertions deterministic.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

HOOK="$HOME/.agentjail/bin/agentjail-hook"
PROJECT="$HOME/work/demo"

scn_init "agent-conformance" "common allow/deny enforcement across Claude, Codex, and Cursor"

if [ ! -x "$HOOK" ]; then
    scn_fail "agentjail hook installed"
    scn_finish
    exit 0
fi

# Claude and Codex use the same PreToolUse wire shape. Their adapter-specific
# distinction is the output contract, so assert both exit status and JSON.
run_exit_hook() {
    local label="$1" expected="$2" payload="$3" rc actual
    printf '%s\n' "$payload" | "$HOOK" --agent="$4" >/dev/null 2>/tmp/agent-conformance.err
    rc=$?
    case "$rc" in 0) actual=allow;; 2) actual=deny;; *) actual="exit$rc";; esac
    scn_check "$label" "$expected" "$actual"
}

run_exit_hook "Claude allow project write" allow \
    '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$PROJECT"'/claude.txt","content":"ok"},"session_id":"conformance-claude","cwd":"'"$PROJECT"'"}' claude
run_exit_hook "Claude deny SSH key read" deny \
    '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"'"$HOME"'/.ssh/id_rsa"},"session_id":"conformance-claude","cwd":"'"$PROJECT"'"}' claude
run_exit_hook "Codex allow project shell" allow \
    '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok > '"$PROJECT"'/codex.txt"},"session_id":"conformance-codex","cwd":"'"$PROJECT"'"}' codex
run_exit_hook "Codex deny rm command" deny \
    '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"},"session_id":"conformance-codex","cwd":"'"$PROJECT"'"}' codex

run_cursor() {
    local label="$1" expected="$2" payload="$3" want actual rc
    printf '%s\n' "$payload" | "$HOOK" --agent=cursor > /tmp/agent-conformance.cursor.out 2>/tmp/agent-conformance.err
    rc=$?
    actual=$(jq -r '.permission // "invalid"' /tmp/agent-conformance.cursor.out 2>/dev/null)
    [ "$rc" -eq 0 ] || actual="exit$rc"
    scn_check "$label" "$expected" "$actual"
}

run_cursor "Cursor allow harmless shell" allow \
    '{"hook_event_name":"beforeShellExecution","command":"pwd","cwd":"'"$PROJECT"'","workspace_roots":["'"$PROJECT"'"]}'
run_cursor "Cursor deny SSH file read" deny \
    '{"hook_event_name":"beforeReadFile","file_path":"'"$HOME"'/.ssh/id_rsa","workspace_roots":["'"$PROJECT"'"]}'
run_cursor "Cursor deny rm command" deny \
    '{"hook_event_name":"beforeShellExecution","command":"rm -rf /","cwd":"'"$PROJECT"'","workspace_roots":["'"$PROJECT"'"]}'

scn_finish
