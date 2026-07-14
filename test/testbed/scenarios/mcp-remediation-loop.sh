#!/usr/bin/env bash
# mcp-remediation-loop.sh — TWO-TERMINAL scenario (self-records to $SCN_CAST).
# The canonical human flow: an agent calls an MCP server agentjail doesn't allow,
# gets denied, a human runs the fix in a SEPARATE terminal (with a typed 'y'
# confirmation the agent can't supply), and the agent's retry then succeeds.
#
# pane 0 = AGENT (sandboxed)   pane 1 = OPERATOR (you)
#
# testbed-mode: tmux
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

AJ="$HOME/.agentjail/bin/agentjail"
HOOK="$HOME/.agentjail/bin/agentjail-hook"
CWD="$HOME/work/demo"
# Unique per run so the "denied before" precondition holds even if a previous
# run already allow-listed a server (allow-list removal needs a TTY confirm).
# Bogus names are harmless and wiped when the box resets to golden.
SRV="demo-remote-$(date +%s)"
SESS="tb_mcp_remediation"
MCPJSON='{"hook_event_name":"PreToolUse","tool_name":"mcp__'"$SRV"'__fetch","tool_input":{"url":"http://x"},"session_id":"rem","cwd":"'"$CWD"'"}'

# decision for the MCP call via the hook: allow (exit 0) or deny (exit 2)
mcp_decision() { echo "$MCPJSON" | "$HOOK" >/dev/null 2>&1; case $? in 0) echo allow;; 2) echo deny;; *) echo err;; esac; }

scn_init "mcp-remediation-loop" "agent MCP call denied -> operator allows in 2nd terminal -> retry allowed"

# --- correctness precondition: the server is not allowed, so it's denied ---
before=$(mcp_decision)
scn_check "MCP call denied before remediation" deny "$before"

# --- the recorded two-terminal re-enactment ---
drive() {
    sleep 1
    scn_pane "$SESS" 0 "# AGENT: call the $SRV MCP server"
    scn_pane "$SESS" 0 "echo '$MCPJSON' | $HOOK; echo exit=\$?  # 2 = DENIED by agentjail"
    sleep 2.5
    scn_pane "$SESS" 1 "# OPERATOR: agentjail denied it. Run the fix it suggested:"
    scn_pane "$SESS" 1 "$AJ mcp allow $SRV"
    sleep 2
    scn_pane "$SESS" 1 "y"                       # human confirmation the agent can't supply
    sleep 2
    scn_pane "$SESS" 0 "# AGENT: retry the same call"
    scn_pane "$SESS" 0 "echo '$MCPJSON' | $HOOK; echo exit=\$?  # 0 = now ALLOWED"
    sleep 2.5
}
scn_record_tmux "$SESS" drive

# --- correctness postcondition: operator's allow took effect ---
after=$(mcp_decision)
scn_check "MCP call allowed after operator ran 'agentjail mcp allow'" allow "$after"
"$AJ" mcp list 2>/dev/null | grep -qi "$SRV" && scn_check "$SRV now in allow-list" yes yes || scn_check "$SRV now in allow-list" yes no

scn_finish
