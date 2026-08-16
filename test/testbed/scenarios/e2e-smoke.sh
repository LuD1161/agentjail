#!/usr/bin/env bash
# e2e-smoke.sh — single-terminal scenario (recorded whole by the runner).
# Exercises agentjail as a human's Claude Code session would, across both tiers,
# on the INSTALLED binaries. Emits a result JSON via reportlib; still runs
# standalone under `testbed.sh test`.
#
# testbed-mode: single
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

HOOK="$HOME/.agentjail/bin/agentjail-hook"
SHIELD="$HOME/.agentjail/bin/agentjail-shield"
PROJECT="$HOME/work/demo"
SECRETS="$HOME/.agentjail/bin/agentjail-secrets"
DEMO_SECRET="testbed/demo"

cleanup_demo_secret() {
    [ ! -x "$SECRETS" ] || "$SECRETS" delete "$DEMO_SECRET" >/dev/null 2>&1 || true
}
trap cleanup_demo_secret EXIT INT TERM

scn_init "e2e-smoke" "clean-box install + hook & shield policy enforcement"

# hook <label> <expected: allow|deny> <json> — maps exit 0->allow, 2->deny.
hook() {
    local rc dec; echo "$3" | "$HOOK" >/dev/null 2>/tmp/he; rc=$?
    case "$rc" in 0) dec=allow;; 2) dec=deny;; *) dec="exit$rc";; esac
    scn_check "$1" "$2" "$dec"
}

# install wiring follows the selected-agent contract from ADR 0053.
installed_agent_hooks=0
if command -v claude >/dev/null 2>&1; then
    installed_agent_hooks=$((installed_agent_hooks+1))
    grep -q agentjail-hook "$HOME/.claude/settings.json" \
        && scn_ok "Claude hook wired in settings.json" \
        || scn_fail "Claude hook wired in settings.json"
fi
if command -v codex >/dev/null 2>&1; then
    installed_agent_hooks=$((installed_agent_hooks+1))
    grep -q 'agentjail-hook --agent=codex' "$HOME/.codex/hooks.json" \
        && scn_ok "Codex hook wired in hooks.json" \
        || scn_fail "Codex hook wired in hooks.json"
fi
[ "$installed_agent_hooks" -gt 0 ] || scn_fail "a supported coding agent is installed"
# macOS uses launchd (LaunchAgent plist); Linux uses systemd --user.
if [ "$(uname -s)" = "Darwin" ]; then
    launchctl list 2>/dev/null | grep -q agentjail && scn_ok "daemon active (launchd)" || scn_fail "daemon active (launchd)"
else
    systemctl --user is-active agentjail-daemon >/dev/null 2>&1 && scn_ok "daemon active (systemd --user)" || scn_fail "daemon active (systemd --user)"
fi

# Tier 1 — hook policy
hook "hook: allow write inside project"       allow '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$PROJECT"'/note.txt","content":"hi"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "hook: deny write ~/.ssh/authorized_keys" deny '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.ssh/authorized_keys","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "hook: deny write ~/.aws/credentials"     deny '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.aws/credentials","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "hook: deny rm -rf /"                     deny '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'

# remediation hint on deny. Capture stderr into a var first: piping the hook
# (which exits 2 on deny) straight into grep trips `set -o pipefail`.
hint_out=$(echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.ssh/authorized_keys","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}' | "$HOOK" 2>&1 1>/dev/null || true)
if grep -qiE "ssh|sensitive|credential|blocked" <<<"$hint_out"; then scn_ok "deny carries remediation hint"; else scn_fail "deny carries remediation hint"; fi

# Tier 2 — shield (cwd = project, like a real session)
cd "$PROJECT" 2>/dev/null || true
rm -f "$HOME/.ssh/id_rsa"; echo ORIG > "$HOME/.ssh/id_rsa"
"$SHIELD" -- bash -c 'echo PWNED > ~/.ssh/id_rsa' >/dev/null 2>&1
grep -q PWNED "$HOME/.ssh/id_rsa" && scn_fail "shield blocks ~/.ssh write" || scn_ok "shield blocks ~/.ssh write"
"$SHIELD" -- bash -c 'cat ~/.ssh/id_rsa' 2>/dev/null | grep -q ORIG && scn_fail "shield blocks ~/.ssh read" || scn_ok "shield blocks ~/.ssh read"
"$SHIELD" -- bash -c 'echo ok > ./shield-ok.txt' >/dev/null 2>&1
[ -f "$PROJECT/shield-ok.txt" ] && scn_ok "shield allows project write" || scn_fail "shield allows project write"

# Secrets broker — on-demand auto-start (ADR 0058, DEFECT-2).
SECRETS_SOCK="$HOME/.agentjail/secrets.sock"
if [ "$(uname -s)" = "Darwin" ]; then
    SECRETS_SVC_FILE="$HOME/Library/LaunchAgents/com.agentjail.secrets.plist"
else
    SECRETS_SVC_FILE="$HOME/.config/systemd/user/agentjail-secrets.service"
fi

# a. loaded-but-not-running service definition was installed.
[ -f "$SECRETS_SVC_FILE" ] && scn_ok "secrets broker service definition installed" || scn_fail "secrets broker service definition installed"

# b. broker is dormant right after install — no manual `serve` was run.
[ -S "$SECRETS_SOCK" ] && scn_fail "secrets broker dormant after install (no socket yet)" || scn_ok "secrets broker dormant after install (no socket yet)"

# c. setting a secret must succeed WITHOUT a manual `agentjail-secrets serve` —
# this is the auto-start path (rpcClient -> EnsureSecretsBroker on connect-refused).
"$SECRETS" set "$DEMO_SECRET" hello-from-e2e-smoke >/tmp/secrets-set.log 2>&1
set_rc=$?
[ "$set_rc" -eq 0 ] && scn_ok "secrets broker: set auto-starts broker" || scn_fail "secrets broker: set auto-starts broker"

# d. broker is now reachable — proves auto-start actually brought it up.
[ -S "$SECRETS_SOCK" ] && scn_ok "secrets broker reachable after set (auto-started)" || scn_fail "secrets broker reachable after set (auto-started)"

# e. round-trip: the secret name comes back from list (never the value).
list_out=$("$SECRETS" list 2>/tmp/secrets-list.log)
if grep -qx "$DEMO_SECRET" <<<"$list_out"; then scn_ok "secrets broker: list round-trips secret name"; else scn_fail "secrets broker: list round-trips secret name"; fi

# f. cleanup is part of the contract: no fixture may remain in the guest keychain.
if "$SECRETS" delete "$DEMO_SECRET" >/tmp/secrets-delete.log 2>&1 \
    && ! "$SECRETS" list 2>/tmp/secrets-list-after-delete.log | grep -qx "$DEMO_SECRET"; then
    scn_ok "secrets broker: fixture removed after round-trip"
else
    scn_fail "secrets broker: fixture removed after round-trip"
fi

scn_finish
