#!/usr/bin/env bash
# codex-approval.sh — live Codex native approval and host-proxy matrix.
# Runs only in a disposable testbed provisioned with --codex-auth.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"
command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout >/dev/null 2>&1 || timeout(){ shift; "$@"; }

AJ="$HOME/.agentjail/bin/agentjail"
HOOK="$HOME/.agentjail/bin/agentjail-hook"
CODEX_REAL="$(command -v codex)"
CODEX_SHIM="$HOME/.agentjail/bin/codex"
POLICY="$HOME/.agentjail/policy.yaml"
PROJECT="$HOME/work/codex-approval"
REMOTE="$PROJECT/.remote.git"
SESSION="codex-approval-$RANDOM"
PANE_LOG="/tmp/codex-approval-pane.log"
CODEX_VERSION="codex-cli ${AGENTJAIL_TESTBED_CODEX_VERSION:-0.147.0}"
PROMPT_MARKER="agentjail approval-exec --operation shell-command"
DISPLAY_MARKER="🔐 AgentJail approval required for:"
EXPECTED_CONTEXT=""
CUSTOM_RULE_INSTALLED=0
GIT_SSH_DISABLED=0

scn_init "codex-approval" "native approval for Bash asks and one bounded host-proxy execution"

cleanup() {
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    if [ "$CUSTOM_RULE_INSTALLED" -eq 1 ]; then
        "$AJ" policy remove codex_approval_probe >/dev/null 2>&1 || true
    fi
    if [ "$GIT_SSH_DISABLED" -eq 1 ]; then
        sed -i.agentjail-test 's/git_ssh: false/git_ssh: true/' "$POLICY" 2>/dev/null || true
        rm -f "$POLICY.agentjail-test"
    fi
    rm -f /tmp/codex-auth.json "$HOME/.codex/auth.json"
    rm -f /tmp/codex-hostproxy-direct.log /tmp/codex-hostproxy-bypass.log
    rm -f "$PANE_LOG"
    [ -z "${HOST_PROXY_SENTINEL:-}" ] || rm -f "$HOST_PROXY_SENTINEL"
}
trap cleanup EXIT INT TERM

finish_and_exit() {
    scn_finish
    exit $?
}

if [ ! -f /tmp/codex-auth.json ]; then
    scn_fail "disposable Codex auth was explicitly provided"
    finish_and_exit
fi
mkdir -p "$HOME/.codex"
chmod 700 "$HOME/.codex"
install -m 0600 /tmp/codex-auth.json "$HOME/.codex/auth.json"
rm -f /tmp/codex-auth.json
CODEX_VERSION_OUTPUT="$("$CODEX_REAL" --version 2>/dev/null || true)"
if [ ! -x "$CODEX_REAL" ] || ! printf '%s\n' "$CODEX_VERSION_OUTPUT" | grep -Fq "$CODEX_VERSION"; then
    scn_fail "installed Codex version is $CODEX_VERSION"
    finish_and_exit
fi
scn_ok "installed Codex version is $CODEX_VERSION"

if grep -q '^[[:space:]]*git_ssh: false$' "$POLICY"; then
    :
elif grep -q '^[[:space:]]*git_ssh: true$' "$POLICY" \
    && sed -i.agentjail-test 's/git_ssh: true/git_ssh: false/' "$POLICY"; then
    rm -f "$POLICY.agentjail-test"
    GIT_SSH_DISABLED=1
else
    scn_fail "scenario isolates native approval from Git-SSH delegation"
    grep -n 'git_ssh' "$POLICY" 2>/dev/null | sed 's/^/    /'
    finish_and_exit
fi

rm -rf "$PROJECT"
mkdir -p "$PROJECT"
git init --bare -q "$REMOTE"
git -C "$PROJECT" init -q
git -C "$PROJECT" config user.name "Codex Approval Test"
git -C "$PROJECT" config user.email "codex-approval@testbed.invalid"
printf '# codex approval\n' > "$PROJECT/README.md"
git -C "$PROJECT" add README.md
git -C "$PROJECT" commit -qm "test: seed approval repository"
git -C "$PROJECT" remote add origin "$REMOTE"

CUSTOM_RULE="/tmp/codex_approval_probe.rego"
cat >"$CUSTOM_RULE" <<'REGO'
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.tool_name == "Bash"
    contains(object.get(input.tool_input, "command", ""), "agentjail-custom-approval-marker")
    r := {
        "action": "ask",
        "rule_id": "custom/codex_approval_probe/confirm-marker",
        "reason": "testbed custom policy requires human approval",
    }
}
REGO
if "$AJ" policy add "$CUSTOM_RULE" >/dev/null; then
    CUSTOM_RULE_INSTALLED=1
    sleep 1
else
    scn_fail "custom Bash ask policy installs for the compatibility scenario"
    finish_and_exit
fi
rm -f "$CUSTOM_RULE"

branch_exists() {
    git --git-dir="$REMOTE" show-ref --verify --quiet "refs/heads/$1"
}

require_daemon() {
    local phase="$1" output="" rc=1 i
    # A tunnel child can still be draining after a non-interactive probe exits.
    # Require control ping and hook round trip. See ADR 0118-codex-approval-broker.
    for i in $(seq 1 10); do
        output="$("$AJ" doctor 2>&1 || true)"
        printf '%s\n' "$output" | grep -q 'Socket.*daemon answered ping' && break
        sleep 0.25
    done
    if ! printf '%s\n' "$output" | grep -q 'Socket.*daemon answered ping'; then
        scn_fail "policy daemon answers its control ping $phase"
        printf '%s\n' "$output" | tail -10 | sed 's/^/    /'
        finish_and_exit
    fi
    for i in $(seq 1 10); do
        output="$(printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"},"session_id":"codex-approval-liveness","cwd":"'"$PROJECT"'"}' \
            | "$HOOK" 2>&1 >/dev/null)"
        rc=$?
        if [ "$rc" -eq 0 ] && ! printf '%s\n' "$output" | grep -qiE 'daemon unreachable|daemon not running'; then
            scn_ok "policy daemon remains available $phase"
            return 0
        fi
        sleep 0.25
    done
    scn_fail "policy daemon remains available $phase"
    printf '%s\n' "$output" \
        | sed -E "s|$HOME|<guest-home>|g; s|$USER|agent|g" \
        | tail -10 \
        | sed 's/^/    /'
    finish_and_exit
}

stop_probe_group() {
    local pid="$1" i
    kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; return; }
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 40); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

wait_for_approval_prompt() {
    local i output
    for i in $(seq 1 60); do
        output="$(tmux capture-pane -p -t "$SESSION:0.0" 2>/dev/null || true)"
        if printf '%s' "$output" | grep -q "Press enter to continue"; then
            echo "  INFO  acknowledging Codex first-run continuation screen"
            tmux send-keys -t "$SESSION:0.0" Enter
            sleep 2
            continue
        fi
        if printf '%s' "$output" | grep -Fq "$PROMPT_MARKER" \
            && printf '%s' "$output" | grep -Fq "$DISPLAY_MARKER" \
            && printf '%s' "$output" | grep -Fq "$EXPECTED_CONTEXT"; then
            return 0
        fi
        if [ $((i % 10)) -eq 0 ]; then
            echo "  INFO  waiting for Codex native approval prompt (${i}s/60s)"
        fi
        sleep 1
    done
    return 1
}

print_sanitized_pane() {
    echo "  Codex pane (challenge redacted):"
    tmux list-panes -t "$SESSION" -F '    dead=#{pane_dead} status=#{pane_dead_status} command=#{pane_current_command}' 2>/dev/null || true
    tmux capture-pane -p -t "$SESSION:0.0" -S - 2>/dev/null \
        | sed -E 's/[A-Za-z0-9_-]{43}/<challenge>/g' \
        | sed -E "s|$HOME|<guest-home>|g; s|$USER@[^ ]*|agent@guest|g; s|(Booting MCP server:).*|\1 <redacted>|" \
        | tail -40 \
        | sed 's/^/    /'
    if [ -s "$PANE_LOG" ]; then
        echo "  Codex terminal stream (challenge redacted):"
        sed -E 's/[A-Za-z0-9_-]{43}/<challenge>/g' "$PANE_LOG" \
            | sed -E "s|$HOME|<guest-home>|g; s|$USER@[^ ]*|agent@guest|g; s|(Booting MCP server:).*|\1 <redacted>|" \
            | tail -40 \
            | sed 's/^/    /'
    fi
}

start_interactive_push() {
    local branch="$1"
    EXPECTED_CONTEXT="HEAD:refs/heads/$branch"
    start_and_wait_for_approval "git -C \"$PROJECT\" push origin HEAD:refs/heads/$branch"
}

start_interactive_command() {
    local command="$1"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    tmux new-session -d -s "$SESSION" -x 180 -y 48
    tmux set-option -t "$SESSION" remain-on-exit on
    rm -f "$PANE_LOG"
    tmux pipe-pane -t "$SESSION:0.0" -o "tee '$PANE_LOG' >/dev/null"
    tmux send-keys -t "$SESSION:0.0" \
        "cd '$PROJECT' && '$CODEX_SHIM' --dangerously-bypass-approvals-and-sandbox --no-alt-screen --dangerously-bypass-hook-trust -C '$PROJECT' 'Run exactly this command once and then stop: $command'" Enter
}

transport_failed_before_tool() {
    tmux capture-pane -p -t "$SESSION:0.0" -S - 2>/dev/null \
        | grep -qiE 'reconnecting|stream disconnected|websocket protocol error|handshake not finished'
}

start_and_wait_for_approval() {
    local command="$1" attempt
    for attempt in 1 2; do
        start_interactive_command "$command"
        wait_for_approval_prompt && return 0
        if [ "$attempt" -eq 1 ] && transport_failed_before_tool; then
            echo "  INFO  Codex transport failed before PreToolUse; retrying once"
            print_sanitized_pane
            continue
        fi
        return 1
    done
    return 1
}

APPROVE_BRANCH="agentjail-approval-approve"
if start_interactive_push "$APPROVE_BRANCH"; then
    scn_ok "AgentJail ask shows the Git push and opens Codex native approval prompt"
    tmux send-keys -t "$SESSION:0.0" "1" Enter
else
    scn_fail "AgentJail ask shows the Git push and opens Codex native approval prompt"
    print_sanitized_pane
    finish_and_exit
fi
for i in $(seq 1 60); do
    branch_exists "$APPROVE_BRANCH" && break
    if [ $((i % 10)) -eq 0 ]; then
        echo "  INFO  waiting for approved branch on local remote (${i}s/60s)"
    fi
    sleep 1
done
if branch_exists "$APPROVE_BRANCH"; then
    scn_ok "approved prompt pushes the exact requested branch"
else
    scn_fail "approved prompt pushes the exact requested branch"
    print_sanitized_pane
fi
tmux kill-session -t "$SESSION" 2>/dev/null || true

CUSTOM_EFFECT="$PROJECT/custom-approved.txt"
CUSTOM_COMMAND="printf agentjail-custom-approval-marker > $CUSTOM_EFFECT"
rm -f "$CUSTOM_EFFECT"
EXPECTED_CONTEXT="agentjail-custom-approval-marker"
if start_and_wait_for_approval "$CUSTOM_COMMAND"; then
    scn_ok "user-authored Bash ask opens the same native approval prompt"
    tmux send-keys -t "$SESSION:0.0" "1" Enter
else
    scn_fail "user-authored Bash ask opens the same native approval prompt"
    print_sanitized_pane
    finish_and_exit
fi
for i in $(seq 1 60); do
    [ -f "$CUSTOM_EFFECT" ] && break
    if [ $((i % 10)) -eq 0 ]; then
        echo "  INFO  waiting for approved custom-policy effect (${i}s/60s)"
    fi
    sleep 1
done
if [ "$(cat "$CUSTOM_EFFECT" 2>/dev/null || true)" = "agentjail-custom-approval-marker" ]; then
    scn_ok "approved custom-policy command executes the exact requested effect"
else
    scn_fail "approved custom-policy command executes the exact requested effect"
    print_sanitized_pane
fi
tmux kill-session -t "$SESSION" 2>/dev/null || true
require_daemon "after approved native prompts"

DECLINE_BRANCH="agentjail-approval-decline"
if start_interactive_push "$DECLINE_BRANCH"; then
    scn_ok "decline path reaches the same native prompt"
    tmux send-keys -t "$SESSION:0.0" Escape
    sleep 5
else
    scn_fail "decline path reaches the same native prompt"
fi
tmux kill-session -t "$SESSION" 2>/dev/null || true
if branch_exists "$DECLINE_BRANCH"; then
    scn_fail "declined prompt leaves the remote unchanged"
else
    scn_ok "declined prompt leaves the remote unchanged"
fi
require_daemon "after a declined native prompt"

NEVER_BRANCH="agentjail-approval-never"
NEVER_LOG="/tmp/codex-approval-never.log"
# Match terminal teardown by assigning the probe its own process group.
set -m
(
    cd "$PROJECT" || exit 1
    exec "$CODEX_SHIM" -a never \
        --dangerously-bypass-hook-trust -s workspace-write -C "$PROJECT" \
        exec --ephemeral \
        "Run exactly this command once and then stop: git -C \"$PROJECT\" push origin HEAD:refs/heads/$NEVER_BRANCH"
) >"$NEVER_LOG" 2>&1 &
NEVER_PID=$!
set +m
for i in $(seq 1 60); do
    kill -0 "$NEVER_PID" 2>/dev/null || break
    if [ $((i % 10)) -eq 0 ]; then
        echo "  INFO  waiting for approval_policy=never rejection (${i}s/60s)"
    fi
    sleep 1
done
if kill -0 "$NEVER_PID" 2>/dev/null; then
    echo "  INFO  stopping timed-out approval_policy=never probe"
fi
stop_probe_group "$NEVER_PID"
if "$AJ" logs --latest=100 --json 2>/dev/null \
    | grep -F "$NEVER_BRANCH" \
    | grep -q 'command_policy/confirm-git-push'; then
    scn_ok "approval_policy=never reaches the parsed AgentJail ask"
else
    scn_fail "approval_policy=never reaches the parsed AgentJail ask"
    sed -E 's/[A-Za-z0-9_-]{43}/<challenge>/g' "$NEVER_LOG" \
        | tail -30 \
        | sed 's/^/    /'
fi
if branch_exists "$NEVER_BRANCH"; then
    scn_fail "approval_policy=never leaves the remote unchanged"
else
    scn_ok "approval_policy=never leaves the remote unchanged"
fi
rm -f "$NEVER_LOG"
require_daemon "after approval_policy=never"

IGNORE_BRANCH="agentjail-approval-ignore-rules"
IGNORE_LOG="/tmp/codex-approval-ignore.log"
# Match terminal teardown by assigning the probe its own process group.
set -m
(
    cd "$PROJECT" || exit 1
    exec "$CODEX_SHIM" \
        --dangerously-bypass-hook-trust -s workspace-write -C "$PROJECT" \
        exec --ephemeral --ignore-rules \
        "Run exactly this command once and then stop: git -C \"$PROJECT\" push origin HEAD:refs/heads/$IGNORE_BRANCH"
) >"$IGNORE_LOG" 2>&1 &
IGNORE_PID=$!
set +m
for i in $(seq 1 60); do
    kill -0 "$IGNORE_PID" 2>/dev/null || break
    if [ $((i % 10)) -eq 0 ]; then
        echo "  INFO  waiting for --ignore-rules rejection (${i}s/60s)"
    fi
    sleep 1
done
if kill -0 "$IGNORE_PID" 2>/dev/null; then
    echo "  INFO  stopping timed-out --ignore-rules probe"
fi
stop_probe_group "$IGNORE_PID"
if "$AJ" logs --latest=100 --json 2>/dev/null \
    | grep -F "$IGNORE_BRANCH" \
    | grep -q 'command_policy/confirm-git-push'; then
    scn_ok "--ignore-rules reaches the parsed AgentJail ask"
else
    scn_fail "--ignore-rules reaches the parsed AgentJail ask"
    sed -E 's/[A-Za-z0-9_-]{43}/<challenge>/g' "$IGNORE_LOG" \
        | tail -30 \
        | sed 's/^/    /'
fi
if branch_exists "$IGNORE_BRANCH"; then
    scn_fail "--ignore-rules cannot redeem the unobserved challenge"
else
    scn_ok "--ignore-rules cannot redeem the unobserved challenge"
fi
rm -f "$IGNORE_LOG"
require_daemon "after --ignore-rules"

HOST_PROXY_DIR="$HOME/hostproxy-fixture"
HOST_PROXY_HELPER="$HOST_PROXY_DIR/benign-host-cli"
HOST_PROXY_APPROVED="$PROJECT/hostproxy-approved.txt"
HOST_PROXY_REJECTED="$PROJECT/hostproxy-rejected.txt"
HOST_PROXY_DIRECT="$PROJECT/hostproxy-direct.txt"
HOST_PROXY_BYPASS="$PROJECT/hostproxy-bypass.txt"
HOST_PROXY_SENTINEL="$HOME/.ssh/agentjail-hostproxy-test"
AUDIT_DB="$HOME/.agentjail/agentjail.db"
mkdir -p "$HOST_PROXY_DIR"
mkdir -p "$HOME/.ssh"
chmod 0700 "$HOME/.ssh"
printf 'host-only-input' >"$HOST_PROXY_SENTINEL"
chmod 0600 "$HOST_PROXY_SENTINEL"
cat >"$HOST_PROXY_HELPER" <<'SH'
#!/bin/sh
test "$(cat "$HOME/.ssh/agentjail-hostproxy-test")" = host-only-input || exit 73
printf '%s' "$2" > "$1"
SH
chmod 0700 "$HOST_PROXY_HELPER"
PROMPT_MARKER="agentjail approval-exec --operation host-proxy"
DISPLAY_MARKER="🔐 AgentJail host access approval required:"
HOST_PROXY_AUDIT_BEFORE="$(sqlite3 "$AUDIT_DB" 'select coalesce(max(id),0) from audit_log;' 2>/dev/null || echo 0)"

DIRECT_LOG="/tmp/codex-hostproxy-direct.log"
timeout 120 "$CODEX_SHIM" --dangerously-bypass-approvals-and-sandbox \
    --dangerously-bypass-hook-trust -C "$PROJECT" exec --ephemeral \
    "Run exactly this command once and then stop: $HOST_PROXY_HELPER $HOST_PROXY_DIRECT direct" \
    >"$DIRECT_LOG" 2>&1 || true
if grep -Fq "$HOST_PROXY_HELPER" "$DIRECT_LOG" && [ ! -e "$HOST_PROXY_DIRECT" ]; then
    scn_ok "real Codex direct execution cannot read the host-only fixture"
else
    scn_fail "real Codex direct execution cannot read the host-only fixture"
fi
require_daemon "after a direct-access denial"

env -u AGENTJAIL_HOST_PROXY_PROOF -u AGENTJAIL_HOST_PROXY_EXECUTABLE \
    "$AJ" proxy -- "$HOST_PROXY_HELPER" "$HOST_PROXY_DIRECT" no-proof >/dev/null 2>&1 || true
if [ ! -e "$HOST_PROXY_DIRECT" ]; then
    scn_ok "direct proxy invocation without a native proof creates no effect"
else
    scn_fail "direct proxy invocation without a native proof creates no effect"
fi

EXPECTED_CONTEXT="hostproxy-approved"
if start_and_wait_for_approval "agentjail proxy -- $HOST_PROXY_HELPER $HOST_PROXY_APPROVED hostproxy-approved"; then
    scn_ok "host proxy shows its exact outside-shield boundary in a native prompt"
    tmux send-keys -t "$SESSION:0.0" "1" Enter
else
    scn_fail "host proxy shows its exact outside-shield boundary in a native prompt"
    print_sanitized_pane
    finish_and_exit
fi
for i in $(seq 1 30); do
    [ -f "$HOST_PROXY_APPROVED" ] && break
    sleep 1
done
if [ "$(cat "$HOST_PROXY_APPROVED" 2>/dev/null || true)" = "hostproxy-approved" ]; then
    scn_ok "approved host proxy proof executes the exact helper with host-only access"
else
    scn_fail "approved host proxy proof executes the exact helper with host-only access"
    print_sanitized_pane
fi
tmux kill-session -t "$SESSION" 2>/dev/null || true

EXPECTED_CONTEXT="hostproxy-rejected"
if start_and_wait_for_approval "agentjail proxy -- $HOST_PROXY_HELPER $HOST_PROXY_REJECTED hostproxy-rejected"; then
    scn_ok "host proxy rejection reaches the same native prompt"
    tmux send-keys -t "$SESSION:0.0" Escape
    sleep 5
else
    scn_fail "host proxy rejection reaches the same native prompt"
fi
tmux kill-session -t "$SESSION" 2>/dev/null || true
if [ -e "$HOST_PROXY_REJECTED" ]; then
    scn_fail "rejected host proxy prompt creates no execution effect"
else
    scn_ok "rejected host proxy prompt creates no execution effect"
fi

BYPASS_LOG="/tmp/codex-hostproxy-bypass.log"
timeout 120 "$CODEX_SHIM" --dangerously-bypass-approvals-and-sandbox \
    --dangerously-bypass-hook-trust -C "$PROJECT" exec --ephemeral \
    "Run exactly this command once and then stop: agentjail proxy -- /bin/sh -c 'printf bypass > $HOST_PROXY_BYPASS'" \
    >"$BYPASS_LOG" 2>&1 || true
if [ ! -e "$HOST_PROXY_BYPASS" ]; then
    scn_ok "host proxy policy denies a shell bypass from real Codex"
else
    scn_fail "host proxy policy denies a shell bypass from real Codex"
fi

REQUESTED="$(sqlite3 "$AUDIT_DB" "select count(*) from audit_log where id > $HOST_PROXY_AUDIT_BEFORE and event_type='host_proxy.requested';" 2>/dev/null || echo 0)"
REDEEMED="$(sqlite3 "$AUDIT_DB" "select count(*) from audit_log where id > $HOST_PROXY_AUDIT_BEFORE and event_type='host_proxy.authorization_redeemed';" 2>/dev/null || echo 0)"
STARTED="$(sqlite3 "$AUDIT_DB" "select count(*) from audit_log where id > $HOST_PROXY_AUDIT_BEFORE and event_type='host_proxy.started';" 2>/dev/null || echo 0)"
COMPLETED="$(sqlite3 "$AUDIT_DB" "select count(*) from audit_log where id > $HOST_PROXY_AUDIT_BEFORE and event_type='host_proxy.completed';" 2>/dev/null || echo 0)"
DENIED="$(sqlite3 "$AUDIT_DB" "select count(*) from audit_log where id > $HOST_PROXY_AUDIT_BEFORE and event_type='host_proxy.denied';" 2>/dev/null || echo 0)"
if [ "$REQUESTED" -ge 2 ] && [ "$REDEEMED" -eq 1 ] && [ "$STARTED" -eq 1 ] && [ "$COMPLETED" -eq 1 ] && [ "$DENIED" -ge 1 ]; then
    scn_ok "audit proves one approved proxy execution plus rejected and denied attempts"
else
    echo "  host proxy audit counts: requested=$REQUESTED redeemed=$REDEEMED started=$STARTED completed=$COMPLETED denied=$DENIED"
    scn_fail "audit proves one approved proxy execution plus rejected and denied attempts"
fi

if sqlite3 "$AUDIT_DB" "select detail from audit_log where id > $HOST_PROXY_AUDIT_BEFORE;" 2>/dev/null \
    | grep -Fq 'host-only-input'; then
    scn_fail "host-only fixture value is absent from audit details"
else
    scn_ok "host-only fixture value is absent from audit details"
fi

scn_finish
