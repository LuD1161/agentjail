#!/usr/bin/env bash
# codex-approval.sh — live Codex native-approval compatibility matrix.
# Runs only in a disposable testbed provisioned with --codex-auth.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

AJ="$HOME/.agentjail/bin/agentjail"
CODEX_REAL="$HOME/.agentjail/bin/codex"
PROJECT="$HOME/work/codex-approval"
REMOTE="$HOME/work/remotes/codex-approval.git"
SESSION="codex-approval-$RANDOM"
CODEX_VERSION="codex-cli 0.146.0"
PROMPT_MARKER="agentjail approval-exec --operation shell-command"
DISPLAY_MARKER="🔐 AgentJail approval required for:"
EXPECTED_CONTEXT=""
CUSTOM_RULE_INSTALLED=0

scn_init "codex-approval" "native approval for built-in and user-authored Bash ask policies"

cleanup() {
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    if [ "$CUSTOM_RULE_INSTALLED" -eq 1 ]; then
        "$AJ" policy remove codex_approval_probe >/dev/null 2>&1 || true
    fi
    rm -f /tmp/codex-auth.json "$HOME/.codex/auth.json"
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

rm -rf "$PROJECT" "$REMOTE"
mkdir -p "$(dirname "$REMOTE")" "$PROJECT"
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
    tmux capture-pane -p -t "$SESSION:0.0" -S - 2>/dev/null \
        | sed -E 's/[A-Za-z0-9_-]{43}/<challenge>/g' \
        | tail -40 \
        | sed 's/^/    /'
}

start_interactive_push() {
    local branch="$1"
    EXPECTED_CONTEXT="HEAD:refs/heads/$branch"
    start_interactive_command "git -C \"$PROJECT\" push origin HEAD:refs/heads/$branch"
}

start_interactive_command() {
    local command="$1"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    tmux new-session -d -s "$SESSION" -x 180 -y 48
    tmux send-keys -t "$SESSION:0.0" \
        "cd '$PROJECT' && '$CODEX_REAL' --dangerously-bypass-approvals-and-sandbox --no-alt-screen --dangerously-bypass-hook-trust -C '$PROJECT' 'Run exactly this command once and then stop: $command'" Enter
}

APPROVE_BRANCH="agentjail-approval-approve"
start_interactive_push "$APPROVE_BRANCH"
if wait_for_approval_prompt; then
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
fi
tmux kill-session -t "$SESSION" 2>/dev/null || true

CUSTOM_EFFECT="$PROJECT/custom-approved.txt"
CUSTOM_COMMAND="printf agentjail-custom-approval-marker > $CUSTOM_EFFECT"
rm -f "$CUSTOM_EFFECT"
EXPECTED_CONTEXT="agentjail-custom-approval-marker"
start_interactive_command "$CUSTOM_COMMAND"
if wait_for_approval_prompt; then
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
fi
tmux kill-session -t "$SESSION" 2>/dev/null || true

DECLINE_BRANCH="agentjail-approval-decline"
start_interactive_push "$DECLINE_BRANCH"
if wait_for_approval_prompt; then
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

NEVER_BRANCH="agentjail-approval-never"
NEVER_LOG="/tmp/codex-approval-never.log"
(
    cd "$PROJECT" || exit 1
    exec "$CODEX_REAL" -a never \
        --dangerously-bypass-hook-trust -s workspace-write -C "$PROJECT" \
        exec --ephemeral \
        "Run exactly this command once and then stop: git -C \"$PROJECT\" push origin HEAD:refs/heads/$NEVER_BRANCH"
) >"$NEVER_LOG" 2>&1 &
NEVER_PID=$!
for i in $(seq 1 60); do
    kill -0 "$NEVER_PID" 2>/dev/null || break
    if [ $((i % 10)) -eq 0 ]; then
        echo "  INFO  waiting for approval_policy=never rejection (${i}s/60s)"
    fi
    sleep 1
done
if kill -0 "$NEVER_PID" 2>/dev/null; then
    echo "  INFO  stopping timed-out approval_policy=never probe"
    pkill -TERM -P "$NEVER_PID" 2>/dev/null || true
    kill -TERM "$NEVER_PID" 2>/dev/null || true
fi
wait "$NEVER_PID" 2>/dev/null || true
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

IGNORE_BRANCH="agentjail-approval-ignore-rules"
IGNORE_LOG="/tmp/codex-approval-ignore.log"
(
    cd "$PROJECT" || exit 1
    exec "$CODEX_REAL" \
        --dangerously-bypass-hook-trust -s workspace-write -C "$PROJECT" \
        exec --ephemeral --ignore-rules \
        "Run exactly this command once and then stop: git -C \"$PROJECT\" push origin HEAD:refs/heads/$IGNORE_BRANCH"
) >"$IGNORE_LOG" 2>&1 &
IGNORE_PID=$!
for i in $(seq 1 60); do
    kill -0 "$IGNORE_PID" 2>/dev/null || break
    if [ $((i % 10)) -eq 0 ]; then
        echo "  INFO  waiting for --ignore-rules rejection (${i}s/60s)"
    fi
    sleep 1
done
if kill -0 "$IGNORE_PID" 2>/dev/null; then
    echo "  INFO  stopping timed-out --ignore-rules probe"
    pkill -TERM -P "$IGNORE_PID" 2>/dev/null || true
    kill -TERM "$IGNORE_PID" 2>/dev/null || true
fi
wait "$IGNORE_PID" 2>/dev/null || true
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

scn_finish
