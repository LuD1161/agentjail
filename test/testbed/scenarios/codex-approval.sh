#!/usr/bin/env bash
# codex-approval.sh — live Codex native-approval compatibility matrix.
# Runs only in a disposable testbed provisioned with --codex-auth.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

AJ="$HOME/.agentjail/bin/agentjail"
PROJECT="$HOME/work/codex-approval"
REMOTE="$HOME/work/remotes/codex-approval.git"
SESSION="codex-approval-$RANDOM"
CODEX_VERSION="codex-cli 0.146.0"
PROMPT_MARKER="AgentJail policy requires|agentjail approval-exec"

scn_init "codex-approval" "native approve, decline, and ignored-rule behavior against a local bare remote"

cleanup() {
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    rm -f /tmp/codex-auth.json "$HOME/.codex/auth.json"
}
trap cleanup EXIT INT TERM

if [ ! -f /tmp/codex-auth.json ]; then
    scn_fail "disposable Codex auth was explicitly provided"
    scn_finish
    exit 0
fi
mkdir -p "$HOME/.codex"
chmod 700 "$HOME/.codex"
install -m 0600 /tmp/codex-auth.json "$HOME/.codex/auth.json"
rm -f /tmp/codex-auth.json
if [ "$(codex --version 2>/dev/null)" != "$CODEX_VERSION" ]; then
    scn_fail "installed Codex version is $CODEX_VERSION"
    scn_finish
    exit 0
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

branch_exists() {
    git --git-dir="$REMOTE" show-ref --verify --quiet "refs/heads/$1"
}

wait_for_pane() {
    local pattern="$1" i output
    for i in $(seq 1 180); do
        output="$(tmux capture-pane -p -t "$SESSION:0.0" -S - 2>/dev/null || true)"
        if printf '%s' "$output" | grep -Eq "$pattern"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

start_interactive_push() {
    local branch="$1"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    tmux new-session -d -s "$SESSION" -x 180 -y 48
    tmux send-keys -t "$SESSION:0.0" \
        "cd '$PROJECT' && '$AJ' run -- codex --no-alt-screen --dangerously-bypass-hook-trust -a on-request -s workspace-write -C '$PROJECT' 'Run exactly this command once and then stop: git push origin HEAD:refs/heads/$branch'" Enter
}

APPROVE_BRANCH="agentjail-approval-approve"
start_interactive_push "$APPROVE_BRANCH"
if wait_for_pane "$PROMPT_MARKER"; then
    scn_ok "AgentJail ask opens Codex native approval prompt"
    tmux send-keys -t "$SESSION:0.0" "1" Enter
else
    scn_fail "AgentJail ask opens Codex native approval prompt"
fi
if wait_for_pane "agentjail-approval-approve"; then
    for _ in $(seq 1 60); do
        branch_exists "$APPROVE_BRANCH" && break
        sleep 1
    done
fi
if branch_exists "$APPROVE_BRANCH"; then
    scn_ok "approved prompt pushes the exact requested branch"
else
    scn_fail "approved prompt pushes the exact requested branch"
fi
tmux kill-session -t "$SESSION" 2>/dev/null || true

DECLINE_BRANCH="agentjail-approval-decline"
start_interactive_push "$DECLINE_BRANCH"
if wait_for_pane "$PROMPT_MARKER"; then
    scn_ok "decline path reaches the same native prompt"
    tmux send-keys -t "$SESSION:0.0" "3" Enter
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

IGNORE_BRANCH="agentjail-approval-ignore-rules"
IGNORE_LOG="/tmp/codex-approval-ignore.log"
(
    cd "$PROJECT" || exit 1
    "$AJ" run -- codex exec --ephemeral --ignore-rules \
        --dangerously-bypass-hook-trust -s workspace-write -C "$PROJECT" \
        "Run exactly this command once and then stop: git push origin HEAD:refs/heads/$IGNORE_BRANCH"
) >"$IGNORE_LOG" 2>&1 || true
if branch_exists "$IGNORE_BRANCH"; then
    scn_fail "--ignore-rules cannot redeem the unobserved challenge"
else
    scn_ok "--ignore-rules cannot redeem the unobserved challenge"
fi
rm -f "$IGNORE_LOG"

scn_finish
