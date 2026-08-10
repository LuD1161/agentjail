#!/usr/bin/env bash
# run-codex-approval-gate.sh — host-side AGE-263 acceptance gate.
# Writes a complete transcript under the worktree's ignored dist/ directory.
set -euo pipefail

TESTBED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKTREE="$(cd "${1:-"$TESTBED_DIR/../.."}" && pwd)"
AUTH_FILE="${CODEX_AUTH_FILE:-$HOME/.codex/auth.json}"
LOG_FILE="${CODEX_APPROVAL_GATE_LOG:-$WORKTREE/dist/codex-approval-gate.log}"
TESTBED_NAME="${CODEX_APPROVAL_TESTBED:-release-gate}"

[ -r "$AUTH_FILE" ] || {
    echo "Codex auth file is not readable: $AUTH_FILE" >&2
    exit 1
}

mkdir -p "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

TEST_HOME="$(mktemp -d "${TMPDIR:-/tmp}/agentjail-go-test.XXXXXX")"
ORIG_GOCACHE="$(go env GOCACHE)"
ORIG_GOMODCACHE="$(go env GOMODCACHE)"
ORIG_GOPATH="$(go env GOPATH)"

cleanup() {
    local rc=$?
    tart stop "tb-$TESTBED_NAME" >/dev/null 2>&1 || true
    case "$TEST_HOME" in
        "${TMPDIR:-/tmp}"/agentjail-go-test.*) rm -rf "$TEST_HOME" ;;
    esac
    echo
    echo "Codex approval gate exit: $rc"
    echo "Transcript: $LOG_FILE"
    return "$rc"
}
trap cleanup EXIT

echo "Codex approval gate"
echo "Worktree: $WORKTREE"
echo "Testbed: tb-$TESTBED_NAME"
echo "Transcript: $LOG_FILE"
echo

cd "$WORKTREE"

if [ "${CODEX_APPROVAL_SCENARIO_ONLY:-0}" != "1" ]; then
    go build ./...
    go vet ./...

    # Most packages need the real macOS home layout, but the policy mutation
    # refusal test must have no controlling TTY. Start a fresh session to satisfy
    # both contracts. The mcpclient package is handled separately because its
    # host-config discovery test is intentionally environment-dependent.
    packages=()
    while IFS= read -r package; do
        [ "$package" = "github.com/LuD1161/agentjail/internal/mcpclient" ] && continue
        packages+=("$package")
    done < <(go list ./...)

    python3 -c \
        'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
        go test "${packages[@]}" -count=1 </dev/null

    HOME="$TEST_HOME" \
        GOCACHE="$ORIG_GOCACHE" \
        GOMODCACHE="$ORIG_GOMODCACHE" \
        GOPATH="$ORIG_GOPATH" \
        go test ./internal/mcpclient -count=1 </dev/null

    make smoke
    make adr-check
else
    echo "Host build/test/smoke gates: skipped (scenario-only retry)"
fi

AGENTJAIL_TESTBED_AGENT=codex \
    bash "$TESTBED_DIR/testbed.sh" reset "$TESTBED_NAME"
AGENTJAIL_TESTBED_AGENT=codex \
    bash "$TESTBED_DIR/testbed.sh" provision "$TESTBED_NAME" --worktree "$WORKTREE"
AGENTJAIL_TESTBED_AGENT=codex \
    bash "$TESTBED_DIR/testbed.sh" test "$TESTBED_NAME" codex-approval --codex-auth "$AUTH_FILE"

git diff --check
git status --short

echo
echo "Codex approval gate: PASS"
