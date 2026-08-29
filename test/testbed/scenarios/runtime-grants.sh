#!/usr/bin/env bash
# runtime-grants.sh — release evidence for runtime-grant capability boundaries.
# It records explicit skips for isolation paths that this release cannot launch.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

AJ="$HOME/.agentjail/bin/agentjail"

scn_init "runtime-grants" "runtime grant diagnostics and isolation capability evidence"

doctor="$($AJ --no-color doctor 2>&1 || true)"
if grep -q 'Runtime grant.*no live runtime grant' <<<"$doctor"; then
    scn_ok "doctor keeps authorization, activation, and reachability separate without a live grant"
else
    scn_fail "doctor keeps authorization, activation, and reachability separate without a live grant"
fi

if grep -q 'Connector transport: microvm.*no production VM launch seam' <<<"$doctor"; then
    scn_skip "microVM connector fixture" "capability evidence: no production vsock/shared-socket launch seam"
else
    scn_fail "microVM connector fixture has explicit unavailable capability evidence"
fi

case "$(uname -s)" in
    Linux)
        if grep -q 'Connector transport: linux_container.*session-scoped AF_UNIX' <<<"$doctor"; then
            scn_ok "Linux advertises only the session-scoped AF_UNIX transport"
            scn_skip "Linux container mount fixture" "capability evidence: no production container launcher bind-mounts the endpoint"
        else
            scn_fail "Linux AF_UNIX transport capability is reported"
        fi
        ;;
    Darwin)
        if grep -q 'Connector transport: macos_guest.*no macOS VM/container shared connector transport' <<<"$doctor"; then
            scn_skip "macOS VM/container fixture" "capability evidence: no shared connector transport is implemented"
        else
            scn_fail "macOS VM/container fixture has explicit unavailable capability evidence"
        fi
        ;;
    *) scn_skip "isolation transport fixture" "unsupported host operating system" ;;
esac

scn_skip "Codex native MCP approval" "Codex 0.148.0 hook contract has no MCP approval transport; compatibility test verifies fail-closed behavior"
scn_ok "Codex shell allow-once remains covered by the separate codex-approval release fixture"
scn_finish
