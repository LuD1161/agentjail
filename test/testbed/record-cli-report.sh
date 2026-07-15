#!/usr/bin/env bash
# record-cli-report.sh <testbed-name> [out-dir] — the Linux twin of the macOS
# mac-cli-report tooling. Records the full CLI scenario suite under asciinema
# INSIDE a provisioned Lima guest, pulls the casts back, and builds a
# self-contained linux-cli-report/index.html via gen-cli-report.sh.
#
#   ./record-cli-report.sh linux-tour                 -> test/testbed/linux-cli-report/
#   ./record-cli-report.sh linux-tour /tmp/out
#
# Why this exists separately from `testbed.sh record`: the anti-self-approval
# guards (`mcp allow`/`block`, `skill ask`/`clear`, `policy disable`) open
# /dev/tty directly (cmd/agentjail/confirm.go) and BLOCK on a typed 'y'. Under
# asciinema's PTY a controlling terminal exists, so those commands would hang
# (until each scenario's `timeout 30`) and the refusal assertions would fail.
# We therefore run each scenario under `setsid` — a fresh session with NO
# controlling terminal — so opening /dev/tty fails and agentjail refuses
# immediately, exactly as it does in headless CI. (macOS ships no `setsid`,
# which is why the mac side kept its own recorder; this one is Linux-only.)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NAME="${1:?usage: record-cli-report.sh <testbed-name> [out-dir]}"
OUT="${2:-$TESTBED_DIR/linux-cli-report}"

[ "$DRIVER" = "lima" ] || die "record-cli-report.sh is Linux/Lima-only (driver=$DRIVER); use the mac tooling on macOS"
command -v setsid >/dev/null 2>&1 || guest_exec "$NAME" "command -v setsid" >/dev/null 2>&1 \
    || die "setsid not found in guest"

# The mac 15-scenario suite. All single-mode (the tmux two-terminal flow,
# mcp-remediation-loop, is not part of this suite). RECORDING order is not the
# report's display order: cli-tour's finale runs a REAL `agentjail uninstall`
# that removes ~/.agentjail, so it MUST be recorded last — otherwise every
# scenario after it runs against a torn-down install. gen-cli-report.sh renders
# scenarios in its own (cli-tour-first) order regardless of capture order.
SCENARIOS=(e2e-smoke try-policy run-shield policy-mgmt mcp skill \
           secret trust egress-grants observability telemetry ui help-regression lifecycle \
           cli-tour)

ts="$(date -u +%Y%m%dT%H%M%SZ)"
casts="$TESTBED_DIR/reports/$ts"; mkdir -p "$casts"
log "recording ${#SCENARIOS[@]} scenarios from '$NAME' -> $casts"

guest_exec "$NAME" "mkdir -p /tmp/testbed/scenarios"
guest_push "$NAME" "$TESTBED_DIR/reportlib.sh" "/tmp/testbed/reportlib.sh"

# Record agentjail build id for the report header.
guest_exec "$NAME" "\$HOME/.agentjail/bin/agentjail status 2>/dev/null | grep -oE 'dev-[a-f0-9]+|v[0-9]+\.[0-9]+\.[0-9]+' | head -1" \
    > "$casts/version.txt" 2>/dev/null || echo unknown > "$casts/version.txt"

for s in "${SCENARIOS[@]}"; do
    script="$TESTBED_DIR/scenarios/${s}.sh"
    [ -f "$script" ] || { log "skip: no scenario ${s}.sh"; continue; }
    log "recording '$s'"
    guest_push "$NAME" "$script" "/tmp/testbed/scenarios/${s}.sh"
    # env for the scenario; recorded under setsid so /dev/tty gates refuse fast.
    # Each recording opens with a neofetch system-info banner (mirrors the macOS
    # suite's fastfetch opener) before the scenario proper runs.
    env="SCN_JSON=/tmp/testbed/${s}.result.json SCN_CAST=/tmp/testbed/${s}.cast TERM=xterm-256color"
    guest_exec "$NAME" \
        "$env asciinema rec --overwrite -q -c 'setsid -w env $env bash -c \"command -v neofetch >/dev/null 2>&1 && { clear; neofetch; echo; }; bash /tmp/testbed/scenarios/${s}.sh\"' /tmp/testbed/${s}.cast" \
        || log "  (scenario reported failures — recording still captured)"
    guest_pull "$NAME" "/tmp/testbed/${s}.cast" "$casts/${s}.cast" 2>/dev/null || log "  (no cast pulled)"
done

# Sanitize casts BEFORE the report is built and anything is committed. A guest's
# terminal output embeds the host-derived username (Lima names it
# <host-user>.guest / <host-user>.linux) throughout $HOME paths, plus whatever
# MCP server names live in the host's ~/.claude.json. Those are personal /
# internal identifiers that must never land in a committed recording or a
# published report. We replace the host username with a neutral "agent" (which
# also genericizes every /home/<user>/... path) and drop the MCP-scan lines that
# would otherwise leak the host's tooling. See AGENTS.md "Recording hygiene".
scrub_host_identifiers() {
    local dir=$1 u="${USER:-$(id -un)}"
    [ -n "$u" ] || return 0
    for c in "$dir"/*.cast; do
        [ -f "$c" ] || continue
        sed -i "s/${u}/agent/g" "$c"
    done
}
log "sanitizing casts (host username -> 'agent')"
scrub_host_identifiers "$casts"

log "building report"
bash "$TESTBED_DIR/gen-cli-report.sh" "$casts" "$OUT"
log "open: $OUT/index.html"
