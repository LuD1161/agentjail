#!/usr/bin/env bash
# testbed.sh — persistent clean-VM sandboxes for agentjail (Stage 1+2).
#
# A testbed is a named VM that behaves like a real end-user machine. One
# testbed per worktree/feature: install that build, run Claude Code against
# it, poke for days, reset to the golden snapshot when done.
#
#   testbed.sh create <name>              new VM from template + golden snapshot
#   testbed.sh ls                         list testbeds
#   testbed.sh ssh <name>                 interactive shell
#   testbed.sh exec <name> -- <cmd...>    run a command in the guest
#   testbed.sh provision <name> [--worktree <path>]
#                                         build tarball -> install.sh ->
#                                         Claude Code + agentjail, ready to use
#   testbed.sh test <name> [scenario]     run a scenario (default: e2e-smoke) in-guest
#   testbed.sh record <name> [scenario..] record scenarios (asciinema) -> reports/<ts>/
#                                         with report.html + summary.json (all if none named)
#   testbed.sh gate [--worktree <path>]   RELEASE GATE: clean box -> provision ->
#                                         scenario, non-zero exit on any failure.
#                                         Run before tagging a release.
#   testbed.sh snapshot <name> <tag>      checkpoint (Lima only)
#   testbed.sh reset <name> [tag]         revert to golden (or named) snapshot
#   testbed.sh destroy <name>             delete the VM
#
# Drivers: Lima/QEMU on Linux (a Linux host), Tart on macOS (the Mac).
# Credential seeding: put a token from `claude setup-token` into
#   ~/.agentjail-testbed/token   (chmod 600)
# and provision will export CLAUDE_CODE_OAUTH_TOKEN inside the guest.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 1; }

cmd="${1:-}"; [ -n "$cmd" ] || usage
shift || true

# ---- create ----------------------------------------------------------------

do_create() {
    local name="${1:?usage: testbed.sh create <name>}"
    case "$DRIVER" in
        lima)
            log "creating $(inst "$name") from lima-template.yaml (first run downloads the Ubuntu image)"
            # 20m: first boot runs a full apt-get cloud-init pass, which can
            # exceed limactl's default readiness timeout on a busy host.
            limactl start --name "$(inst "$name")" --tty=false --timeout 20m "$TESTBED_DIR/lima-template.yaml"
            log "taking golden snapshot"
            limactl stop "$(inst "$name")"
            limactl snapshot create "$(inst "$name")" --tag golden
            limactl start "$(inst "$name")"
            log "testbed '$name' ready. Next: $0 provision $name"
            ;;
        tart)
            tart list | awk '{print $2}' | grep -qx "$TART_GOLDEN" \
                || die "golden image '$TART_GOLDEN' not found — see README.md 'Mac side' to bake it"
            log "cloning $TART_GOLDEN -> $(inst "$name") (APFS copy-on-write, instant)"
            tart clone "$TART_GOLDEN" "$(inst "$name")"
            log "starting VM headless"
            # Capture tart run's stderr: Virtualization.framework refusals (most
            # commonly "The number of VMs exceeds the system limit") land here and
            # were previously swallowed by >/dev/null, so the code waited 120s and
            # misblamed DHCP. Poll for both the run process dying AND the IP so a
            # VM that never starts fails fast with the real reason.
            local runlog; runlog="$(mktemp -t tart-run.XXXXXX)"
            tart run --no-graphics "$(inst "$name")" >"$runlog" 2>&1 &
            local runpid=$!
            log "waiting for IP"
            local i=0 ip=""
            while :; do
                if ! kill -0 "$runpid" 2>/dev/null; then
                    log "tart run exited before the VM came up:"
                    sed 's/^/    /' "$runlog" >&2
                    rm -f "$runlog"
                    die "VM failed to start (see error above). macOS caps how many VMs run at once; stop another VM and retry: tart stop <name>  (running now: $(tart_running_names | paste -sd' ' -))"
                fi
                ip="$(tart_ip_any "$(inst "$name")" || true)"
                [ -n "$ip" ] && break
                i=$((i+1))
                [ "$i" -lt 60 ] || { rm -f "$runlog"; die "VM is running but never got an IP after 120s (DHCP)"; }
                sleep 2
            done
            rm -f "$runlog"
            log "waiting for SSH (sshd comes up a few seconds after the IP)"
            tart_wait_ssh "$name" 120 \
                || die "VM '$(inst "$name")' got IP $ip but SSH never became reachable within 120s"
            log "testbed '$name' ready. Next: $0 provision $name"
            ;;
    esac
}

# ---- provision --------------------------------------------------------------

do_provision() {
    local name="${1:?usage: testbed.sh provision <name> [--worktree <path>]}"; shift
    local worktree="$REPO_ROOT"
    while [ $# -gt 0 ]; do
        case "$1" in
            --worktree) worktree="$(cd "$2" && pwd)"; shift 2 ;;
            *) die "unknown provision flag: $1" ;;
        esac
    done

    local goos goarch
    case "$DRIVER" in
        lima) goos=linux ;;
        tart) goos=darwin ;;
    esac
    goarch=$(guest_exec "$name" "uname -m")
    case "$goarch" in
        x86_64|amd64) goarch=amd64 ;;
        arm64|aarch64) goarch=arm64 ;;
        *) die "unsupported guest arch: $goarch" ;;
    esac

    log "building dist tarball from $worktree ($goos/$goarch)"
    make -C "$worktree" dist-tarball DIST_GOOS="$goos" DIST_GOARCH="$goarch"
    local tarball
    tarball=$(ls -t "$worktree"/dist/agentjail-*-"$goos"-"$goarch".tar.gz | head -1)
    [ -n "$tarball" ] || die "dist-tarball produced no tarball"

    log "pushing tarball + install.sh + guest-provision.sh"
    guest_push "$name" "$tarball" /tmp/agentjail-local.tar.gz
    guest_push "$name" "$worktree/install.sh" /tmp/agentjail-install.sh
    guest_push "$name" "$TESTBED_DIR/guest-provision.sh" /tmp/guest-provision.sh

    local token_file="$HOME/.agentjail-testbed/token"
    if [ -f "$token_file" ]; then
        log "seeding Claude Code OAuth token"
        guest_push "$name" "$token_file" /tmp/claude-token
    else
        log "NOTE: no $token_file — Claude Code will be installed but not logged in."
        log "      Run 'claude setup-token' on the host and save the token there (chmod 600)."
    fi

    # Sync the host's global MCP servers into the guest so the testbed's Claude
    # Code sees the same MCP surface a real session does (agentjail's netproxy
    # allowlist seeding keys off installed MCPs). We copy only the global
    # `.mcpServers` block from ~/.claude.json — project-scoped and
    # claude.ai-connected (OAuth) servers don't travel to a headless guest.
    local host_claude="$HOME/.claude.json"
    if command -v jq >/dev/null 2>&1 && [ -f "$host_claude" ] \
        && jq -e '(.mcpServers // {}) | length > 0' "$host_claude" >/dev/null 2>&1; then
        local mcp_tmp
        mcp_tmp="$(mktemp "${TMPDIR:-/tmp}/agentjail-mcp.XXXXXX")"
        jq '{mcpServers: (.mcpServers // {})}' "$host_claude" > "$mcp_tmp"
        log "syncing host global MCP servers -> guest ($(jq -r '.mcpServers | keys | join(", ")' "$mcp_tmp"))"
        guest_push "$name" "$mcp_tmp" /tmp/claude-mcp.json
        rm -f "$mcp_tmp"
    else
        log "no global MCP servers on host (or jq missing) — skipping MCP sync"
    fi

    log "running guest-provision.sh inside the guest"
    guest_exec "$name" "bash /tmp/guest-provision.sh"
    log "provisioned. Try: $0 ssh $name   then: agentjail status && claude"
}

# ---- the rest ---------------------------------------------------------------

do_ls() {
    case "$DRIVER" in
        lima) limactl list | awk -v p="^${TB_PREFIX}" 'NR==1 || $1 ~ p' ;;
        tart) tart list | awk -v p="${TB_PREFIX}" 'NR==1 || $2 ~ "^"p' ;;
    esac
}

do_ssh() {
    local name="${1:?usage: testbed.sh ssh <name>}"
    case "$DRIVER" in
        lima) limactl shell --workdir "/home/${USER}.linux" "$(inst "$name")" ;;
        tart) ssh "${TART_SSH_OPTS[@]}" "${TART_SSH_USER}@$(tart_ip "$name")" ;;
    esac
}

do_exec() {
    local name="${1:?usage: testbed.sh exec <name> -- <cmd...>}"; shift
    [ "${1:-}" = "--" ] && shift
    guest_exec "$name" "$@"
}

# do_gate is the release gate: a fresh, clean box (reset to the post-cloud-init
# golden, or created if absent) provisioned from the given worktree and run
# through a scenario. Any failure -> non-zero exit, so it can gate `git tag`.
# The gate testbed is left at rest afterward (reset next run) for speed.
do_gate() {
    local worktree="$REPO_ROOT" name="release-gate" scenario="e2e-smoke"
    while [ $# -gt 0 ]; do
        case "$1" in
            --worktree) worktree="$(cd "$2" && pwd)"; shift 2 ;;
            --scenario) scenario="$2"; shift 2 ;;
            *) die "unknown gate flag: $1" ;;
        esac
    done

    log "RELEASE GATE starting (driver=$DRIVER, worktree=$worktree)"
    # Single-VM invariant (Tart): macOS caps concurrently running VMs (~2), so
    # the gate runs exactly one testbed VM. Stop any OTHER running testbed VMs up
    # front to guarantee a free slot, and register a cleanup that stops THIS gate
    # VM on exit (success, failure, or interrupt) so a run never leaves an orphan
    # holding a slot. Stopped (not deleted) = reset-and-reuse next run for speed.
    if [ "$DRIVER" = tart ]; then
        tart_stop_other_testbeds "$(inst "$name")"
        trap "tart stop '$(inst "$name")' >/dev/null 2>&1 || true" EXIT
    fi
    if "${DRIVER}_exists" "$name"; then
        log "reusing '$name' — resetting to clean golden"
        do_reset "$name"
    else
        do_create "$name"
    fi
    do_provision "$name" --worktree "$worktree"
    log "RELEASE GATE: running scenario '$scenario' on a clean box"
    if do_test "$name" "$scenario"; then
        log "RELEASE GATE ✓ PASS — safe to tag"
        return 0
    else
        die "RELEASE GATE ✗ FAIL — do NOT release"
    fi
}

do_test() {
    local name="${1:?usage: testbed.sh test <name> [scenario]}" scenario="${2:-e2e-smoke}"
    local script="$TESTBED_DIR/scenarios/${scenario}.sh"
    [ -f "$script" ] || die "scenario not found: $script"
    log "running scenario '$scenario' in '$name'"
    guest_exec "$name" "mkdir -p /tmp/testbed/scenarios"
    guest_push "$name" "$TESTBED_DIR/reportlib.sh" "/tmp/testbed/reportlib.sh"
    # Unconditional, not just for chaos-*: a conditional push is one more place
    # for the shipping contract to drift out from under the guard. See AGE-236.
    guest_push "$name" "$TESTBED_DIR/scenarios/chaos-lib.sh" "/tmp/testbed/scenarios/chaos-lib.sh"
    guest_push "$name" "$script" "/tmp/testbed/scenarios/${scenario}.sh"
    guest_exec "$name" "$(chaos_env) bash /tmp/testbed/scenarios/${scenario}.sh"
}

# do_record runs scenarios under asciinema in the guest, pulls each recording
# (.cast) + result (.result.json) back to test/testbed/reports/<ts>/, then
# builds a self-contained report.html + summary.json. Scenario recording mode
# comes from a `# testbed-mode: single|tmux` header line (default single):
#   single -> the runner wraps the whole script in `asciinema rec`
#   tmux   -> the scenario self-records a 2-pane session to $SCN_CAST
do_record() {
    local name="${1:?usage: testbed.sh record <name> [scenario...]}"; shift
    local scenarios=("$@")
    if [ ${#scenarios[@]} -eq 0 ]; then
        # chaos-lib.sh matches scenarios/*.sh but is a sourced library, not a
        # scenario -- executing it would run nothing and report nothing.
        for f in "$TESTBED_DIR"/scenarios/*.sh; do
            local b; b="$(basename "$f" .sh)"
            [ "$b" = "chaos-lib" ] && continue
            scenarios+=("$b")
        done
    fi
    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local out="$TESTBED_DIR/reports/$ts"; mkdir -p "$out"

    guest_exec "$name" "mkdir -p /tmp/testbed/scenarios"
    guest_push "$name" "$TESTBED_DIR/reportlib.sh" "/tmp/testbed/reportlib.sh"
    guest_push "$name" "$TESTBED_DIR/scenarios/chaos-lib.sh" "/tmp/testbed/scenarios/chaos-lib.sh"

    for s in "${scenarios[@]}"; do
        local script="$TESTBED_DIR/scenarios/${s}.sh"
        [ -f "$script" ] || { log "skip: no scenario ${s}.sh"; continue; }
        # `|| true`: single-mode scenarios omit the header, so the grep pipeline
        # exits 1 — without this, `set -e`/pipefail kills the whole record run.
        local mode; mode=$(grep -oE '# *testbed-mode: *[a-z]+' "$script" | grep -oE '[a-z]+$' | tail -1 || true); mode="${mode:-single}"
        log "recording '$s' (mode=$mode)"
        guest_push "$name" "$script" "/tmp/testbed/scenarios/${s}.sh"
        local cenv; cenv="$(chaos_env)"
        local env="$cenv SCN_JSON=/tmp/testbed/${s}.result.json SCN_CAST=/tmp/testbed/${s}.cast TERM=xterm-256color"
        if [ "$mode" = "tmux" ]; then
            guest_exec "$name" "$env bash /tmp/testbed/scenarios/${s}.sh" || log "  (scenario reported failures)"
        else
            guest_exec "$name" "$env asciinema rec --overwrite -q -c 'env $env bash /tmp/testbed/scenarios/${s}.sh' /tmp/testbed/${s}.cast" || log "  (scenario reported failures)"
        fi
        guest_pull "$name" "/tmp/testbed/${s}.result.json" "$out/${s}.result.json" 2>/dev/null || log "  (no result json)"
        guest_pull "$name" "/tmp/testbed/${s}.cast" "$out/${s}.cast" 2>/dev/null || log "  (no cast)"
    done

    log "building report"
    bash "$TESTBED_DIR/gen-report.sh" "$out"
    log "open: $out/report.html"
}

do_snapshot() {
    local name="${1:?usage: testbed.sh snapshot <name> <tag>}" tag="${2:?need a tag}"
    case "$DRIVER" in
        lima)
            limactl stop "$(inst "$name")"
            limactl snapshot create "$(inst "$name")" --tag "$tag"
            limactl start "$(inst "$name")"
            ;;
        tart)
            # Tart has no snapshot tags; a checkpoint is a clone at rest.
            tart stop "$(inst "$name")" || true
            tart clone "$(inst "$name")" "$(inst "$name")-$tag"
            log "checkpoint saved as VM '$(inst "$name")-$tag' (start manually if needed)"
            ;;
    esac
}

do_reset() {
    local name="${1:?usage: testbed.sh reset <name> [tag]}" tag="${2:-golden}"
    case "$DRIVER" in
        lima)
            limactl stop "$(inst "$name")" || true
            limactl snapshot apply "$(inst "$name")" --tag "$tag"
            limactl start "$(inst "$name")"
            ;;
        tart)
            log "tart reset = delete + re-clone from $TART_GOLDEN"
            tart stop "$(inst "$name")" 2>/dev/null || true
            tart delete "$(inst "$name")"
            do_create "$name"
            ;;
    esac
}

do_destroy() {
    local name="${1:?usage: testbed.sh destroy <name>}"
    case "$DRIVER" in
        lima) limactl delete -f "$(inst "$name")" ;;
        tart)
            tart stop "$(inst "$name")" 2>/dev/null || true
            tart delete "$(inst "$name")"
            ;;
    esac
}

case "$cmd" in
    create)    do_create "$@" ;;
    provision) do_provision "$@" ;;
    ls)        do_ls "$@" ;;
    ssh)       do_ssh "$@" ;;
    exec)      do_exec "$@" ;;
    test)      do_test "$@" ;;
    record)    do_record "$@" ;;
    gate)      do_gate "$@" ;;
    snapshot)  do_snapshot "$@" ;;
    reset)     do_reset "$@" ;;
    destroy)   do_destroy "$@" ;;
    *)         usage ;;
esac
