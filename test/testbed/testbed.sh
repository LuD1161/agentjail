#!/usr/bin/env bash
# testbed.sh — persistent clean-VM sandboxes for agentjail (Stage 1+2).
#
# A testbed is a named VM that behaves like a real end-user machine. One
# testbed per worktree/feature: install that build, run the selected agent
# against it, poke for days, reset to the golden snapshot when done.
#
#   testbed.sh create <name>              new VM from template + golden snapshot
#   testbed.sh ls                         list testbeds
#   testbed.sh ssh <name>                 interactive shell
#   testbed.sh exec <name> -- <cmd...>    run a command in the guest
#   AGENTJAIL_TESTBED_AGENT=codex testbed.sh provision <name> [--worktree <path>]
#                                         build tarball -> install.sh ->
#                                         selected agent + agentjail, ready to use
#   testbed.sh test <name> [scenario] [--codex-auth <path>]
#                                         run a scenario (default: e2e-smoke) in-guest
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
# Agent selection: AGENTJAIL_TESTBED_AGENT=codex|claude-code (default: codex).
# Claude credential seeding: put a token from `claude setup-token` into
#   ~/.agentjail-testbed/token   (chmod 600)
# and provision will export CLAUDE_CODE_OAUTH_TOKEN inside the guest.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TESTBED_AGENT="${AGENTJAIL_TESTBED_AGENT:-codex}"
case "$TESTBED_AGENT" in
    codex|claude-code) ;;
    *) die "unsupported AGENTJAIL_TESTBED_AGENT '$TESTBED_AGENT' (supported: codex, claude-code)" ;;
esac

ACTIVE_AUTH_TESTBED=""
ACTIVE_GATE_TESTBED=""
ACTIVE_PARTIAL_CREATE=""
CLEANUP_FILES=()

register_cleanup_file() { CLEANUP_FILES+=("$1"); }

forget_cleanup_file() {
    local target="$1" i
    for i in "${!CLEANUP_FILES[@]}"; do
        [ "${CLEANUP_FILES[$i]}" = "$target" ] && CLEANUP_FILES[$i]=""
    done
}

cleanup_injected_auth() {
    [ -n "$ACTIVE_AUTH_TESTBED" ] || return 0
    guest_exec "$ACTIVE_AUTH_TESTBED" "rm -f /tmp/codex-auth.json \"\$HOME/.codex/auth.json\"" >/dev/null 2>&1 || true
    ACTIVE_AUTH_TESTBED=""
}

stop_testbed() {
    local name="$1"
    case "$DRIVER" in
        lima)
            limactl stop "$(inst "$name")" >/dev/null 2>&1 || true
            if lima_running "$name"; then
                log "graceful stop did not release $(inst "$name"); forcing shutdown"
                limactl stop -f "$(inst "$name")" >/dev/null 2>&1 || true
            fi
            lima_running "$name" && return 1
            ;;
        tart)
            tart stop "$(inst "$name")" >/dev/null 2>&1 || true
            tart_running_names | grep -qx "$(inst "$name")" && return 1
            ;;
    esac
    return 0
}

cleanup_host_files() {
    local path rc=0
    for path in "${CLEANUP_FILES[@]}"; do
        [ -z "$path" ] || rm -f -- "$path" || rc=1
    done
    CLEANUP_FILES=()
    return "$rc"
}

destroy_testbed_verified() {
    local name="$1"
    do_destroy "$name" >/dev/null 2>&1 || true
    if "${DRIVER}_exists" "$name"; then
        log "ERROR: cleanup could not delete $(inst "$name")"
        return 1
    fi
}

cleanup_testbed_lifecycle() {
    local rc=0
    if [ -n "$ACTIVE_PARTIAL_CREATE" ]; then
        log "removing partially-created testbed $(inst "$ACTIVE_PARTIAL_CREATE")"
        destroy_testbed_verified "$ACTIVE_PARTIAL_CREATE" || rc=1
        ACTIVE_PARTIAL_CREATE=""
    fi
    if [ -n "$ACTIVE_GATE_TESTBED" ]; then
        if [ "${AGENTJAIL_TESTBED_KEEP_VM:-0}" = "1" ]; then
            log "stopping gate VM $(inst "$ACTIVE_GATE_TESTBED") (retained by AGENTJAIL_TESTBED_KEEP_VM=1)"
            if ! stop_testbed "$ACTIVE_GATE_TESTBED"; then
                log "ERROR: cleanup could not stop $(inst "$ACTIVE_GATE_TESTBED")"
                rc=1
            fi
        else
            log "destroying gate VM $(inst "$ACTIVE_GATE_TESTBED") to release RAM and disk"
            destroy_testbed_verified "$ACTIVE_GATE_TESTBED" || rc=1
        fi
        ACTIVE_GATE_TESTBED=""
    fi
    return "$rc"
}

cleanup_all() {
    local rc=$? cleanup_rc=0
    trap - EXIT INT TERM
    # Deleting the default ephemeral gate VM removes its auth cache without a
    # potentially blocking guest round-trip during signal handling.
    if [ -n "$ACTIVE_GATE_TESTBED" ] && [ "${AGENTJAIL_TESTBED_KEEP_VM:-0}" = "0" ]; then
        ACTIVE_AUTH_TESTBED=""
    else
        cleanup_injected_auth || cleanup_rc=1
    fi
    cleanup_host_files || cleanup_rc=1
    cleanup_testbed_lifecycle || cleanup_rc=1
    if [ "$rc" -eq 0 ] && [ "$cleanup_rc" -ne 0 ]; then
        log "ERROR: testbed cleanup was incomplete"
        rc=1
    fi
    exit "$rc"
}

case "${AGENTJAIL_TESTBED_KEEP_VM:-0}" in 0|1) ;; *) die "AGENTJAIL_TESTBED_KEEP_VM must be 0 or 1" ;; esac
trap cleanup_all EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() { sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 1; }

cmd="${1:-}"; [ -n "$cmd" ] || usage
shift || true

# ---- create ----------------------------------------------------------------

do_create() {
    local name="${1:?usage: testbed.sh create <name>}"
    # Before the clone, not after: a refused create must not leave a disk behind.
    # No exemption for the gate -- it reaches this same function, and one rule
    # with no special cases is worth more than a gate that never has to think.
    assert_testbed_capacity "$name"
    assert_host_resources "$name" create
    ACTIVE_PARTIAL_CREATE="$name"
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
            register_cleanup_file "$runlog"
            tart run --no-graphics "$(inst "$name")" >"$runlog" 2>&1 &
            local runpid=$!
            log "waiting for IP"
            local i=0 ip=""
            while :; do
                if ! kill -0 "$runpid" 2>/dev/null; then
                    log "tart run exited before the VM came up:"
                    sed 's/^/    /' "$runlog" >&2
                    rm -f "$runlog"
                    forget_cleanup_file "$runlog"
                    die "VM failed to start (see error above). macOS caps how many VMs run at once; stop another VM and retry: tart stop <name>  (running now: $(tart_running_names | paste -sd' ' -))"
                fi
                ip="$(tart_ip_any "$(inst "$name")" || true)"
                [ -n "$ip" ] && break
                i=$((i+1))
                [ "$i" -lt 60 ] || { rm -f "$runlog"; forget_cleanup_file "$runlog"; die "VM is running but never got an IP after 120s (DHCP)"; }
                sleep 2
            done
            rm -f "$runlog"
            forget_cleanup_file "$runlog"
            log "waiting for SSH (sshd comes up a few seconds after the IP)"
            tart_wait_ssh "$name" 120 \
                || die "VM '$(inst "$name")' got IP $ip but SSH never became reachable within 120s"
            log "testbed '$name' ready. Next: $0 provision $name"
            ;;
    esac
    ACTIVE_PARTIAL_CREATE=""
}

# ---- provision --------------------------------------------------------------

do_provision() {
    local name="${1:?usage: testbed.sh provision <name> [--worktree <path>]}"; shift
    local worktree="$REPO_ROOT"
    while [ $# -gt 0 ]; do
        case "$1" in
            --worktree) worktree="$(cd "$2" && pwd)"; shift 2 ;;
            --with-codex)
                die "--with-codex was replaced by AGENTJAIL_TESTBED_AGENT=codex"
                ;;
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

    if [ "$TESTBED_AGENT" = "claude-code" ]; then
        local token_file="$HOME/.agentjail-testbed/token"
        if [ -f "$token_file" ]; then
            log "seeding Claude Code OAuth token"
            if ! guest_push "$name" "$token_file" /tmp/claude-token; then
                guest_exec "$name" "rm -f /tmp/claude-token" || true
                log "NOTE: $token_file exists but is unreadable — continuing without optional Claude login."
                log "      Installed-policy scenarios still run; live-agent scenarios will SKIP."
            fi
        else
            log "NOTE: no $token_file — Claude Code will be installed but not logged in."
            log "      Run 'claude setup-token' on the host and save the token there (chmod 600)."
        fi
    else
        log "Codex auth is injected only for the live scenario, never during provisioning"
    fi
    # Sync the host's global MCP servers into the guest so the testbed's Claude
    # Code sees the same MCP surface a real session does (agentjail's netproxy
    # allowlist seeding keys off installed MCPs). We copy only the global
    # `.mcpServers` block from ~/.claude.json — project-scoped and
    # claude.ai-connected (OAuth) servers don't travel to a headless guest.
    local host_claude="$HOME/.claude.json"
    if [ "$TESTBED_AGENT" = "claude-code" ] \
        && command -v jq >/dev/null 2>&1 && [ -f "$host_claude" ] \
        && jq -e '(.mcpServers // {}) | length > 0' "$host_claude" >/dev/null 2>&1; then
        local mcp_tmp
        mcp_tmp="$(mktemp "${TMPDIR:-/tmp}/agentjail-mcp.XXXXXX")"
        register_cleanup_file "$mcp_tmp"
        jq '{mcpServers: (.mcpServers // {})}' "$host_claude" > "$mcp_tmp"
        log "syncing host global MCP servers -> guest ($(jq -r '.mcpServers | keys | join(", ")' "$mcp_tmp"))"
        guest_push "$name" "$mcp_tmp" /tmp/claude-mcp.json
        rm -f "$mcp_tmp"
        forget_cleanup_file "$mcp_tmp"
    else
        log "no global MCP servers on host (or jq missing) — skipping MCP sync"
    fi

    log "running guest-provision.sh inside the guest"
    guest_exec "$name" "AGENTJAIL_TESTBED_AGENT=$(printf '%q' "$TESTBED_AGENT") AGENTJAIL_TESTBED_CODEX_VERSION=$(printf '%q' "${AGENTJAIL_TESTBED_CODEX_VERSION:-0.147.0}") bash /tmp/guest-provision.sh"
    log "provisioned for $TESTBED_AGENT. Try: $0 ssh $name   then: agentjail status"
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
# The gate VM is destroyed afterward by default. Set
# AGENTJAIL_TESTBED_KEEP_VM=1 to retain it stopped for a faster next run.
do_gate() {
    local worktree="$REPO_ROOT" name="${AGENTJAIL_TESTBED_NAME:-release-gate-$TESTBED_AGENT}"
    local scenarios=() scenario_override=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --worktree) worktree="$(cd "$2" && pwd)"; shift 2 ;;
            --scenario) scenarios=("$2"); scenario_override=1; shift 2 ;;
            *) die "unknown gate flag: $1" ;;
        esac
    done

    if [ "$scenario_override" -eq 0 ]; then
        case "$TESTBED_AGENT" in
            codex) scenarios=("e2e-smoke" "credentialed-cli" "tunnel-agent") ;;
            claude-code) scenarios=("e2e-smoke") ;;
        esac
    fi

    local codex_home="${CODEX_HOME:-$HOME/.codex}"
    local codex_auth="${CODEX_AUTH_FILE:-$codex_home/auth.json}"
    local codex_bin="" codex_version="" needs_codex=0 s candidate
    for s in "${scenarios[@]}"; do
        case "$s" in tunnel-agent|codex-approval|credentialed-cli) needs_codex=1 ;; esac
    done
    if [ "$needs_codex" -eq 1 ]; then
        while IFS= read -r candidate; do
            case "$candidate" in
                "$HOME/.agentjail/bin/"*) ;;
                *) codex_bin="$candidate"; break ;;
            esac
        done < <(type -a -p codex 2>/dev/null)
        [ -x "$codex_bin" ] || die "real Codex CLI not found outside AgentJail's shim directory"
        [ -r "$codex_auth" ] || die "Codex auth cache is required for the release gate: $codex_auth"
        local auth_mode
        auth_mode="$(stat -c %a "$codex_auth" 2>/dev/null || stat -f %Lp "$codex_auth")"
        case "$auth_mode" in
            400|600) ;;
            *) die "Codex auth cache must be private (mode 600 or 400), got $auth_mode: $codex_auth" ;;
        esac
        codex_version="${CODEX_TESTBED_VERSION:-$("$codex_bin" --version 2>/dev/null | awk '$1 == "codex-cli" {print $2; exit}')}"
        [ -n "$codex_version" ] || die "could not determine the host Codex CLI version"
        "$codex_bin" login status >/dev/null 2>&1 || die "host Codex CLI is not authenticated"
    fi

    log "RELEASE GATE starting (driver=$DRIVER, worktree=$worktree)"
    # Single-VM invariant (Tart): macOS caps concurrently running VMs (~2), so
    # the gate runs exactly one testbed VM. Stop any OTHER running testbed VMs up
    # front to guarantee a free slot. The unified EXIT cleanup owns this gate VM
    # on both hosts and cannot replace credential or temporary-file cleanup.
    if [ "$DRIVER" = tart ]; then
        tart_stop_other_testbeds "$(inst "$name")"
    fi
    local allocation=create
    if "${DRIVER}_exists" "$name"; then
        allocation=reuse
        ACTIVE_GATE_TESTBED="$name"
        # Count memory after releasing this gate's previous allocation.
        stop_testbed "$name"
    fi
    assert_host_resources "$name" "$allocation"
    ACTIVE_GATE_TESTBED="$name"
    # Ask before the clone, not after a 20-minute provision discovers the cap.
    # The gate is not exempt from MAX_TESTBEDS -- it asks for a slot instead.
    gate_reclaim_slot "$(inst "$name")"
    if "${DRIVER}_exists" "$name"; then
        log "reusing '$name' — resetting to clean golden"
        do_reset "$name"
    else
        do_create "$name"
    fi
    if [ "$needs_codex" -eq 1 ]; then
        AGENTJAIL_TESTBED_CODEX_VERSION="$codex_version"
        do_provision "$name" --worktree "$worktree"
    else
        do_provision "$name" --worktree "$worktree"
    fi
    for s in "${scenarios[@]}"; do
        log "RELEASE GATE: running scenario '$s' on a clean box"
        case "$s" in
            tunnel-agent|codex-approval|credentialed-cli)
                do_test "$name" "$s" --codex-auth "$codex_auth" \
                    || die "RELEASE GATE ✗ FAIL ($s) — do NOT release"
                ;;
            *) do_test "$name" "$s" || die "RELEASE GATE ✗ FAIL ($s) — do NOT release" ;;
        esac
    done
    log "RELEASE GATE ✓ PASS — safe to tag"
    return 0
}

do_test() {
    local name="${1:?usage: testbed.sh test <name> [scenario] [--codex-auth <path>]}"; shift
    local scenario="e2e-smoke" codex_auth=""
    if [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; then
        scenario="$1"
        shift
    fi
    while [ $# -gt 0 ]; do
        case "$1" in
            --codex-auth)
                codex_auth="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
                [ -f "$codex_auth" ] || die "Codex auth file not found: $codex_auth"
                shift 2
                ;;
            *) die "unknown test flag: $1" ;;
        esac
    done
    if [ -n "$codex_auth" ] && [ "$scenario" != "codex-approval" ] && [ "$scenario" != "tunnel-agent" ] && [ "$scenario" != "credentialed-cli" ]; then
        die "--codex-auth is accepted only by the codex-approval, credentialed-cli, and tunnel-agent scenarios"
    fi
    local script="$TESTBED_DIR/scenarios/${scenario}.sh"
    [ -f "$script" ] || die "scenario not found: $script"
    log "running scenario '$scenario' in '$name'"
    guest_exec "$name" "mkdir -p /tmp/testbed/scenarios"
    guest_push "$name" "$TESTBED_DIR/reportlib.sh" "/tmp/testbed/reportlib.sh"
    # Unconditional, not just for chaos-*: a conditional push is one more place
    # for the shipping contract to drift out from under the guard. See AGE-236.
    guest_push "$name" "$TESTBED_DIR/scenarios/chaos-lib.sh" "/tmp/testbed/scenarios/chaos-lib.sh"
    guest_push "$name" "$script" "/tmp/testbed/scenarios/${scenario}.sh"
    if [ -n "$codex_auth" ]; then
        log "injecting disposable Codex auth immediately before the scenario"
        if ! guest_push "$name" "$codex_auth" /tmp/codex-auth.json; then
            guest_exec "$name" "rm -f /tmp/codex-auth.json" || true
            return 1
        fi
        if ! guest_exec "$name" "chmod 600 /tmp/codex-auth.json"; then
            guest_exec "$name" "rm -f /tmp/codex-auth.json" || true
            return 1
        fi
        ACTIVE_AUTH_TESTBED="$name"
    fi
    local rc=0
    guest_exec "$name" "$(chaos_env) AGENTJAIL_TESTBED_CODEX_VERSION=$(printf '%q' "${AGENTJAIL_TESTBED_CODEX_VERSION:-0.147.0}") bash /tmp/testbed/scenarios/${scenario}.sh" || rc=$?
    if [ -n "$codex_auth" ]; then
        cleanup_injected_auth
    fi
    return "$rc"
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
