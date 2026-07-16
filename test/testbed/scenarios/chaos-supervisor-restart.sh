#!/usr/bin/env bash
# chaos-supervisor-restart.sh — failure injection: kill the daemon PID out from
# under the supervisor, cleanly (SIGTERM) and uncleanly (SIGKILL), and assert it
# comes back. Runs INSIDE a provisioned testbed guest.
#
# The two signals take different code paths: SIGTERM lets the daemon shut down
# and exit 0, SIGKILL gives it no chance. Only Restart=always covers BOTH — the
# Linux auto-updater's clean exit(0) went un-restarted under Restart=on-failure
# and left the box unenforced. See ADR 0070-supervisor-restarts-daemon-on-clean-exit.
#
# Unlike chaos-daemon-outage.sh this NEVER uses `systemctl stop` / `launchctl
# bootout` — the whole point is to leave the supervisor armed and watch it act.
#
# SAFE TO RE-RUN: the daemon is restored on every exit path (trap).
set -u
AJ="$HOME/.agentjail/bin/agentjail"
SOCK="$HOME/.agentjail/daemon.sock"

command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout  >/dev/null 2>&1 || timeout(){ shift; "$@"; }

PASS=0; FAIL=0; SKIP=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

OS=$(uname -s)
UNIT="agentjail-daemon"
LABEL="com.agentjail.daemon"
PLIST="$HOME/Library/LaunchAgents/com.agentjail.daemon.plist"
UNIT_FILE="$HOME/.config/systemd/user/agentjail-daemon.service"

daemon_active() {
    case "$OS" in
        Darwin) launchctl list 2>/dev/null | awk -v l="$LABEL" '$3==l && $1!="-" {f=1} END{exit !f}' ;;
        *)      systemctl --user is-active "$UNIT" >/dev/null 2>&1 ;;
    esac
}
daemon_pid() {
    case "$OS" in
        Darwin) launchctl list 2>/dev/null | awk -v l="$LABEL" '$3==l {print $1}' ;;
        *)      systemctl --user show -p MainPID --value "$UNIT" 2>/dev/null ;;
    esac
}
daemon_start() {
    case "$OS" in
        Darwin) launchctl bootstrap "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 \
                    || launchctl kickstart -k "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true ;;
        *)      systemctl --user start "$UNIT" >/dev/null 2>&1 || true ;;
    esac
}
# wait_respawn OLDPID — a NEW live main PID plus a real socket. launchd throttles
# respawns to ~10s and systemd sets RestartSec=2, so allow generous headroom.
wait_respawn() {
    local old="$1" i new
    for i in $(seq 1 60); do
        if daemon_active; then
            new=$(daemon_pid)
            case "${new:-}" in ''|0|-) new="" ;; esac
            if [ -n "$new" ] && [ "$new" != "$old" ] && [ -S "$SOCK" ]; then
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}

restore() { daemon_active || daemon_start; }
trap restore EXIT INT TERM

# --- preconditions ---------------------------------------------------------
case "$OS" in
    Linux)
        command -v systemctl >/dev/null 2>&1 && systemctl --user show "$UNIT" >/dev/null 2>&1 \
            || { skip "systemd --user unit '$UNIT' not available"; echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="; exit 0; } ;;
    Darwin)
        command -v launchctl >/dev/null 2>&1 && [ -f "$PLIST" ] \
            || { skip "launchd plist not installed"; echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="; exit 0; } ;;
    *)
        skip "unsupported OS '$OS' — no systemd/launchd supervisor to exercise"
        echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="; exit 0 ;;
esac

# ===========================================================================
echo "=== supervisor config pins ADR 0070 (static) ==="
# Cheap and OS-specific: the exact regression that shipped the outage is a
# config word. Assert it on both backends so they cannot drift apart.
if [ "$OS" = "Darwin" ]; then
    if [ -f "$PLIST" ] && grep -A1 'KeepAlive' "$PLIST" | grep -q '<true/>'; then
        ok "launchd plist sets KeepAlive=true"
    else
        bad "launchd plist does not set KeepAlive=true"
    fi
    skip "systemd Restart=always check (not Linux)"
else
    skip "launchd KeepAlive check (not macOS)"
    if [ -f "$UNIT_FILE" ]; then
        if grep -qE '^Restart=always' "$UNIT_FILE"; then
            ok "systemd unit sets Restart=always (clean exit(0) is restarted — ADR 0070)"
        else
            bad "systemd unit does not set Restart=always"
        fi
        if grep -qE '^Restart=on-failure' "$UNIT_FILE"; then
            bad "systemd unit regressed to Restart=on-failure — a clean exit(0) would NOT restart (ADR 0070)"
        else
            ok "systemd unit is not Restart=on-failure"
        fi
    else
        skip "systemd unit file not found on disk — cannot pin Restart= statically"
    fi
fi

if ! daemon_active; then
    skip "daemon not active at scenario start — nothing to kill (run e2e-smoke first)"
    echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
    exit 0
fi

# ===========================================================================
echo "=== 2a. clean kill (SIGTERM) — the auto-updater's exit path ==="
PID0=$(daemon_pid); case "${PID0:-}" in ''|0|-) PID0="" ;; esac
if [ -z "$PID0" ]; then
    skip "SIGTERM restart (supervisor reports no main PID for the daemon)"
else
    echo "  killing the daemon with SIGTERM"
    kill -TERM "$PID0" 2>/dev/null || true
    if wait_respawn "$PID0"; then
        ok "supervisor restarted the daemon after a CLEAN exit (SIGTERM)"
        [ -S "$SOCK" ] && ok "socket re-created after the SIGTERM restart" || bad "no socket after the SIGTERM restart"
    else
        bad "supervisor did NOT restart the daemon after SIGTERM within 60s — this is the ADR 0070 regression"
    fi
fi

sleep 5   # stay clear of systemd's StartLimitBurst / launchd's respawn throttle

# ===========================================================================
echo "=== 2b. unclean kill (SIGKILL) — a crash ==="
PID1=$(daemon_pid); case "${PID1:-}" in ''|0|-) PID1="" ;; esac
if [ -z "$PID1" ]; then
    skip "SIGKILL restart (no live main PID — the SIGTERM stage may not have recovered)"
else
    echo "  killing the daemon with SIGKILL"
    kill -KILL "$PID1" 2>/dev/null || true
    if wait_respawn "$PID1"; then
        ok "supervisor restarted the daemon after an UNCLEAN kill (SIGKILL)"
        [ -S "$SOCK" ] && ok "socket re-created after the SIGKILL restart" || bad "no socket after the SIGKILL restart"
    else
        bad "supervisor did NOT restart the daemon after SIGKILL within 60s"
    fi
fi

# ===========================================================================
echo "=== enforcement is real again, not just 'active' ==="
# `is-active` was green throughout the 3-day outage. Prove the restarted daemon
# actually decides, rather than trusting the supervisor's own status word.
HOOK="$HOME/.agentjail/bin/agentjail-hook"
PROJECT="$HOME/work/demo"
if [ -x "$HOOK" ]; then
    sleep 2
    OUT=$(printf '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"%s/.ssh/authorized_keys","content":"x"},"session_id":"chaos","cwd":"%s"}' "$HOME" "$PROJECT" \
        | timeout 20 "$HOOK" 2>&1); RC=$?
    if [ "$RC" = 2 ]; then
        ok "restarted daemon enforces policy again (deny still denies)"
    else
        bad "restarted daemon did not deny a known-bad write (exit $RC, expected 2)"
    fi
    # Covers both fail-open renderings: the stdout systemMessage (allow) and the
    # stderr banner (deny). Either wording means the daemon is still unreachable.
    if echo "$OUT" | grep -qiE 'daemon unreachable|daemon not running'; then
        bad "hook is still failing open after the restart (daemon still unreachable)"
    else
        ok "hook is no longer failing open after the restart"
    fi
else
    skip "post-restart enforcement check (agentjail-hook not installed)"
fi

if [ -x "$AJ" ]; then
    DOC=$(timeout 60 "$AJ" doctor 2>&1)
    echo "$DOC" | grep -qi "All checks passed" && ok "doctor green after the restart cycle" \
        || bad "doctor not green after the restart cycle — box left degraded"
else
    skip "doctor check (agentjail not installed)"
fi

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
