#!/usr/bin/env bash
# chaos-hook-tamper.sh — failure injection: the agent's hook config is tampered
# with mid-session. Runs INSIDE a provisioned testbed guest.
#
# hookwatch re-injects the agentjail-hook entry when it is stripped from an
# agent settings file (ADR 0026). But hookwatch is a goroutine INSIDE the daemon
# (internal/daemonapp/main.go) — it is blind exactly when the daemon is down,
# which is the AGE-212 state. This scenario asserts what actually happens in
# BOTH states rather than assuming the watchdog is always awake.
#
# SAFE TO RE-RUN: the original settings file and the daemon are restored on
# every exit path (trap).
set -u
AJ="$HOME/.agentjail/bin/agentjail"
SETTINGS="$HOME/.claude/settings.json"
BACKUP="/tmp/chaos-hook-tamper.settings.bak"
SOCK="$HOME/.agentjail/daemon.sock"

# shellcheck source=test/testbed/scenarios/chaos-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/chaos-lib.sh"

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

# hookwatch's fallback poll is a 30s ticker (fsnotify covers the fast path), so
# a "did not re-inject" verdict is only honest after a full tick plus margin.
REINJECT_WAIT=90
NEGATIVE_WAIT=45

svc_supported() {
    case "$OS" in
        Darwin) command -v launchctl >/dev/null 2>&1 && [ -f "$PLIST" ] ;;
        Linux)  command -v systemctl >/dev/null 2>&1 && systemctl --user show "$UNIT" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}
daemon_active() {
    case "$OS" in
        Darwin) launchctl list 2>/dev/null | awk -v l="$LABEL" '$3==l && $1!="-" {f=1} END{exit !f}' ;;
        *)      systemctl --user is-active "$UNIT" >/dev/null 2>&1 ;;
    esac
}
daemon_stop() {
    case "$OS" in
        Darwin) launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true ;;
        *)      systemctl --user stop "$UNIT" >/dev/null 2>&1 || true ;;
    esac
}
daemon_start() {
    case "$OS" in
        Darwin) launchctl bootstrap "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 \
                    || launchctl kickstart -k "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true ;;
        *)      systemctl --user start "$UNIT" >/dev/null 2>&1 || true ;;
    esac
}
wait_up()   { local i; for i in $(seq 1 30); do daemon_active && [ -S "$SOCK" ] && return 0; sleep 1; done; return 1; }
wait_down() { local i; for i in $(seq 1 30); do daemon_active || return 0; sleep 1; done; return 1; }

hook_present() { [ -f "$SETTINGS" ] && grep -q 'agentjail-hook' "$SETTINGS"; }
# wait_hook_present SECONDS — poll for re-injection.
wait_hook_present() { local i; for i in $(seq 1 "$1"); do hook_present && return 0; sleep 1; done; return 1; }

restore() {
    if [ -f "$BACKUP" ]; then
        mkdir -p "$(dirname "$SETTINGS")" 2>/dev/null || true
        cp "$BACKUP" "$SETTINGS" && rm -f "$BACKUP"
    fi
    daemon_active || daemon_start
    wait_up >/dev/null 2>&1 || true
}
trap restore EXIT INT TERM

# --- preconditions ---------------------------------------------------------
if ! svc_supported; then
    skip "no supported service manager for $OS — cannot drive the daemon-down half"
    echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
    exit 0
fi
if [ ! -f "$SETTINGS" ]; then
    skip "~/.claude/settings.json not present (run provision/e2e-smoke first)"
    echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
    exit 0
fi
if ! daemon_active; then
    skip "daemon not active at scenario start — the daemon-up half is not testable"
    echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
    exit 0
fi
# These assertions track HEAD; the binaries under test may not. A stale binary
# reports fake FAILs against features it predates. See AGE-236, chaos-lib.sh.
chaos_assert_fresh_binaries "$AJ"

cp "$SETTINGS" "$BACKUP" || { skip "could not back up the settings file"; echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="; exit 0; }

hook_present && ok "baseline: agentjail-hook is wired in the Claude settings file" \
             || { bad "baseline: agentjail-hook is NOT wired — nothing to tamper with"; echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="; exit 1; }

# ===========================================================================
echo "=== 5a. hook entry stripped, daemon UP -> hookwatch must re-inject ==="
# The redirect always lands, but observing the stripped state races hookwatch's
# fsnotify path, which repairs in ~5ms — the shell cannot win. Seeing the hook
# back here is not a failed tamper: we wrote '{}', so its return IS re-injection.
# 5c proves the strip lands (with the daemon down it sticks).
echo '{}' > "$SETTINGS"
if hook_present; then
    ok "hook re-injected before the strip was observable — fsnotify beat the check (we wrote '{}'; its return is the repair)"
else
    ok "hook entry stripped from the settings file"
fi
if wait_hook_present "$REINJECT_WAIT"; then
    ok "hookwatch re-injected the hook with the daemon UP (ADR 0026)"
else
    bad "hookwatch did NOT re-inject within ${REINJECT_WAIT}s with the daemon up"
fi
cp "$BACKUP" "$SETTINGS"
sleep 2

# ===========================================================================
echo "=== 5b. settings file DELETED entirely, daemon UP ==="
# hookwatch's check() stats each target and `continue`s when the stat fails, and
# fsnotify only acts on Write|Create — so a delete is logged, never repaired.
# This pins the CURRENT behaviour so a future change to it is a visible diff,
# not a silent one.
rm -f "$SETTINGS"
[ -f "$SETTINGS" ] && bad "delete did not take effect" || ok "settings file deleted"
sleep "$NEGATIVE_WAIT"
if [ -f "$SETTINGS" ]; then
    echo "  NOTE: the file came back — hookwatch now repairs a full delete."
    echo "  That is an IMPROVEMENT over the pinned behaviour; update this check."
    bad "settings file was recreated after delete — behaviour changed from the pinned baseline (good news; re-pin this check)"
else
    ok "pinned gap: a full delete is NOT repaired after ${NEGATIVE_WAIT}s (hookwatch only re-injects into an existing file)"
fi
# `status` must not claim the hook is wired when the config is gone.
# Grep the Claude Code line specifically: codex/cursor are legitimately "not
# installed" in this guest, so a bare grep would pass no matter what Claude says.
if [ -x "$AJ" ]; then
    CLINE=$(timeout 30 "$AJ" status 2>&1 | sed $'s/\033\\[[0-9;]*m//g' | grep -i 'Claude Code' | head -1)
    if [ -z "$CLINE" ]; then
        skip "status hook check (no 'Claude Code' line in status output)"
    elif echo "$CLINE" | grep -q 'not installed'; then
        ok "status reports the Claude hook as not installed while the config is deleted"
    else
        bad "status still shows the Claude hook as installed with the config deleted — an unenforced box looks healthy"
    fi
else
    skip "status check (agentjail not installed)"
fi
cp "$BACKUP" "$SETTINGS"
sleep 2
hook_present && ok "settings file restored after the delete stage" || bad "settings file not restored after the delete stage"

# ===========================================================================
echo "=== 5c. hook entry stripped, daemon DOWN -> watchdog is blind ==="
# hookwatch lives inside the daemon process. With the daemon down nothing is
# watching, so tampering sticks. This is the compounding half of AGE-212: the
# outage disables the thing that would have repaired the outage's blast radius.
daemon_stop
if ! wait_down; then
    skip "daemon-down half (daemon would not stop within 30s)"
else
    ok "daemon stopped"
    echo '{}' > "$SETTINGS"
    sleep "$NEGATIVE_WAIT"
    if hook_present; then
        bad "hook was re-injected with the daemon DOWN — unexpected; hookwatch runs inside the daemon"
    else
        ok "hook NOT re-injected while the daemon is down (watchdog is blind during an outage)"
    fi
    # Recovery: bringing the daemon back must repair the tamper it slept through.
    cp "$BACKUP" "$SETTINGS"
    daemon_start
    if wait_up; then
        ok "daemon restarted after the blind window"
    else
        bad "daemon did NOT come back after the blind window — box left degraded"
    fi
    sleep 2
    echo '{}' > "$SETTINGS"
    if wait_hook_present "$REINJECT_WAIT"; then
        ok "hookwatch repairs tampering again once the daemon is back"
    else
        bad "hookwatch did NOT repair tampering after the daemon returned"
    fi
fi

# ===========================================================================
echo "=== restore ==="
cp "$BACKUP" "$SETTINGS"
hook_present && ok "original settings file restored" || bad "original settings file NOT restored — guest left tampered"
daemon_active && ok "daemon active at scenario end" || bad "daemon not active at scenario end"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
