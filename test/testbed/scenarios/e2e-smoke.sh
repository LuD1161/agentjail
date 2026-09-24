#!/usr/bin/env bash
# e2e-smoke.sh — single-terminal scenario (recorded whole by the runner).
# Exercises agentjail as a human's Claude Code session would, across both tiers,
# on the INSTALLED binaries. Emits a result JSON via reportlib; still runs
# standalone under `testbed.sh test`.
#
# testbed-mode: single
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

HOOK="$HOME/.agentjail/bin/agentjail-hook"
SHIELD="$HOME/.agentjail/bin/agentjail-shield"
PROJECT="$HOME/work/demo"
SECRETS="$HOME/.agentjail/bin/agentjail-secrets"
DEMO_SECRET="testbed/demo"
POLICY="$HOME/.agentjail/policy.yaml"
POLICY_WORK="$(mktemp -d "${TMPDIR:-/tmp}/agentjail-smoke-policy.XXXXXX")" || exit 1
POLICY_BACKUP="$POLICY_WORK/policy.yaml"
POLICY_CHANGED=0

cleanup() {
    local rc=$? restored=1
    trap - EXIT INT TERM
    if [ "$POLICY_CHANGED" -eq 1 ] && ! policy_mode restore; then
        echo "FAIL  could not restore and reload the original policy" >&2
        echo "Original policy retained at $POLICY_BACKUP" >&2
        restored=0
        rc=1
    fi
    [ ! -x "$SECRETS" ] || "$SECRETS" delete "$DEMO_SECRET" >/dev/null 2>&1 || true
    [ "$restored" -eq 0 ] || rm -rf "$POLICY_WORK"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

scn_init "e2e-smoke" "clean-box monitor default + opted-in hook enforcement & shield isolation"

# Probe the applied mode through the hook and durable store, not configuration.
# See ADR 0150-evaluate-only-default and ADR 0066-reload-off-the-agent-socket.
policy_mode() {
    python3 - "$1" "$POLICY_BACKUP" <<'PY'
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

operation, backup_name = sys.argv[1:]
root = Path.home() / ".agentjail"
policy = root / "policy.yaml"
backup = Path(backup_name)

try:
    if operation in ("enforce", "restore"):
        data = backup.read_bytes()
        if operation == "enforce":
            data, count = re.subn(rb"(?m)^enforcement:[^\r\n]*", b"enforcement: enforce", data)
            if count > 1:
                raise RuntimeError("ambiguous enforcement setting")
            if count == 0:
                data = b"enforcement: enforce\n" + data
        staged = None
        try:
            with tempfile.NamedTemporaryFile(dir=policy.parent, prefix=".e2e-smoke-policy-", delete=False) as stream:
                staged = Path(stream.name)
                stream.write(data)
            shutil.copymode(backup, staged)
            os.replace(staged, policy)
        finally:
            if staged is not None and staged.exists():
                staged.unlink()
        request = {"type": "daemon_reload", "ctl_token": (root / "control.token").read_text().strip()}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(10)
            connection.connect(str(root / "run/daemon-ctl.sock"))
            connection.sendall(json.dumps(request).encode() + b"\n")
            frame = connection.makefile("rb").readline(65537)
        if len(frame) > 65536 or not frame.endswith(b"\n") or json.loads(frame).get("ok") is not True:
            raise RuntimeError("daemon did not acknowledge policy reload")
    else:
        expected_exit, expected_action, expected_would = {
            "verify-monitor": (0, "allow", "deny"),
            "verify-enforce": (2, "deny", ""),
        }[operation]
        session = "e2e-smoke-" + operation + "-" + uuid.uuid4().hex
        project = str(Path.home() / "work/demo")
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Read",
                   "tool_input": {"file_path": "/etc/hosts"}, "session_id": session, "cwd": project}
        response = subprocess.run([str(root / "bin/agentjail-hook")], input=json.dumps(payload),
                                  text=True, capture_output=True, timeout=5)
        if response.returncode != expected_exit:
            raise RuntimeError("hook exit %d, expected %d" % (response.returncode, expected_exit))
        if expected_action == "allow" and json.loads(response.stdout).get("hookSpecificOutput", {}).get("permissionDecision") != "allow":
            raise RuntimeError("monitor hook did not return allow")
        deadline = time.monotonic() + 5
        uri = (root / "agentjail.db").as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1) as database:
            while True:
                row = database.execute(
                    "SELECT action, would_action FROM decisions WHERE session_id=? AND tool_name='Read' "
                    "AND cwd=? AND json_extract(tool_input_redacted,'$.file_path')='/etc/hosts' ORDER BY id DESC LIMIT 1",
                    (session, project)).fetchone()
                if row is not None:
                    if row != (expected_action, expected_would):
                        raise RuntimeError("durable verdict %r, expected %r" % (row, (expected_action, expected_would)))
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("fresh hook decision was not persisted")
                time.sleep(0.1)
except Exception as error:
    print("policy mode check failed: " + str(error), file=sys.stderr)
    sys.exit(1)
PY
}

if ! cp -p "$POLICY" "$POLICY_BACKUP"; then
    scn_fail "original policy is available for restoration"
    scn_finish
    exit 1
fi

# hook <label> <expected: allow|deny> <json> — maps exit 0->allow, 2->deny.
hook() {
    local rc dec; echo "$3" | "$HOOK" >/dev/null 2>/tmp/he; rc=$?
    case "$rc" in 0) dec=allow;; 2) dec=deny;; *) dec="exit$rc";; esac
    scn_check "$1" "$2" "$dec"
}

# install wiring follows the selected-agent contract from ADR 0053.
installed_agent_hooks=0
if command -v claude >/dev/null 2>&1; then
    installed_agent_hooks=$((installed_agent_hooks+1))
    grep -q agentjail-hook "$HOME/.claude/settings.json" \
        && scn_ok "Claude hook wired in settings.json" \
        || scn_fail "Claude hook wired in settings.json"
fi
if command -v codex >/dev/null 2>&1; then
    installed_agent_hooks=$((installed_agent_hooks+1))
    grep -q 'agentjail-hook --agent=codex' "$HOME/.codex/hooks.json" \
        && scn_ok "Codex hook wired in hooks.json" \
        || scn_fail "Codex hook wired in hooks.json"
fi
[ "$installed_agent_hooks" -gt 0 ] || scn_fail "a supported coding agent is installed"
# macOS uses launchd (LaunchAgent plist); Linux uses systemd --user.
if [ "$(uname -s)" = "Darwin" ]; then
    launchctl list 2>/dev/null | grep -q agentjail && scn_ok "daemon active (launchd)" || scn_fail "daemon active (launchd)"
else
    systemctl --user is-active agentjail-daemon >/dev/null 2>&1 && scn_ok "daemon active (systemd --user)" || scn_fail "daemon active (systemd --user)"
fi

# Fresh installs must allow the benign read and persist its canonical denial.
if policy_mode verify-monitor; then
    scn_ok "default monitor allows hook and durably records would-deny"
else
    scn_fail "default monitor allows hook and durably records would-deny"
    scn_finish
    exit 1
fi

POLICY_CHANGED=1
if policy_mode enforce && policy_mode verify-enforce; then
    scn_ok "explicit enforce reload completes and a fresh hook durably denies"
else
    scn_fail "explicit enforce reload completes and a fresh hook durably denies"
    scn_finish
    exit 1
fi

# Tier 1 — explicitly opted-in hook policy.
hook "hook: allow write inside project"       allow '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$PROJECT"'/note.txt","content":"hi"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "hook: deny write ~/.ssh/authorized_keys" deny '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.ssh/authorized_keys","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "hook: deny write ~/.aws/credentials"     deny '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.aws/credentials","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'
hook "hook: deny rm -rf /"                     deny '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"},"session_id":"e2e","cwd":"'"$PROJECT"'"}'

# remediation hint on deny. Capture stderr into a var first: piping the hook
# (which exits 2 on deny) straight into grep trips `set -o pipefail`.
hint_out=$(echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/.ssh/authorized_keys","content":"x"},"session_id":"e2e","cwd":"'"$PROJECT"'"}' | "$HOOK" 2>&1 1>/dev/null || true)
if grep -qiE "ssh|sensitive|credential|blocked" <<<"$hint_out"; then scn_ok "deny carries remediation hint"; else scn_fail "deny carries remediation hint"; fi

# Tier 2 — shield (cwd = project, like a real session)
cd "$PROJECT" 2>/dev/null || true
rm -f "$HOME/.ssh/id_rsa"; echo ORIG > "$HOME/.ssh/id_rsa"
"$SHIELD" -- bash -c 'echo PWNED > ~/.ssh/id_rsa' >/dev/null 2>&1
grep -q PWNED "$HOME/.ssh/id_rsa" && scn_fail "shield blocks ~/.ssh write" || scn_ok "shield blocks ~/.ssh write"
"$SHIELD" -- bash -c 'cat ~/.ssh/id_rsa' 2>/dev/null | grep -q ORIG && scn_fail "shield blocks ~/.ssh read" || scn_ok "shield blocks ~/.ssh read"
"$SHIELD" -- bash -c 'echo ok > ./shield-ok.txt' >/dev/null 2>&1
[ -f "$PROJECT/shield-ok.txt" ] && scn_ok "shield allows project write" || scn_fail "shield allows project write"

# Secrets broker — on-demand auto-start (ADR 0058, DEFECT-2).
SECRETS_SOCK="$HOME/.agentjail/secrets.sock"
if [ "$(uname -s)" = "Darwin" ]; then
    SECRETS_SVC_FILE="$HOME/Library/LaunchAgents/com.agentjail.secrets.plist"
else
    SECRETS_SVC_FILE="$HOME/.config/systemd/user/agentjail-secrets.service"
fi

# a. loaded-but-not-running service definition was installed.
[ -f "$SECRETS_SVC_FILE" ] && scn_ok "secrets broker service definition installed" || scn_fail "secrets broker service definition installed"

# b. broker is dormant right after install — no manual `serve` was run.
[ -S "$SECRETS_SOCK" ] && scn_fail "secrets broker dormant after install (no socket yet)" || scn_ok "secrets broker dormant after install (no socket yet)"

# c. setting a secret must succeed WITHOUT a manual `agentjail-secrets serve` —
# this is the auto-start path (rpcClient -> EnsureSecretsBroker on connect-refused).
"$SECRETS" set "$DEMO_SECRET" hello-from-e2e-smoke >/tmp/secrets-set.log 2>&1
set_rc=$?
[ "$set_rc" -eq 0 ] && scn_ok "secrets broker: set auto-starts broker" || scn_fail "secrets broker: set auto-starts broker"

# d. broker is now reachable — proves auto-start actually brought it up.
[ -S "$SECRETS_SOCK" ] && scn_ok "secrets broker reachable after set (auto-started)" || scn_fail "secrets broker reachable after set (auto-started)"

# e. round-trip: the secret name comes back from list (never the value).
list_out=$("$SECRETS" list 2>/tmp/secrets-list.log)
if grep -qx "$DEMO_SECRET" <<<"$list_out"; then scn_ok "secrets broker: list round-trips secret name"; else scn_fail "secrets broker: list round-trips secret name"; fi

# f. cleanup is part of the contract: no fixture may remain in the guest keychain.
if "$SECRETS" delete "$DEMO_SECRET" >/tmp/secrets-delete.log 2>&1 \
    && ! "$SECRETS" list 2>/tmp/secrets-list-after-delete.log | grep -qx "$DEMO_SECRET"; then
    scn_ok "secrets broker: fixture removed after round-trip"
else
    scn_fail "secrets broker: fixture removed after round-trip"
fi

if policy_mode restore && policy_mode verify-monitor; then
    POLICY_CHANGED=0
    scn_ok "original policy restored and monitor behavior re-attested"
else
    scn_fail "original policy restored and monitor behavior re-attested"
fi

scn_finish
