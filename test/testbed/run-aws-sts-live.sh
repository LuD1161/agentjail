#!/usr/bin/env bash
# Runs the disposable macOS AWS STS testbed and coordinates an external profile.
set -euo pipefail
set +x
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib.sh"

NAME="${AWS_E2E_TESTBED_NAME:-aws-sts-live}"
VM="$(inst "$NAME")"
MANIFEST="${AWS_E2E_MANIFEST:-/tmp/agentjail-aws-sts-handoff.json}"
FINISH_SIGNAL="${AWS_E2E_FINISH_SIGNAL:-/tmp/agentjail-aws-sts-finish}"
CLEANUP_STATUS="${AWS_E2E_CLEANUP_STATUS:-/tmp/agentjail-aws-sts-cleanup.json}"
AUTH="${CODEX_AUTH_FILE:-${CODEX_HOME:-$HOME/.codex}/auth.json}"
PROFILE_HINT="${AWS_E2E_PROFILE_HINT:-smo}"
AWS_BIN_HINT="${AWS_E2E_AWS_BIN_HINT:-$HOME/.pyenv/versions/3.11.6/bin/aws}"
REPORT_ROOT="$SCRIPT_DIR/reports"
PROVISIONED=0
VM_OWNED=0
FINISH_SENT=0
REPORT_DIR=""

die_run() { printf 'aws-sts-live: %s\n' "$*" >&2; exit 1; }

finish_external() {
    if [ "$PROVISIONED" -eq 1 ] && [ "$FINISH_SENT" -eq 0 ]; then
        : >"$FINISH_SIGNAL"
        FINISH_SENT=1
    fi
}

cleanup_vm() {
    [ "$VM_OWNED" -eq 1 ] || return 0
    if [ "${AGENTJAIL_TESTBED_KEEP_VM:-0}" = 1 ]; then
        tart stop "$VM" >/dev/null 2>&1 || true
        printf 'aws-sts-live: retained stopped VM %s by request\n' "$VM" >&2
    else
        bash "$SCRIPT_DIR/testbed.sh" destroy "$NAME" >/dev/null 2>&1 || true
        if tart_exists "$NAME"; then
            printf 'aws-sts-live: cleanup could not delete exact temporary VM %s\n' "$VM" >&2
            return 1
        fi
    fi
}

cleanup() {
    local rc=$? cleanup_rc=0
    trap - EXIT INT TERM
    finish_external || cleanup_rc=1
    cleanup_vm || cleanup_rc=1
    if [ "$rc" -eq 0 ] && [ "$cleanup_rc" -ne 0 ]; then rc=1; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$DRIVER" = tart ] || die_run "this live workflow requires macOS and Tart"
if [ ! -x "$AWS_BIN_HINT" ] || ! "$AWS_BIN_HINT" --version >/dev/null 2>&1; then
    die_run "the printed AWS CLI path cannot start: $AWS_BIN_HINT"
fi
[ -r "$AUTH" ] || die_run "Codex auth cache is required: $AUTH"
auth_mode="$(stat -f %Lp "$AUTH")"
case "$auth_mode" in 400|600) ;; *) die_run "Codex auth cache must be mode 400 or 600, got $auth_mode" ;; esac
codex_real=""
while IFS= read -r candidate; do
    case "$candidate" in "$HOME/.agentjail/bin/"*) ;; *) codex_real="$candidate"; break ;; esac
done < <(type -a -p codex 2>/dev/null)
[ -x "$codex_real" ] || die_run "real Codex CLI was not found outside the AgentJail shim"
"$codex_real" login status >/dev/null 2>&1 || die_run "host Codex CLI is not authenticated"
tart list | awk 'NR>1 {print $2}' | grep -qx "$TART_TUNNEL_GOLDEN" \
    || die_run "required golden image $TART_TUNNEL_GOLDEN is absent"
for required in \
    aws-sts-provision.sh aws-sts-guest-import.py aws-sts-audit.sh \
    aws-sts-stream-filter.py aws-sts-package.py \
    scenarios/aws-sts-direct.sh scenarios/aws-sts-live.sh
do
    [ -r "$SCRIPT_DIR/$required" ] || die_run "required harness component is unreadable: $required"
done
git -C "$REPO_ROOT" check-ignore -q "$REPORT_ROOT/.ignore-probe" \
    || die_run "evidence root is not gitignored: $REPORT_ROOT"
mkdir -p "$REPORT_ROOT"
chmod 0700 "$REPORT_ROOT"
report_probe="$(mktemp "$REPORT_ROOT/.aws-sts-preflight.XXXXXX")" \
    || die_run "evidence root is not writable: $REPORT_ROOT"
unlink "$report_probe"
[ ! -e "$MANIFEST" ] || die_run "refusing to overwrite an existing AWS handoff: $MANIFEST"
[ ! -e "$FINISH_SIGNAL" ] || die_run "refusing to reuse an existing finish signal: $FINISH_SIGNAL"
if [ -e "$CLEANUP_STATUS" ]; then
    jq -e '((.schema_version==1 and .status=="pass") or (.schema_version==2 and .cleanup=="pass")) and (.run_id|length>10)' "$CLEANUP_STATUS" >/dev/null 2>&1 \
        || die_run "refusing to overwrite an invalid or failed cleanup status: $CLEANUP_STATUS"
    unlink "$CLEANUP_STATUS"
fi
if tart_exists "$NAME"; then
    die_run "exact disposable VM $VM already exists; inspect it before deleting or choose AWS_E2E_TESTBED_NAME"
fi

printf '==> creating and provisioning one disposable Tart VM from %s\n' "$TART_TUNNEL_GOLDEN" >&2
bash "$SCRIPT_DIR/testbed.sh" create "$NAME"
VM_OWNED=1
AGENTJAIL_TESTBED_AGENT=codex bash "$SCRIPT_DIR/testbed.sh" provision "$NAME" --worktree "$REPO_ROOT"
guest_push "$NAME" "$SCRIPT_DIR/aws-sts-guest-import.py" /tmp/aws-sts-guest-import.py
guest_exec "$NAME" "chmod 0700 /tmp/aws-sts-guest-import.py; cp /opt/homebrew/etc/ca-certificates/cert.pem /tmp/agentjail-aws-ca-bundle.crt; chmod 0444 /tmp/agentjail-aws-ca-bundle.crt; test -s /tmp/agentjail-aws-ca-bundle.crt"
# shellcheck disable=SC2016 # Expansion belongs to the remote login shell.
guest_exec "$NAME" 'PATH="$HOME/.agentjail/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" "$HOME/.agentjail/bin/agentjail" run --no-git-ssh -- codex --version >/dev/null'

printf '\nACTION REQUIRED — run this exact command in a normal host terminal:\n\n' >&2
printf '  AWS_PROFILE=%q AWS_E2E_AWS_BIN=%q bash %q --guest %q\n\n' \
    "$PROFILE_HINT" "$AWS_BIN_HINT" "$SCRIPT_DIR/aws-sts-provision.sh" "$NAME" >&2
printf 'The command uses the source profile only on the host and waits for automatic cleanup.\n' >&2
printf 'This harness is now waiting for its non-secret handoff manifest.\n' >&2

for _ in $(seq 1 1200); do
    [ ! -f "$MANIFEST" ] || break
    [ ! -f "$CLEANUP_STATUS" ] || die_run "external provisioner exited before producing a handoff"
    sleep 1
done
[ -f "$MANIFEST" ] || die_run "timed out after 20 minutes waiting for the external provisioning command"
jq -e '.schema_version==3 and .status=="ready" and (.run_id|length>10) and (.marker_key_sha256|length==64) and (.credential_fingerprints|length==3)' "$MANIFEST" >/dev/null \
    || die_run "external handoff manifest failed schema validation"
PROVISIONED=1
run_id="$(jq -r .run_id "$MANIFEST")"
expires_at="$(jq -r .expires_at "$MANIFEST")"
expiry_epoch="$(python3 - "$expires_at" <<'PY'
from datetime import datetime
import sys
try:
    print(int(datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")).timestamp()))
except (IndexError, ValueError):
    print(0)
PY
)"
[ "$expiry_epoch" -gt "$(( $(date +%s) + 900 ))" ] || die_run "STS session has less than 15 minutes remaining"
REPORT_DIR="$REPORT_ROOT/aws-sts-$run_id"
[ ! -e "$REPORT_DIR" ] || die_run "refusing to overwrite evidence directory $REPORT_DIR"
mkdir -m 0700 "$REPORT_DIR"
cp "$MANIFEST" "$REPORT_DIR/environment.json"
guest_push "$NAME" "$MANIFEST" /tmp/agentjail-aws-sts-handoff.json
guest_exec "$NAME" "chmod 0600 /tmp/agentjail-aws-sts-handoff.json"

direct_rc=0 live_rc=0 audit_rc=0
bash "$SCRIPT_DIR/testbed.sh" test "$NAME" aws-sts-direct || direct_rc=$?
AGENTJAIL_TESTBED_AGENT=codex bash "$SCRIPT_DIR/testbed.sh" test "$NAME" aws-sts-live --codex-auth "$AUTH" || live_rc=$?
guest_push "$NAME" "$SCRIPT_DIR/aws-sts-audit.sh" /tmp/testbed/aws-sts-audit.sh
guest_exec "$NAME" "chmod 0700 /tmp/testbed/aws-sts-audit.sh; bash /tmp/testbed/aws-sts-audit.sh" || audit_rc=$?

for artifact in \
    aws-sts-direct.result.json aws-sts-direct.proof.json \
    aws-sts-live.result.json aws-sts-live.proof.json \
    aws-sts-live.raw-scan.json aws-sts-live.metadata.json aws-sts-live.log.tail.txt \
    aws-sts-live.audit.json
do
    guest_pull "$NAME" "/tmp/testbed/results/$artifact" "$REPORT_DIR/$artifact" 2>/dev/null \
        || printf 'aws-sts-live: evidence artifact unavailable: %s\n' "$artifact" >&2
done

finish_external
for _ in $(seq 1 300); do [ -f "$CLEANUP_STATUS" ] && break; sleep 1; done
if [ -f "$CLEANUP_STATUS" ]; then
    cp "$CLEANUP_STATUS" "$REPORT_DIR/aws-cleanup.json"
else
    printf '{"schema_version":1,"run_id":"%s","status":"missing"}\n' "$run_id" >"$REPORT_DIR/aws-cleanup.json"
fi
python3 "$SCRIPT_DIR/aws-sts-package.py" "$REPORT_DIR" \
    "$SCRIPT_DIR/scenarios/aws-sts-direct.sh" "$SCRIPT_DIR/scenarios/aws-sts-live.sh" \
    "$SCRIPT_DIR/aws-sts-stream-filter.py"
unlink "$CLEANUP_STATUS" 2>/dev/null || true

results_ok=0
if [ "$direct_rc" -eq 0 ] && [ "$live_rc" -eq 0 ] && [ "$audit_rc" -eq 0 ] \
    && jq -e '.result=="pass" and .counts.fail==0 and .counts.skip==0' "$REPORT_DIR/aws-sts-direct.result.json" >/dev/null 2>&1 \
    && jq -e '.result=="pass" and .counts.fail==0 and .counts.skip==0' "$REPORT_DIR/aws-sts-live.result.json" >/dev/null 2>&1 \
    && jq -e --arg run "$run_id" '.schema_version==2 and .status=="pass" and .cleanup=="pass" and .run_id==$run and .assertions.direct_denied_object_absent==true' "$REPORT_DIR/aws-cleanup.json" >/dev/null 2>&1; then
    results_ok=1
fi

printf '\nAWS STS E2E evidence: %s\n' "$REPORT_DIR"
if [ "$results_ok" -ne 1 ]; then
    die_run "one or more direct, Codex, audit, SKIP, or cleanup assertions failed"
fi
printf 'AWS STS E2E: PASS — direct broker, real Codex, negative policy, leakage, audit, and cleanup checks all executed\n'
