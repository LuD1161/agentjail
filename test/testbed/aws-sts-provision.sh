#!/usr/bin/env bash
# Creates a one-hour AWS role session and imports it directly into a prepared Tart guest.
set -euo pipefail
set +x
umask 077

usage() {
    printf 'usage: AWS_PROFILE=<profile> %s --guest <testbed-name>\n' "$0" >&2
    exit 2
}

guest=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --guest) guest="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$guest" ] || usage
: "${AWS_PROFILE:?AWS_PROFILE is required; run this command outside the coding-agent sandbox}"

AWS_BIN="${AWS_E2E_AWS_BIN:-$(command -v aws 2>/dev/null || true)}"
REGION="${AWS_E2E_REGION:-us-west-2}"
MANIFEST="${AWS_E2E_MANIFEST:-/tmp/agentjail-aws-sts-handoff.json}"
FINISH_SIGNAL="${AWS_E2E_FINISH_SIGNAL:-/tmp/agentjail-aws-sts-finish}"
CLEANUP_STATUS="${AWS_E2E_CLEANUP_STATUS:-/tmp/agentjail-aws-sts-cleanup.json}"
VM="tb-$guest"

pass() { printf 'PASS  %s\n' "$1"; }
die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
[ -x "$AWS_BIN" ] || die "working AWS CLI not found; set AWS_E2E_AWS_BIN"
"$AWS_BIN" --version >/dev/null 2>&1 || die "configured AWS CLI cannot start; set AWS_E2E_AWS_BIN to a working installation"
command -v tart >/dev/null 2>&1 || die "Tart is required"
tart list | awk 'NR>1 {print $2}' | grep -qx "$VM" || die "prepared guest $VM does not exist"
GUEST_IP="$(tart ip "$VM" 2>/dev/null || true)"
[ -n "$GUEST_IP" ] || die "prepared guest $VM is not running or has no IP"
ssh_opts=(-o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)
ssh "${ssh_opts[@]}" "admin@$GUEST_IP" test -x /tmp/aws-sts-guest-import.py \
    || die "guest import helper is missing; leave the waiting harness running"

[ ! -e "$MANIFEST" ] || die "handoff already exists at $MANIFEST"
unlink "$FINISH_SIGNAL" 2>/dev/null || true
unlink "$CLEANUP_STATUS" 2>/dev/null || true
WORK="$(mktemp -d /tmp/agentjail-aws-sts-provision.XXXXXX)"
case "$WORK" in /tmp/agentjail-aws-sts-provision.*) ;; *) die "unexpected temporary directory: $WORK" ;; esac
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 6)"
BUCKET_SUFFIX="$(printf '%s' "$RUN_ID" | tr '[:upper:]' '[:lower:]')"
TARGET_BUCKET="agentjail-sts-target-$BUCKET_SUFFIX"
DECOY_BUCKET="agentjail-sts-decoy-$BUCKET_SUFFIX"
ROLE_NAME="agentjail-sts-e2e-$RUN_ID"
ROLE_POLICY_NAME="agentjail-sts-e2e-list-target"
BOOTSTRAP_USER="agentjail-sts-bootstrap-$RUN_ID"
BOOTSTRAP_POLICY="agentjail-sts-bootstrap-assume"
CREDENTIAL_NAME="aws/sts-e2e-$RUN_ID"
MARKER_KEY="proof-$(openssl rand -hex 12).txt"

validate_bucket_name() {
    local value="$1"
    if [ "${#value}" -lt 3 ] || [ "${#value}" -gt 63 ] \
        || ! printf '%s' "$value" | grep -Eq '^[a-z0-9][a-z0-9-]*[a-z0-9]$'; then
        die "generated invalid S3 bucket name"
    fi
}
validate_bucket_name "$TARGET_BUCKET"
validate_bucket_name "$DECOY_BUCKET"

TARGET_CREATED=0; DECOY_CREATED=0; MARKER_CREATED=0
ROLE_CREATED=0; ROLE_POLICY_CREATED=0
BOOTSTRAP_USER_CREATED=0; BOOTSTRAP_KEY_CREATED=0; BOOTSTRAP_POLICY_CREATED=0
CLEANED=0
DIRECT_DENIED_ABSENT=null
CODEX_DENIED_ABSENT=null

write_cleanup_status() {
    python3 - "$CLEANUP_STATUS" "$RUN_ID" "$1" "$2" "$DIRECT_DENIED_ABSENT" "$CODEX_DENIED_ABSENT" <<'PY'
import json, os, sys
def boolean(value):
    return {"true": True, "false": False, "null": None}[value]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({
        "schema_version": 2,
        "run_id": sys.argv[2],
        "status": sys.argv[3],
        "cleanup": sys.argv[4],
        "assertions": {
            "direct_denied_object_absent": boolean(sys.argv[5]),
            "codex_denied_object_absent": boolean(sys.argv[6]),
        },
    }, handle, sort_keys=True)
    handle.write("\n")
os.chmod(sys.argv[1], 0o600)
PY
}

cleanup() {
    local failed=0 cleanup_status=pass overall_status=pass
    [ "$CLEANED" -eq 0 ] || return 0
    CLEANED=1
    set +e
    if [ "$MARKER_CREATED" -eq 1 ]; then
        "$AWS_BIN" s3api delete-object --region "$REGION" --bucket "$TARGET_BUCKET" --key "$MARKER_KEY" >/dev/null 2>&1 || failed=1
    fi
    if [ "$TARGET_CREATED" -eq 1 ]; then
        "$AWS_BIN" s3api delete-object --region "$REGION" --bucket "$TARGET_BUCKET" --key agentjail-direct-must-be-denied >/dev/null 2>&1 || failed=1
        "$AWS_BIN" s3api delete-object --region "$REGION" --bucket "$TARGET_BUCKET" --key codex-must-be-denied >/dev/null 2>&1 || failed=1
    fi
    if [ "$ROLE_CREATED" -eq 1 ]; then
        [ "$ROLE_POLICY_CREATED" -eq 0 ] || "$AWS_BIN" iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$ROLE_POLICY_NAME" >/dev/null 2>&1 || failed=1
        "$AWS_BIN" iam delete-role --role-name "$ROLE_NAME" >/dev/null 2>&1 || failed=1
    fi
    if [ "$BOOTSTRAP_USER_CREATED" -eq 1 ]; then
        [ "$BOOTSTRAP_POLICY_CREATED" -eq 0 ] || "$AWS_BIN" iam delete-user-policy --user-name "$BOOTSTRAP_USER" --policy-name "$BOOTSTRAP_POLICY" >/dev/null 2>&1 || failed=1
        [ "$BOOTSTRAP_KEY_CREATED" -eq 0 ] || "$AWS_BIN" iam delete-access-key --user-name "$BOOTSTRAP_USER" --access-key-id "${BOOT_ACCESS:-}" >/dev/null 2>&1 || failed=1
        "$AWS_BIN" iam delete-user --user-name "$BOOTSTRAP_USER" >/dev/null 2>&1 || failed=1
    fi
    [ "$DECOY_CREATED" -eq 0 ] || "$AWS_BIN" s3api delete-bucket --region "$REGION" --bucket "$DECOY_BUCKET" >/dev/null 2>&1 || failed=1
    [ "$TARGET_CREATED" -eq 0 ] || "$AWS_BIN" s3api delete-bucket --region "$REGION" --bucket "$TARGET_BUCKET" >/dev/null 2>&1 || failed=1
    unlink "$MANIFEST" 2>/dev/null || true
    unlink "$FINISH_SIGNAL" 2>/dev/null || true
    case "$WORK" in /tmp/agentjail-aws-sts-provision.*) rm -r "$WORK" 2>/dev/null || failed=1 ;; esac
    [ "$failed" -eq 0 ] || cleanup_status=fail
    if [ "$cleanup_status" != pass ] || [ "$DIRECT_DENIED_ABSENT" != true ]; then
        overall_status=fail
    fi
    write_cleanup_status "$overall_status" "$cleanup_status"
    if [ "$cleanup_status" = pass ]; then
        printf 'CLEANUP  PASS — exact temporary AWS resources removed\n'
    else
        printf 'CLEANUP  FAIL — inspect exact resources for run %s\n' "$RUN_ID" >&2
    fi
    [ "$overall_status" = pass ]
}
trap 'cleanup || true' EXIT
trap 'exit 130' INT TERM

create_bucket() {
    local name="$1"
    if [ "$REGION" = us-east-1 ]; then
        "$AWS_BIN" s3api create-bucket --region "$REGION" --bucket "$name" >/dev/null
    else
        "$AWS_BIN" s3api create-bucket --region "$REGION" --bucket "$name" --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
    fi
}

harden_bucket() {
    local name="$1"
    "$AWS_BIN" s3api put-public-access-block --region "$REGION" --bucket "$name" --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' >/dev/null
    "$AWS_BIN" s3api put-bucket-encryption --region "$REGION" --bucket "$name" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' >/dev/null
}

CALLER="$($AWS_BIN sts get-caller-identity --query '[Account,Arn]' --output text 2>"$WORK/caller.stderr")" || die "configured profile cannot call sts:GetCallerIdentity"
IFS=$'\t' read -r ACCOUNT CALLER_ARN <<<"$CALLER"
case "$ACCOUNT" in ''|*[!0-9]*) die "AWS account was not numeric" ;; esac
[ -n "$CALLER_ARN" ] || die "AWS caller ARN was empty"
pass "authorized source identity is available"

create_bucket "$TARGET_BUCKET"; TARGET_CREATED=1; harden_bucket "$TARGET_BUCKET"
create_bucket "$DECOY_BUCKET"; DECOY_CREATED=1; harden_bucket "$DECOY_BUCKET"
printf 'AgentJail live STS proof; no secret material.\n' >"$WORK/marker.txt"
"$AWS_BIN" s3api put-object --region "$REGION" --bucket "$TARGET_BUCKET" --key "$MARKER_KEY" --body "$WORK/marker.txt" >/dev/null
MARKER_CREATED=1
pass "private target and decoy buckets are ready"

BOOTSTRAP_ARN="$($AWS_BIN iam create-user --user-name "$BOOTSTRAP_USER" --query 'User.Arn' --output text)"; BOOTSTRAP_USER_CREATED=1
BOOT_KEY_LINE="$($AWS_BIN iam create-access-key --user-name "$BOOTSTRAP_USER" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)"
IFS=$'\t' read -r BOOT_ACCESS BOOT_SECRET <<<"$BOOT_KEY_LINE"; BOOTSTRAP_KEY_CREATED=1
[ -n "$BOOT_ACCESS" ] && [ -n "$BOOT_SECRET" ] || die "bootstrap key was incomplete"
TRUST_POLICY="$(printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:PrincipalArn":"%s"}}}]}' "$ACCOUNT" "$BOOTSTRAP_ARN")"
ROLE_ARN="$($AWS_BIN iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document "$TRUST_POLICY" --description 'Temporary AgentJail STS test role' --max-session-duration 3600 --query 'Role.Arn' --output text)"; ROLE_CREATED=1
ROLE_POLICY="$(printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListBucket","s3:GetBucketLocation"],"Resource":"arn:aws:s3:::%s"}]}' "$TARGET_BUCKET")"
"$AWS_BIN" iam put-role-policy --role-name "$ROLE_NAME" --policy-name "$ROLE_POLICY_NAME" --policy-document "$ROLE_POLICY"; ROLE_POLICY_CREATED=1
ASSUME_POLICY="$(printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"%s"}]}' "$ROLE_ARN")"
"$AWS_BIN" iam put-user-policy --user-name "$BOOTSTRAP_USER" --policy-name "$BOOTSTRAP_POLICY" --policy-document "$ASSUME_POLICY"; BOOTSTRAP_POLICY_CREATED=1

SESSION_LINE=""
for _ in $(seq 1 30); do
    if SESSION_LINE="$(env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE AWS_ACCESS_KEY_ID="$BOOT_ACCESS" AWS_SECRET_ACCESS_KEY="$BOOT_SECRET" AWS_EC2_METADATA_DISABLED=true "$AWS_BIN" sts assume-role --role-arn "$ROLE_ARN" --role-session-name agentjail-e2e --duration-seconds 3600 --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken,Expiration]' --output text 2>"$WORK/assume.stderr")"; then break; fi
    sleep 2
done
IFS=$'\t' read -r TEMP_ACCESS TEMP_SECRET TEMP_TOKEN TEMP_EXPIRATION <<<"$SESSION_LINE"
case "$TEMP_ACCESS" in ASIA*) ;; *) die "AssumeRole did not return an STS key" ;; esac
[ -n "$TEMP_SECRET" ] && [ -n "$TEMP_TOKEN" ] && [ -n "$TEMP_EXPIRATION" ] || die "AssumeRole returned incomplete credentials"
hash_value() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }
ACCESS_SHA="$(hash_value "$TEMP_ACCESS")"; SECRET_SHA="$(hash_value "$TEMP_SECRET")"; SESSION_SHA="$(hash_value "$TEMP_TOKEN")"

# Metadata expands locally; credential values travel only over encrypted stdin.
# shellcheck disable=SC2029
printf '%s\0%s\0%s\0%s\0' "$TEMP_ACCESS" "$TEMP_SECRET" "$TEMP_TOKEN" "$REGION" \
| ssh "${ssh_opts[@]}" "admin@$GUEST_IP" "AGENTJAIL_IMPORT_NAME=$(printf %q "$CREDENTIAL_NAME") AGENTJAIL_IMPORT_ACCOUNT=$(printf %q "$ACCOUNT") /usr/bin/python3 /tmp/aws-sts-guest-import.py" \
| grep -qx 'guest_import=ok' || die "guest broker import failed"
pass "one-hour STS role was imported directly into the Tart guest broker"

"$AWS_BIN" iam delete-user-policy --user-name "$BOOTSTRAP_USER" --policy-name "$BOOTSTRAP_POLICY"; BOOTSTRAP_POLICY_CREATED=0
"$AWS_BIN" iam delete-access-key --user-name "$BOOTSTRAP_USER" --access-key-id "$BOOT_ACCESS"
"$AWS_BIN" iam delete-user --user-name "$BOOTSTRAP_USER"
BOOTSTRAP_KEY_CREATED=0; BOOTSTRAP_USER_CREATED=0
unset BOOT_ACCESS BOOT_SECRET BOOT_KEY_LINE SESSION_LINE TEMP_ACCESS TEMP_SECRET TEMP_TOKEN
pass "disposable bootstrap user and access key were deleted"

MARKER_SHA="$(hash_value "$MARKER_KEY")"
python3 - "$MANIFEST" "$RUN_ID" "$ACCOUNT" "$REGION" "$TARGET_BUCKET" "$DECOY_BUCKET" "$ROLE_NAME" "$ROLE_POLICY_NAME" "$CREDENTIAL_NAME" "$MARKER_SHA" "$TEMP_EXPIRATION" "$ACCESS_SHA" "$SECRET_SHA" "$SESSION_SHA" <<'PY'
import json, os, sys
keys = ["run_id","account","region","target_bucket","decoy_bucket","role_name","role_policy_name","credential_name","marker_key_sha256","expires_at"]
data = {"schema_version": 3, "status": "ready"}
data.update(dict(zip(keys, sys.argv[2:12])))
data["credential_fingerprints"] = dict(zip(["access_key_sha256","secret_key_sha256","session_token_sha256"], sys.argv[12:15]))
with open(sys.argv[1], "x", encoding="utf-8") as handle:
    json.dump(data, handle, sort_keys=True); handle.write("\n")
os.chmod(sys.argv[1], 0o600)
PY
printf 'READY  run_id=%s handoff=%s\n' "$RUN_ID" "$MANIFEST"
printf 'WAIT   leave this terminal open; cleanup is automatic after validation or 45 minutes\n'
for _ in $(seq 1 2700); do [ ! -e "$FINISH_SIGNAL" ] || break; sleep 1; done
[ -e "$FINISH_SIGNAL" ] && printf 'FINISH received from harness\n' || printf 'TIMEOUT reached; cleaning automatically\n'
object_is_absent() {
    local key="$1" error_file="$2"
    if "$AWS_BIN" s3api head-object --region "$REGION" --bucket "$TARGET_BUCKET" --key "$key" >/dev/null 2>"$error_file"; then
        return 1
    fi
    grep -Eq '\((404|NoSuchKey|NotFound)\)|Not Found' "$error_file"
}
if [ -e "$FINISH_SIGNAL" ]; then
    object_is_absent agentjail-direct-must-be-denied "$WORK/direct-head.stderr" && DIRECT_DENIED_ABSENT=true || DIRECT_DENIED_ABSENT=false
    [ "$DIRECT_DENIED_ABSENT" = true ] && pass "AWS confirms the denied direct write left no object" || printf 'FAIL  denied direct object exists or could not be verified\n' >&2
fi
cleanup || die "AWS postconditions or exact resource cleanup did not pass"
trap - EXIT INT TERM
