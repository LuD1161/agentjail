#!/usr/bin/env bash
set -u
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

AJ="$HOME/.agentjail/bin/agentjail"
INPUT=/tmp/agentjail-aws-sts-handoff.json
PROOF=/tmp/testbed/results/aws-sts-direct.proof.json
ok(){ scn_ok "$1"; }; bad(){ scn_fail "$1"; }
scn_init aws-sts-direct "real AWS CLI uses only the guest brokered STS session"
if ! jq -e '.schema_version==3 and .status=="ready"' "$INPUT" >/dev/null 2>&1; then bad "versioned AWS handoff is ready"; scn_finish; exit 1; fi
credential=$(jq -r .credential_name "$INPUT"); account=$(jq -r .account "$INPUT")
role=$(jq -r .role_name "$INPUT"); region=$(jq -r .region "$INPUT")
target=$(jq -r .target_bucket "$INPUT"); decoy=$(jq -r .decoy_bucket "$INPUT"); marker_sha=$(jq -r .marker_key_sha256 "$INPUT")
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
brokered(){ env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN AWS_EC2_METADATA_DISABLED=true AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null "$AJ" run --no-git-ssh --credential "$credential" -- aws --region "$region" --ca-bundle /tmp/agentjail-aws-ca-bundle.crt --no-cli-pager "$@"; }

if [ ! -e "$HOME/.aws/credentials" ] && [ ! -e "$HOME/.aws/config" ]; then ok "guest has no ambient shared AWS configuration"; else bad "guest has no ambient shared AWS configuration"; fi
if env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN AWS_EC2_METADATA_DISABLED=true AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null aws --region "$region" --ca-bundle /tmp/agentjail-aws-ca-bundle.crt sts get-caller-identity >/tmp/aws-direct-outside.out 2>/tmp/aws-direct-outside.err; then bad "AWS identity is unavailable outside the broker session"; else ok "AWS identity is unavailable outside the broker session"; fi

if brokered sts get-caller-identity --output json >/tmp/aws-direct-identity.json 2>/tmp/aws-direct-identity.err \
 && jq -e --arg account "$account" --arg role "$role" '.Account==$account and (.Arn|startswith("arn:aws:sts::"+$account+":assumed-role/"+$role+"/"))' /tmp/aws-direct-identity.json >/dev/null; then ok "brokered identity is the expected assumed role"; else bad "brokered identity is the expected assumed role"; fi
if brokered s3api list-objects-v2 --bucket "$target" --output json >/tmp/aws-direct-target.json 2>/tmp/aws-direct-target.err \
 && python3 - "$marker_sha" /tmp/aws-direct-target.json <<'PY'
import hashlib,json,sys
with open(sys.argv[2]) as handle: keys=[row["Key"] for row in json.load(handle).get("Contents", [])]
raise SystemExit(0 if any(hashlib.sha256(key.encode()).hexdigest()==sys.argv[1] for key in keys) else 1)
PY
then ok "target list contains the unknown marker fingerprint"; else bad "target list contains the unknown marker fingerprint"; fi
if brokered s3api list-objects-v2 --bucket "$decoy" --max-items 1 >/tmp/aws-direct-decoy.out 2>/tmp/aws-direct-decoy.err; then bad "decoy bucket list is denied"; elif grep -q 'AccessDenied' /tmp/aws-direct-decoy.err; then ok "decoy bucket list is denied"; else bad "decoy bucket list is denied"; fi
printf 'must not be stored\n' >/tmp/aws-direct-denied-body
if brokered s3api put-object --bucket "$target" --key agentjail-direct-must-be-denied --body /tmp/aws-direct-denied-body >/tmp/aws-direct-write.out 2>/tmp/aws-direct-write.err; then bad "target write is denied"; elif grep -q 'AccessDenied' /tmp/aws-direct-write.err; then ok "target write is denied"; else bad "target write is denied"; fi
if python3 - "$INPUT" /tmp/aws-direct-identity.json /tmp/aws-direct-identity.err /tmp/aws-direct-target.json /tmp/aws-direct-target.err /tmp/aws-direct-decoy.out /tmp/aws-direct-decoy.err /tmp/aws-direct-write.out /tmp/aws-direct-write.err /tmp/aws-direct-outside.out /tmp/aws-direct-outside.err <<'PY'
import hashlib,json,re,sys
with open(sys.argv[1]) as f: expected=set(json.load(f)["credential_fingerprints"].values())
pattern=re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
for path in sys.argv[2:]:
 try: data=open(path,"rb").read()
 except OSError: continue
 if any(hashlib.sha256(v).hexdigest() in expected for v in pattern.findall(data)): raise SystemExit(1)
PY
then ok "direct command outputs contain no exact STS credential"; else bad "direct command outputs contain no exact STS credential"; fi
jq -n --argjson identity "$(jq -c '{Account,Arn}' /tmp/aws-direct-identity.json 2>/dev/null || printf '{}')" --argjson keys "$(jq -c '[.Contents[]?.Key]' /tmp/aws-direct-target.json 2>/dev/null || printf '[]')" --arg target "$target" '{identity:$identity,target_bucket:$target,target_keys:$keys,decoy_error_code:"AccessDenied",write_error_code:"AccessDenied"}' >"$PROOF"
chmod 0600 "$PROOF"
scn_finish
