#!/usr/bin/env bash
# credentialed-cli.sh — installed-path gate for static broker credentials
# delivered to real AWS CLI, kubectl, and GitHub CLI processes.
set -u

AJ="$HOME/.agentjail/bin/agentjail"
PROJECT="$HOME/work/demo"
PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout  >/dev/null 2>&1 || timeout(){ shift; "$@"; }

hash_stream() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | awk '{print $1}'
}

cleanup() {
    if [ -n "${STUB_PID:-}" ]; then
        kill "$STUB_PID" >/dev/null 2>&1 || true
        wait "$STUB_PID" 2>/dev/null || true
    fi
    for name in aws/testbed kube/testbed github/testbed kube/unsafe-exec kube/unsafe-file; do
        "$AJ" credential remove "$name" >/dev/null 2>&1 || true
    done
    rm -f "$PROJECT/aws" /tmp/agentjail-unsafe-tool \
        /tmp/agentjail-aws-config-list /tmp/agentjail-aws-identity.json \
        /tmp/agentjail-kube-version.json /tmp/agentjail-credential-stub.js \
        /tmp/agentjail-credential-stub.log /tmp/agentjail-credential-stub.port
    rm -f "$HOME/.aws/credentials" "$HOME/.kube/config" "$HOME/.config/gh/hosts.yml"
}
trap cleanup EXIT

cd "$PROJECT" || { bad "no project dir ($PROJECT)"; exit 1; }

for tool in aws kubectl gh; do
    command -v "$tool" >/dev/null 2>&1 && ok "$tool installed at $(command -v "$tool")" || bad "$tool is not installed"
done
echo "INFO  $(aws --version 2>&1)"
echo "INFO  $(kubectl version --client 2>&1 | head -1)"
echo "INFO  $(gh --version 2>&1 | head -1)"

mkdir -p "$HOME/.aws" "$HOME/.kube" "$HOME/.config/gh"
printf 'HOST_AWS_SECRET_SENTINEL\n' > "$HOME/.aws/credentials"
printf 'HOST_KUBE_SECRET_SENTINEL\n' > "$HOME/.kube/config"
printf 'HOST_GH_SECRET_SENTINEL\n' > "$HOME/.config/gh/hosts.yml"

AWS_ACCESS_FINGERPRINT=$(printf %s AKIATESTBED000000001 | hash_stream)
AWS_SECRET_FINGERPRINT=$(printf %s testbed-secret-not-real | hash_stream)
AWS_SESSION_FINGERPRINT=$(printf %s testbed-session-not-real | hash_stream)
KUBE_FINGERPRINT=$(printf %s kube-test-token-not-real | hash_stream)
GH_FINGERPRINT=$(printf %s ghp_testbed_not_real | hash_stream)

# Validate actual provider protocols rather than only asking each CLI where it
# found its credential. The stub recomputes AWS SigV4 from the expected secret
# and accepts the Kubernetes request only with the expected bearer token.
# See GOTCHAS.md #59.
cat > /tmp/agentjail-credential-stub.js <<'NODE'
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');

const accessKey = 'AKIATESTBED000000001';
const secretKey = 'testbed-secret-not-real';
const sessionToken = 'testbed-session-not-real';
const kubeToken = 'kube-test-token-not-real';
const log = label => fs.appendFileSync('/tmp/agentjail-credential-stub.log', label + '\n');
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const hmac = (key, value) => crypto.createHmac('sha256', key).update(value).digest();
const xml = `<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/agentjail-test</Arn><UserId>AGENTJAILTEST</UserId><Account>123456789012</Account></GetCallerIdentityResult>
  <ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`;

function verifySigV4(req, body) {
  const auth = req.headers.authorization || '';
  const match = auth.match(/^AWS4-HMAC-SHA256 Credential=([^/]+)\/([^,]+), SignedHeaders=([^,]+), Signature=([0-9a-f]+)$/);
  if (!match || match[1] !== accessKey || req.headers['x-amz-security-token'] !== sessionToken) return false;
  const scope = match[2];
  const parts = scope.split('/');
  if (parts.length !== 4 || parts[2] !== 'sts' || parts[3] !== 'aws4_request') return false;
  const signedHeaders = match[3];
  const canonicalHeaders = signedHeaders.split(';').map(name => {
    const value = String(req.headers[name] || '').trim().replace(/\s+/g, ' ');
    return `${name}:${value}\n`;
  }).join('');
  const url = new URL(req.url, `http://${req.headers.host}`);
  const canonicalRequest = [req.method, url.pathname, url.searchParams.toString(), canonicalHeaders, signedHeaders, sha256(body)].join('\n');
  const amzDate = req.headers['x-amz-date'];
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonicalRequest)].join('\n');
  const dateKey = hmac(Buffer.from('AWS4' + secretKey), parts[0]);
  const regionKey = hmac(dateKey, parts[1]);
  const serviceKey = hmac(regionKey, parts[2]);
  const signingKey = hmac(serviceKey, 'aws4_request');
  const expected = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  return expected.length === match[4].length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(match[4]));
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    if (req.url === '/version') {
      if (req.headers.authorization !== `Bearer ${kubeToken}`) {
        res.writeHead(401); res.end('unauthorized'); return;
      }
      log('KUBE_BEARER_OK');
      res.writeHead(200, {'content-type': 'application/json'});
      res.end(JSON.stringify({major: '1', minor: '30', gitVersion: 'v1.30.0'}));
      return;
    }
    if (!verifySigV4(req, body)) {
      res.writeHead(403, {'content-type': 'text/xml'}); res.end('<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>'); return;
    }
    log('AWS_SIGV4_OK');
    res.writeHead(200, {'content-type': 'text/xml'}); res.end(xml);
  });
});
server.listen(0, '127.0.0.1', () => {
  fs.writeFileSync('/tmp/agentjail-credential-stub.port', String(server.address().port));
});
NODE
rm -f /tmp/agentjail-credential-stub.log /tmp/agentjail-credential-stub.port
node /tmp/agentjail-credential-stub.js >/dev/null 2>&1 &
STUB_PID=$!
for _ in $(seq 1 50); do
    [ -s /tmp/agentjail-credential-stub.port ] && break
    sleep 0.1
done
if [ ! -s /tmp/agentjail-credential-stub.port ]; then
    bad "local credential protocol stub failed to start"
    exit 1
fi
STUB_PORT=$(cat /tmp/agentjail-credential-stub.port)
STUB_URL="http://127.0.0.1:$STUB_PORT"

AWS_ACCESS_KEY_ID=AKIATESTBED000000001 \
AWS_SECRET_ACCESS_KEY=testbed-secret-not-real \
AWS_SESSION_TOKEN=testbed-session-not-real \
AWS_DEFAULT_REGION=us-west-2 \
    "$AJ" credential set aws/testbed --tool aws --from-current-env >/dev/null \
    && ok "AWS static credential imported through user-facing CLI" \
    || bad "AWS static credential import failed"

printf '#!/bin/sh\nexit 99\n' > "$PROJECT/aws"
chmod 0700 "$PROJECT/aws"
if PATH="$PROJECT:$PATH" "$AJ" run --no-git-ssh \
    --credential=aws=aws/testbed -- true >/tmp/agentjail-unsafe-tool 2>&1; then
    bad "workspace-controlled AWS CLI lookalike was allowed"
elif grep -q 'agent-writable path' /tmp/agentjail-unsafe-tool; then
    ok "workspace-controlled AWS CLI lookalike rejected before credential injection"
else
    bad "workspace-controlled AWS CLI lookalike failed for the wrong reason"
fi
rm -f "$PROJECT/aws" /tmp/agentjail-unsafe-tool

KUBECONFIG_BODY="apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: $STUB_URL
users:
- name: test
  user:
    token: kube-test-token-not-real
contexts:
- name: agentjail-test
  context:
    cluster: test
    user: test
current-context: agentjail-test
"

KUBECONFIG_EXEC='apiVersion: v1
kind: Config
clusters:
- name: test
  cluster: {server: https://127.0.0.1:65535}
users:
- name: test
  user:
    exec:
      command: credential-stealer
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Never
contexts:
- name: test
  context: {cluster: test, user: test}
current-context: test
'
if printf '%s' "$KUBECONFIG_EXEC" \
    | "$AJ" credential set kube/unsafe-exec --tool kubectl --from-stdin >/dev/null 2>&1; then
    bad "kubeconfig exec credential plugin was accepted"
else
    ok "kubeconfig exec credential plugin rejected before storage"
fi

KUBECONFIG_FILE_REF='apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:65535
    certificate-authority: /home/agent/.kube/ca.crt
users:
- name: test
  user:
    tokenFile: /home/agent/.kube/token
contexts:
- name: test
  context: {cluster: test, user: test}
current-context: test
'
if printf '%s' "$KUBECONFIG_FILE_REF" \
    | "$AJ" credential set kube/unsafe-file --tool kubectl --from-stdin >/dev/null 2>&1; then
    bad "kubeconfig host credential file references were accepted"
else
    ok "kubeconfig host credential file references rejected before storage"
fi

printf '%s' "$KUBECONFIG_BODY" \
    | "$AJ" credential set kube/testbed --tool kubectl --from-stdin >/dev/null \
    && ok "kubeconfig imported through stdin without argv exposure" \
    || bad "kubeconfig import failed"

GH_TOKEN=ghp_testbed_not_real \
    "$AJ" credential set github/testbed --tool gh --from-current-env >/dev/null \
    && ok "GitHub token imported through user-facing CLI" \
    || bad "GitHub token import failed"

CREDENTIAL_LIST=$("$AJ" credential list 2>&1)
if printf '%s\n' "$CREDENTIAL_LIST" | grep -q 'aws/testbed' \
    && printf '%s\n' "$CREDENTIAL_LIST" | grep -q 'kube/testbed' \
    && printf '%s\n' "$CREDENTIAL_LIST" | grep -q 'github/testbed' \
    && ! printf '%s\n' "$CREDENTIAL_LIST" | grep -Eq 'testbed-secret|testbed-session|kube-test-token|ghp_'; then
    ok "credential list returns selected names without values"
else
    bad "credential list omitted a name or exposed a value"
fi
if printf '%s\n' "$CREDENTIAL_LIST" | grep -Eq 'unsafe-exec|unsafe-file'; then
    bad "rejected kubeconfig was persisted"
else
    ok "rejected kubeconfigs were not persisted"
fi

CHECK='set -eu
hash_stream() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | awk "{print \$1}"
}
aws configure list > /tmp/agentjail-aws-config-list
grep -Eq "access_key[[:space:]].*[[:space:]]env" /tmp/agentjail-aws-config-list
grep -Eq "secret_key[[:space:]].*[[:space:]]env" /tmp/agentjail-aws-config-list
test "$(printf %s "$AWS_ACCESS_KEY_ID" | hash_stream)" = __AWS_ACCESS_FINGERPRINT__
test "$(printf %s "$AWS_SECRET_ACCESS_KEY" | hash_stream)" = __AWS_SECRET_FINGERPRINT__
test "$(printf %s "$AWS_SESSION_TOKEN" | hash_stream)" = __AWS_SESSION_FINGERPRINT__
test "$AWS_DEFAULT_REGION" = us-west-2
test "$AWS_EC2_METADATA_DISABLED" = true
aws sts get-caller-identity --endpoint-url "$AGENTJAIL_TEST_STUB_URL" --no-cli-pager > /tmp/agentjail-aws-identity.json
grep -q 123456789012 /tmp/agentjail-aws-identity.json
test "$(kubectl config current-context)" = agentjail-test
test "$(kubectl config view --raw --minify -o "jsonpath={.users[0].user.token}" | hash_stream)" = __KUBE_FINGERPRINT__
kubectl get --raw /version > /tmp/agentjail-kube-version.json
grep -q v1.30.0 /tmp/agentjail-kube-version.json
test "$(stat -c %a "$KUBECONFIG" 2>/dev/null || stat -f %Lp "$KUBECONFIG")" = 600
case "$KUBECONFIG" in /tmp/agentjail-credentials-*/kubeconfig) ;; *) exit 21 ;; esac
case "$(command -v aws)" in /tmp/agentjail-credentials-*/bin/aws) ;; *) exit 22 ;; esac
case "$(command -v kubectl)" in /tmp/agentjail-credentials-*/bin/kubectl) ;; *) exit 23 ;; esac
case "$(command -v gh)" in /tmp/agentjail-credentials-*/bin/gh) ;; *) exit 24 ;; esac
case "$GH_CONFIG_DIR" in /tmp/agentjail-credentials-*/gh-config) ;; *) exit 25 ;; esac
test "$(stat -c %a "$GH_CONFIG_DIR" 2>/dev/null || stat -f %Lp "$GH_CONFIG_DIR")" = 700
test "$AGENTJAIL_CREDENTIAL_TOOLS" = aws,kubectl,gh
test "$(gh auth token | tr -d "\\n" | hash_stream)" = __GH_FINGERPRINT__
! cat "$HOME/.aws/credentials" 2>/dev/null | grep -q HOST_AWS_SECRET_SENTINEL
! cat "$HOME/.kube/config" 2>/dev/null | grep -q HOST_KUBE_SECRET_SENTINEL
! cat "$HOME/.config/gh/hosts.yml" 2>/dev/null | grep -q HOST_GH_SECRET_SENTINEL
'
CHECK=${CHECK/__GH_FINGERPRINT__/$GH_FINGERPRINT}
CHECK=${CHECK/__AWS_ACCESS_FINGERPRINT__/$AWS_ACCESS_FINGERPRINT}
CHECK=${CHECK/__AWS_SECRET_FINGERPRINT__/$AWS_SECRET_FINGERPRINT}
CHECK=${CHECK/__AWS_SESSION_FINGERPRINT__/$AWS_SESSION_FINGERPRINT}
CHECK=${CHECK/__KUBE_FINGERPRINT__/$KUBE_FINGERPRINT}

# This scenario tests broker credentials, not the seed project's default Git SSH
# bootstrap. See ADR 0126-session-ssh-bootstrap.
OUT=$(AWS_ACCESS_KEY_ID=AMBIENT_AWS_ACCESS_NOT_SELECTED \
    AWS_SECRET_ACCESS_KEY=AMBIENT_AWS_SECRET_NOT_SELECTED \
    AWS_SESSION_TOKEN=AMBIENT_AWS_SESSION_NOT_SELECTED \
    AWS_DEFAULT_REGION=AMBIENT_AWS_REGION_NOT_SELECTED \
    GH_TOKEN=AMBIENT_GH_NOT_SELECTED \
    KUBECONFIG="$HOME/.kube/config" \
    AGENTJAIL_TEST_STUB_URL="$STUB_URL" \
    timeout 60 "$AJ" run \
    --no-git-ssh \
    --credential=aws=aws/testbed \
    --credential=kubectl=kube/testbed \
    --credential=gh=github/testbed \
    -- bash -c "$CHECK" 2>&1)
RC=$?
if printf '%s\n' "$OUT" | grep -Eq 'AKIATESTBED000000001|testbed-secret-not-real|testbed-session-not-real|kube-test-token-not-real|ghp_testbed_not_real|AMBIENT_(AWS|GH)'; then
    bad "credential value appeared in shield output"
else
    ok "shield output contains no selected or ambient credential values"
fi
printf '%s\n' "$OUT" | sed -E 's/(AKIA|ghp_|testbed-secret|testbed-session|kube-test-token)[^[:space:]]*/[REDACTED]/g'
if [ "$RC" = 0 ]; then
    ok "one shielded session used AWS env, kubeconfig file, and GH env credentials"
else
    bad "credentialed CLI session failed (rc=$RC)"
fi

if grep -qx AWS_SIGV4_OK /tmp/agentjail-credential-stub.log 2>/dev/null; then
    ok "AWS CLI made a provider request with a valid secret-derived SigV4 signature"
else
    bad "AWS CLI did not complete a valid SigV4-authenticated provider request"
fi
if grep -qx KUBE_BEARER_OK /tmp/agentjail-credential-stub.log 2>/dev/null; then
    ok "kubectl made an API request with the broker-delivered bearer token"
else
    bad "kubectl did not complete a bearer-authenticated API request"
fi

printf '%s\n' "$OUT" | grep -q 'aws ready with broker credential "aws/testbed"' \
    && ok "agent readiness notice names AWS credential without its value" \
    || bad "AWS readiness notice missing"
printf '%s\n' "$OUT" | grep -q 'kubectl ready with broker credential "kube/testbed"' \
    && ok "agent readiness notice names Kubernetes credential without its value" \
    || bad "Kubernetes readiness notice missing"
printf '%s\n' "$OUT" | grep -q 'gh ready with broker credential "github/testbed"' \
    && ok "agent readiness notice names GitHub credential without its value" \
    || bad "GitHub readiness notice missing"

if find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name 'agentjail-credentials-*' -print -quit | grep -q .; then
    bad "credential session directory remained after normal exit"
else
    ok "credential session directory removed after normal exit"
fi

if grep -R -a -E 'AKIATESTBED000000001|testbed-secret-not-real|testbed-session-not-real|kube-test-token-not-real|ghp_testbed_not_real|AMBIENT_(AWS|GH)' "$HOME/.agentjail" >/dev/null 2>&1; then
    bad "credential value persisted in AgentJail state or logs"
else
    ok "AgentJail state and logs contain no plaintext credential values"
fi

for name in aws/testbed kube/testbed github/testbed; do
    "$AJ" credential remove "$name" >/dev/null 2>&1 || bad "credential remove failed for $name"
done
POST_REMOVE_LIST=$("$AJ" credential list 2>&1)
if printf '%s\n' "$POST_REMOVE_LIST" | grep -Eq 'aws/testbed|kube/testbed|github/testbed'; then
    bad "credential remove left a selected broker entry"
else
    ok "credential remove deletes all selected broker entries"
fi

echo "=== RESULT: $PASS pass, $FAIL fail ==="
[ "$FAIL" = 0 ]
