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
    for name in aws/testbed kube/testbed github/testbed kube/unsafe-exec kube/unsafe-file; do
        "$AJ" credential remove "$name" >/dev/null 2>&1 || true
    done
    rm -f "$PROJECT/aws" /tmp/agentjail-unsafe-tool \
        /tmp/agentjail-aws-config-list
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

KUBECONFIG_BODY='apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:65535
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
'

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
test "$(kubectl config current-context)" = agentjail-test
test "$(kubectl config view --raw --minify -o "jsonpath={.users[0].user.token}" | hash_stream)" = __KUBE_FINGERPRINT__
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
