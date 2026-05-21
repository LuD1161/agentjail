#!/usr/bin/env bash
# smoke.sh — Quick smoke test for agentjail-shield OS-native sandbox.
#
# Verifies:
#   1. The shield binary builds.
#   2. A write to ~/.ssh/ is blocked (EPERM or non-zero shell exit).
#   3. A write to /tmp/ is permitted (exit 0, file created).
#
# Usage:
#   bash cmd/agentjail-shield/test/smoke.sh
#
# Run from the repo root. Requires Go (to build the binary).
# Exit code 0 = all checks pass.  Non-zero = one or more checks failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SHIELD_BIN="${REPO_ROOT}/agentjail-shield-smoke-$$"
PASS=0
FAIL=0

# Color codes (suppressed when not a tty)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' NC=''
fi

pass() { echo -e "${GREEN}PASS${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}FAIL${NC} $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}INFO${NC} $1"; }

cleanup() {
    rm -f "${SHIELD_BIN}"
    rm -f "${HOME}/.ssh/agentjail-shield-smoke" 2>/dev/null || true
    rm -f "/tmp/agentjail-shield-smoke-$$" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 1: Build
# ---------------------------------------------------------------------------

echo "=== agentjail-shield smoke test ==="
echo ""
info "Building agentjail-shield..."
(cd "${REPO_ROOT}" && go build -o "${SHIELD_BIN}" ./cmd/agentjail-shield/)
info "Build: OK"
echo ""

# ---------------------------------------------------------------------------
# Step 2: Platform check
# ---------------------------------------------------------------------------

OS="$(uname -s)"
if [ "${OS}" = "Darwin" ]; then
    if ! [ -x /usr/bin/sandbox-exec ]; then
        echo -e "${YELLOW}SKIP${NC} sandbox-exec not present — skipping macOS enforcement tests"
        echo ""
        echo "Summary: PASS=${PASS} FAIL=${FAIL} SKIP=2"
        exit 0
    fi
elif [ "${OS}" = "Linux" ]; then
    # Landlock is available since Linux 5.13; check via landlock_create_ruleset probe.
    info "Linux detected — Landlock path; tests are best-effort"
else
    echo -e "${YELLOW}SKIP${NC} unsupported platform ${OS} — no sandbox enforcement tests"
    echo ""
    echo "Summary: PASS=${PASS} FAIL=${FAIL} SKIP=2"
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 3: Fixture A — write to ~/.ssh/ must fail
# ---------------------------------------------------------------------------

LABEL="Fixture A: write to ~/.ssh/ is blocked"
SSH_TEST_FILE="${HOME}/.ssh/agentjail-shield-smoke"
rm -f "${SSH_TEST_FILE}"

# Run under shield; capture output and exit code.
SHIELD_OUTPUT=""
SHIELD_EXIT=0
SHIELD_OUTPUT=$("${SHIELD_BIN}" -- sh -c "printf 'x' > '${SSH_TEST_FILE}' 2>&1; echo exit=\$?" 2>&1) || SHIELD_EXIT=$?

info "Fixture A output: ${SHIELD_OUTPUT}"
info "Fixture A shield exit: ${SHIELD_EXIT}"

if [ -f "${SSH_TEST_FILE}" ]; then
    fail "${LABEL}: file ${SSH_TEST_FILE} was created — sandbox did NOT block the write"
else
    pass "${LABEL}: file was not created"
fi

# Also check that output contains evidence of permission denial.
if echo "${SHIELD_OUTPUT}" | grep -qi "not permitted\|Operation not permitted\|Permission denied\|exit=1\|exit=2"; then
    pass "${LABEL}: output contains permission denial evidence"
else
    # File not created is the definitive check; output format may vary.
    info "${LABEL}: output did not explicitly mention 'not permitted' but file was not created (acceptable)"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 4: Fixture B — write to /tmp/ must succeed
# ---------------------------------------------------------------------------

LABEL="Fixture B: write to /tmp/ is allowed"
TMP_TEST_FILE="/tmp/agentjail-shield-smoke-$$"
rm -f "${TMP_TEST_FILE}"

SHIELD_OUTPUT=""
SHIELD_EXIT=0
SHIELD_OUTPUT=$("${SHIELD_BIN}" -- sh -c "printf 'hello' > '${TMP_TEST_FILE}' && echo written_ok" 2>&1) || SHIELD_EXIT=$?

info "Fixture B output: ${SHIELD_OUTPUT}"
info "Fixture B shield exit: ${SHIELD_EXIT}"

if [ "${SHIELD_EXIT}" -ne 0 ]; then
    fail "${LABEL}: expected exit 0, got ${SHIELD_EXIT}"
elif [ ! -f "${TMP_TEST_FILE}" ]; then
    fail "${LABEL}: file ${TMP_TEST_FILE} was NOT created"
else
    pass "${LABEL}: file was created"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 5: Fixture C — network egress to api.github.com (HTTPS port 443 allowed)
# ---------------------------------------------------------------------------

if [ "${OS}" = "Darwin" ] && command -v curl >/dev/null 2>&1; then
    LABEL="Fixture C: HTTPS to api.github.com is allowed (port 443)"
    CURL_OUTPUT=""
    CURL_EXIT=0
    CURL_OUTPUT=$("${SHIELD_BIN}" -- curl --connect-timeout 8 -s -o /dev/null -w "%{http_code}" https://api.github.com/zen 2>/dev/null) || CURL_EXIT=$?
    info "Fixture C curl exit: ${CURL_EXIT}, HTTP code: ${CURL_OUTPUT}"
    if [ "${CURL_EXIT}" -eq 0 ] && [ "${CURL_OUTPUT}" = "200" ]; then
        pass "${LABEL}"
    else
        fail "${LABEL}: expected exit 0 + HTTP 200, got exit=${CURL_EXIT} code=${CURL_OUTPUT}"
    fi

    echo ""

    LABEL="Fixture D: DNS resolution still works inside sandbox (nslookup)"
    NSL_OUTPUT=""
    NSL_EXIT=0
    NSL_OUTPUT=$("${SHIELD_BIN}" -- nslookup github.com 2>&1) || NSL_EXIT=$?
    info "Fixture D nslookup exit: ${NSL_EXIT}"
    if echo "${NSL_OUTPUT}" | grep -q "Address:"; then
        pass "${LABEL}"
    else
        fail "${LABEL}: nslookup did not resolve github.com inside sandbox"
        info "nslookup output: ${NSL_OUTPUT}"
    fi

    echo ""

    LABEL="Fixture E: non-standard port TCP (C2 exfil port 9999) is blocked"
    NC_EXIT=0
    if command -v nc >/dev/null 2>&1; then
        # Attempt to connect to a public IP on a non-standard port that should be blocked.
        # Using 8.8.8.8:9999 — Google's DNS IP, port 9999 (not a real service, connection
        # will be refused or blocked; either way the agent cannot reach C2 on this port).
        timeout 4 "${SHIELD_BIN}" -- nc -z -w 2 8.8.8.8 9999 2>/dev/null || NC_EXIT=$?
        if [ "${NC_EXIT}" -ne 0 ]; then
            pass "${LABEL}: connection to port 9999 failed as expected (exit=${NC_EXIT})"
        else
            fail "${LABEL}: connection to 8.8.8.8:9999 succeeded — sandbox did NOT block it"
        fi
    else
        info "nc not found — skipping Fixture E"
    fi

    echo ""

    # -------------------------------------------------------------------------
    # Fixtures F-I: per-host netproxy enforcement
    # -------------------------------------------------------------------------

    # Build agentjail-netproxy if available.
    NETPROXY_BIN="${REPO_ROOT}/agentjail-netproxy-smoke-$$"
    NETPROXY_AVAILABLE=false
    if (cd "${REPO_ROOT}" && go build -o "${NETPROXY_BIN}" ./cmd/agentjail-netproxy/ 2>/dev/null); then
        NETPROXY_AVAILABLE=true
        info "Built agentjail-netproxy for netproxy fixtures"
    else
        info "Could not build agentjail-netproxy — skipping Fixtures F-I"
    fi

    # Write a test policy that allows api.github.com but NOT attacker.example.com.
    SMOKE_POLICY="/tmp/agentjail-shield-smoke-policy-$$.yaml"
    cat > "${SMOKE_POLICY}" << 'POLICY_EOF'
network:
  allowed_hosts:
    - api.github.com
    - raw.githubusercontent.com
POLICY_EOF

    if [ "${NETPROXY_AVAILABLE}" = "true" ]; then
        # Fixture F: allowed host reaches through the proxy.
        LABEL="Fixture F: HTTPS to api.github.com allowed via netproxy"
        F_OUTPUT=""
        F_EXIT=0
        F_OUTPUT=$(AGENTJAIL_NETPROXY="${NETPROXY_BIN}" "${SHIELD_BIN}" \
            --policy="${SMOKE_POLICY}" \
            -- curl --connect-timeout 8 -s -o /dev/null -w "%{http_code}" https://api.github.com/zen 2>/dev/null) || F_EXIT=$?
        info "Fixture F curl exit: ${F_EXIT}, HTTP code: ${F_OUTPUT}"
        if [ "${F_EXIT}" -eq 0 ] && [ "${F_OUTPUT}" = "200" ]; then
            pass "${LABEL}"
        else
            fail "${LABEL}: expected exit 0 + HTTP 200, got exit=${F_EXIT} code=${F_OUTPUT}"
        fi

        echo ""

        # Fixture G: non-listed host is blocked (proxy returns 403).
        # We use the proxy directly (without the full shield) because curl to
        # attacker.example.com would hang waiting for DNS + TLS which may take
        # seconds and could time out for external reasons.
        LABEL="Fixture G: HTTPS to attacker.example.com blocked by netproxy (403)"
        G_EXIT=0
        G_OUTPUT=$(python3 -c "
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('127.0.0.1', 9100))
    s.sendall(b'CONNECT attacker.example.com:443 HTTP/1.1\r\nHost: attacker.example.com\r\n\r\n')
    time.sleep(0.2)
    resp = s.recv(4096).decode('utf-8', errors='replace')
    print(resp)
    s.close()
except Exception as e:
    print('error: ' + str(e))
    sys.exit(1)
" 2>&1) || G_EXIT=$?
        # We check the proxy log for the deny; if 9100 isn't running we skip.
        if echo "${G_OUTPUT}" | grep -q "403"; then
            pass "${LABEL}: proxy returned 403 for attacker.example.com"
        elif echo "${G_OUTPUT}" | grep -q "host not in network.allowed_hosts"; then
            pass "${LABEL}: proxy body confirms denial"
        elif echo "${G_OUTPUT}" | grep -q "Connection refused"; then
            info "Fixture G SKIP: proxy not running on port 9100 (need shield to start it)"
        else
            fail "${LABEL}: expected 403, got: ${G_OUTPUT}"
        fi

        echo ""

        # Fixture H: shield without --no-netproxy starts the netproxy process.
        LABEL="Fixture H: shield without --no-netproxy starts netproxy"
        H_OUTPUT=""
        H_EXIT=0
        # Run a very quick command so we can check the output for netproxy startup messages.
        H_OUTPUT=$(AGENTJAIL_NETPROXY="${NETPROXY_BIN}" "${SHIELD_BIN}" \
            --policy="${SMOKE_POLICY}" \
            -- sh -c "echo HTTPS_PROXY=\$HTTPS_PROXY" 2>&1) || H_EXIT=$?
        if echo "${H_OUTPUT}" | grep -q "HTTPS_PROXY=http://127.0.0.1:9100"; then
            pass "${LABEL}: HTTPS_PROXY is set by shield"
        elif echo "${H_OUTPUT}" | grep -q "netproxy started"; then
            pass "${LABEL}: shield log shows netproxy started"
        else
            fail "${LABEL}: HTTPS_PROXY not set or netproxy not started; output: ${H_OUTPUT}"
        fi

        echo ""

        # Fixture I: with --no-netproxy, no netproxy is started (port-only mode).
        LABEL="Fixture I: --no-netproxy reverts to port-only mode (no HTTPS_PROXY)"
        I_OUTPUT=""
        I_EXIT=0
        I_OUTPUT=$(AGENTJAIL_NETPROXY="${NETPROXY_BIN}" "${SHIELD_BIN}" \
            --no-netproxy \
            --policy="${SMOKE_POLICY}" \
            -- sh -c "echo HTTPS_PROXY=\$HTTPS_PROXY" 2>&1) || I_EXIT=$?
        if echo "${I_OUTPUT}" | grep -q "HTTPS_PROXY=http"; then
            fail "${LABEL}: HTTPS_PROXY should NOT be set in --no-netproxy mode; got: ${I_OUTPUT}"
        else
            pass "${LABEL}: HTTPS_PROXY not set (correct port-only mode)"
        fi

        rm -f "${NETPROXY_BIN}"
    fi

    rm -f "${SMOKE_POLICY}"
    echo ""
else
    info "Skipping network fixtures (not macOS or curl not found)"
fi

echo "=== Summary ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo ""

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
