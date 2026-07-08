#!/usr/bin/env bash
#
# ssh-pinned-identity.sh - ADR 0056 acceptance proof (Option 2).
#
# Reproduces, against a real throwaway sshd + a real ssh-agent, the exact
# failure mode this fix addresses AND the reason the first shipped recipe was
# insufficient.
#
# The real blind spot (confirmed live under the shield): the user's ssh_config
# pins IdentityFile with `IdentitiesOnly yes`, and the agent holds a DIFFERENT
# key than the pinned one. Under `IdentitiesOnly yes`, OpenSSH only offers
# agent keys whose public half matches a CONFIGURED IdentityFile, so the
# agent's real key is never offered and auth fails - and the shield denies the
# pinned on-disk key read, so there is no on-disk fallback either.
#
# This fixture models that faithfully with TWO distinct keys:
#   P (pinned)  - named as the config IdentityFile, made unreadable (chmod 000)
#                 to simulate the shield's EPERM. NOT authorized on the server.
#   Q (agent)   - a DIFFERENT key, the only key loaded into a fresh isolated
#                 agent, and the only key authorized on the throwaway sshd.
#
# Assertions:
#   1. The FIRST shipped recipe ("-o IdentityFile=none -o IdentityAgent=<sock>",
#      WITHOUT IdentitiesOnly=no) FAILS - because IdentitiesOnly yes still
#      restricts offers to P, and Q is never presented. This is the regression
#      the earlier same-key fixture failed to catch.
#   2. The CORRECTED recipe ("-o IdentitiesOnly=no -o IdentityFile=none -o
#      IdentityAgent=<sock>") SUCCEEDS - IdentitiesOnly=no lifts the restriction
#      so Q is offered and accepted.
#
# Gated behind AGENTJAIL_SSH_E2E=1 so it self-skips cleanly in CI and in any
# environment without a usable sshd/ssh-agent. Run locally with:
#
#   AGENTJAIL_SSH_E2E=1 ./cmd/agentjail-shield/test/ssh-pinned-identity.sh
#
set -u

SCRIPT_NAME="ssh-pinned-identity.sh"

skip() {
	echo "SKIP: ${SCRIPT_NAME}: $1"
	exit 0
}

fail() {
	echo "FAIL: ${SCRIPT_NAME}: $1"
	cleanup
	exit 1
}

if [ "${AGENTJAIL_SSH_E2E:-}" != "1" ]; then
	skip "set AGENTJAIL_SSH_E2E=1 to run (requires a local sshd + ssh-agent)"
fi

for bin in sshd ssh-keygen ssh-agent ssh; do
	if ! command -v "$bin" >/dev/null 2>&1; then
		skip "required binary '$bin' not found in PATH"
	fi
done

# Some sshd builds (e.g. macOS) refuse to run unless invoked by absolute
# path, even when found via PATH lookup. Resolve it explicitly.
SSHD_BIN="$(command -v sshd)"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/agentjail-ssh-e2e.XXXXXX")"
chmod 700 "$WORKDIR"

SSHD_PID=""
AGENT_PID=""

cleanup() {
	if [ -n "$SSHD_PID" ]; then
		kill "$SSHD_PID" >/dev/null 2>&1
		wait "$SSHD_PID" 2>/dev/null
	fi
	if [ -n "$AGENT_PID" ]; then
		kill "$AGENT_PID" >/dev/null 2>&1
	fi
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

HOST_KEY="$WORKDIR/host_key"
PINNED_KEY="$WORKDIR/pinned_key_P"   # P: named in config, unreadable, NOT authorized
AGENT_KEY="$WORKDIR/agent_key_Q"     # Q: loaded into the agent, authorized on sshd
AUTHORIZED_KEYS="$WORKDIR/authorized_keys"
SSHD_CONFIG="$WORKDIR/sshd_config"
SSH_CONFIG="$WORKDIR/ssh_config"
KNOWN_HOSTS="$WORKDIR/known_hosts"
SSHD_LOG="$WORKDIR/sshd.log"

ssh-keygen -q -t ed25519 -f "$HOST_KEY" -N '' || fail "could not generate host key"
ssh-keygen -q -t ed25519 -f "$PINNED_KEY" -N '' || fail "could not generate pinned key P"
ssh-keygen -q -t ed25519 -f "$AGENT_KEY" -N '' || fail "could not generate agent key Q"

# Authorize ONLY Q on the server. P is deliberately not authorized - even if it
# were somehow read, it could not authenticate. The point is that Q must be
# offered, which only happens once IdentitiesOnly=no is set.
cp "$AGENT_KEY.pub" "$AUTHORIZED_KEYS"
chmod 600 "$AUTHORIZED_KEYS"

# Pick a high, likely-free port. Not perfectly race-free, but good enough
# for a throwaway single-use local sshd in a test run.
PORT=$(( (RANDOM % 20000) + 20000 ))

cat > "$SSHD_CONFIG" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $HOST_KEY
AuthorizedKeysFile $AUTHORIZED_KEYS
PidFile $WORKDIR/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
PermitRootLogin no
LogLevel ERROR
Subsystem sftp /bin/false
EOF

"$SSHD_BIN" -D -f "$SSHD_CONFIG" -E "$SSHD_LOG" &
SSHD_PID=$!

# Wait for sshd to come up (or die trying).
UP=0
for _ in $(seq 1 50); do
	if ! kill -0 "$SSHD_PID" 2>/dev/null; then
		break
	fi
	if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
		exec 3<&- 3>&-
		UP=1
		break
	fi
	sleep 0.1
done

if [ "$UP" != "1" ]; then
	skip "could not start a local sshd in this environment (see $SSHD_LOG); not a fix regression, environment lacks sshd capability"
fi

# Fresh, isolated ssh-agent so this test never touches the caller's real agent
# or keys. Load ONLY Q into it.
AGENT_OUT="$(ssh-agent -s)" || fail "could not start ssh-agent"
eval "$AGENT_OUT" >/dev/null
AGENT_PID="$SSH_AGENT_PID"

ssh-add "$AGENT_KEY" >/dev/null 2>&1 || fail "ssh-add failed to load agent key Q"

# Simulate the shield: on-disk private key reads are denied. P is the pinned
# key; make it unreadable. (Q's on-disk file is irrelevant now - it lives in
# the agent.)
chmod 000 "$PINNED_KEY"

# Config pins P with IdentitiesOnly yes - the real-world trap. The agent holds
# Q, a DIFFERENT key, which IdentitiesOnly yes will refuse to offer.
cat > "$SSH_CONFIG" <<EOF
Host pinnedtest
	HostName 127.0.0.1
	Port $PORT
	User $(whoami)
	IdentitiesOnly yes
	IdentityFile $PINNED_KEY
	StrictHostKeyChecking no
	UserKnownHostsFile $KNOWN_HOSTS
	BatchMode yes
	ConnectTimeout 5
EOF

# --- Assertion 1: the FIRST shipped recipe is insufficient --------------
# "-o IdentityFile=none -o IdentityAgent=<sock>" WITHOUT IdentitiesOnly=no.
# IdentitiesOnly yes still restricts offers to the configured identity (P), so
# the agent's key Q is never presented and auth fails. This is exactly the
# regression the earlier same-key fixture missed.
if ssh -F "$SSH_CONFIG" -o IdentityFile=none -o IdentityAgent="$SSH_AUTH_SOCK" pinnedtest true >"$WORKDIR/old_recipe.log" 2>&1; then
	fail "expected the FIRST shipped recipe (no IdentitiesOnly=no) to FAIL when the agent key differs from the pinned key, but it SUCCEEDED. See $WORKDIR/old_recipe.log"
fi
echo "OK: first shipped recipe (no IdentitiesOnly=no) failed as expected - agent key Q was never offered"

# --- Assertion 2: the corrected recipe works ---------------------------
# Adding IdentitiesOnly=no lifts the restriction so Q is offered and accepted.
if ! ssh -F "$SSH_CONFIG" -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent="$SSH_AUTH_SOCK" pinnedtest true >"$WORKDIR/fixed.log" 2>&1; then
	fail "expected the corrected recipe (-o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent=\$SSH_AUTH_SOCK) to SUCCEED, but it FAILED. See $WORKDIR/fixed.log"
fi
echo "OK: corrected recipe succeeded - IdentitiesOnly=no let the agent key Q be offered"

echo "PASS: ${SCRIPT_NAME}: pinned-IdentityFile blind spot (agent key != pinned key) reproduced and fixed by IdentitiesOnly=no"
exit 0
