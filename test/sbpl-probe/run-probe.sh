#!/usr/bin/env bash
# AGE-216 item 3: verify-by-execution of the macOS sbpl control-socket claims.
#
# MUST be run from a terminal that is NOT inside an agentjail shielded session
# (macOS refuses nested Seatbelt sandboxes: sandbox_apply -> EPERM). Check with:
#     echo "$AGENTJAIL_SHIELDED"     # must be empty
#
# Probe-hygiene invariants (AGE-216):
#   - probe $HOME is outside /tmp   (the shield grants /tmp read-write)
#   - cwd does not enclose probe $HOME (cwd-encloses-home path is a silent pass)
#   - socket paths stay < 104 bytes (sockaddr_un)
#
# Every gate is mutation-tested: we defeat it, watch it fail, then restore.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
BUILD="$(mktemp -d /private/tmp/ajprobe-build.XXXXXX)"
PROBE_HOME="${PROBE_HOME:-/Users/$USER/ajprobe-run}"
RUN="$PROBE_HOME/.agentjail/run"

if [ -n "${AGENTJAIL_SHIELDED:-}" ]; then
  echo "FATAL: running inside a shielded session; sandbox-exec cannot nest." >&2
  exit 2
fi

case "$PROBE_HOME" in
  /tmp/*|/private/tmp/*) echo "FATAL: probe HOME must be outside /tmp" >&2; exit 2;;
esac
case "$PROBE_HOME" in
  "$PWD"*) echo "FATAL: cwd encloses probe HOME - result would be invalid" >&2; exit 2;;
esac

mkdir -p "$RUN"
for s in netproxy-ctl.sock daemon-ctl.sock secrets.sock; do
  p="$RUN/$s"
  [ ${#p} -lt 104 ] || { echo "FATAL: socket path >=104 bytes: $p (${#p})" >&2; exit 2; }
done

echo "### building real binaries + probe"
( cd "$REPO_ROOT" && go build -o "$BUILD/agentjail-shield" ./cmd/agentjail-shield ) || exit 2
( cd "$REPO_ROOT" && go build -o "$BUILD/agentjail-netproxy" ./cmd/agentjail-netproxy ) || exit 2

# Pure-Go binaries omit LC_UUID under internal linking and dyld then refuses to
# exec them; force the external linker so the probe actually runs.
mkdir -p "$BUILD/probe"
cat > "$BUILD/probe/go.mod" <<'EOF'
module probe

go 1.21
EOF
cp "$REPO_ROOT/test/sbpl-probe/probe.go" "$BUILD/probe/main.go"
( cd "$BUILD/probe" && CGO_ENABLED=1 go build -ldflags="-linkmode=external" -o "$BUILD/probe-bin" . ) || exit 2

PROBE="$BUILD/probe-bin"
SHIELD="$BUILD/agentjail-shield"

start_server() { # $1 = socket path
  "$PROBE" server "$1" >/dev/null 2>&1 &
  echo $!
  sleep 0.5
}
sandboxed_connect() { # $1 = profile file, $2 = socket
  /usr/bin/sandbox-exec -f "$1" "$PROBE" client "$2" 2>&1
}

NETPROXY_SOCK="$RUN/netproxy-ctl.sock"
DAEMON_SOCK="$RUN/daemon-ctl.sock"
SECRETS_SOCK="$RUN/secrets.sock"

pids=()
for s in "$NETPROXY_SOCK" "$DAEMON_SOCK" "$SECRETS_SOCK"; do
  pids+=( "$(start_server "$s")" )
done
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$BUILD"; }
trap cleanup EXIT

echo
echo "=========================================================="
echo "E0  CONTROL - unsandboxed connect must succeed"
echo "     (if this fails, every later DENIED is vacuous)"
echo "=========================================================="
for s in "$NETPROXY_SOCK" "$DAEMON_SOCK" "$SECRETS_SOCK"; do
  printf '  %-18s -> %s\n' "$(basename "$s")" "$("$PROBE" client "$s")"
done

echo
echo "=========================================================="
echo "E1  Does Seatbelt model AF_UNIX connect() as network-outbound?"
echo "     profile: (allow default) + (deny network*)"
echo "=========================================================="
cat > "$BUILD/e1.sbpl" <<'EOF'
(version 1)
(allow default)
(deny network*)
EOF
echo "  result: $(sandboxed_connect "$BUILD/e1.sbpl" "$NETPROXY_SOCK")"

echo
echo "=========================================================="
echo "E2  Rule-ordering semantics: last-match-wins or deny-wins?"
echo "=========================================================="
cat > "$BUILD/e2a.sbpl" <<EOF
(version 1)
(allow default)
(deny network-outbound (literal "$NETPROXY_SOCK"))
(allow network-outbound (path "$NETPROXY_SOCK"))
EOF
echo "  deny THEN allow  -> $(sandboxed_connect "$BUILD/e2a.sbpl" "$NETPROXY_SOCK")"
cat > "$BUILD/e2b.sbpl" <<EOF
(version 1)
(allow default)
(allow network-outbound (path "$NETPROXY_SOCK"))
(deny network-outbound (literal "$NETPROXY_SOCK"))
EOF
echo "  allow THEN deny  -> $(sandboxed_connect "$BUILD/e2b.sbpl" "$NETPROXY_SOCK")"
echo "  (CONNECT_OK on 'deny THEN allow' == last-match-wins is REAL)"

echo
echo "=========================================================="
echo "E3  THE REAL PROFILE, from the real shield binary"
echo "=========================================================="
HOME="$PROBE_HOME" AGENTJAIL_NETPROXY="$BUILD/agentjail-netproxy" \
  "$SHIELD" --profile-print --netproxy -- /bin/echo hi 2>"$BUILD/real.sbpl"
sed -i '' '/^===/d' "$BUILD/real.sbpl"
echo "  control-socket rules actually present in the real profile:"
grep -n "ctl.sock\|secrets.sock" "$BUILD/real.sbpl" | sed 's/^/    /' || echo "    (none)"
echo
for s in "$NETPROXY_SOCK" "$DAEMON_SOCK" "$SECRETS_SOCK"; do
  printf '  %-18s -> %s\n' "$(basename "$s")" "$(sandboxed_connect "$BUILD/real.sbpl" "$s")"
done

echo
echo "=========================================================="
echo "E4  MUTATION TEST - defeat the gate, watch the test fail"
echo "     strip the netproxy-ctl deny from the real profile;"
echo "     connect MUST flip to CONNECT_OK or the gate proves nothing"
echo "=========================================================="
grep -v "netproxy-ctl.sock" "$BUILD/real.sbpl" > "$BUILD/mutated.sbpl"
echo "  mutated  -> $(sandboxed_connect "$BUILD/mutated.sbpl" "$NETPROXY_SOCK")"
echo "  restored -> $(sandboxed_connect "$BUILD/real.sbpl" "$NETPROXY_SOCK")"

echo
echo "=========================================================="
echo "E5  SSH_AUTH_SOCK ordering fragility"
echo "     generator emits (allow network-outbound (path \$SSH_AUTH_SOCK))"
echo "     AFTER the control-socket denies. Point it at daemon-ctl.sock."
echo "=========================================================="
HOME="$PROBE_HOME" AGENTJAIL_NETPROXY="$BUILD/agentjail-netproxy" \
  SSH_AUTH_SOCK="$DAEMON_SOCK" \
  "$SHIELD" --profile-print --netproxy -- /bin/echo hi 2>"$BUILD/ssh.sbpl"
sed -i '' '/^===/d' "$BUILD/ssh.sbpl"
echo "  rule order emitted:"
grep -n "daemon-ctl.sock" "$BUILD/ssh.sbpl" | sed 's/^/    /'
echo
echo "  daemon-ctl.sock -> $(sandboxed_connect "$BUILD/ssh.sbpl" "$DAEMON_SOCK")"
echo "  (CONNECT_OK here == the later allow overrides the earlier deny)"
echo
echo "### done"
