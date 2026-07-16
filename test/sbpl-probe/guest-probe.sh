#!/bin/bash
# AGE-216 item 3 - executed inside a clean, UNSHIELDED macOS guest.
set -uo pipefail

KIT=/Users/admin/probe-kit
PROBE="$KIT/probe-bin"
SHIELD="$KIT/agentjail-shield"
PROBE_HOME=/Users/admin/ajprobe-run
RUN="$PROBE_HOME/.agentjail/run"
WORK=/private/tmp/probe-work

# Hygiene gates (AGE-216): fail loudly rather than silently produce a fake pass.
[ -z "${AGENTJAIL_SHIELDED:-}" ] || { echo "FATAL: shielded"; exit 2; }
mkdir -p "$RUN" "$WORK"
cd "$WORK" || exit 2
case "$PROBE_HOME" in /tmp/*|/private/tmp/*) echo "FATAL: HOME in /tmp"; exit 2;; esac
case "$PROBE_HOME" in "$PWD"*) echo "FATAL: cwd encloses HOME"; exit 2;; esac
echo "hygiene: cwd=$PWD  probe_home=$PROBE_HOME  (cwd does not enclose home, home outside /tmp)"

NP="$RUN/netproxy-ctl.sock"; DM="$RUN/daemon-ctl.sock"; SE="$PROBE_HOME/.agentjail/secrets.sock"   # NOT under run/ -- see sandbox.SecretsSocketPathForHome
for p in "$NP" "$DM" "$SE"; do
  [ ${#p} -lt 104 ] || { echo "FATAL: sockaddr_un overflow: $p"; exit 2; }
done
echo "sockaddr_un: all paths < 104 bytes (max ${#NP})"

pids=()
for s in "$NP" "$DM" "$SE"; do "$PROBE" server "$s" >/dev/null 2>&1 & pids+=($!); done
sleep 1
trap 'for p in "${pids[@]}"; do kill $p 2>/dev/null; done' EXIT

sbx() { /usr/bin/sandbox-exec -f "$1" "$PROBE" client "$2" 2>&1; }

echo
echo "=== E0  CONTROL: unsandboxed connect (must be CONNECT_OK, else all later results vacuous)"
for s in "$NP" "$DM" "$SE"; do printf '  %-20s %s\n' "$(basename $s)" "$("$PROBE" client "$s")"; done

echo
echo "=== E1  Does Seatbelt model AF_UNIX connect() as network-outbound?"
printf '(version 1)\n(allow default)\n(deny network*)\n' > e1.sbpl
echo "  (allow default)+(deny network*) -> $(sbx e1.sbpl "$NP")"

echo
echo "=== E2  Ordering semantics"
printf '(version 1)\n(allow default)\n(deny network-outbound (literal "%s"))\n(allow network-outbound (path "%s"))\n' "$NP" "$NP" > e2a.sbpl
echo "  deny THEN allow -> $(sbx e2a.sbpl "$NP")   [CONNECT_OK => last-match-wins]"
printf '(version 1)\n(allow default)\n(allow network-outbound (path "%s"))\n(deny network-outbound (literal "%s"))\n' "$NP" "$NP" > e2b.sbpl
echo "  allow THEN deny -> $(sbx e2b.sbpl "$NP")"

echo
echo "=== E2c Does an unfiltered (deny network*) LAST override earlier filtered allows?"
printf '(version 1)\n(allow default)\n(allow network-outbound (path "%s"))\n(deny network*)\n' "$NP" > e2c.sbpl
echo "  filtered allow THEN (deny network*) -> $(sbx e2c.sbpl "$NP")"
echo "     [DENIED => catch-all wins => the shield's network allow-list is DEAD]"
echo "     [CONNECT_OK => specificity beats order]"

echo
echo "=== E3  THE REAL PROFILE from the real shield binary"
HOME="$PROBE_HOME" AGENTJAIL_NETPROXY="$KIT/agentjail-netproxy" \
  "$SHIELD" --profile-print --netproxy -- /bin/echo hi 2>real.raw
awk '/^=== agentjail-shield: generated sbpl profile ===/{f=1;next} /^={10,}$/{f=0} f' real.raw > real.sbpl
echo "  control-plane rules present in real profile:"
grep -n "ctl\.sock\|secrets\.sock" real.sbpl | sed 's/^/    /' || echo "    (NONE)"
echo
for s in "$NP" "$DM" "$SE"; do printf '  %-20s %s\n' "$(basename $s)" "$(sbx real.sbpl "$s")"; done

# Mutation testing lives in guest-mutate.sh. It is NOT done here because the
# obvious one-liner is a trap: `grep -v netproxy-ctl.sock` deletes only the
# (literal ...) line of a two-line rule, leaving a dangling
# "(deny network-outbound" -> sbpl syntax error. sandbox-exec then refuses the
# profile, the connect fails, and the "mutation" looks like a passing gate while
# testing nothing. guest-mutate.sh removes whole rules and asserts the mutated
# profile still COMPILES before believing any result.

echo
echo "=== E5  SSH_AUTH_SOCK ordering: point it at daemon-ctl.sock"
HOME="$PROBE_HOME" AGENTJAIL_NETPROXY="$KIT/agentjail-netproxy" SSH_AUTH_SOCK="$DM" \
  "$SHIELD" --profile-print --netproxy -- /bin/echo hi 2>ssh.raw
awk '/^=== agentjail-shield: generated sbpl profile ===/{f=1;next} /^={10,}$/{f=0} f' ssh.raw > ssh.sbpl
echo "  emitted rule order for daemon-ctl.sock:"
grep -n "daemon-ctl.sock" ssh.sbpl | sed 's/^/    /'
echo "  daemon-ctl.sock -> $(sbx ssh.sbpl "$DM")   [CONNECT_OK => later allow overrides earlier deny]"
echo
echo "### done"
