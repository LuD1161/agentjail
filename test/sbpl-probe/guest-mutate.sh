#!/bin/bash
# AGE-216: corrected mutation tests. The earlier attempt deleted only the
# (literal ...) line of a two-line rule, leaving a dangling "(deny
# network-outbound" -> sbpl syntax error, so the gate was never exercised.
# Here we remove the WHOLE rule and assert the profile still compiles.
set -uo pipefail
KIT=/Users/admin/probe-kit
PROBE="$KIT/probe-bin"; SHIELD="$KIT/agentjail-shield"
PROBE_HOME=/Users/admin/ajprobe-run; RUN="$PROBE_HOME/.agentjail/run"
WORK=/private/tmp/probe-work; mkdir -p "$RUN" "$WORK"; cd "$WORK" || exit 2
NP="$RUN/netproxy-ctl.sock"; DM="$RUN/daemon-ctl.sock"; SE="$RUN/secrets.sock"

pids=(); for s in "$NP" "$DM" "$SE"; do "$PROBE" server "$s" >/dev/null 2>&1 & pids+=($!); done
sleep 1; trap 'for p in "${pids[@]}"; do kill $p 2>/dev/null; done' EXIT
sbx() { /usr/bin/sandbox-exec -f "$1" "$PROBE" client "$2" 2>&1 | head -1; }

HOME="$PROBE_HOME" AGENTJAIL_NETPROXY="$KIT/agentjail-netproxy" \
  "$SHIELD" --profile-print --netproxy -- /bin/echo hi 2>real.raw
awk '/^=== agentjail-shield: generated sbpl profile ===/{f=1;next} /^={10,}$/{f=0} f' real.raw > real.sbpl

# drop_rule <marker> : delete the whole "(deny|allow ...\n    (... marker ...))" rule
drop_rule() { python3 -c '
import sys,re
src,marker,out=sys.argv[1],sys.argv[2],sys.argv[3]
lines=open(src).read().split("\n"); keep=[];i=0
while i<len(lines):
    if i+1<len(lines) and lines[i].strip().startswith("(deny network-outbound") and marker in lines[i+1]:
        i+=2; continue
    keep.append(lines[i]); i+=1
open(out,"w").write("\n".join(keep))
' "$1" "$2" "$3"; }

echo "=== M0  does the UNMUTATED real profile compile + deny? (baseline)"
echo "  netproxy-ctl.sock -> $(sbx real.sbpl "$NP")"

echo
echo "=== M1  MUTATION: remove the netproxy-ctl deny rule ENTIRELY"
drop_rule real.sbpl "netproxy-ctl.sock" mut1.sbpl
echo "  profile compiles? -> $(/usr/bin/sandbox-exec -f mut1.sbpl /bin/echo COMPILES 2>&1 | head -1)"
echo "  netproxy-ctl.sock -> $(sbx mut1.sbpl "$NP")"
echo "     ^ MUST be CONNECT_OK; if still DENIED the deny rule was never the gate"

echo
echo "=== M2  MUTATION: remove the daemon-ctl deny rule ENTIRELY"
drop_rule real.sbpl "daemon-ctl.sock" mut2.sbpl
echo "  profile compiles? -> $(/usr/bin/sandbox-exec -f mut2.sbpl /bin/echo COMPILES 2>&1 | head -1)"
echo "  daemon-ctl.sock   -> $(sbx mut2.sbpl "$DM")"

echo
echo "=== M3  WHY is secrets.sock denied when it has NO deny rule?"
echo "     Hypothesis: the (deny network*) catch-all covers it."
grep -v '^(deny network\*)$' real.sbpl > mut3.sbpl
echo "  removed catch-all; compiles? -> $(/usr/bin/sandbox-exec -f mut3.sbpl /bin/echo COMPILES 2>&1 | head -1)"
echo "  secrets.sock      -> $(sbx mut3.sbpl "$SE")"
echo "     ^ CONNECT_OK => secrets.sock is gated ONLY by the catch-all, not an explicit deny"
echo "  netproxy-ctl.sock -> $(sbx mut3.sbpl "$NP")"
echo "     ^ still DENIED => its explicit deny stands on its own"
echo
echo "### done"
