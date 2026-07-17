#!/bin/bash
# Reproduce the assertions of TestSandboxExec_DarwinTempDirCarveOuts against the
# FIXED shield profile, on a clean unshielded guest where sandbox_apply is not
# constrained by an already-applied profile.
set -uo pipefail
KIT="${KIT:-/Users/admin/probe-kit}"
WORK="${WORK:-/private/tmp/carveout}"; mkdir -p "$WORK"; cd "$WORK" || exit 2

HOME_REAL=/Users/admin
AGENTJAIL_NETPROXY="$KIT/agentjail-netproxy" "$KIT/agentjail-shield" --profile-print -- /bin/echo hi 2>raw
awk '/^=== agentjail-shield: generated sbpl profile ===/{f=1;next} /^={10,}$/{f=0} f' raw > p.sbpl

echo "profile accepted by sandbox_apply? -> $(/usr/bin/sandbox-exec -f p.sbpl /bin/echo ACCEPTED 2>&1 | head -1)"
echo "control-socket denies emitted: $(grep -c 'ctl.sock\|secrets.sock' p.sbpl)"
echo

/usr/bin/sandbox-exec -f p.sbpl /usr/bin/python3 -c '
import os, socket, sys
pid = os.getpid()
tmpdir = os.environ.get("TMPDIR", "/tmp").rstrip("/")
tmp_sock_path = "/tmp/aj-carve-%d.sock" % pid
tmpdir_sock_path = os.path.join(tmpdir, "aj-carve-%d.sock" % pid)

def report(name, fn):
    try:
        fn(); print("%s=ok" % name)
    except Exception as e:
        print("%s=denied:%s" % (name, e))

def bind_tmp():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try: os.remove(tmp_sock_path)
    except OSError: pass
    s.bind(tmp_sock_path); s.listen(1)

def bindconnect_tmpdir():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try: os.remove(tmpdir_sock_path)
    except OSError: pass
    s.bind(tmpdir_sock_path); s.listen(1)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(tmpdir_sock_path)

def write_tmpdir():
    with open(os.path.join(tmpdir, "aj-carve-w-%d.txt" % pid), "w") as f: f.write("x")

def write_vardb():
    with open("/private/var/db/aj-carve-%d.txt" % pid, "w") as f: f.write("x")

def connect_tmp():
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(tmp_sock_path)

report("bind_tmp", bind_tmp)                     # expect ok
report("bindconnect_tmpdir", bindconnect_tmpdir) # expect ok
report("write_tmpdir", write_tmpdir)             # expect ok
report("write_vardb", write_vardb)               # expect denied
report("connect_tmp", connect_tmp)               # expect denied (shim-egress risk)
' 2>&1
