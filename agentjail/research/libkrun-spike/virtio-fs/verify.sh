#!/usr/bin/env bash
#  verify: run hello-virtfs, capture stdout, assert
#   - guest read /work/from-host.txt (RW: read)
#   - guest wrote /work/from-guest.txt (RW: write, verified on host)
#   - guest cat of /opt/homebrew failed (isolation: out-of-mount is invisible)
#
# Exit: 0 on PASS, non-zero with FAIL: messages on first violation.

set -euo pipefail

HOSTBIN="${1:?missing argv1: host binary}"
ROOTFS="${2:?missing argv2: rootfs dir}"
WORKDIR="${3:?missing argv3: host workdir}"

OUT="$(mktemp -t t0013-verify.XXXXXX)"
trap 'rm -f "$OUT"' EXIT

# Run the spike. Even on success krun_start_enter exits the guest
# workload's exit code; capture both fds.
"$HOSTBIN" "$ROOTFS" "$WORKDIR" >"$OUT" 2>&1 || true

echo "----- guest stdout -----"
cat "$OUT"
echo "------------------------"

fail {
    echo "FAIL: $*" >&2
    exit 1
}

# --- RW: read --------------------------------------------------------
expected_read="$(cat "$WORKDIR/from-host.txt")"
got_read="$(grep -E '^from-host-payload=' "$OUT" | sed 's/^from-host-payload=/')"
if [ -z "$got_read" ]; then
    fail "guest did not print from-host-payload= (mount or read failed)"
fi
if [ "$got_read" != "$expected_read" ]; then
    fail "from-host payload mismatch: expected=[$expected_read] got=[$got_read]"
fi
echo "PASS: guest read /work/from-host.txt (RW: read)"

# --- RW: write -------------------------------------------------------
grep -q '^guest_write=ok' "$OUT" || fail "guest_write != ok"
if [ ! -f "$WORKDIR/from-guest.txt" ]; then
    fail "host can't see /work/from-guest.txt — guest write did not land on host"
fi
guest_payload="$(cat "$WORKDIR/from-guest.txt")"
case "$guest_payload" in
    "from guest uptime="*) ;;
    *) fail "from-guest.txt has unexpected payload: [$guest_payload]" ;;
esac
echo "PASS: host sees /work/from-guest.txt = [$guest_payload] (RW: write)"

# --- Isolation: out-of-mount paths are invisible --------------------
# cat /opt/homebrew/Cellar must fail in the guest. The exit code printed
# by the guest after the cat is the cat itself (busybox cat returns 1 on
# missing file). 0 means the path was visible — containment FAIL.
iso_exit="$(grep -E '^isolation_exit=' "$OUT" | sed 's/^isolation_exit=/')"
[ -n "$iso_exit" ] || fail "guest did not print isolation_exit="
if [ "$iso_exit" = "0" ]; then
    fail "guest saw /opt/homebrew/Cellar (isolation: out-of-mount paths leaked into guest)"
fi
echo "PASS: cat /opt/homebrew/Cellar in guest -> exit=$iso_exit (isolation: invisible)"

# Same check via `ls` for belt + braces — ls returns 2 on ENOENT.
iso_ls_exit="$(grep -E '^isolation_ls_exit=' "$OUT" | sed 's/^isolation_ls_exit=/')"
[ -n "$iso_ls_exit" ] || fail "guest did not print isolation_ls_exit="
if [ "$iso_ls_exit" = "0" ]; then
    fail "guest ls'd /opt/homebrew (isolation: out-of-mount paths leaked into guest)"
fi
echo "PASS: ls /opt/homebrew in guest -> exit=$iso_ls_exit (isolation: invisible)"

echo "ALL PASS ( virtio-fs round-trip + isolation)"
