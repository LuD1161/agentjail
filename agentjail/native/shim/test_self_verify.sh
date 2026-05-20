#!/usr/bin/env bash
# Integration test for the shim's self-verification path.
#
# Steps:
#   1. Locate the freshly built shim ($DEST → ../../../bin/agentjail-shim).
#   2. Copy it to a temp dir; ad-hoc sign with hardened runtime.
#   3. Confirm a clean run reaches our shim's own error path (exit 127:
#      "cannot find real binary on PATH" — because we run it under an empty
#      PATH so it cannot resolve a real tool). That proves verify_self()
#      returned 0 and main() continued.
#   4. Flip one byte deep inside the text segment to break the signature.
#   5. Run the tampered binary and confirm it exits non-zero.
#      On macOS arm64, AMFI typically SIGKILLs the process at exec time
#      (rc=137), which is the strongest possible outcome — the kernel
#      refuses to even load the tampered binary. On macOS x86_64 or when
#      AMFI is permissive, our in-process verify_self() shells out to
#      codesign --verify and returns 126.
#      Either way, the binary must NOT successfully execv anything.
#
# Skips cleanly on non-Darwin hosts (Linux/FreeBSD), where this code path
# is intentionally a no-op (see verify_self() in shim.c).

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHIM="${SCRIPT_DIR}/../../../bin/agentjail-shim"

if [ "$(uname)" != "Darwin" ]; then
  echo "SKIP: test_self_verify.sh is macOS-only"
  exit 0
fi

if [ ! -x "$SHIM" ]; then
  echo "FAIL: shim not built at $SHIM (run 'make build' first)" >&2
  exit 1
fi

WORK="$(mktemp -d -t agentjail-shim-verify.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CLEAN="$WORK/agentjail-shim"
cp "$SHIM" "$CLEAN"

echo "[1/4] sign clean copy with hardened runtime (ad-hoc)"
codesign --force --sign - --options runtime "$CLEAN" >/dev/null 2>&1
codesign --verify --strict "$CLEAN" || {
  echo "FAIL: codesign --verify failed on freshly signed clean copy" >&2
  exit 1
}

echo "[2/4] clean copy runs through verify_self (expect exit 127 from main)"
# Empty PATH so the shim's resolve_real() fails, producing exit 127 from main's
# error path. If verify_self() refused, we would instead see exit 126.
set +e
PATH="" "$CLEAN" >/dev/null 2>&1
CLEAN_RC=$?
set -e
if [ "$CLEAN_RC" -ne 127 ]; then
  echo "FAIL: clean signed shim returned $CLEAN_RC (expected 127 from main's PATH-resolution failure)" >&2
  exit 1
fi
echo "       clean rc=$CLEAN_RC OK"

echo "[3/4] flip one byte deep in the text segment"
TAMPERED="$WORK/agentjail-shim-tampered"
cp "$CLEAN" "$TAMPERED"
# Flip a byte at offset = size/2 so we stay safely inside .text on both arm64
# and x86_64; the signature blob sits at the *end* of the Mach-O so we leave
# it alone (we want the verifier to see a bad code-hash, not a missing
# signature).
python3 - "$TAMPERED" <<'PY'
import sys
p = sys.argv[1]
with open(p, "rb") as f:
    data = bytearray(f.read())
i = len(data) // 2
data[i] ^= 0xFF
with open(p, "wb") as f:
    f.write(data)
PY

# Sanity: codesign itself must now report invalid.
if codesign --verify --strict "$TAMPERED" 2>/dev/null; then
  echo "FAIL: codesign still reports tampered binary as valid (byte-flip landed in dead space?)" >&2
  exit 1
fi

echo "[4/4] tampered binary must refuse to run"
set +e
PATH="" "$TAMPERED" >/dev/null 2>&1
TAMP_RC=$?
set -e
# Acceptable refusal codes:
#   137  - SIGKILL from AMFI (most common on macOS arm64)
#   126  - our verify_self() detected the bad signature and exited explicitly
#   9    - raw signal value (some shells expose this instead of 128+sig)
case "$TAMP_RC" in
  137|126|9)
    echo "       tampered rc=$TAMP_RC OK (refused)"
    ;;
  0|127)
    echo "FAIL: tampered binary ran successfully (rc=$TAMP_RC) — verify_self() did not refuse" >&2
    exit 1
    ;;
  *)
    # Any other nonzero is still a refusal, but flag it so we notice unusual
    # macOS / AMFI behaviour in CI output.
    echo "       tampered rc=$TAMP_RC OK (refused; unusual code, please verify on this host)"
    ;;
esac

echo "PASS: shim self-verify integration test"
