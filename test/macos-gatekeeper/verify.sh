#!/bin/sh
# verify.sh — macOS Gatekeeper / quarantine source-of-truth check.
#
# Confirms that an agentjail binary installed via the curl|sh path (or brew)
# will actually run on a clean macOS host WITHOUT a Gatekeeper prompt.
#
# The load-bearing fact (see docs/adr/0005-macos-gatekeeper-distribution.md):
# Gatekeeper only blocks files carrying the `com.apple.quarantine` extended
# attribute, which curl / tar / brew never set — only browsers, Finder, Mail,
# and AirDrop do. spctl(8) is NOT the source of truth here: it reports
# "rejected" for any non-notarized binary even though that same binary runs
# fine when launched from a shell. The real, observable source of truth is:
#
#   1. the installed binary has NO com.apple.quarantine xattr, and
#   2. the binary actually executes (exit 0) — i.e. neither AMFI (arm64,
#      kills unsigned binaries before main()) nor Gatekeeper (quarantine)
#      stops it.
#
# This script asserts both. It is the gate that fails the release if a future
# pipeline change ever reintroduces quarantine (e.g. switching the artifact
# transport to something that sets the xattr).
#
# Usage:
#   test/macos-gatekeeper/verify.sh [/path/to/agentjail]
# Default binary path: $HOME/.agentjail/bin/agentjail
#
# Exit codes:
#   0  PASS — Gatekeeper-clean and runnable
#   1  FAIL — com.apple.quarantine is set (Gatekeeper will block it)
#   2  FAIL — binary did not execute (AMFI / Gatekeeper killed it)
#   3  FAIL — binary not found
#   77 SKIP — not macOS
#
# POSIX sh — no bash-isms; passes shellcheck.
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "verify: not macOS — skipping (exit 77)"
    exit 77
fi

BIN="${1:-$HOME/.agentjail/bin/agentjail}"

if [ ! -f "$BIN" ]; then
    echo "verify: binary not found at $BIN" >&2
    exit 3
fi

echo "verify: target = $BIN"

# (1) Quarantine xattr must be ABSENT — it is the only thing that arms Gatekeeper.
#     `xattr -p` exits non-zero when the attribute is absent, which is what we want.
if xattr -p com.apple.quarantine "$BIN" >/dev/null 2>&1; then
    echo "verify: FAIL — com.apple.quarantine is SET on $BIN" >&2
    echo "        Gatekeeper will block this binary. Something quarantined it" >&2
    echo "        (a browser/Finder download?). The curl|sh and brew paths must" >&2
    echo "        never set it. Inspect with: xattr -l '$BIN'" >&2
    xattr -l "$BIN" >&2 || true
    exit 1
fi
echo "verify: ok — no com.apple.quarantine xattr"

# (2) The binary must actually run. On Apple Silicon an unsigned binary (not even
#     ad-hoc signed) is SIGKILLed by AMFI before main(); a quarantined one is
#     blocked by Gatekeeper. Successfully running `agentjail version` is the
#     definitive proof that neither happens on this host/arch.
if OUT="$("$BIN" version 2>&1)"; then
    echo "verify: ok — binary executes: ${OUT}"
else
    rc=$?
    echo "verify: FAIL — '$BIN version' did not run (exit ${rc})" >&2
    echo "        ${OUT}" >&2
    exit 2
fi

# (3) Informational: confirm at least an ad-hoc signature is present. The
#     macOS linker applies this for free to binaries built on a macOS runner;
#     it is REQUIRED for execution on arm64 and harmless on amd64. Not fatal
#     here because (2) already proved the binary runs on this arch.
if command -v codesign >/dev/null 2>&1; then
    SIG=$(codesign -dvv "$BIN" 2>&1 || true)
    if printf '%s' "$SIG" | grep -q "Signature=adhoc"; then
        echo "verify: ok — ad-hoc code signature present"
    elif printf '%s' "$SIG" | grep -q "Authority="; then
        echo "verify: ok — Developer ID / notarized signature present"
    else
        echo "verify: note — binary is unsigned (ok on amd64; would not run on arm64)"
    fi
fi

echo "verify: PASS — $BIN is Gatekeeper-clean and runnable"
