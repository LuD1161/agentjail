#!/usr/bin/env python3
import hashlib
import json
import re
import sys

MAX_BYTES = 32 * 1024 * 1024
TOKEN = re.compile(rb"[A-Za-z0-9+/=]{16,4096}")


def main() -> int:
    fingerprint_path, status_path = sys.argv[1:3]
    with open(fingerprint_path, encoding="utf-8") as handle:
        expected = set(json.load(handle)["credential_fingerprints"].values())
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    overflow = len(raw) > MAX_BYTES
    raw = raw[:MAX_BYTES]
    exact_seen = False

    def redact(match: re.Match[bytes]) -> bytes:
        nonlocal exact_seen
        value = match.group(0)
        if hashlib.sha256(value).hexdigest() in expected:
            exact_seen = True
            return b"[REDACTED_EXACT_AWS_CREDENTIAL]"
        if value.startswith((b"ASIA", b"AKIA")) or len(value) >= 80:
            return b"[REDACTED_CREDENTIAL_SHAPED_VALUE]"
        return value

    sanitized = TOKEN.sub(redact, raw)
    sys.stdout.buffer.write(sanitized)
    with open(status_path, "w", encoding="utf-8") as handle:
        json.dump({"exact_credential_seen": exact_seen, "overflow": overflow}, handle)
        handle.write("\n")
    return 1 if overflow else 0


if __name__ == "__main__":
    raise SystemExit(main())
