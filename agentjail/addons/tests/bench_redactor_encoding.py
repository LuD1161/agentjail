"""Microbench — encoding-aware redactor cost.

Measures wall time of `_sanitize_with_encoding` on a 100 KiB body, both
gzipped (with one cred hit) and identity-encoded (control). Reports p50,
p95, p99.

Run:
    cd addons
    python3 tests/bench_redactor_encoding.py
"""

from __future__ import annotations

import gzip
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ADDONS_DIR = os.path.dirname(HERE)
if ADDONS_DIR not in sys.path:
    sys.path.insert(0, ADDONS_DIR)

# Same mitmproxy shim as the unit tests.
if "mitmproxy" not in sys.modules:
    import types
    mitm = types.ModuleType("mitmproxy")
    ctx_mod = types.ModuleType("mitmproxy.ctx")

    class _Log:
        def warn(self, *_a, **_k):
            pass

        def info(self, *_a, **_k):
            pass

    ctx_mod.log = _Log()
    http_mod = types.ModuleType("mitmproxy.http")

    class _R:
        @staticmethod
        def make(*_a, **_k):
            return None

    class _F:
        pass

    http_mod.Response = _R
    http_mod.HTTPFlow = _F
    mitm.ctx = ctx_mod
    mitm.http = http_mod
    sys.modules["mitmproxy"] = mitm
    sys.modules["mitmproxy.ctx"] = ctx_mod
    sys.modules["mitmproxy.http"] = http_mod

import agentjail_addon as ad  # noqa: E402

CRED = b"sk-live-BENCHCRED-ABCDEFGHIJKLMNOPQRSTUVWX"


def make_payload(target_bytes: int = 100 * 1024) -> bytes:
    chunk = b'{"role":"user","content":"some chat content with the cred '
    chunk += CRED + b' embedded once near the start and lorem ipsum filler.","ts":1234567890}\n'
    out = bytearray()
    while len(out) < target_bytes:
        out.extend(chunk)
    return bytes(out[:target_bytes])


def bench(label: str, fn, iters: int = 500):
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        samples.append((t1 - t0) * 1000.0)
    samples.sort()
    p50 = statistics.median(samples)
    p95 = samples[int(len(samples) * 0.95)]
    p99 = samples[int(len(samples) * 0.99)]
    print(f"{label:30s}  p50={p50:6.3f}ms  p95={p95:6.3f}ms  p99={p99:6.3f}ms  n={iters}")


def main():
    # Install one cred substring (mirrors what the daemon would register).
    ad._CRED_SUBSTRINGS[:] = [CRED]

    plain = make_payload(100 * 1024)
    gzipped = gzip.compress(plain)
    print(f"plain bytes:    {len(plain):,}")
    print(f"gzipped bytes:  {len(gzipped):,}")

    bench("identity 100KiB", lambda: ad._sanitize_with_encoding(plain, ""))
    bench("gzip 100KiB (hit)", lambda: ad._sanitize_with_encoding(gzipped, "gzip"))

    # No-cred fast path on a gzipped body — should match identity passthrough.
    ad._CRED_SUBSTRINGS[:] = []
    bench("gzip 100KiB (no cred set)", lambda: ad._sanitize_with_encoding(gzipped, "gzip"))


if __name__ == "__main__":
    main()
