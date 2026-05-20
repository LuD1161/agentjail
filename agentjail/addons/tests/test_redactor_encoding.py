"""Content-Encoding coverage for the addon's substring redactor.

Exercises `_sanitize_with_encoding`, `_decompress_body`, `_recompress_body`,
and `_pick_encoding` directly. The mitmproxy hook surface (`request`,
`response`) is NOT covered here — it is exercised by the smoke harness; the
encoding helpers are pure data-in / data-out and benefit from isolated unit
tests.

The addon module reads cred substrings from `AGENTJAIL_CRED_SUBSTRINGS_B64`
at import time. To install a known set the tests import the module once,
then poke `_CRED_SUBSTRINGS` directly (the variable is module-private but
unit tests are allowed to reach in — this mirrors how the Go-side redactor
tests poke the registry).

Run:
    cd addons
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import gzip
import os
import sys
import unittest
import zlib

# Make the addon importable without installing it as a package.
HERE = os.path.dirname(os.path.abspath(__file__))
ADDONS_DIR = os.path.dirname(HERE)
if ADDONS_DIR not in sys.path:
    sys.path.insert(0, ADDONS_DIR)

# mitmproxy is not always installed in the test env; the addon top-level
# imports `from mitmproxy import ctx, http`. Provide a minimal shim so the
# helpers we're testing can import cleanly without the real lib.
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

    class _Response:
        @staticmethod
        def make(*_a, **_k):
            return None

    class _HTTPFlow:
        pass

    http_mod.Response = _Response
    http_mod.HTTPFlow = _HTTPFlow
    mitm.ctx = ctx_mod
    mitm.http = http_mod
    sys.modules["mitmproxy"] = mitm
    sys.modules["mitmproxy.ctx"] = ctx_mod
    sys.modules["mitmproxy.http"] = http_mod

import agentjail_addon as ad  # noqa: E402


# A simple headers shim that mimics mitmproxy's case-insensitive Headers
# (multidict-flavored). The addon only calls `.get("content-encoding")`.
class _Headers:
    def __init__(self, mapping):
        self._m = {k.lower(): v for k, v in (mapping or {}).items()}

    def get(self, key, default=None):
        return self._m.get(key.lower(), default)


CRED = b"sk-live-AKIAEXAMPLECRED1234567890"


class TestPickEncoding(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(ad._pick_encoding(_Headers({})), "")

    def test_identity(self):
        self.assertEqual(ad._pick_encoding(_Headers({"content-encoding": "identity"})), "")

    def test_gzip(self):
        self.assertEqual(ad._pick_encoding(_Headers({"content-encoding": "gzip"})), "gzip")

    def test_gzip_case_insensitive(self):
        self.assertEqual(ad._pick_encoding(_Headers({"content-encoding": "GZIP"})), "gzip")

    def test_deflate(self):
        self.assertEqual(ad._pick_encoding(_Headers({"content-encoding": "deflate"})), "deflate")

    def test_unknown(self):
        self.assertEqual(ad._pick_encoding(_Headers({"content-encoding": "br"})), "unsupported")

    def test_stacked(self):
        self.assertEqual(ad._pick_encoding(_Headers({"content-encoding": "gzip, deflate"})), "unsupported")


class TestDecompressBody(unittest.TestCase):
    def test_gzip_roundtrip(self):
        raw = b"hello world " * 32
        comp = gzip.compress(raw)
        out, err = ad._decompress_body(comp, "gzip")
        self.assertIsNone(err)
        self.assertEqual(out, raw)

    def test_deflate_zlib_wrapped(self):
        raw = b"hello world " * 32
        comp = zlib.compress(raw)
        out, err = ad._decompress_body(comp, "deflate")
        self.assertIsNone(err)
        self.assertEqual(out, raw)

    def test_deflate_raw_fallback(self):
        raw = b"raw deflate body"
        compressor = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
        comp = compressor.compress(raw) + compressor.flush()
        out, err = ad._decompress_body(comp, "deflate")
        self.assertIsNone(err)
        self.assertEqual(out, raw)

    def test_malformed_gzip(self):
        out, err = ad._decompress_body(b"not a gzip stream", "gzip")
        self.assertIsNone(out)
        self.assertIsNotNone(err)
        self.assertTrue(err.startswith("decompress_failed"), err)

    def test_bomb_capped(self):
        # 16 MiB + 1 byte of zeros compresses to ~16 KiB. Decompressing
        # should trip the size cap and fail-closed.
        raw = b"\x00" * (ad._REDACT_MAX_BODY_BYTES + 1)
        comp = gzip.compress(raw)
        out, err = ad._decompress_body(comp, "gzip")
        self.assertIsNone(out)
        self.assertEqual(err, "decompress_too_large")


class TestRecompressBody(unittest.TestCase):
    def test_gzip(self):
        raw = b"some body"
        out, err = ad._recompress_body(raw, "gzip")
        self.assertIsNone(err)
        self.assertEqual(gzip.decompress(out), raw)

    def test_deflate(self):
        raw = b"some body"
        out, err = ad._recompress_body(raw, "deflate")
        self.assertIsNone(err)
        self.assertEqual(zlib.decompress(out), raw)

    def test_unknown(self):
        out, err = ad._recompress_body(b"x", "br")
        self.assertIsNone(out)
        self.assertEqual(err, "unsupported_encoding")


class TestSanitizeWithEncoding(unittest.TestCase):
    def setUp(self):
        # Save & restore the module-level registry around each test.
        self._saved = list(ad._CRED_SUBSTRINGS)
        ad._CRED_SUBSTRINGS[:] = [CRED]

    def tearDown(self):
        ad._CRED_SUBSTRINGS[:] = self._saved

    def test_identity_passthrough_no_cred(self):
        ad._CRED_SUBSTRINGS[:] = []
        body = b"hello world"
        out, err = ad._sanitize_with_encoding(body, "")
        self.assertIsNone(err)
        self.assertEqual(out, body)

    def test_gzip_redacts(self):
        body = b'{"key":"' + CRED + b'","tail":"x"}'
        comp = gzip.compress(body)
        out, err = ad._sanitize_with_encoding(comp, "gzip")
        self.assertIsNone(err)
        # Output is a valid gzip stream that decodes to the redacted body.
        decoded = gzip.decompress(out)
        self.assertNotIn(CRED, decoded)
        self.assertIn(b"<agentjail:redacted:cred-id-", decoded)
        # And the wire bytes differ from the input (we did something).
        self.assertNotEqual(out, comp)

    def test_deflate_redacts(self):
        body = b'{"k":"' + CRED + b'"}'
        comp = zlib.compress(body)
        out, err = ad._sanitize_with_encoding(comp, "deflate")
        self.assertIsNone(err)
        decoded = zlib.decompress(out)
        self.assertNotIn(CRED, decoded)
        self.assertIn(b"<agentjail:redacted:cred-id-", decoded)

    def test_gzip_no_match_returns_original(self):
        # When no substring matches, return the ORIGINAL compressed bytes —
        # don't perturb the byte stream for no reason.
        body = b"nothing sensitive here"
        comp = gzip.compress(body)
        out, err = ad._sanitize_with_encoding(comp, "gzip")
        self.assertIsNone(err)
        self.assertEqual(out, comp)

    def test_bomb_fails_closed(self):
        raw = b"\x00" * (ad._REDACT_MAX_BODY_BYTES + 1)
        comp = gzip.compress(raw)
        out, err = ad._sanitize_with_encoding(comp, "gzip")
        self.assertIsNone(out)
        self.assertEqual(err, "decompress_too_large")

    def test_malformed_fails_closed(self):
        out, err = ad._sanitize_with_encoding(b"not a gzip stream", "gzip")
        self.assertIsNone(out)
        self.assertTrue(err.startswith("decompress_failed"), err)

    def test_unsupported_with_cred_fails_closed(self):
        out, err = ad._sanitize_with_encoding(b"opaque body", "unsupported")
        self.assertIsNone(out)
        self.assertEqual(err, "unsupported_encoding")

    def test_unsupported_without_cred_passes_through(self):
        ad._CRED_SUBSTRINGS[:] = []
        body = b"opaque body"
        out, err = ad._sanitize_with_encoding(body, "unsupported")
        self.assertIsNone(err)
        self.assertEqual(out, body)

    def test_skip_decompress_when_no_cred(self):
        # Fast path: with no registered cred there is nothing to redact, so
        # gzip body should pass through untouched without paying the
        # decompress cost.
        ad._CRED_SUBSTRINGS[:] = []
        body = b"plain"
        comp = gzip.compress(body)
        out, err = ad._sanitize_with_encoding(comp, "gzip")
        self.assertIsNone(err)
        self.assertEqual(out, comp)


if __name__ == "__main__":
    unittest.main()
