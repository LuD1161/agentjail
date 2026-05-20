"""SSE response coverage for the addon's substring redactor.

The mitmproxy response hook receives a fully buffered response body, not a
live event callback per SSE frame. The addon therefore sanitizes SSE payloads
by splitting the buffered body on blank-line event boundaries and redacting
each event independently before the body is captured or forwarded.

These tests pin that behavior with a synthetic SSE fixture:

  1. Creds inside an event are redacted.
  2. Bytes from adjacent events are NOT merged for one whole-body scan.
  3. Gzipped SSE still redacts after decompress/recompress.
"""

from __future__ import annotations

import gzip
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDONS_DIR = os.path.dirname(HERE)
if ADDONS_DIR not in sys.path:
    sys.path.insert(0, ADDONS_DIR)

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


CRED = b"sk-live-AKIAEXAMPLECRED1234567890"


def _sse(events):
    return b"".join(events)


class TestSSERedactor(unittest.TestCase):
    def setUp(self):
        self._saved = list(ad._CRED_SUBSTRINGS)
        ad._CRED_SUBSTRINGS[:] = [CRED]

    def tearDown(self):
        ad._CRED_SUBSTRINGS[:] = self._saved

    def test_redacts_each_event_independently(self):
        body = _sse(
            [
                b"event: message\n"
                b"data: hello\n"
                b"data: token=" + CRED + b"\n\n",
                b"event: keepalive\n"
                b"data: sk-live-AKIAEXAMPL\n\n",
                b"event: keepalive\n"
                b"data: ECRED1234567890\n\n",
            ]
        )

        out, err = ad._sanitize_payload(body, "text/event-stream; charset=utf-8")
        self.assertIsNone(err)
        self.assertNotIn(CRED, out)
        self.assertIn(b"token=<agentjail:redacted:cred-id-cli>", out)
        # The second and third events only form the full cred if merged across
        # the SSE boundary; per-event redaction must not join them.
        self.assertIn(b"data: sk-live-AKIAEXAMPL\n\n", out)
        self.assertIn(b"data: ECRED1234567890\n\n", out)

    def test_gzipped_sse_redacts_after_roundtrip(self):
        body = _sse(
            [
                b"event: message\r\n"
                b"data: {\"api_key\":\"" + CRED + b"\"}\r\n\r\n",
                b": keep-alive\r\n\r\n",
            ]
        )
        comp = gzip.compress(body)

        out, err = ad._sanitize_with_encoding(comp, "gzip", "text/event-stream")
        self.assertIsNone(err)
        decoded = gzip.decompress(out)
        self.assertNotIn(CRED, decoded)
        self.assertIn(b"<agentjail:redacted:cred-id-cli>", decoded)
        self.assertIn(b": keep-alive\r\n\r\n", decoded)


if __name__ == "__main__":
    unittest.main()
