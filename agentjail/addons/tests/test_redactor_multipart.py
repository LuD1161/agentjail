"""Multipart/form-data coverage for the addon's substring redactor.

The request hook currently redacts request bodies before body capture and
forwarding. For multipart uploads we need narrower behavior than the plain
whole-body scan:

  1. Text parts (ordinary form fields, JSON snippets) should be redacted.
  2. Binary file parts should pass through byte-for-byte unchanged.

These tests exercise the encoding-aware sanitizer directly with a synthetic
multipart fixture so the parsing and part-classification logic stays pinned
without needing a live mitmproxy process.
"""

from __future__ import annotations

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
BOUNDARY = "----agentjail-boundary-7MA4YWxkTrZu0gW"
CONTENT_TYPE = f'multipart/form-data; boundary="{BOUNDARY}"'


def _multipart(parts):
    chunks = []
    for headers, body in parts:
        chunks.append(f"--{BOUNDARY}\r\n".encode("ascii"))
        for key, value in headers:
            chunks.append(f"{key}: {value}\r\n".encode("utf-8"))
        chunks.append(b"\r\n")
        chunks.append(body)
        chunks.append(b"\r\n")
    chunks.append(f"--{BOUNDARY}--\r\n".encode("ascii"))
    return b"".join(chunks)


class TestMultipartRedactor(unittest.TestCase):
    def setUp(self):
        self._saved = list(ad._CRED_SUBSTRINGS)
        ad._CRED_SUBSTRINGS[:] = [CRED]

    def tearDown(self):
        ad._CRED_SUBSTRINGS[:] = self._saved

    def test_text_part_redacted_binary_passed_through(self):
        text_body = b"token=" + CRED + b"&note=hello"
        binary_body = b"\x89PNG\r\n\x1a\n" + CRED + b"\x00\x01\x02tail"
        body = _multipart(
            [
                (
                    [("Content-Disposition", 'form-data; name="metadata"')],
                    text_body,
                ),
                (
                    [
                        (
                            "Content-Disposition",
                            'form-data; name="file"; filename="avatar.png"',
                        ),
                        ("Content-Type", "image/png"),
                    ],
                    binary_body,
                ),
            ]
        )

        out, err = ad._sanitize_with_encoding(body, "", CONTENT_TYPE)
        self.assertIsNone(err)
        self.assertNotIn(text_body, out)
        self.assertIn(b"token=<agentjail:redacted:cred-id-cli>&note=hello", out)
        self.assertIn(binary_body, out)

    def test_json_part_redacted_without_filename(self):
        json_body = b'{"api_key":"' + CRED + b'","mode":"test"}'
        body = _multipart(
            [
                (
                    [
                        ("Content-Disposition", 'form-data; name="payload"'),
                        ("Content-Type", "application/json"),
                    ],
                    json_body,
                ),
            ]
        )

        out, err = ad._sanitize_with_encoding(body, "", CONTENT_TYPE)
        self.assertIsNone(err)
        self.assertNotIn(CRED, out)
        self.assertIn(b"<agentjail:redacted:cred-id-cli>", out)


if __name__ == "__main__":
    unittest.main()
