"""Chunked Transfer-Encoding coverage for the addon's substring redactor.

Mitmproxy's HTTP/1.1 parser decodes `Transfer-Encoding: chunked` framing into
the merged body bytes BEFORE our request/response hooks fire. By the time the
addon reads `flow.request.raw_content` (or `flow.response.raw_content`), the
chunk sizes, CRLFs, and trailer have been stripped and the body is a single
contiguous `bytes` blob. The same is true when `Content-Encoding: gzip` rides
inside a chunked transfer — the chunks frame the compressed bytes, mitmproxy
strips the framing, and we see the full gzip stream.

This means the existing `_sanitize_with_encoding` already handles chunked
bodies — `Transfer-Encoding` is a wire-level concern that never reaches the
helper. These tests pin that behavior so a future change (e.g. streaming
hooks) cannot silently regress it.

We do NOT exercise mitmproxy's HTTP parser here (it has its own test suite).
Instead, we:

  1. Synthesize the bytes that the parser would emit on the hook side after
     decoding a chunked stream (i.e. the merged body),
  2. Run them through `_sanitize_with_encoding` exactly the way the request
     hook does,
  3. Assert the cred substring is redacted (plain), or redacted-then-
     recompressed (gzip), regardless of how the original was framed.

Plus a defensive test: the bomb cap is measured on the MERGED body length,
not on any single chunk; pin that so a chunked-streaming refactor cannot
sneak past the cap by sending one large body as many small chunks.

Run:
    cd agentjail/addons
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import gzip
import os
import sys
import unittest

# Make the addon importable without installing it as a package.
HERE = os.path.dirname(os.path.abspath(__file__))
ADDONS_DIR = os.path.dirname(HERE)
if ADDONS_DIR not in sys.path:
    sys.path.insert(0, ADDONS_DIR)

# mitmproxy is not always installed in the test env; the addon top-level
# imports `from mitmproxy import ctx, http`. Provide a minimal shim so the
# helpers we're testing can import cleanly without the real lib. Mirrors the
# shim in test_redactor_encoding.py.
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


def _encode_chunked(chunks):
    """Encode `chunks` (list of bytes) as an HTTP/1.1 chunked-transfer body.

    Returned bytes match what would travel on the wire BEFORE mitmproxy
    decodes the framing. We use it only to derive the merged body via
    `_decode_chunked` so the tests document the relationship explicitly.
    """
    out = bytearray()
    for c in chunks:
        out.extend(f"{len(c):x}\r\n".encode("ascii"))
        out.extend(c)
        out.extend(b"\r\n")
    out.extend(b"0\r\n\r\n")
    return bytes(out)


def _decode_chunked(wire):
    """Decode an HTTP/1.1 chunked-transfer wire body to merged bytes.

    Minimal RFC 9112 §7.1 implementation — no trailers, no chunk extensions.
    Mirrors what mitmproxy's parser hands the hook in `raw_content`.
    """
    i = 0
    out = bytearray()
    while True:
        # Read chunk-size line.
        j = wire.find(b"\r\n", i)
        if j < 0:
            raise ValueError("malformed chunked body: missing size CRLF")
        size = int(wire[i:j].decode("ascii"), 16)
        i = j + 2
        if size == 0:
            # Terminator; expect trailing CRLF (we ignore trailers).
            return bytes(out)
        out.extend(wire[i:i + size])
        i += size
        if wire[i:i + 2] != b"\r\n":
            raise ValueError("malformed chunked body: missing chunk CRLF")
        i += 2


class TestChunkedCodec(unittest.TestCase):
    """Sanity-check the test helpers themselves before relying on them."""

    def test_roundtrip_single_chunk(self):
        body = b"hello world"
        wire = _encode_chunked([body])
        self.assertEqual(_decode_chunked(wire), body)

    def test_roundtrip_multi_chunk(self):
        chunks = [b"alpha ", b"beta ", b"gamma"]
        wire = _encode_chunked(chunks)
        self.assertEqual(_decode_chunked(wire), b"".join(chunks))

    def test_empty_body(self):
        wire = _encode_chunked([])
        self.assertEqual(_decode_chunked(wire), b"")


class TestChunkedPostPlain(unittest.TestCase):
    """Chunked POST request body, no Content-Encoding."""

    def setUp(self):
        self._saved = list(ad._CRED_SUBSTRINGS)
        ad._CRED_SUBSTRINGS[:] = [CRED]

    def tearDown(self):
        ad._CRED_SUBSTRINGS[:] = self._saved

    def test_cred_split_across_chunks_still_redacted(self):
        # The cred is split across three chunks on the wire. After mitmproxy
        # decodes the framing the merged body contains the full substring,
        # which the redactor must catch.
        prefix = b'{"key":"'
        suffix = b'","tail":"x"}'
        # Split CRED roughly into thirds.
        third = len(CRED) // 3
        c1 = prefix + CRED[:third]
        c2 = CRED[third:2 * third]
        c3 = CRED[2 * third:] + suffix
        wire = _encode_chunked([c1, c2, c3])
        merged = _decode_chunked(wire)
        # Sanity: the cred was indeed reassembled.
        self.assertIn(CRED, merged)

        # Hook sees `merged` (no Content-Encoding header on the chunked body).
        out, err = ad._sanitize_with_encoding(merged, "")
        self.assertIsNone(err)
        self.assertNotIn(CRED, out)
        self.assertIn(b"<agentjail:redacted:cred-id-", out)

    def test_many_small_chunks(self):
        # 200 single-byte chunks reassemble to the same body the redactor
        # handles on every other path; pins that we don't accidentally
        # become chunk-count-sensitive.
        body = b"X" * 100 + CRED + b"Y" * 100
        wire = _encode_chunked([body[i:i + 1] for i in range(len(body))])
        merged = _decode_chunked(wire)
        self.assertEqual(merged, body)

        out, err = ad._sanitize_with_encoding(merged, "")
        self.assertIsNone(err)
        self.assertNotIn(CRED, out)


class TestChunkedPostGzipped(unittest.TestCase):
    """Chunked POST request with Content-Encoding: gzip.

    The chunks frame the gzipped bytes. After framing is stripped, we have
    a normal gzip stream that the encoding-aware redactor decompresses,
    redacts, and recompresses.
    """

    def setUp(self):
        self._saved = list(ad._CRED_SUBSTRINGS)
        ad._CRED_SUBSTRINGS[:] = [CRED]

    def tearDown(self):
        ad._CRED_SUBSTRINGS[:] = self._saved

    def test_gzipped_body_in_chunks_redacts(self):
        body = b'{"key":"' + CRED + b'","tail":"x"}'
        comp = gzip.compress(body)
        # Frame the compressed bytes across several chunks — splits the
        # gzip stream at arbitrary byte offsets, which is exactly how a
        # real chunked Transfer-Encoding sender behaves.
        chunks = [comp[i:i + 7] for i in range(0, len(comp), 7)]
        wire = _encode_chunked(chunks)
        merged = _decode_chunked(wire)
        self.assertEqual(merged, comp)

        out, err = ad._sanitize_with_encoding(merged, "gzip")
        self.assertIsNone(err)
        decoded = gzip.decompress(out)
        self.assertNotIn(CRED, decoded)
        self.assertIn(b"<agentjail:redacted:cred-id-", decoded)


class TestChunkedResponsePlain(unittest.TestCase):
    """Chunked response body, no Content-Encoding.

    The response hook does not currently invoke the redactor (see Content-Encoding handling
    findings — response-side redaction is a tracked follow-up). We test
    the helper directly so the day the response hook IS wired up,
    chunked-encoded responses are already covered.
    """

    def setUp(self):
        self._saved = list(ad._CRED_SUBSTRINGS)
        ad._CRED_SUBSTRINGS[:] = [CRED]

    def tearDown(self):
        ad._CRED_SUBSTRINGS[:] = self._saved

    def test_chunked_response_redacts(self):
        # A typical streaming JSON response: a few framing bytes, then the
        # cred (e.g. echoed in an error reply), then more framing.
        chunks = [
            b'{"error":"upstream rejected token ',
            CRED,
            b' please rotate"}',
        ]
        wire = _encode_chunked(chunks)
        merged = _decode_chunked(wire)
        self.assertIn(CRED, merged)

        out, err = ad._sanitize_with_encoding(merged, "")
        self.assertIsNone(err)
        self.assertNotIn(CRED, out)
        self.assertIn(b"<agentjail:redacted:cred-id-", out)


class TestChunkedResponseGzipped(unittest.TestCase):
    """Chunked response body with Content-Encoding: gzip.

    Common in production — every major API CDN serves gzipped responses
    and Transfer-Encoding: chunked is the only way to stream a body whose
    final size is not known when the headers are flushed.
    """

    def setUp(self):
        self._saved = list(ad._CRED_SUBSTRINGS)
        ad._CRED_SUBSTRINGS[:] = [CRED]

    def tearDown(self):
        ad._CRED_SUBSTRINGS[:] = self._saved

    def test_gzipped_chunked_response_redacts(self):
        body = b'{"error":"token ' + CRED + b' rejected"}'
        comp = gzip.compress(body)
        # Two chunks: half of the gzip stream each.
        mid = len(comp) // 2
        wire = _encode_chunked([comp[:mid], comp[mid:]])
        merged = _decode_chunked(wire)
        self.assertEqual(merged, comp)

        out, err = ad._sanitize_with_encoding(merged, "gzip")
        self.assertIsNone(err)
        decoded = gzip.decompress(out)
        self.assertNotIn(CRED, decoded)
        self.assertIn(b"<agentjail:redacted:cred-id-", decoded)


class TestChunkedSizeCap(unittest.TestCase):
    """The size cap is measured on the MERGED body, not per-chunk.

    Pins a defensive invariant: a sender cannot bypass the bomb cap by
    splitting a large body across many small chunks. The size check fires
    on the post-merge length the same way it fires on a single-shot body.
    """

    def setUp(self):
        self._saved = list(ad._CRED_SUBSTRINGS)
        ad._CRED_SUBSTRINGS[:] = [CRED]

    def tearDown(self):
        ad._CRED_SUBSTRINGS[:] = self._saved

    def test_oversize_merged_body_fails_closed_plain(self):
        # 16 MiB + 1 byte split across many 4 KiB chunks. After merging,
        # the body exceeds _REDACT_MAX_BODY_BYTES; the plain-path sanitizer
        # must fail-closed exactly as for a single-shot body.
        total = ad._REDACT_MAX_BODY_BYTES + 1
        body = b"A" * total
        chunk_sz = 4096
        wire = _encode_chunked([body[i:i + chunk_sz] for i in range(0, total, chunk_sz)])
        merged = _decode_chunked(wire)
        self.assertEqual(len(merged), total)

        out, err = ad._sanitize_with_encoding(merged, "")
        # _sanitize_body returns (b"", "body_too_large_to_redact") for the
        # oversize plain case.
        self.assertEqual(out, b"")
        self.assertEqual(err, "body_too_large_to_redact")

    def test_oversize_merged_body_fails_closed_gzip_bomb(self):
        # Same shape but the chunks carry gzipped bytes whose decompressed
        # size exceeds the cap.
        raw = b"\x00" * (ad._REDACT_MAX_BODY_BYTES + 1)
        comp = gzip.compress(raw)
        # Frame across many small chunks; merged equals `comp`.
        wire = _encode_chunked([comp[i:i + 1024] for i in range(0, len(comp), 1024)])
        merged = _decode_chunked(wire)
        self.assertEqual(merged, comp)

        out, err = ad._sanitize_with_encoding(merged, "gzip")
        self.assertIsNone(out)
        self.assertEqual(err, "decompress_too_large")


if __name__ == "__main__":
    unittest.main()
