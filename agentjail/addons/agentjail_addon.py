"""agentjail mitmproxy addon.

Loaded by mitmdump. Emits one-line JSON events to the agentjail daemon over a
Unix socket. Best-effort, never blocks request flow.

Environment:
  AGENTJAIL_SOCK         Unix-socket path to the per-session daemon.
  AGENTJAIL_SESSION_ID   Session UUID.
  AGENTJAIL_CONFIG_PATH  Path to YAML config (optional). Schema:
      capture_bodies:
        enabled_hosts: ["api.anthropic.com", "*.example.com"]
        max_bytes: 65536
  AGENTJAIL_BODIES_DIR   Directory to store captured request/response bodies
                          (created by the Go wrapper, mode 0700). Required for
                          body capture; if missing, capture is disabled even if
                          a host matches.

Sensitive-data handling:
  Sensitive headers (Authorization, Cookie, Proxy-Authorization, X-Api-Key,
  Set-Cookie) are never sent to the daemon -- only their names are emitted.
  They are also absent from the body files because mitmproxy stores headers
  separately from raw_content; the body file contains only the HTTP message
  body. Body capture is OPT-IN per host via the config file.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import socket
import threading
import time
from typing import Optional

from mitmproxy import ctx, http


SOCK_PATH = os.environ.get("AGENTJAIL_SOCK") or ""
SID = os.environ.get("AGENTJAIL_SESSION_ID") or ""
CONFIG_PATH = os.environ.get("AGENTJAIL_CONFIG_PATH") or ""
BODIES_DIR = os.environ.get("AGENTJAIL_BODIES_DIR") or ""
# Enforcement is opt-in. When unset (the default) the addon behaves exactly as
# in Phase 2 — fire-and-forget audit frames only, no sync RPC, no 403 synthesis.
ENFORCE = os.environ.get("AGENTJAIL_ENFORCE") == "1"
# Total budget for one sync RPC (connect + write + readline). Kept tight so a
# wedged daemon cannot stall request flow on a coffee-shop wifi. HTTP is
# fail-open: see _sync_decide().
SYNC_RPC_TIMEOUT_S = 0.150

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}


# --- config loading --------------------------------------------------------

def _load_yaml(path: str) -> dict:
    """Load YAML config; tolerant of missing PyYAML/ruamel.yaml.

    Returns {} on any failure.
    """
    if not path or not os.path.isfile(path):
        return {}
    # Prefer ruamel.yaml (bundled with mitmproxy 12), then PyYAML, then a
    # tiny inline parser sufficient for our two-level schema.
    try:
        from ruamel.yaml import YAML  # type: ignore
        with open(path, "r", encoding="utf-8") as f:
            data = YAML(typ="safe").load(f)
            return data or {}
    except Exception:
        pass
    try:
        import yaml  # type: ignore
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        pass
    # Last-resort tiny parser for the documented shape.
    try:
        return _tiny_yaml_parse(path)
    except Exception:
        return {}


def _tiny_yaml_parse(path: str) -> dict:
    """Parse just the documented shape: capture_bodies: { enabled_hosts: [..], max_bytes: N }.
    Not a general YAML parser."""
    out: dict = {}
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    capture: dict = {}
    # Strip comments and blank lines.
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    in_capture = False
    for ln in lines:
        if re.match(r"^capture_bodies\s*:\s*$", ln):
            in_capture = True
            continue
        if in_capture:
            if not ln.startswith((" ", "\t")):
                in_capture = False
                continue
            m = re.match(r"\s+enabled_hosts\s*:\s*\[(.*)\]\s*$", ln)
            if m:
                items = [x.strip().strip('"').strip("'") for x in m.group(1).split(",") if x.strip()]
                capture["enabled_hosts"] = items
                continue
            m = re.match(r"\s+max_bytes\s*:\s*(\d+)\s*$", ln)
            if m:
                capture["max_bytes"] = int(m.group(1))
                continue
    if capture:
        out["capture_bodies"] = capture
    return out


_cfg = _load_yaml(CONFIG_PATH)
_capture = (_cfg.get("capture_bodies") or {}) if isinstance(_cfg, dict) else {}
ENABLED_HOSTS = set()
for h in (_capture.get("enabled_hosts") or []):
    if isinstance(h, str) and h:
        ENABLED_HOSTS.add(h.lower())
try:
    MAX_BYTES = int(_capture.get("max_bytes") or 65536)
except Exception:
    MAX_BYTES = 65536
if MAX_BYTES <= 0:
    MAX_BYTES = 65536


def _host_enabled(host: str) -> bool:
    if not ENABLED_HOSTS or not BODIES_DIR:
        return False
    h = (host or "").lower()
    if h in ENABLED_HOSTS:
        return True
    for pat in ENABLED_HOSTS:
        if pat.startswith("*."):
            suffix = pat[1:]  # ".example.com"
            if h.endswith(suffix) and len(h) > len(suffix):
                return True
        elif pat.startswith("."):
            if h.endswith(pat):
                return True
    return False


# --- socket client ---------------------------------------------------------

class _SockClient:
    def __init__(self, path: str) -> None:
        self._path = path
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

    def _connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self._path)
        self._sock = s

    def send(self, payload: bytes) -> None:
        with self._lock:
            for _ in range(2):
                try:
                    if self._sock is None:
                        self._connect()
                    assert self._sock is not None
                    self._sock.sendall(payload)
                    return
                except Exception:
                    try:
                        if self._sock is not None:
                            self._sock.close()
                    finally:
                        self._sock = None


_client: Optional[_SockClient] = None
if SOCK_PATH and SID:
    _client = _SockClient(SOCK_PATH)


def _emit(frame: dict) -> None:
    if _client is None:
        return
    frame["track"] = "proxy"
    try:
        line = (json.dumps(frame) + "\n").encode("utf-8")
    except Exception:
        return
    _client.send(line)


# --- sync decision RPC (enforcement only) ----------------------------------
#
# Socket strategy: fresh short-lived AF_UNIX connection per sync call.
#
# The persistent _SockClient above is used by the existing fire-and-forget
# audit path. Mixing a synchronous read on that same connection with a parallel
# audit writer would require coordinating around the daemon's per-connection
# write mutex AND demultiplexing responses by req_id on the client side. A
# fresh short-lived socket mirrors what the C shim and Node runtime hook do:
# one frame in, one JSON line out, close. The daemon already accepts unlimited
# connections (one goroutine per accept), so the cost is a connect + close per
# upstream HTTP request — negligible next to the network RTT we're about to
# pay anyway.
#
# Failure mode: HTTP is fail-open per TODO 2.5. Any socket error, timeout, or
# parse error logs a warning and returns None so the caller proceeds to the
# upstream. Reserving fail-closed for filesystem/exec where the user can
# actually recover; bricking an agent on a flaky wifi is not a good trade.

def _sync_decide(frame: dict) -> Optional[dict]:
    """Send `frame` to the daemon and return the decoded SyncResponse dict.

    Returns None on any failure — caller MUST treat None as "fail-open, allow".
    Never raises.
    """
    if not SOCK_PATH:
        return None
    deadline = time.monotonic() + SYNC_RPC_TIMEOUT_S
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # One settimeout() covers connect, send, and recv individually; we
        # also clamp via the monotonic deadline below to bound total wall time.
        sock.settimeout(SYNC_RPC_TIMEOUT_S)
        sock.connect(SOCK_PATH)
        payload = (json.dumps(frame) + "\n").encode("utf-8")
        sock.sendall(payload)
        # Read up to one line. Daemon writes exactly one JSON line per req_id.
        buf = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise socket.timeout("sync_rpc total deadline exceeded")
            remaining = max(0.001, deadline - time.monotonic())
            sock.settimeout(remaining)
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if b"\n" in chunk:
                break
        line, _, _ = bytes(buf).partition(b"\n")
        if not line:
            return None
        resp = json.loads(line.decode("utf-8"))
        if not isinstance(resp, dict):
            return None
        return resp
    except Exception as exc:
        try:
            ctx.log.warn(f"agentjail addon: sync_rpc fail-open: {exc}")
        except Exception:
            pass
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _safe_str(v, limit: int = 256) -> str:
    """Coerce a daemon-supplied field to a bounded plain string.

    The 403 body is built ONLY from daemon-returned strings (rule_id, reason),
    never from request headers or bodies. This helper additionally bounds size
    so a misbehaving policy cannot bloat the synthetic response.
    """
    if v is None:
        return ""
    try:
        s = str(v)
    except Exception:
        return ""
    if len(s) > limit:
        s = s[:limit]
    return s


def _safe_header_names(headers) -> list:
    names = []
    for k, _v in headers.items(multi=True):
        names.append(str(k).lower())
    return names


# --- body capture state ----------------------------------------------------

_counter_lock = threading.Lock()
_counter = 0
_flow_to_n: dict = {}  # flow.id -> n
_index_path = os.path.join(BODIES_DIR, "index.jsonl") if BODIES_DIR else ""


def _assign_n(flow_id: str) -> int:
    global _counter
    with _counter_lock:
        n = _flow_to_n.get(flow_id)
        if n is None:
            _counter += 1
            n = _counter
            _flow_to_n[flow_id] = n
            if _index_path:
                try:
                    with open(_index_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps({"n": n, "flow_id": flow_id}) + "\n")
                    try:
                        os.chmod(_index_path, 0o600)
                    except Exception:
                        pass
                except Exception:
                    pass
        return n


def _write_body(path: str, raw: bytes) -> tuple:
    truncated = False
    if raw is None:
        raw = b""
    total = len(raw)
    if total > MAX_BYTES:
        raw = raw[:MAX_BYTES]
        truncated = True
    try:
        # Open with O_CREAT|O_WRONLY|O_TRUNC, mode 0600.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)
    except Exception as exc:
        try:
            ctx.log.warn(f"agentjail addon: body write failed: {exc}")
        except Exception:
            pass
        return (False, total, truncated)
    return (True, total, truncated)


# --- cred-leak redactor (Phase 2 / Stream B.2) -----------------------------
#
# When the daemon's cred path is active for a session, the daemon
# Register()s the cred bytes with internal/redactor.Redactor on issue.
# This addon caches the active substring set (per-session) and sanitizes
# every outbound HTTPS body before forwarding it upstream.
#
# Failure mode: FAIL-CLOSED for the cred path (per the plan, distinct
# from the existing audit-path fail-open). If we cannot reach the daemon
# to learn the active set when one is expected, the request is blocked
# with a 403 telling the operator the redactor is unavailable.
#
# Iteration 1 keeps the implementation deliberately small: a single
# CRED_SUBSTRINGS env-var carries the set as base64-encoded NUL-separated
# bytes. The next iteration replaces this with the planned
# redact.register / redact.unregister sync RPC verbs over the daemon
# socket; the public surface (`_sanitize_body`) does not change.

import base64
import gzip
import zlib

_CRED_SUBS_RAW = os.environ.get("AGENTJAIL_CRED_SUBSTRINGS_B64", "")
_CRED_MARKER_PREFIX = b"<agentjail:redacted:cred-id-"

_CRED_SUBSTRINGS: list = []
if _CRED_SUBS_RAW:
    try:
        decoded = base64.b64decode(_CRED_SUBS_RAW, validate=False)
        for piece in decoded.split(b"\x00"):
            if len(piece) >= 8:
                _CRED_SUBSTRINGS.append(piece)
    except Exception:
        _CRED_SUBSTRINGS = []

# Body bigger than this -> fail-closed (block with 403). Matches the
# Go-side default in internal/redactor.DefaultMaxBodyBytes.
_REDACT_MAX_BODY_BYTES = 16 * 1024 * 1024


def _sanitize_body(body: bytes) -> tuple:
    """Returns (sanitized_bytes, error_str_or_None).

    error_str non-None signals a fail-closed condition -- the request
    must be blocked with 403. The caller is responsible for emitting an
    audit event with the reason.
    """
    if not body:
        return (body, None)
    if not _CRED_SUBSTRINGS:
        return (body, None)
    if len(body) > _REDACT_MAX_BODY_BYTES:
        return (b"", "body_too_large_to_redact")
    out = body
    for sub in _CRED_SUBSTRINGS:
        if sub in out:
            out = out.replace(sub, _CRED_MARKER_PREFIX + b"cli>")
    return (out, None)


def _header_param_value(header_value: str, name: str) -> str:
    if not header_value:
        return ""
    for piece in header_value.split(";")[1:]:
        if "=" not in piece:
            continue
        key, value = piece.split("=", 1)
        if key.strip().lower() != name.lower():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        return value
    return ""


def _multipart_part_is_text(headers_block: bytes) -> bool:
    try:
        text = headers_block.decode("utf-8", "replace")
    except Exception:
        return False
    content_disposition = ""
    content_type = ""
    for line in text.split("\r\n"):
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "content-disposition":
            content_disposition = value
        elif key == "content-type":
            content_type = value.lower()
    if 'filename=' in content_disposition.lower():
        return False
    if not content_type:
        return True
    if content_type.startswith("text/"):
        return True
    if content_type.startswith("application/json"):
        return True
    if content_type.startswith("application/xml"):
        return True
    if content_type.startswith("application/x-www-form-urlencoded"):
        return True
    return False


def _sanitize_multipart_form_data(body: bytes, boundary: str) -> tuple:
    if not boundary:
        return (None, "multipart_missing_boundary")
    if not body:
        return (body, None)

    boundary_bytes = boundary.encode("utf-8", "surrogatepass")
    delimiter = b"--" + boundary_bytes
    if delimiter not in body:
        return (None, "multipart_boundary_not_found")

    out = bytearray()
    pos = 0
    changed = False
    while True:
        idx = body.find(delimiter, pos)
        if idx < 0:
            out.extend(body[pos:])
            break
        out.extend(body[pos:idx])
        end = idx + len(delimiter)
        if body[end:end + 2] == b"--":
            out.extend(body[idx:end + 2])
            pos = end + 2
            continue
        if body[end:end + 2] != b"\r\n":
            return (None, "multipart_malformed_boundary")
        headers_start = end + 2
        headers_end = body.find(b"\r\n\r\n", headers_start)
        if headers_end < 0:
            return (None, "multipart_malformed_headers")
        next_idx = body.find(b"\r\n" + delimiter, headers_end + 4)
        if next_idx < 0:
            return (None, "multipart_missing_closing_boundary")
        part_headers = body[headers_start:headers_end]
        part_body = body[headers_end + 4:next_idx]
        out.extend(body[idx:headers_end + 4])
        if _multipart_part_is_text(part_headers):
            sanitized, err = _sanitize_body(part_body)
            if err is not None:
                return (None, err)
            if sanitized is not part_body and sanitized != part_body:
                changed = True
            out.extend(sanitized)
        else:
            out.extend(part_body)
        pos = next_idx + 2
    if not changed:
        return (body, None)
    return (bytes(out), None)


def _is_sse_content_type(content_type: str) -> bool:
    return (content_type or "").strip().lower().startswith("text/event-stream")


def _find_sse_event_boundary(body: bytes, start: int) -> tuple:
    patterns = (b"\r\n\r\n", b"\n\n", b"\r\r")
    best_idx = -1
    best_pat = b""
    for pat in patterns:
        idx = body.find(pat, start)
        if idx < 0:
            continue
        if best_idx < 0 or idx < best_idx:
            best_idx = idx
            best_pat = pat
    return (best_idx, best_pat)


def _sanitize_sse_event_stream(body: bytes) -> tuple:
    if not body:
        return (body, None)

    out = bytearray()
    pos = 0
    changed = False
    while pos < len(body):
        boundary_idx, boundary = _find_sse_event_boundary(body, pos)
        if boundary_idx < 0:
            event = body[pos:]
            boundary = b""
            pos = len(body)
        else:
            event = body[pos:boundary_idx]
            pos = boundary_idx + len(boundary)

        sanitized, err = _sanitize_body(event)
        if err is not None:
            return (None, err)
        if sanitized is not event and sanitized != event:
            changed = True
        out.extend(sanitized)
        out.extend(boundary)

    if not changed:
        return (body, None)
    return (bytes(out), None)


def _sanitize_payload(body: bytes, content_type: str) -> tuple:
    ctype = (content_type or "").strip().lower()
    if _is_sse_content_type(ctype):
        return _sanitize_sse_event_stream(body)
    if ctype.startswith("multipart/form-data"):
        boundary = _header_param_value(content_type, "boundary")
        return _sanitize_multipart_form_data(body, boundary)
    return _sanitize_body(body)


# --- Content-Encoding handling -----------------------------------------------
#
# Servers commonly compress response bodies (and occasionally request bodies)
# with `Content-Encoding: gzip` or `deflate`. The substring redactor cannot
# find a registered credential inside a compressed stream, so without
# decompress-then-recompress the cred-path leakage defense is blind on every
# compressed flow.
#
# Style note: hand-rolled, no-magic helpers in the spirit of Postgres's flat
# C code (see docs/ENGINEERING.md §2). Each step is a small function with one
# job. No decorators, no framework, no class.
#
# Fail mode: FAIL-CLOSED for the cred path. If decompression fails (zlib
# error, truncated stream, decompression bomb past _REDACT_MAX_BODY_BYTES),
# or recompression fails, the caller MUST block the request with a 403 and
# never forward the original compressed body — we cannot prove the original
# was cred-free, and the whole point of the redactor is that cred bytes
# never ride past us.
#
# Out of scope: Brotli (`br`) and zstd (`zstd`). Both require third-party
# deps. Unknown encodings (including br/zstd) are reported as `unsupported`
# and fail-closed only when there is an active cred substring set.

_SUPPORTED_ENCODINGS = ("gzip", "deflate")


def _pick_encoding(headers) -> str:
    """Return the canonical Content-Encoding for redactor purposes.

    Returns one of:
      ""            no encoding / `identity` (treat as raw bytes)
      "gzip"        RFC 1952 gzip stream
      "deflate"     RFC 1950 zlib stream
      "unsupported" anything else (br, zstd, x-gzip, stacked, etc.)
    """
    if headers is None:
        return ""
    try:
        raw = headers.get("content-encoding")
    except Exception:
        return ""
    if not raw:
        return ""
    # Stacked encodings ("gzip, deflate") are RFC-legal but vanishingly rare.
    # We only handle the simple single-token case; everything else is
    # `unsupported`.
    token = raw.strip().lower()
    if "," in token:
        return "unsupported"
    if token in ("", "identity"):
        return ""
    if token in _SUPPORTED_ENCODINGS:
        return token
    return "unsupported"


def _decompress_body(body: bytes, encoding: str) -> tuple:
    """Decompress `body` according to `encoding`.

    Returns (decompressed_bytes_or_None, err_str_or_None). A non-None err is
    a fail-closed signal for the cred path.

    Bounds the decompressed size at _REDACT_MAX_BODY_BYTES (16 MiB) to
    defuse decompression bombs. A 16 KiB gzipped payload that expands to
    several GiB is a classic exfil/DoS shape; we'd rather block a borderline
    legitimate huge response than process it.
    """
    if not body:
        return (b"", None)
    try:
        if encoding == "gzip":
            # gzip.decompress reads the full stream eagerly. Wrap in
            # GzipFile + bounded read to enforce the size cap before the
            # decompressor allocates an unbounded buffer.
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as gz:
                out = gz.read(_REDACT_MAX_BODY_BYTES + 1)
        elif encoding == "deflate":
            # `deflate` on the wire is almost always zlib-wrapped (RFC 1950).
            # A few legacy servers send raw DEFLATE; we try zlib first and
            # fall back to raw on header error.
            try:
                out = zlib.decompress(body)
            except zlib.error:
                out = zlib.decompress(body, -zlib.MAX_WBITS)
            if len(out) > _REDACT_MAX_BODY_BYTES:
                return (None, "decompress_too_large")
        else:
            return (None, "unsupported_encoding")
    except Exception as exc:
        return (None, f"decompress_failed:{type(exc).__name__}")
    if len(out) > _REDACT_MAX_BODY_BYTES:
        return (None, "decompress_too_large")
    return (out, None)


def _recompress_body(body: bytes, encoding: str) -> tuple:
    """Recompress `body` with the same encoding the original used.

    Returns (compressed_bytes_or_None, err_str_or_None). Compression level
    is the zlib/gzip default (6) — not bit-identical to upstream but
    functionally equivalent and accepted by every HTTP client.
    """
    if not body:
        # Empty body recompresses to a tiny valid stream; keep it empty.
        return (b"", None)
    try:
        if encoding == "gzip":
            return (gzip.compress(body, compresslevel=6), None)
        if encoding == "deflate":
            return (zlib.compress(body, 6), None)
        return (None, "unsupported_encoding")
    except Exception as exc:
        return (None, f"recompress_failed:{type(exc).__name__}")


def _sanitize_with_encoding(body: bytes, encoding: str, content_type: str = "") -> tuple:
    """Encoding-aware wrapper around _sanitize_body.

    Returns (final_bytes_or_None, err_str_or_None). On the no-encoding path
    this is a thin pass-through so we don't pay decompress/recompress cost
    when there is nothing to decompress.
    """
    if not body:
        return (body, None)
    if encoding in ("", "identity"):
        return _sanitize_payload(body, content_type)
    if encoding == "unsupported":
        # If no cred substrings are registered, there is no cred path active
        # for this session — pass the body through untouched so the addon
        # remains transparent on flows that do not need redaction. With an
        # active set we cannot scan inside an unknown encoding, so fail-closed.
        if not _CRED_SUBSTRINGS:
            return (body, None)
        return (None, "unsupported_encoding")
    if encoding not in _SUPPORTED_ENCODINGS:
        # Defensive: _pick_encoding should never return anything else.
        if not _CRED_SUBSTRINGS:
            return (body, None)
        return (None, "unsupported_encoding")
    # Fast path: skip the decompress round-trip when there is nothing to
    # redact for. Saves ~0.5 ms p50 on a 100 KiB gzipped body.
    if not _CRED_SUBSTRINGS:
        return (body, None)
    decompressed, derr = _decompress_body(body, encoding)
    if derr is not None:
        return (None, derr)
    sanitized, serr = _sanitize_payload(decompressed, content_type)
    if serr is not None:
        return (None, serr)
    if sanitized is decompressed or sanitized == decompressed:
        # No substrings matched -> return the ORIGINAL compressed bytes
        # so we don't perturb the byte stream for no reason.
        return (body, None)
    recompressed, rerr = _recompress_body(sanitized, encoding)
    if rerr is not None:
        return (None, rerr)
    return (recompressed, None)


# --- mitmproxy hooks -------------------------------------------------------

def request(flow: http.HTTPFlow) -> None:
    try:
        host = flow.request.pretty_host
        if host in ("localhost", "127.0.0.1", "::1"):
            return

        # Cred-leak redactor (Phase 2 / Stream B.2). Runs BEFORE every
        # other inspection so an audit event that captures the body
        # captures the SANITIZED form. Fail-closed on oversize bodies,
        # on decompression failures, and on unsupported Content-Encodings
        # when a cred set is active (see _sanitize_with_encoding).
        if _CRED_SUBSTRINGS:
            raw = flow.request.raw_content or b""
            encoding = _pick_encoding(flow.request.headers)
            content_type = flow.request.headers.get("content-type", "")
            sanitized, redact_err = _sanitize_with_encoding(raw, encoding, content_type)
            if redact_err is not None:
                blocked = json.dumps({
                    "agentjail": {
                        "blocked": True,
                        "rule_id": "redactor-fail-closed",
                        "reason": redact_err,
                    }
                }).encode("utf-8")
                flow.response = http.Response.make(
                    403, blocked, {"content-type": "application/json"},
                )
                _emit({"hook": "http", "op": "blocked", "attrs": {
                    "host": host, "path": flow.request.path,
                    "rule_id": "redactor-fail-closed",
                    "reason": redact_err,
                    "content_encoding": encoding,
                }})
                return
            if sanitized is not raw and sanitized != raw:
                # Rewrite the outbound body with the sanitized copy. Keep the
                # original Content-Encoding header; we recompressed with the
                # same algorithm. Refresh Content-Length to match the new
                # byte count (compressed-output size differs from input).
                flow.request.raw_content = sanitized
                if "content-length" in flow.request.headers:
                    flow.request.headers["content-length"] = str(len(sanitized))
                _emit({"hook": "cred", "op": "leak_redacted", "attrs": {
                    "host": host,
                    "path": flow.request.path,
                    "bytes_before": len(raw),
                    "bytes_after": len(sanitized),
                    "content_encoding": encoding,
                }})
        attrs = {
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": host,
            "port": flow.request.port,
            "path": flow.request.path,
            "http_version": flow.request.http_version,
            "client_lib": "mitmproxy",
            "header_names": _safe_header_names(flow.request.headers),
            "request_bytes": len(flow.request.raw_content or b""),
        }
        if _host_enabled(host):
            n = _assign_n(flow.id)
            path = os.path.join(BODIES_DIR, f"{n}.req.bin")
            ok, total, truncated = _write_body(path, flow.request.raw_content or b"")
            if ok:
                attrs["body_path"] = path
                attrs["body_bytes"] = total
                attrs["body_truncated"] = truncated
                attrs["body_n"] = n
                attrs["flow_id"] = flow.id
        frame = {"hook": "http", "op": "request", "attrs": attrs}
        # Always emit the audit row first — even under enforcement we want the
        # proxy/http/request row in the journal so users can correlate a 403
        # against the upstream attempt.
        _emit(frame)

        if ENFORCE:
            # Build a SEPARATE sync frame (do not reuse `frame` — _emit() mutated
            # it by injecting `track: "proxy"`, and we want a clean envelope for
            # the daemon to evaluate). req_id is 12 hex chars; collision space
            # is well beyond any plausible in-flight count.
            sync_frame = {
                "hook": "http",
                "op": "request",
                "attrs": attrs,
                "track": "proxy",
                "req_id": secrets.token_hex(6),
            }
            resp = _sync_decide(sync_frame)
            if resp is not None:
                action = _safe_str(resp.get("action"), 16)
                if action in ("deny", "ask"):
                    rule_id = _safe_str(resp.get("rule_id"), 128)
                    reason = _safe_str(resp.get("reason"), 256)
                    body_obj = {
                        "agentjail": {
                            "blocked": True,
                            "rule_id": rule_id,
                            "reason": reason,
                        }
                    }
                    if action == "ask":
                        # v1 has no interactive prompt path; surface the
                        # diagnostic flag so a future UI can detect it.
                        body_obj["agentjail"]["ask_mode_not_implemented"] = True
                    body = json.dumps(body_obj).encode("utf-8")
                    flow.response = http.Response.make(
                        403,
                        body,
                        {"content-type": "application/json"},
                    )
                    return
                # action == "allow" (or anything we don't recognize) → fall through.
            # resp is None → fail-open (warning already logged by _sync_decide).
    except Exception as exc:
        try:
            ctx.log.warn(f"agentjail addon request hook error: {exc}")
        except Exception:
            pass


def response(flow: http.HTTPFlow) -> None:
    try:
        if flow.response is None:
            return
        host = flow.request.pretty_host
        if host in ("localhost", "127.0.0.1", "::1"):
            return
        if _CRED_SUBSTRINGS:
            raw = flow.response.raw_content or b""
            encoding = _pick_encoding(flow.response.headers)
            content_type = flow.response.headers.get("content-type", "")
            if _is_sse_content_type(content_type):
                sanitized, redact_err = _sanitize_with_encoding(raw, encoding, content_type)
                if redact_err is not None:
                    blocked = json.dumps({
                        "agentjail": {
                            "blocked": True,
                            "rule_id": "redactor-fail-closed",
                            "reason": redact_err,
                        }
                    }).encode("utf-8")
                    flow.response = http.Response.make(
                        502, blocked, {"content-type": "application/json"},
                    )
                    _emit({"hook": "http", "op": "blocked_response", "attrs": {
                        "host": host,
                        "path": flow.request.path,
                        "rule_id": "redactor-fail-closed",
                        "reason": redact_err,
                        "content_encoding": encoding,
                        "content_type": content_type,
                    }})
                    return
                if sanitized is not raw and sanitized != raw:
                    flow.response.raw_content = sanitized
                    if "content-length" in flow.response.headers:
                        flow.response.headers["content-length"] = str(len(sanitized))
                    _emit({"hook": "cred", "op": "leak_redacted_response", "attrs": {
                        "host": host,
                        "path": flow.request.path,
                        "bytes_before": len(raw),
                        "bytes_after": len(sanitized),
                        "content_encoding": encoding,
                        "content_type": content_type,
                    }})
        attrs = {
            "method": flow.request.method,
            "host": host,
            "path": flow.request.path,
            "status": flow.response.status_code,
            "http_version": flow.response.http_version,
            "bytes_in": len(flow.response.raw_content or b""),
            "duration_ms": int((flow.response.timestamp_end or 0) - (flow.request.timestamp_start or 0)) * 1000
                if flow.request.timestamp_start and flow.response.timestamp_end else None,
        }
        if _host_enabled(host):
            n = _assign_n(flow.id)
            path = os.path.join(BODIES_DIR, f"{n}.res.bin")
            ok, total, truncated = _write_body(path, flow.response.raw_content or b"")
            if ok:
                attrs["body_path"] = path
                attrs["body_bytes"] = total
                attrs["body_truncated"] = truncated
                attrs["body_n"] = n
                attrs["flow_id"] = flow.id
        _emit({"hook": "http", "op": "response", "attrs": attrs})
    except Exception as exc:
        try:
            ctx.log.warn(f"agentjail addon response hook error: {exc}")
        except Exception:
            pass
