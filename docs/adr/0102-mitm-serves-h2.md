# 0102 - MITM serves h2

Status: Accepted

## Context

[ADR 0077](./0077-tunnel-mitm-default-and-consent.md) (D4) and [ADR
0093](./0093-sni-inspection-tier.md) shipped the MITM offering only
`http/1.1` in `tls.Config.NextProtos`, and auditing the ALPN downgrade when a
client asked for h2 ([AGE-222](../GOTCHAS.md#12-advertise-what-you-serve)).
That was the honest version of a real limitation, not a fix: gRPC and anything
pinning h2 still failed inside the tunnel, and the only escape hatch was
`--no-mitm`, which forfeits HTTP(S) policy entirely.

`golang.org/x/net/http2` was already an indirect dependency. Serving h2 for
real was deferred as AGE-223.

## Decision

`internal/mitm/mitm.go` `Handle` now offers `NextProtos: []string{"h2",
"http/1.1"}` (server preference order — Go's ALPN pick is server preference,
RFC 7301 §3.2) and branches on
`clientTLS.ConnectionState().NegotiatedProtocol` after the handshake:

- `"h2"` → `serveH2` (`internal/mitm/h2.go`), a new path.
- anything else → the existing hand-rolled HTTP/1.1 keep-alive loop,
  unchanged.

**Client leg:** `(&http2.Server{}).ServeConn(clientTLS, &http2.ServeConnOpts{
Handler: recordingHandler})`. `net/http2`'s server owns framing, flow control,
and stream multiplexing; the agent side of the tunnel never sees raw h2
frames from our code.

**Upstream leg:** one `http.Transport{TLSClientConfig: upstreamTLS,
ForceAttemptHTTP2: true}` per tunnel, shared across every h2 stream on that
tunnel (so upstream connections pool the way a real h2 client's would). Using
`http.Transport` instead of a bare `http2.Transport` means an upstream that
can't do h2 is served h1 transparently by the transport's own ALPN fallback —
no separate downgrade path to write and audit.

**Recording:** `h2RecordingHandler.ServeHTTP` (`internal/mitm/h2.go`) is a
line-for-line mirror of the h1 loop's body: buffer the request up to
`maxBodyScan` via the same `startCapture`/`bodyCapture` machinery, run
`netpolicy.RecognizeHTTP` + `Matcher.Evaluate` the same way, write the same
403 JSON body on deny, stream the upstream response through a `countingWriter`
+ `bodyCapture` tee with an explicit `Flush()` per chunk (SSE-shaped
responses must not buffer), and call `finishCaptures` + `emit` on every exit
path. One deliberate gap: response/request trailers are forwarded
best-effort (trailer field names pre-declared via `w.Header().Add("Trailer",
...)` before `WriteHeader`, values set after the body loop) but request
trailers are not exercised by any test — most HTTP APIs a coding agent talks
to don't send them.

**`noteH2Downgrade`** ([AGE-222](../GOTCHAS.md#12-advertise-what-you-serve))
moves from "client offered h2" (now the normal, honored case) to "client
offered h2 and `NegotiatedProtocol` came back something else" — a genuine TLS
stack anomaly, not the common path. `GetConfigForClient` still records the
offer (it's the only place `ClientHelloInfo.SupportedProtos` is visible); the
check against `NegotiatedProtocol` happens after `Handshake()` returns.

## Consequences

- gRPC and other h2-only clients now work inside the tunnel with policy
  enforcement intact; `--no-mitm` is no longer the only way to keep them
  working.
- Two upstream dial strategies now exist per tunnel: `tls.Dial` for h1 (one
  conn, kept for the life of the tunnel) and a pooled `http.Transport` for h2
  (opened lazily per stream, may open multiple upstream conns under
  concurrent streams). This mirrors what a real h2-capable client would do,
  but it means upstream connection count is no longer 1:1 with client tunnels
  for h2 traffic.
- `internal/mitm/alpn_test.go`'s existing tests exercise `noteH2Downgrade`
  directly and did not need to change — only the caller moved. New tests in
  `internal/mitm/h2_test.go` cover the h2 round trip, the "no downgrade notice
  for an honored h2 offer" case, and h2 policy deny.
