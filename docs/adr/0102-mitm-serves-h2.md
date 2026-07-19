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

## Streaming request bodies are not scanned for policy (AGE-223 follow-up)

`h2RecordingHandler.ServeHTTP`'s original body-buffering step
(`io.ReadAll(io.LimitReader(r.Body, maxBodyScan+1))`) assumed every request
body ends on its own. A unary request does — the client sends `END_STREAM`
right after its one DATA frame — but a client-streaming or bidirectional RPC
keeps the request stream open while it waits on a response, so `r.Body` never
reaches EOF and that `ReadAll` blocks forever. The request never reaches
upstream: a deadlock, not a slow scan.

**Decision:** `isStreamingRequest` (`internal/mitm/h2.go`) detects a request
that might not end on its own — `Content-Type` starting with
`application/grpc` (gRPC is always potentially streaming, unary included, so
every gRPC request is treated this way regardless of `Content-Length`), or
`r.ContentLength < 0` (no bounded length declared at all). For those, the
handler never buffers the body: it streams `r.Body` straight through the
existing tee-capture path (the same mechanism the `>maxBodyScan` case already
used) and calls `netpolicy.RecognizeHTTP` with a nil body slice, so
header/method/path-keyed policy (including deny) still evaluates and still
fires. A bounded body (`ContentLength >= 0`, `<= maxBodyScan`) keeps the
original pre-read-for-policy behavior unchanged.

**Consequence — stated non-coverage:** body-*content* policy (a template
matching on request body bytes) does not apply to a streaming request. This
is deliberate: the alternative is buffering an unbounded stream to scan it,
which is exactly the deadlock above with a size cap instead of none. No
deadlock beats a full body scan on a body that may never end. The body is
still captured to disk via the tee path (so it shows up in `network.db` after
the fact) — only the synchronous policy-eval-before-forward step is skipped.
See `internal/mitm/h2_streaming_test.go` (`TestH2StreamingRequestDoesNotDeadlock`,
`TestH2StreamingRequestHeaderPolicyDenyStillFires`).
