# Plan 030: Enforce strict bounded control frames

> **Executor instructions:** Begin only after plans 017 and 029 are reviewed
> DONE. Read the accepted menu-review ADR and current Go client/server tests.
> Harden the existing control protocol for every verb before adding the review
> dispatch. Preserve one connection per operation and existing deadlines.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the exact grantctl framing/client tests, serialized daemon decoder/reply
> paths, and handoff. Any uncommitted overlap is a STOP condition.

## Status

- **Priority:** P0
- **Effort:** M
- **Risk:** HIGH
- **Depends on:** plans 017 and 029
- **Category:** security / protocol
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

`json.Decoder(io.LimitReader(...))` does not prove a message is within the
limit: it can decode an early valid object without reading the byte beyond the
limit, and it accepts trailing values. Swift and Go need one testable framing
rule. A newline-delimited frame lets the server answer without waiting for EOF,
while a `Max+1` bounded read detects missing delimiters and oversize input.

## Protocol rule

- One connection carries one request and one response.
- Each frame is compact valid UTF-8 JSON containing no raw LF byte, plus one
  terminal `\n` delimiter. JSON string newlines remain escaped as `\\n`.
- `MaxControlMsgBytes` includes the newline.
- A reader buffers at most `MaxControlMsgBytes+1`, requires the delimiter,
  rejects invalid UTF-8, then decodes exactly one JSON value and permits only
  space, tab, or CR afterward before the delimiter.
- A second newline frame is never decoded or dispatched; the endpoint replies
  to the first and closes the connection. Normal bounded chunked I/O may read
  ahead after the first delimiter into the same fixed buffer, but those bytes
  are discarded and never become a second operation.
- Writers marshal and size-check the complete frame before writing any bytes.
- An over-limit response is replaced by one small typed `ok=false` error; no
  partial oversized JSON is sent.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Framing | `rtk go test ./internal/grantctl -run 'Test.*Frame|TestRoundTrip' -count=1` | pass |
| Server | `rtk go test ./internal/daemonapp -run 'Test.*Control.*Frame|Test.*Grant' -count=1` | pass |
| Race | `rtk go test ./internal/grantctl ./internal/daemonapp -race` | pass |
| Vet | `rtk go vet ./internal/grantctl ./internal/daemonapp` | pass |
| Build | `rtk env CGO_ENABLED=0 go build ./cmd/agentjail ./cmd/agentjail-daemon` | pass |

## Scope

**In scope:**

- new typed framing helper/test files under `internal/grantctl/`
- `internal/grantctl/client.go` and focused client tests
- the serialized decode/reply helpers in `internal/daemonapp/grantserver.go`
- focused server tests, preferably a new framing-specific test file, plus only
  existing control-socket tests mechanically affected by the frame rule
- one concise entry in `docs/GOTCHAS.md`
- `plans/macos-app/handoffs/030.md`

**Out of scope:** adding the review dispatch (plan 018), registry semantics,
control-token/auth order, proxyctl/netproxy framing, socket paths, streaming,
Swift, audit, deadlines, or a dependency.

## Git workflow

One signed local commit: `fix(grants): bound control frames`. Use the shared
lock and explicit paths. Do not push.

## Steps

### Step 1: Define typed request/response frame helpers

Add small helpers around the existing typed `Request` and `Response`, not a
generic untyped protocol. Use a bounded buffered read that stops at the first
newline and distinguishes missing delimiter, over limit, malformed JSON, and
trailing-in-frame data. Do **not** use `DisallowUnknownFields`: the envelopes
are additive wire contracts. Ignore unknown object fields while typed dispatch
rejects unknown request types and versioned handlers reject unsupported versions.

Do not use `io.ReadAll` without a `Max+1` limiter. Do not allocate based on a
caller-supplied length. Do not perform one underlying `Read` per byte: the
control socket must parse before token authentication, so a 64-KiB hostile
frame must not amplify into roughly 64,000 unauthenticated syscalls. Use fixed
bounded chunks and decode only the prefix ending at the first delimiter.

**Verify:** table tests cover empty, newline-only, exact maximum, max+1, no
newline, raw LF inside pretty-printed JSON, valid object plus SP/HTAB/CR, junk,
second JSON value before newline, invalid UTF-8, fragmented reads, and an
otherwise-valid request/response with an unknown additive field.

### Step 2: Marshal before writing

Marshal the complete typed object, append one newline, check its size, then use
a complete-write loop. A response that would exceed the cap must produce a
small constant refusal frame prepared before any bytes of the original are
written. If even the refusal cannot be encoded, close and return an error.

**Verify:** a short writer exercises partial writes; an oversized review/list
response sends one parseable refusal and no prefix of the original payload.

### Step 3: Migrate the Go client

Use the shared typed frame helpers for request and response in `roundTrip` and
`roundTripSlow`. Preserve dial/reply deadline meanings and one connection per
operation. Existing Go `json.Encoder` already wrote a newline, so the wire stays
compatible with supported in-repo clients.

**Verify:** all current grant/reload/update-audit clients pass; a fake server
tests trailing junk, two frames, overflow, partial response, and timeout. The
client consumes only the first frame and closes without treating a second frame
as another response.

### Step 4: Migrate the authenticated daemon control server

Replace only `handleCtlConn` request decoding and `reply` encoding. Keep peer
UID and token authentication before the switch exactly where they are. A
malformed/oversized frame must never reach dispatch; a spy proves zero registry,
reload, or audit calls. Sending two request frames may dispatch only the first,
then the connection closes.

Do not touch agent-facing `handleConn` or hook/policy evaluation.

### Step 5: Record the green-suite blind spot, verify, and commit

Add a concise GOTCHAS entry: `LimitReader` bounded how much a decoder could ask
for, not whether the peer sent one complete bounded frame; decode exactly one
delimited value and size-check before writing. Run focused/full race, vet, and
CGO-disabled builds. Diff authentication/dispatch order in the handoff, then
commit owned files under the lock.

## Done criteria

- [ ] Request/response frames have one newline-delimited, 64-KiB-including-delimiter rule.
- [ ] Unknown fields remain additive-compatible while unknown type/version is rejected.
- [ ] Oversize, missing delimiter, malformed, and trailing-in-frame data fail before dispatch.
- [ ] A second frame is never decoded, dispatched, or interpreted as a second response.
- [ ] Reading is chunked and bounded; no per-byte underlying read loop exists before authentication.
- [ ] Writers size-check before emitting bytes; oversized responses are one bounded refusal.
- [ ] Token authentication remains before every dispatch case and hot path is untouched.
- [ ] Existing verbs, race, vet, and CGO-disabled builds pass.
- [ ] GOTCHAS records why a green single-decode test did not enforce framing.
- [ ] Signed local commit contains only owned paths.

## STOP conditions

- A safe frame requires EOF/half-close and would deadlock an existing supported client.
- Strict decoding would break documented additive compatibility.
- Authentication must move below dispatch or agent-facing framing must change.
- The fix expands into proxyctl/netproxy or requires a dependency.

## Maintenance notes

Keep `MaxControlMsgBytes` a property of the complete wire frame, not merely the
decoder's willingness to stop reading. Future control verbs inherit these
helpers by construction.
