# Plan 020: Build the Swift Unix-socket review client

> **Executor instructions:** Plans 017 and 019 must be reviewed DONE. Parallel
> implementation may begin after the orchestrator acknowledges plan 030's
> exact claim because its normative frame rule is already locked; plan 020
> cannot be reviewed DONE until plan 030 lands and its implementation/handoff
> has been cross-checked. Read the Go fixture, accepted ADR, `AGENTS.md`, and
> coordination protocol. Plan 030 is the framing authority; mirror it exactly.
> Implement Foundation/Darwin only; no third-party package.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the exact new Models/Transport/test paths and handoff. Read, but never
> claim, the Go fixture. Existing uncommitted Models/Transport work is a STOP.

## Status

- **Priority:** P0
- **Effort:** M
- **Risk:** MED
- **Depends on:** plans 017, 019, and 030
- **Category:** app / security
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

The app needs a narrow typed client for the existing authenticated Unix socket.
The client handles a bearer token that shielded agents cannot read, so token
lifetime, bounded I/O, error classification, and wire compatibility are
security properties. A testable core client keeps those concerns out of
SwiftUI and notification callbacks.

## Current state

Plan 017 defines the v1 JSON contract and golden fixture in
`internal/grantctl/testdata/review_snapshot_v1.json`. The Go client uses a
64-KiB limited decoder and bounded deadlines in
`internal/grantctl/client.go:11-45`. The human CLI loads
`~/.agentjail/control.token` before each operation at
`cmd/agentjail/cmd_grants.go:118-137`. Plan 019 supplies a dependency-free
Swift package but deliberately has no models or transport.

Plan 030 supplies the normative one-newline-frame rule, including exact size,
invalid-UTF-8, additive-field, and second-frame behavior. Swift may implement
against that locked contract in parallel, but must cross-check the landed Go
helpers/tests before handoff and match the reviewed implementation exactly.

The default paths are:

```text
~/.agentjail/control.token
~/.agentjail/run/daemon-ctl.sock
```

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Swift tests | `rtk swift test --package-path macos/AgentjailApproval --filter Transport` | all transport tests pass |
| Full Swift | `rtk swift test --package-path macos/AgentjailApproval` | pass |
| Build | `rtk swift build --package-path macos/AgentjailApproval --product AgentjailApproval` | pass with Swift 6 checks |
| Secret scan | `rtk rg -n 'UserDefaults|Keychain|SecItem|print\(|NSLog|os_log|SQLite|agentjail.db' macos/AgentjailApproval/Sources/AgentjailApprovalCore/Models macos/AgentjailApproval/Sources/AgentjailApprovalCore/Transport` | no production matches |

## Scope

**In scope:**

- `macos/AgentjailApproval/Sources/AgentjailApprovalCore/Models/**`
- `macos/AgentjailApproval/Sources/AgentjailApprovalCore/Transport/**`
- `macos/AgentjailApproval/Tests/AgentjailApprovalCoreTests/Models/**`
- `macos/AgentjailApproval/Tests/AgentjailApprovalCoreTests/Transport/**`
- `plans/macos-app/handoffs/020.md`

**Out of scope:** `Package.swift`, app entry, state/UI/notifications, Go source,
database access, policy writes, Keychain/UserDefaults, shelling out to the CLI,
or a persistent socket/token.

## Git workflow

One signed local commit: `feat(macos): add approval control client`. Use the
shared commit lock and explicit file staging. Do not push.

## Steps

### Step 1: Mirror the v1 domain types

Create Swift `Codable`, `Sendable`, equatable types matching the Go fixture
exactly. Use named enums for review kind and approval scope; unknown values and
protocol versions are typed errors, not silently mapped to project-host.
Represent Unix milliseconds without floating-point loss and provide derived
`Date` values only at the presentation boundary.

Load the canonical Go fixture directly in tests using a repository-relative
path derived from `#filePath`. Do not copy or edit it; plan 017 is its sole
owner and plan 026 will add a semantic drift gate.

**Verify:** fixture decodes and re-encodes to the expected semantic object; a
missing required field, unknown enum, and future version each fail, while an
unknown additive object field is tolerated.

### Step 2: Define the consumer-owned interface and errors

Define a `ReviewControlling: Sendable` protocol with async methods:

- fetch v1 snapshot;
- approve a review ID;
- deny a review ID.

Define errors that let state/UI distinguish token missing/unreadable,
unauthorized, daemon unavailable, timeout, protocol mismatch, server refusal,
malformed reply, and oversize reply. Preserve the server's bounded refusal text
for display but never include request JSON or token.

**Verify:** tests exhaustively map fake transport outcomes to the typed errors.

### Step 3: Implement per-request token loading

Add an injected token loader for tests and a production loader that reads the
existing file and validates the current ctlauth contract: exactly 64 lowercase
hex characters after surrounding-whitespace trim. It returns the token only to
the request method. The client object must not store the token as a property or
persist it anywhere. Keep it scoped to the round trip; do not claim memory
zeroization Swift cannot guarantee.

**Verify:** a spy proves the loader is called once per request, token rotation
between requests is honored, and no model/error description contains it.

### Step 4: Implement bounded Unix-domain I/O

Use Darwin POSIX Unix sockets in an injected transport. Requirements:

- explicit `sockaddr_un` path-length validation;
- bounded connect/send/receive deadline (3 seconds total for normal verbs);
- handle partial writes and interrupted syscalls;
- send one newline-terminated JSON value and read exactly one
  newline-terminated JSON response, with the delimiter included in a hard
  64-KiB ceiling;
- reject a missing delimiter, an over-limit frame, and non-whitespace bytes
  after the single JSON value within the frame; close after the first frame so
  a second frame is never processed;
- reject invalid UTF-8 and any raw LF before the one terminal delimiter; writers
  emit compact JSON and escape string newlines;
- close the descriptor on every path;
- perform blocking syscall work off the main actor;
- no retry of mutation verbs after an ambiguous write/read failure;
- one new connection per operation, matching the Go server contract.

Do not use `Process`, `/usr/bin/nc`, a shell, or the web UI.

**Verify:** a fake Unix server covers partial reads/writes, delayed timeout,
disconnect before reply, 64-KiB exact/overflow, missing newline, valid JSON plus
trailing junk, a second frame, bad socket path, malformed JSON, `ok=false`, and
success for snapshot/approve/deny.

### Step 5: Prove mutation semantics

Approve/deny send only protocol fields, token, and review/grant ID. They do not
send host, project path, session ID, reason, or policy content. A server refusal
is returned exactly once; the client never converts it to success or retries.

**Verify:** fake server asserts request keys and counts one request per action.

### Step 6: Verify and commit

Run filtered/full Swift tests, build, scans, write the handoff, and commit under
the shared lock.

## Done criteria

- [ ] Swift models decode Go v1 fixture exactly and reject unknown versions/enums.
- [ ] Token is loaded per request and never stored/logged/persisted.
- [ ] Unix I/O is deadline- and size-bounded with complete cleanup.
- [ ] Mutations carry ID only and are never automatically retried.
- [ ] Typed errors distinguish empty queue from unavailable/unauthorized/unsupported.
- [ ] Tests and Swift 6 build pass with no external dependency.
- [ ] Signed local commit touches only owned paths.

## STOP conditions

- Go fixture/contract changed after plan 017 review.
- Correct bounded I/O needs a third-party library or Package.swift edit.
- A platform API requires storing the token outside request scope.
- The daemon expects persistent/multi-message connections.

## Maintenance notes

The transport is intentionally boring: connect, one request, one response,
close. Any retry policy belongs in the state layer, and mutation retries must
remain user-driven because a lost reply may follow a committed decision.
