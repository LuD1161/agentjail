# ADR 0054: macOS shield - per-user temp-dir and AF_UNIX local-socket parity

**Status:** Accepted

## Context

[ADR 0034](./0034-platform-backend-shared-contract.md) established that
per-OS shield backends must consume a single shared contract and treats
drift between `shield_linux.go` and `shield_darwin.go` as a bug -- its
cautionary example is exactly the class of issue found here: a fix that
lands cleanly on Linux but silently EPERMs on macOS.

Two concrete drifts were found empirically (via `sandbox-exec` testing on
this branch) between the Linux Landlock backend and the macOS Seatbelt
(sbpl) backend in `cmd/agentjail-shield/shield_darwin.go`:

**1. Per-user temp dir.** macOS sets `$TMPDIR` to a per-user directory of
the shape `/var/folders/<xx>/<yyy>/T`, not `/tmp`. The shield's blanket
`(deny file-write* (subpath "/private/var"))` denied writes to this
directory. Many ordinary tools write there during normal operation --
`xcrun`, compilers, and Go's own build tooling all stage files under
`$TMPDIR`. On Linux, Landlock grants `/tmp` and the current working
directory read-write, so the equivalent operations succeed there. The
result was platform drift: the same tool worked unsandboxed and worked
sandboxed on Linux, but failed with "Operation not permitted" sandboxed on
macOS.

**2. AF_UNIX local sockets.** Apple Seatbelt models AF_UNIX socket
operations as NETWORK operations: `bind()` on a unix socket is
`network-bind`, and `connect()` is `network-outbound`. The shield's
`(deny network*)` catch-all near the end of the generated profile
therefore silently denied ALL local unix-socket IPC, not just TCP egress.
Landlock on Linux governs AF_UNIX sockets through filesystem access on the
socket's inode, and Landlock's `/tmp` + cwd read-write grant lets local
unix sockets under `/tmp` work normally. This is the same class of
platform drift: local IPC tools worked on Linux and broke on macOS.

Concrete symptoms observed: Codex CLI's app-server failed to bind its
local IPC socket under the shield (`failed to initialize in-process
app-server client: Operation not permitted`, see
[ADR 0055](./0055-self-sandboxing-tool-escape-hatch.md) for the follow-on
investigation), and generic `$TMPDIR` writes from compilers/`xcrun`
failed outright.

## Decision

**Temp-dir carve-out.** After the existing `(deny file-write* (subpath
"/private/var"))` rule, emit an explicit `(allow file-write* (subpath
...))` carve-out for the validated per-user temp directory. sbpl uses
last-match-wins, so placing the allow after the deny is what makes the
carve-out effective.

- The temp dir is read from the environment and validated with a strict
  structural regex before use: `^/(private/)?var/folders/[^/]+/[^/]+/T$`.
- This is fail-closed: if the value does not match that exact shape
  (extra path segments, symlink tricks, an attempt to smuggle `/` or a
  broad tree in), no carve-out is emitted at all. We never widen the rule
  to something broader than the validated path.
- Both forms are emitted -- the canonical `/private/var/folders/...` path
  and the `/var/folders/...` symlink form -- because macOS canonicalizes
  `/var` to `/private/var` and sbpl subpath matching is not symlink-aware.

**AF_UNIX bind-broad / connect-narrow asymmetry.** Before the `(deny
network*)` catch-all, the darwin profile now allows:

- `network-bind` on a broad set: `/tmp`, `/private/tmp`, and the
  validated per-user temp dir. This restores parity with Linux, where
  binding a unix socket under `/tmp` already worked via Landlock.
- `network-outbound` (connect) only on the narrow per-user temp dir, NOT
  on `/tmp` broadly.

The asymmetry is deliberate: binding creates a new socket the sandboxed
agent controls, so a broad bind surface is low risk. Connecting reaches
into sockets that already exist and may be owned by other processes on
the same host; allowing connect only within the per-user temp dir (rather
than all of `/tmp`, which is world-writable and shared across every user
session) narrows that exposure while still covering the common case of a
tool's own IPC socket living in its own `$TMPDIR`.

**ssh-agent socket.** The shield explicitly allows `network-outbound` to
the resolved `SSH_AUTH_SOCK` path (in addition to the temp-dir rule
above), and `SSH_AUTH_SOCK` is kept in `EnvAllowlistBaseline`
(`internal/sandbox/env.go`) so it reaches the agent process. This lets
sandboxed `ssh` sign through the user's already-running ssh-agent without
ever reading the private key file -- private key file reads stay denied
by `file_policy.rego`'s `SensitiveFilePatterns` regardless. See the
[SSH and ssh-agent](../SANDBOX.md#ssh-and-ssh-agent) section of
`docs/SANDBOX.md` for the user-facing flow, and `agentjail doctor` /
the hook's one-shot advisory for the UX that nudges a user toward loading
the key into the agent (`ssh-add --apple-use-keychain <key>` on macOS)
instead of ever suggesting a key-file read hole.

**Contrast with a comparable macOS Seatbelt sandbox.** [a comparable macOS Seatbelt sandbox](https://github.com/a comparable macOS Seatbelt sandbox) is a
comparable macOS Seatbelt sandbox, but it takes the opposite base
posture: deny-default, requiring an explicit `(allow system-socket
(socket-domain AF_UNIX))` just to permit any unix socket at all. For the
"ssh key not loaded in the agent" case, a comparable macOS Seatbelt sandbox's guidance misdirects the
user toward granting the key FILE. agentjail's shield stays allow-default
at the base layer and deliberately never widens credential-file reads --
the UX always points at loading the key into ssh-agent instead.

## Consequences

- Platform parity restored for local unix-socket IPC and per-user temp
  writes: tools that already worked unsandboxed and worked sandboxed on
  Linux now also work sandboxed on macOS.
- Codex CLI's app-server AF_UNIX bind now succeeds under the shield. Its
  separate, intermittent init-time EPERM (credential-shaped file reads
  during startup) is a distinct issue tracked in
  [ADR 0055](./0055-self-sandboxing-tool-escape-hatch.md) -- this ADR
  fixes the AF_UNIX symptom, not the full class of nested-sandbox
  failures.
- **Residual boundary (not zero-risk):** the `network-outbound` allow
  within the per-user temp dir permits the sandboxed agent to `connect()`
  to ANY pre-existing same-user unix socket living in that directory --
  for example a same-user local proxy or dev tool someone else already
  started there. This is materially narrower than allowing connect
  across all of `/tmp` (world-writable, shared across every user on the
  host), but it is not zero exposure. It is accepted under the current
  threat model: the directory is per-user (not shared across accounts),
  and TCP egress out of the sandbox remains separately restricted by the
  port/netproxy enforcement described in `docs/SANDBOX.md`. This
  boundary should be re-evaluated if a stronger connect-time identity
  check becomes available.
- The temp-dir carve-out's fail-closed validation means an unusual
  `$TMPDIR` shape (unexpected structure, symlink games, an empty or
  malformed value) results in no carve-out being emitted at all rather
  than a broadened one -- the safe failure mode is "temp writes stay
  denied," not "grant something wider than intended."
