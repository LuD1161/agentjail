# 0015 — Auto-update trust model: signing, analytics, TOFU

Status: Accepted

## Context

agentjail needs a self-update mechanism (`agentjail update`). As a security
tool that enforces policy on every shell command and file write, the update
path is a high-value target: a compromised update could silently swap out
policies, replace the binary, or disable protections. Getting the update path
wrong is worse than not shipping one.

Several distinct concerns intersect here:

1. **Integrity vs. authentication.** SHA256 checksums verify that a downloaded
   file matches what the server sent; they do not prove that the server
   content was produced by the maintainer. An attacker who can rewrite a GitHub
   release asset can also rewrite its SHA256SUMS file. Integrity checking and
   signature verification are separate properties; a sound trust model requires
   both.

2. **Initial install vs. subsequent updates.** The install script runs in a
   POSIX shell environment (`install.sh`) where non-standard cryptographic
   tooling cannot be assumed. After the first install, the binary is available
   and can verify its own updates. The trust model for the two phases
   necessarily differs.

3. **Server-side analytics.** To understand the installed base (version
   distribution, OS/arch mix, growth) without requiring opt-in client telemetry,
   the update endpoint must be able to log server-side request metadata. A thin
   proxy layer in front of GitHub releases is sufficient for this.

4. **Agent self-protection.** The update flow must not be exploitable by a
   compromised agent — `agentjail update` must require a human at an interactive
   TTY and must be blocked in hook context.

## Decision

### 1. Release signing: minisign (Ed25519)

Every release includes a `SHA256SUMS` file (one `<hash>  <filename>` line per
asset) and a corresponding `SHA256SUMS.minisig` detached signature produced by
the maintainer's Ed25519 key via
[minisign](https://jedisct1.github.io/minisign/).

- **Private key held offline** by the maintainer and never stored in CI
  secrets; the signing step is a manual gate in the release process.
- **Public key embedded in the binary at build time** (a `const` in
  `internal/updater/trustedkey.go`, injected via `-ldflags` from the
  Makefile). Binary consumers verify the signature without any network fetch
  for the public key.
- **Verification library:** `github.com/jedisct1/go-minisign` — pure Go
  Ed25519 implementation, MIT license. No CGo, no additional system
  dependencies.

### 2. Update endpoint: Cloudflare Worker at `releases.agentjail.io`

A thin Cloudflare Worker at `releases.agentjail.io` sits in front of GitHub
releases and provides two routes:

| Route | Behavior |
|---|---|
| `GET /v1/latest` | Returns JSON `{version, assets: [{name, sha256, size}]}`, cached 5 min at the edge |
| `GET /download/{version}/{filename}` | 302-redirects to the GitHub release asset URL |

The Worker serves two purposes:
- **Stable URL contract:** the client always calls `releases.agentjail.io`,
  decoupling the update path from GitHub's URL structure.
- **Server-side telemetry:** Cloudflare Workers Analytics Engine records
  request count, country, agentjail version header, and OS/arch header. This
  is the only source of install-base analytics and runs entirely server-side,
  with no code on the client.

### 3. Go dependencies

Two new direct dependencies:

| Package | Purpose | License |
|---|---|---|
| `golang.org/x/mod/semver` | Canonical semver comparison for "is there a newer version?" | BSD-3-Clause |
| `github.com/jedisct1/go-minisign` | Ed25519 signature verification of `SHA256SUMS.minisig` | MIT |

`golang.org/x/mod` is stdlib-adjacent (maintained by the Go team) and already
present in many Go module graphs. `go-minisign` is pure Go with no transitive
non-stdlib dependencies. Neither introduces CGo.

As required by AGENTS.md, `make licenses` must be re-run after adding these
dependencies to keep `THIRD_PARTY_LICENSES` current.

### 4. Privacy

Server-side data collected by the Cloudflare Worker:

- Request count (time-series via Analytics Engine)
- Country (from Cloudflare's `CF-IPCountry` header)
- agentjail version (sent as `X-Agentjail-Version` request header by the client)
- OS and architecture (sent as `X-Agentjail-Platform`, e.g. `darwin/arm64`)

No PII is collected beyond IP address (processed by Cloudflare, not stored by
agentjail). No persistent user identifier is generated or sent.

**Opt-out:** setting `AGENTJAIL_NO_UPDATE_CHECK=1` disables all passive
version checks (the background check that runs at startup) and suppresses
platform headers on any explicit `agentjail update` invocation that the user
still chooses to run. This variable and its effect are documented in README.md.

The telemetry model is disclosed in `README.md` and `docs/TELEMETRY.md`.

### 5. Trust model: TOFU (Trust On First Use)

The initial install (via `install.sh | sh`) operates under a different trust
model than subsequent updates:

**Initial install (TOFU):**
- `install.sh` fetches the binary and its SHA256 from GitHub releases over
  TLS, verifies the checksum, and installs.
- POSIX shell cannot reasonably verify a minisign signature without assuming
  the availability of the `minisign` binary, which breaks the "zero
  prerequisites" install story.
- Initial trust is therefore anchored to: GitHub account security +
  Cloudflare TLS certificate + SHA256 integrity check. This is the same
  model used by Homebrew, Rustup, and most comparable tools.
- A compromised initial install (e.g. a GitHub account takeover that replaces
  the release asset before download) cannot be remediated by the update
  mechanism — the embedded public key in the binary would itself be wrong.
  This limitation is inherent to TOFU and is documented, not mitigated.

**Subsequent updates (`agentjail update`):**
- The running binary calls `/v1/latest`, compares semver, fetches the new
  binary and `SHA256SUMS` + `SHA256SUMS.minisig` via the Worker.
- SHA256 of the downloaded binary is verified against `SHA256SUMS`.
- `SHA256SUMS.minisig` is verified against the embedded public key using
  `go-minisign`. **Both checks must pass**; either failure aborts the update.
- The old binary is preserved at `<path>.bak` until the new binary starts
  successfully.

### 6. Agent self-protection

The update command is explicitly guarded against agent execution:

- **Interactive TTY required.** `agentjail update` reads confirmation from
  `/dev/tty` directly. It refuses to proceed if `stdin` is not a TTY, so a
  non-interactive agent invocation (typical of hook context) cannot complete
  the update.
- **OPA policy gate.** `command_policy` gains an always-on rule
  (`command_policy/no_self_update_in_hook`) that denies `agentjail update` and
  `agentjail upgrade` when evaluated in hook context
  (`input.hook_context == true`). This rule is part of the self-protection
  locked set defined in ADR 0014 — it cannot be disabled via `disabled_rules`.

## Consequences

- **Release process change:** every release must include `SHA256SUMS` and
  `SHA256SUMS.minisig`. The release checklist and `Makefile` release target
  must enforce this; a release without the signature file will cause all
  update clients to reject the new version.
- **Two new Go dependencies** (`golang.org/x/mod/semver`,
  `jedisct1/go-minisign`) require `make licenses` to be re-run and
  `THIRD_PARTY_LICENSES` to be updated.
- **Cloudflare Worker must be deployed** before `agentjail update` can
  function in production. The Worker configuration is maintained in a
  separate `workers/` directory (not the main Go module). Until the Worker is
  deployed, update checks fail gracefully (non-fatal warning, binary
  unchanged).
- **TOFU limitation is accepted and documented.** The same limitation applies
  to Homebrew, Rustup, and virtually every other "curl | sh" distributed
  tool. The appropriate mitigations (GitHub 2FA, branch protection,
  release tag signing via `git tag -s`) are operational controls on the
  maintainer side, not properties of this ADR.
- **No anonymous persistent identifier.** Not collecting one keeps the privacy
  story simple and the opt-out meaningful; the cost is that session-level
  analytics (returning vs. new installs) are not available.

## Amendment: Daemon-Side Update Notifications (2026-06-21)

The daemon now makes passive version-check network requests every ~6 hours
(previously: CLI-only, on invocation, throttled to once per 24h). This changes
the network profile but NOT the trust model: the daemon only notifies the user
via an OS notification; it never downloads or replaces binaries automatically.
The user must still explicitly run `agentjail update` to apply the update.

The `AGENTJAIL_NO_UPDATE_CHECK` env var disables both CLI and daemon checks.
For launchd-managed daemons, set this via the plist's `EnvironmentVariables`
dict.
