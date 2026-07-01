# ADR 0037: macOS keychain access for the shielded agent

- **Status:** Accepted
- **Date:** 2026-06-30
- **Deciders:** agentjail-core
- **Related:** [ADR 0001](0001-os-sandbox-enforcement-layer.md) (OS sandbox), [ADR 0025](0025-layered-self-protection.md) (layered self-protection), [ADR 0034](0034-platform-backend-shared-contract.md) (per-OS shared contract)

## Context

`agentjail-shield` sandboxes coding agents on macOS via Apple Seatbelt
(`sandbox-exec`). The darwin profile uses `(allow default)` plus explicit
deny lists. Until now, `~/Library/Keychains` was in both the file-read-deny
and file-write-deny lists in `sensitiveReadPaths` / `sensitiveWritePaths`
(`cmd/agentjail-shield/shield_darwin.go`).

This blocked Claude Code login ("Not logged in") because Claude reads its
OAuth credential from `~/Library/Keychains/login.keychain-db` via the legacy
`SecKeychain` file-based API.

Denying only the file path is not a coherent sandbox posture, because macOS
keychain access has two independent paths into the same data:

1. **File path** -- direct reads of the keychain database files
   (`login.keychain-db`, its `-wal`/`-shm` companions). Seatbelt file-read/
   file-write rules gate this path.
2. **Mach IPC path** -- modern `Security.framework` / `SecItem*` calls do not
   read the DB file directly; they talk to `securityd`/`SecurityServer` over
   Mach IPC, which then reads the file on the caller's behalf.

Under `(allow default)`, Mach services are already allowed unless explicitly
denied. So the prior configuration was the **worst quadrant**: file-read
denied (blocks Claude's legacy `SecKeychain` file path) while Mach is wide
open (does **not** stop a modern `Security.framework` caller). It broke the
legitimate flow while providing no real containment against a determined
Mach-IPC caller.

This matches the finding in the [nono](https://github.com/nolabs-ai/nono)
reference sandbox's security-model documentation: the keychain must be
treated as a single coherent gate -- the file grant and the Mach grant have to
move together, not be decided independently. nono's own history records
that a narrow "only the two `login.keychain-db*` files" grant was
empirically unreliable for token refresh (commit `3c8b675`), so nono grants
the whole user `~/Library/Keychains` root for its `claude-code` profile -- the
system keychain is never included in that grant.

## Decision

Enable the **user keychain root** (`~/Library/Keychains`, read+write) by
default for the shielded agent's own process, by removing it from
`sensitiveReadPaths` and `sensitiveWritePaths` in `shield_darwin.go`. Under
`(allow default)`, removing a path from the deny list is what grants it -- no
new explicit `(allow ...)` rule is needed for the user keychain root itself.

We reject the narrower "grant only `login.keychain-db` + its `-wal`/`-shm`
companions" alternative. nono tried this first and found it unreliable for
Claude's token-refresh flow (files are created/rotated in ways a static
two-file allowlist misses). Matching nono's `claude-code` profile -- the
whole user keychain root, never the system keychain -- is the option with a
working precedent.

The **hardened opt-out** (denying both the file path *and* the four keychain
Mach services -- `com.apple.SecurityServer`, `com.apple.securityd`,
`com.apple.security.keychaind`, `com.apple.secd` -- plus
`com.apple.security.agent`) is deferred to a follow-up. Tracked as
[AGE-94](https://linear.app/agentjail/issue/AGE-94) in Linear.

The system keychains (`/System/Library/Keychains`, `/Library/Keychains` --
no home prefix) are untouched by this change: they were already read-allowed
via existing carve-outs and were never in the write-deny list to begin with;
macOS file permissions and SIP guard writes to them, not an SBPL deny rule
we define.

## Consequences

**Positive:**
- Claude Code login and claude.ai MCP connector auth work again inside the
  shield on macOS.
- The read+write grant is symmetric with Mach, closing the "worst quadrant"
  gap: an agent that can reach the keychain via Mach can now also reach it
  via the file path, and vice versa -- no more asymmetric, easily-confused
  posture.

**Negative / residual risk (precise accounting):**
- Mach services (`securityd`/`SecurityServer`) were already allowed under
  `(allow default)` before this change. A `Security.framework` caller inside
  the shielded process can obtain **plaintext** keychain items, subject only
  to `securityd`'s per-item ACL. Protection for keychain contents now rests
  on securityd's ACL layer, **not** the shield -- this was already true before
  this ADR (Mach was already open); this decision does not newly open that
  path, but it does mean the file-level denial is no longer providing a
  false sense of coverage on that path.
- Raw file reads of the keychain DB still yield ciphertext (SQLite pages are
  encrypted at rest), but the Mach route is the realistic path for extracting
  secrets and it is open regardless of this decision.
- The **write** grant adds tamper/data-loss risk beyond the pre-existing Mach
  exposure: a hook-bypassing subprocess (raw syscalls, not going through the
  agent's tool-call interface) could corrupt the keychain DB/WAL/SHM files
  directly. Token refresh requires write access, so this is accepted as the
  cost of a working login flow.
- Offline brute-force of the keychain DB file (if exfiltrated) and metadata
  leakage (item labels/attributes, which are not always encrypted) remain
  residual risks independent of this change.

**Layered defense retained:**
- This decision only changes what the **shield** (Tier 1.5, kernel/SBPL
  boundary) permits for the shielded agent's *own* process launching Claude
  Code. The **hook** layer (`file_policy.rego`, `command_policy.rego`) is
  unchanged and still denies an agent's explicit tool-driven access, e.g. a
  `Read` tool call or a `cat ~/Library/Keychains/login.keychain-db` Bash
  command. The shield lets Claude's internal auth flow through; the hook
  still blocks visible, agent-initiated direct reads of the same path. This
  is consistent with the layered model in
  [ADR 0025](0025-layered-self-protection.md): each layer has a distinct,
  named role, and the hook remains the signal/UX layer for direct agent
  requests even where the shield now permits the underlying OS-level access
  for the host process.

**Follow-ups:**
1. [AGE-94] Hardened opt-out flag that denies both the keychain file path and
   the four keychain-related Mach services plus `com.apple.security.agent`,
   for users who don't need Claude Code's keychain-based auth (e.g. API-key-
   only setups).
