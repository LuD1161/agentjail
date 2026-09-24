# ADR 0151 — Install lifecycle

## Status

Accepted. Refines ADR 0141-unified-macos-app and the complete-removal claim in
ADR 0063-shim-fails-open-uninstall-is-total.

## Context

The native app and CLI use the same daemon, authenticated projections and
`~/.agentjail` state. They do not need a second database or a synchronization
service. They do need a shared installation contract: file presence alone does
not establish that a CLI, hook and running daemon belong to a usable deployment.
The app also passed `--with-cli-path` to a CLI that ignored it.

Uninstall removed binaries after recording hook-cleanup errors. A registration
left in a settings file, or still held by a client while settings reload, then
invoked a nonexistent executable. Tests checked the resulting files without
executing a retained command. Reopening the app could automatically install the
components again, reversing the user's explicit removal.

## Decision

### One installation and one state projection

The bundled CLI supplies an additive typed `installation` field in `status
--json`. It compares the canonical CLI/hook with its candidate payload, checks
role links, the expected service definition, policy presence and core rules, and
probes the daemon's reported version. The native UI consumes that projection
instead of inferring readiness from an executable file.

A healthy matching or supported newer installation is adopted without replacing
payloads or restarting the daemon. An older app cannot silently downgrade a newer
CLI. Explicit repair of a newer installation uses that installed CLI; unknown
identity requires resolution instead of automatic replacement. Existing policy,
history and consent remain in the canonical state directory. A newer CLI supplies
its own versioned readiness projection so an older app does not repeatedly repair
a service definition against an obsolete template. Unsupported projections show
compatibility guidance instead of offering a repair that cannot succeed.

Explicit installation also retries an absent optional broker definition when
adopting a matching deployment, without restarting the healthy daemon. Broker
setup retains its existing optional failure behavior.

Hashes describe files on disk. The existing daemon probe attests its reported
version, not a hash of its loaded executable. Two development binaries sharing
one version remain indistinguishable at that runtime boundary.

`--with-cli-path` installs the CLI environment/profile entry independently of
agent-launch shim consent. It honors the existing PATH opt-out and preserves
unrelated shell configuration. As with every shell installer, an already running
shell does not inherit a changed environment; new shells load the new entry.

### Explicit uninstall and retained commands

Stop the daemon before detaching integrations, preserving
ADR 0065-stop-the-daemon-before-unhooking. Any failed hook or IDE-wrapper cleanup
stops destructive teardown and reports the remaining configuration error.
Malformed Claude settings must return an error, not unchanged success. Remove
only owned hooks and status-line entries, including preserving foreign hooks
that share a matcher group.

Successful removal deletes operational binaries, services, policies, history,
and credentials unless credential retention was requested. It leaves only:

- `bin/agentjail-hook`, a small inert shell responder for retained registrations;
- `bin/agentjail`, a small responder for cached status-line calls; other commands
  fail, including approval, credential and agent execution commands;
- `uninstalled.json`, a versioned receipt of the user's choice.

The hook returns `{"permission":"allow"}` for the current explicit Cursor
adapter and `{}` for Claude/Codex. It discards input without logging it. These
responses withdraw AgentJail intervention; they do not approve a native prompt,
redeem a challenge, provide credentials, or preserve an enforcement claim.
The real executable is atomically replaced only through deliberate uninstall;
ordinary missing binaries, daemon outages and policy denials keep their existing
semantics. No runtime bypass flag is added to the active hook.

Cached status lines become quiet until the client loads the restored original
configuration. The compatibility files contain no user data and run no service.
They remain because a process can retain an old command for an unknown duration;
a timeout cannot safely prove that the command is no longer needed. A subsequent
explicit installation replaces them with real payloads.

The receipt is written before retiring the real CLI so a write failure leaves a
usable retry command. The app recognizes the receipt only when operational state
is absent and executable files are absent or exactly the known compatibility
responders. The receipt alone cannot disable a working installation. Automatic
first-launch setup respects this state; explicit setup can install again and
clears the receipt.

### External contracts checked

Checked on 2026-09-23 with installed Claude Code 2.1.261, Codex 0.156.1 and Cursor
CLI 2026.09.10-fd3934a:

- Claude's [JSON output contract](https://code.claude.com/docs/en/hooks#json-output)
  permits omitted decision fields. Its
  [reload guidance](https://code.claude.com/docs/en/hooks-guide#hooks-shows-no-hooks-configured)
  describes normal automatic settings reload and occasional missed updates.
- Codex's matching [release schemas](https://github.com/openai/codex/blob/rust-v0.156.1/codex-rs/hooks/src/schema.rs#L87)
  and [output parser](https://github.com/openai/codex/blob/rust-v0.156.1/codex-rs/hooks/src/engine/output_parser.rs#L184)
  establish `{}` as neutral for all five registered events, including Stop.
- Cursor's [hook schemas](https://cursor.com/docs/hooks#beforeshellexecution--beforemcpexecution)
  and [file-read response](https://cursor.com/docs/hooks#beforereadfile) use
  `permission: allow` for the three currently installed events. An empty success
  response is not used as a cross-agent contract.

This does not assert that all clients cache settings until restart. Local tests
execute retained command invocations in temporary installations. Live vendor
sessions were not run during this change; legacy untagged Cursor registrations
and clients outside these contracts are not newly attested.

## Consequences

CLI-first and app-first installation share readiness, preserve user data, and
avoid unnecessary service churn. The app no longer silently reverses explicit
uninstall. Retained ordinary hooks stop producing missing-command errors.

Uninstall is operational removal, not removal of every byte: the compatibility
responders and receipt are intentional and reported. Existing sandbox boundaries
and pending broker operations do not become authorized by uninstall. Removal of
the application bundle or system-extension consent remains a separate macOS
lifecycle operation; leaving the app present no longer reinstalls hooks by
itself.

Validation must include both install orders, exact/mixed/newer payloads, stale
daemon versions, explicit uninstall/reinstall, failed configuration cleanup,
retained command execution, and bounded native status reads. Signed-app acceptance
must be repeated on the final integrated artifact.
