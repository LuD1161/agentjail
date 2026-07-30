# ADR 0062: the shell rc block, not the shim file, records PATH-shim consent

**Status:** Accepted

## Context

`agentjail install --with-path-shim` writes two things:

1. `~/.agentjail/bin/claude` — a `/bin/sh` shim that `exec`s `agentjail-shield -- <real claude>`.
2. A fenced `# >>> agentjail >>>` block in the user's shell rc, prepending
   `~/.agentjail/bin` to `PATH`.

Both were treated as one unit, but they have very different lifetimes. `~/.agentjail` is
removed wholesale by `removeInstallDir` on uninstall; the rc block is not. They fall out of
sync, and every mechanism that reasoned about the shim keyed off the file:

- `refreshPathShimIfExists` early-returned when the file was absent, so it refreshed an
  existing shim but never restored a deleted one — despite being called unconditionally
  from install specifically to survive `brew upgrade` / `curl | sh`.
- `agentjail doctor` stat'd the file and reported `not installed (opt-in)`.

An uninstall/reinstall cycle therefore produced a silent, unrecoverable downgrade: the rc
still prepends `~/.agentjail/bin` to `PATH`, but no `claude` sits there, so the shell
resolves straight past it to the real unshielded binary. No error, no missing command — the
user believes they are shielded and is not, and no subsequent install ever repairs it.
Doctor called this state "not installed (opt-in)", which reads as a choice the user made.

A second, independent leak had the same root: two writers append a PATH export, each with
its own marker — `pathRCMarker` ("# added by agentjail installer", from `install.sh`) and
the fenced `# >>> agentjail >>>` block (from `addToShellProfile`) — but
`stripAgentjailPathBlock` only knew the first. Uninstall left the shim's block behind
forever, which is how the dangling state persists across a full uninstall.

Making the shim non-opt-in (folding it into `--all`) was considered and rejected: `--all` is
what `curl | sh` runs, and a piped installer must not silently edit a shell profile and start
intercepting the user's `claude`. The shim is also not a coverage guarantee — it only catches
interactive shells that sourced the profile, missing VS Code (hence the separate
`claudeProcessWrapper`), cron, non-interactive shells, and absolute-path invocations.
Ubiquity is the job of verified activation (draft ADR 0029), not of a PATH entry.

## Decision

The rc block is the durable record of consent; the shim file is a derived artifact.

- `shellRCCandidates(home)` is the single source of truth for which rc files agentjail may
  have written to (honoring `$ZDOTDIR`), shared by the writer, the scrubber, and the probe.
- `shimConsentRecorded(home)` reports consent by looking for `shimRCMarkerStart` in any
  candidate rc.
- `refreshPathShimIfExists` becomes `reassertPathShim`: it regenerates the shim when the
  file exists (refresh) **or** when consent is recorded but the file is gone (restore),
  announcing the restore on stderr. Still called unconditionally from install.
- `stripAgentjailPathBlock` scrubs both marker forms. The fenced form is removed
  start-through-end inclusive; an unterminated fence (hand-edited rc) falls back to the
  conservative bare-marker rule — drop the next line only if it references
  `.agentjail/bin` — so it can never swallow the rest of the file.
- `doctor` distinguishes three states: `ok`, `not installed (opt-in)`, and a **failing**
  dangling state ("MISSING but your shell profile opts into it — `claude` is running
  UNSHIELDED").

The shim stays opt-in, and stays out of `--all`.

## Consequences

Opting into the shim is now sticky: it survives uninstall/reinstall, `curl | sh` updates,
and brew upgrades, because consent lives in the file agentjail does not delete. The silent
downgrade is repaired automatically on the next install, and is loudly visible via doctor
until then. Uninstall no longer orphans its own PATH block.

`agentjail install` can now write `~/.agentjail/bin/claude` without `--with-path-shim` being
passed on that invocation. This is intended — it is a repair of a recorded choice, not a new
one — but it does mean the only way to fully opt out is `agentjail uninstall` (which now
scrubs the block), or removing the rc block by hand. A user who deletes only the shim file
and expects it to stay gone will find it restored; the rc block is the off switch.

Consent detection is a substring match on rc contents, so a marker inside a comment or a
heredoc would be read as consent. Acceptable: the marker is agentjail-specific, and the
failure mode is an unwanted shim install rather than a silent security downgrade.

The shim remains one launch path among several. Sessions started outside a profile-sourcing
shell are still unshielded, and the hook still only warns. Closing that gap is verified
activation (draft ADR 0029) and is out of scope here.

## Implementation note

The shared `internal/pathshim` package owns target enumeration, wrapper rendering,
consent detection, and restoration. Install, doctor, and uninstall call that
contract instead of maintaining separate target lists or templates.
