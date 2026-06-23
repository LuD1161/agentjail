# ADR 0026: Daemon Auto-Update

Status: Accepted

## Context

Phase 1 added daemon-side update notifications. Users often dismissed
the notification and forgot to update. For a security tool, running stale
versions means missing policy improvements and bug fixes.

Every major CLI tool (Claude Code, Codex, rustup, Homebrew) uses the same
pattern: download the new binary, replace the old one, restart. No watchdog,
no rollback daemon, no helper process.

## Decision

The daemon automatically downloads, verifies (minisign + SHA256), and swaps
binaries when a newer version is available. After swapping, it exits and
launchd restarts it from the new binary (KeepAlive: true).

- Opt-out via AGENTJAIL_AUTO_UPDATE=false or AGENTJAIL_NO_UPDATE_CHECK=1
- Same signature verification as manual `agentjail update`
- Dev builds (empty signing key) skip auto-update
- Homebrew installations skip auto-update (notification only)
- macOS only (launchd); Linux support deferred
- On swap failure: rollback from backup, send notification, continue running

## Consequences

- Users receive updates within ~6 hours of release
- No additional binaries or daemons needed
- If a new version crashes on start, launchd will retry and eventually
  back off. User can reinstall via curl|sh or brew reinstall
- The brief interruption during binary swap (~seconds) matches manual
  agentjail update behavior
