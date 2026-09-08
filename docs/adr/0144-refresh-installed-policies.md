# ADR 0144 — Refresh installed core policies

## Status

Accepted.

## Context

Manual and background updates replace binaries and restart the daemon. Only
installation refreshed the core Rego files. An updated daemon could therefore
keep evaluating an older installed rule, including the retired sensitive-path
heuristic (ADR 0143-retire-path-heuristic).

## Decision

The multicall CLI supplies its existing core-policy installer to the daemon
entrypoint. After acquiring the instance lock and before loading any modules,
the daemon invokes that installer for its configured rules directory. The CLI
refreshes only the user's standard installed rules directory; explicit source
or development bundles are left alone. Both symlink and subcommand daemon
launches use the same entrypoint.

Refresh errors stop startup. The existing installer atomically replaces each
managed core file; custom rules and enabled library files are preserved. No
daemon accepts requests from a partially refreshed bundle. A later start
retries the complete refresh. Binary rollback also restores that version's
embedded policies when its daemon starts. Older releases that predate this
startup contract cannot guarantee policy rollback.

## Consequences

- Updating from an older release needs no new updater-side command: the new
  daemon itself refreshes policies before serving requests.
- Policy files on disk match the running binary's core policy bundle, while
  user policy overlays, library choices, and custom rules remain intact.
- Edits to installed core files are overwritten at startup; customizations
  belong in supported overlays and custom rules.
- The standalone development daemon entrypoint retains its existing behavior
  without an injected installer. Production distributions use the multicall
  binary and role symlinks.
- Startup performs additional local writes before compiling OPA. Policy reloads
  subsequently read the refreshed files; no hot-path work is added.
