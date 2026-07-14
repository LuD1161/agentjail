# ADR 0059 - Consolidate role binaries into a multicall `agentjail` binary (6 -> 2)

- **Status:** Accepted (implemented 2026-07-14)
- **Date:** 2026-07-14
- **Deciders:** agentjail-core
- **Related:** [ADR 0002](0002-latency-as-engineering-metric.md) (latency as an engineering metric), [ADR 0034](0034-platform-backend-shared-contract.md) (per-OS interface + shared contract), [ADR 0058](0058-secrets-broker-auto-start.md) (secrets broker auto-start), [ADR 0035](0035-domain-driven-interface-first-typesafe.md) (domain-driven, interface-first)
- **Review:** the plan was reviewed by an independent model (Codex, `codex-review:plan`) to APPROVED over three rounds before implementation. The two revision findings - keep the hook out of the multicall binary on latency grounds, and reconcile stale role files rather than assume a clean dir - are incorporated below.

## Context

agentjail shipped **six** separate binaries: `agentjail` (the cobra CLI),
`agentjail-hook`, `agentjail-daemon`, `agentjail-shield`, `agentjail-netproxy`,
and `agentjail-secrets`. The five non-CLI binaries were each their own
`package main` under `cmd/agentjail-*`, all statically linking the same shared
`internal/*` packages. That shape had a recurring cost:

- **Six artifacts to build, sign, notarize, and atomically update.** Every
  release signs six binaries (`Makefile` `sign`, `.github/workflows/release.yml`),
  notarizes six, and the self-update path downloaded and swapped six
  (`selfupdate.UpdateBinaries`). Any binary missed by an install/update path
  drifted (the historical "shield/netproxy only refresh via a separate `cp` step"
  gap that [ADR 0058](0058-secrets-broker-auto-start.md)'s
  `refreshAuxiliaryBinaries` papercut fix worked around).
- **The CLI was already one cobra binary** importing `internal/store` + OPA; the
  five role binaries were never folded in even though four of them
  (daemon/shield/netproxy/secrets) are launch-once services where process startup
  latency is irrelevant.

Two facts make consolidation feasible now:

- `modernc.org/sqlite` is pure Go, so the whole tree builds `CGO_ENABLED=0` - a
  single static binary can carry the daemon's SQLite + OPA weight.
- Go dispatches a multicall binary on `filepath.Base(os.Args[0])`: one binary
  invoked under several names runs a different role per name.

### The measured constraint: the hook must stay separate

The obvious end state is 6 -> 1. It is wrong, and [ADR 0002](0002-latency-as-engineering-metric.md)
is why. **In Go, every imported package's `init()` runs at process start
regardless of which subcommand executes** - a merged binary pays the union of all
roles' init cost on every invocation. The hook runs on *every* tool call against
an ~8-11ms end-to-end budget; the daemon links OPA + SQLite. Measured
(`CGO_ENABLED=0`, cold-ish start to `--help`, 30x avg):

| binary | size | start |
|---|---|---|
| `agentjail-hook` (thin socket client) | ~9.2 MB | ~8 ms |
| `agentjail-daemon` (OPA + SQLite) | ~37 MB | ~14 ms |

Folding OPA/SQLite `init()` into the hook adds ~6 ms per tool call - unacceptable
against the budget. The hook does not import OPA/store/daemon (verified:
`go list -deps ./cmd/agentjail-hook` shows no `open-policy-agent`, `internal/store`,
`internal/daemonapp`, or `modernc.org/sqlite`), so keeping it a separate lean
binary costs nothing and protects the hot path.

## Decision

**Consolidate to two shipped binaries, not one:**

1. **`agentjail`** - a multicall binary that is the CLI *and* the daemon, shield,
   netproxy, and secrets roles, selected by `filepath.Base(os.Args[0])`
   (`cmd/agentjail/main.go`). Invoked as `agentjail` it runs the cobra CLI;
   invoked as `agentjail-daemon` it runs the daemon; and so on. A hidden
   subcommand form (`agentjail daemon ...`, `cmd_role.go`) is also accepted as a
   fallback for any launcher that does not preserve `argv[0]`'s basename.
2. **`agentjail-hook`** - unchanged, its own lean binary (latency hot path).

**Role logic moved into importable packages.** Each former `cmd/agentjail-*`
`main` became `internal/{daemonapp,shieldapp,netproxyapp,secretsapp}` exposing
`func Run(args []string) int`; the `cmd/agentjail-*` dirs are retained as thin
shims (`os.Exit(<role>app.Run(os.Args[1:]))`) so the packages still compile
standalone as a build check, but they are never shipped or installed. The
shield's per-OS build-tag split (`_linux`/`_darwin`/`_other`) is preserved inside
`internal/shieldapp` per [ADR 0034](0034-platform-backend-shared-contract.md).

**Role names are symlinks, never real files.** `agentjail-daemon`,
`agentjail-shield`, `agentjail-netproxy`, and `agentjail-secrets` are relative
symlinks to `agentjail` in the same directory, reconciled by
`selfupdate.EnsureRoleSymlinks(binDir)` (`internal/selfupdate/rolesymlinks.go`).
Existing launchd plists, systemd units, PATH shims, and hook-config paths that
reference a role name keep working unchanged - the symlink resolves and `argv[0]`
dispatch sees the expected role. `EnsureRoleSymlinks` lives in `internal/selfupdate`
(not `cmd/agentjail`, which is unimportable `package main`) because both the CLI
install/update paths and the daemon's background auto-update
(`internal/daemonapp`) must reconcile symlinks after a swap.

**THE WATCHPOINT.** Any install/update path that lays down a role name must call
`EnsureRoleSymlinks` *after* the real `agentjail` binary is in place, and must
never `os.Rename`/`cp` a real binary directly over a role path - doing so
silently replaces the symlink with a real file that then stops tracking future
upgrades. `EnsureRoleSymlinks` defends this by `Lstat`+`Remove` (never
dereferenced) of whatever occupies each role path - a stale real file from a
pre-refactor install *or* an existing symlink - before creating a fresh symlink.
It is idempotent and covered by `TestEnsureRoleSymlinks_ReplacesStaleRealFile`.
Every path is wired: `agentjail install`, `agentjail uninstall`
(`RemoveRoleSymlinks`), `agentjail update`, the daemon auto-updater, `install.sh`,
and `scripts/dev-deploy.sh`.

**Update payload and version injection trimmed to the two real binaries.**
`selfupdate.UpdateBinaries` = `{agentjail, agentjail-hook}`; role binaries are no
longer downloaded or swapped. Version is injected once into the shared
`buildinfo.Version` symbol (`internal/buildinfo`) via its fully-qualified ldflag
path - this replaced the per-role `-X main.version=` injections, which silently
no-op once a role is an imported package rather than `package main` (a
release-blocking bug caught during this work: the CI release build still used
`-X main.version=`, so every tagged release would have shipped as `dev`).

## Consequences

**Positive:**

- **Two artifacts, not six**, to build, codesign, notarize, and self-update. The
  release workflow's build/sign/verify/gatekeeper/tarball loops and the Makefile
  `sign`/`DIST_BINS` targets all enumerate exactly `{agentjail, agentjail-hook}`.
- **Drift closed by construction.** A role name cannot go stale relative to
  `agentjail` because it *is* `agentjail` (a symlink). The class of bug that
  `refreshAuxiliaryBinaries` patched around is structurally gone; that helper was
  removed.
- **Hook hot path untouched** - it remains its own lean binary with no OPA/SQLite
  init tax, protecting the [ADR 0002](0002-latency-as-engineering-metric.md)
  budget.
- Likely smaller total on-disk footprint (one shared multicall image + four tiny
  symlinks vs. five full static binaries).

**Negative / new surface:**

- **`argv[0]` dispatch is basename-sensitive.** A launcher that invokes a role by
  a path whose basename is not the role name would fall through to the CLI.
  Mitigated by the hidden `agentjail <role>` subcommand form and by the fact that
  every launcher we control (launchd `ProgramArguments`, systemd `ExecStart`, PATH
  shims, hook config) invokes by the role name.
- **Larger single binary for the services** (it carries OPA + SQLite). Acceptable:
  these are launch-once processes where startup latency is irrelevant, which is the
  exact axis [ADR 0002](0002-latency-as-engineering-metric.md) says not to spend
  the budget defending.
- **The four `cmd/agentjail-*` shims are dead weight** kept only as a compile
  check; they must stay in lockstep with their `internal/*app` package or the
  build-check loses meaning. A future cleanup could drop them once CI covers the
  `internal/*app` packages directly.
- **Homebrew and other packagers must create the role symlinks themselves** after
  `bin.install`-ing the two real binaries. The generated formula now installs the
  two and loops `bin.install_symlink "agentjail" => <role>` over all four role
  names (the previous formula's list was also missing `agentjail-secrets`).

## Implementation outcome (2026-07-14)

Landed on `feat/multicall-binary` (commits `7cbd7edc` .. `4070c3e4`):

- **T1** - `internal/{secretsapp,netproxyapp,daemonapp,shieldapp}` extracted from
  `cmd/agentjail-*`; `cmd/agentjail-*` reduced to thin shims. Shield per-OS
  build-tag split preserved.
- **T3** - `cmd/agentjail/main.go` `argv[0]` dispatch switch + hidden
  `cmd_role.go` subcommands (`Hidden:true`, `DisableFlagParsing:true`).
- **T4** - `internal/buildinfo.Version` unifies version injection; all reporters
  (CLI `version`, daemon startup log, netproxy fingerprint, hook telemetry) read
  it; Makefile ldflag fully-qualified.
- **T5/T6** - `selfupdate.EnsureRoleSymlinks`/`RemoveRoleSymlinks`/`RoleNames`
  wired into install/uninstall/update/auto-update/`install.sh`/`dev-deploy.sh`;
  `UpdateBinaries` trimmed to two; `refreshAuxiliaryBinaries` deleted.
- **T7** - `.github/workflows/release.yml` and `Makefile` trimmed to two binaries
  and the `-X main.version=` -> `-X buildinfo.Version=` fix; Homebrew formula
  installs two + symlinks four.

**Verified inline:** `go build ./...` + `go vet ./...` clean; `go test ./...` =
1560 pass over 41 packages; the watchpoint test passes; `make dist-tarball`
produces a tarball containing exactly `agentjail` + `agentjail-hook`; a symlinked
`agentjail-daemon` from that tarball dispatches to the daemon (not the CLI);
`go list -deps ./cmd/agentjail-hook` confirms the hook links no OPA/store/SQLite.
The `make e2e-release` clean-VM gate exercises the real `install.sh` symlink
reconciliation on the true user path and must pass before tagging.
