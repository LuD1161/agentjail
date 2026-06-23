# agentjail -- agent instructions

Every coding agent (Claude Code, Codex CLI, Cursor, Aider, etc.) working in this repo must follow these instructions. They override default behavior.

This file is the canonical, tool-agnostic rule set. Tool-specific configs (e.g. a local `CLAUDE.md`, `.cursorrules`, `.codex/instructions.md`) should reference or `@`-import this file rather than duplicate it. Personal/per-contributor preferences belong in your own gitignored config, not here.

## What this project is

agentjail gives every coding agent (Claude Code, Codex CLI, Cursor) a policy guardrail -- enforcing what files it can read/write, which MCPs it can call, and which shell commands it can run -- without requiring any changes to the agent itself.

Three deployment tiers, in build order:
1. **Tier 1 -- Hooks** (shipped): plug into the hook systems that Claude Code / Codex / Cursor already ship. Zero new infrastructure. Lightest isolation.
2. **Tier 2 -- MicroVM/Container**: run the agent in isolation; monitor at the container boundary. Stronger isolation for setups that need hard containment.
3. **Tier 3 -- Kernel module**: EDR-style, system-wide. Strongest isolation, works for any process on the machine.

## Read this before doing anything

1. **[`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)** -- mandatory first read. Architecture overview: hook → daemon → OPA flow, isolation tiers, policy model.
2. **[`docs/ENGINEERING.md`](./docs/ENGINEERING.md)** -- engineering principles that govern every change.
3. **[`docs/adr/0001-os-sandbox-enforcement-layer.md`](./docs/adr/0001-os-sandbox-enforcement-layer.md)** -- OS sandbox (agentjail-shield) decision.
4. **[`docs/adr/0002-latency-as-engineering-metric.md`](./docs/adr/0002-latency-as-engineering-metric.md)** -- latency targets.
5. **[`docs/adr/0003-mcp-reverse-proxy.md`](./docs/adr/0003-mcp-reverse-proxy.md)** -- MCP proxy strategy.
6. **[`docs/adr/0004-credential-broker-tier1.md`](./docs/adr/0004-credential-broker-tier1.md)** -- credential broker design (Tier 1.5 OSS path).
7. **[`docs/adr/`](./docs/adr/)** -- all ADRs. Each captures one decision with Context / Decision / Consequences.

## Standard libraries -- no hacky patterns

OSS-relevant dependencies:
- Logging: stdlib `log/slog` (JSON output)
- YAML: `gopkg.in/yaml.v3`
- Retry: `cenkalti/backoff/v4` (or stdlib loops with `time.Sleep`)
- Policy: `github.com/open-policy-agent/opa`
- TUI: `github.com/charmbracelet/bubbletea`
- Crypto: stdlib `crypto/*`; AES-GCM via `crypto/cipher`

**Avoid:** ORMs, DI containers (Wire/Fx), custom retry libraries, bespoke logging frameworks, frontend frameworks.

New libraries require an ADR justifying the addition. After adding or removing
any dependency, regenerate the attribution file with `make licenses` (CI fails
the release if `THIRD_PARTY_LICENSES` is stale).

## Small atomic commits

- Conventional Commits: `type(scope): description`
- **One commit = one cohesive change.**
- Each new package → its own commit
- Each service method + its tests → one commit
- After every commit: `go build && go vet && go test ./<changed-pkg>/...` must pass
- **Sign off every commit** -- `git commit -s` (DCO; see [Sign every commit](#sign-every-commit-dco))
- Never bypass pre-commit/pre-push hooks (`--no-verify`) unless the user explicitly asks
- Never force-push to `main`
- Push after each commit (the user has authorized continuous push for this project)

## Sign every commit (DCO)

Every commit MUST carry a `Signed-off-by:` trailer (Developer Certificate of
Origin -- see [`CONTRIBUTING.md`](./CONTRIBUTING.md)). The `DCO` CI check fails
any PR containing an unsigned commit, so this is not optional.

- **Coding agents / CLI:** always commit with `-s` -- `git commit -s -m "..."`.
- **Make it automatic (one-time per clone)** so you can never forget -- enable
  the tracked `prepare-commit-msg` hook, which appends the trailer for you:

  ```sh
  git config core.hooksPath .githooks
  ```

  The hook lives at [`.githooks/prepare-commit-msg`](./.githooks/prepare-commit-msg)
  and is idempotent (won't duplicate an existing sign-off).
- Your `git config user.name` / `user.email` must be set and real -- the CI check
  verifies the trailer matches a `Name <local@domain>` shape.
- Forgot on an existing branch? `git rebase --signoff origin/main` then
  `git push --force-with-lease`.

## Update docs with every commit

Documentation drift is a bug. Every commit that changes user-visible behavior, adds a new package, or changes defaults must:
1. Update [`README.md`](./README.md) if the change affects user-facing flows
2. Write an ADR under [`docs/adr/NNNN-slug.md`](./docs/adr/) if the change resolves a previously-undecided design question

This goes in the same commit as the code change, not a follow-up.

## Decision log (ADRs)

- Format: `docs/adr/NNNN-short-slug.md`
- Sections: Context / Decision / Consequences (status: Proposed / Accepted / Superseded by NNNN)
- Triggers for a new ADR:
  - Picking one library over another from a shortlist
  - Reversing a prior decision
  - Any significant architectural choice

## Common workflows

### Before any non-trivial code change
1. Read the relevant doc(s) under `docs/`
2. Check `git log --oneline -20` for what recently landed
3. Look at any open `docs/adr/` items that touch your area

### Before opening a PR / pushing
1. `go build ./... && go vet ./... && go test ./...` -- all green
2. `make smoke` -- every fixture PASSes or SKIPs cleanly
3. Updated `README.md` / `docs/adr/` per the cadence rule
4. Conventional commit message with sign-off

### Before cutting a release

Every tagged release must include:

1. **Release summary SVG** -- create `assets/releases/vX.Y.Z-summary.svg` with a
   visual summary of the release. Keep it simple: dark background (#0d1117),
   title bar with version + one-liner, then the key changes as labeled cards
   or before/after comparisons. See existing SVGs in `assets/releases/` for
   the style. Commit and push before tagging so the raw URL works in the
   release notes.
2. **TL;DR bullets** -- the GitHub release body starts with the SVG image, then
   a `## TL;DR` section with 2-4 bullet points (not a wall of text). Each
   bullet is one sentence starting with an action word.
3. **Detailed changelog** -- below the TL;DR, use `### Added / Changed / Fixed /
   Security` sections with one entry per change.
4. **agentjail.io changelog** -- add the release to
   `agentjail.io/src/data/releases.ts` (same format as existing entries).
5. **No em dashes** -- use regular hyphens (`-`) or double hyphens (`--`)
   everywhere: release title, body, SVG text, and changelog entries. Em
   dashes render inconsistently in terminals and CLIs.

### When in doubt
- About scope: ask the user before expanding scope
- About a library choice: check the standard libraries list above; write an ADR if you need to add one
- About a security trade-off: never relax fail-closed semantics for the cred path without an ADR
- About commit size: smaller is better; if it touches >3 files outside test/, split it
