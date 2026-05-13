# Contributing to agentjail

This document covers build setup, workspace structure, dev workflows, and the engineering principles that govern all contributions. For the user-facing overview see [README.md](./README.md).

## Quick start

```sh
# 1. Build all binaries
make build

# 2. Run the test suite
go test ./... -race

# 3. Run the smoke fixtures
make smoke
```

## What this project is

agentjail gives every coding agent (Claude Code, Codex CLI, Cursor) a policy guardrail — enforcing what files it can read/write, which MCPs it can call, and which shell commands it can run — without requiring any changes to the agent itself.

Three deployment tiers, in build order:

1. **Tier 1 — Hooks** (current focus): plug into the hook systems that Claude Code / Codex / Cursor already ship. Zero new infrastructure. Lightest isolation.
2. **Tier 2 — MicroVM/Container**: run the agent in isolation; monitor at the container boundary. Stronger isolation for setups that need hard containment.
3. **Tier 3 — Kernel module**: EDR-style, system-wide. Strongest isolation, works for any process on the machine.

See [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) for the architecture overview and isolation tier model.

## Repository layout

| Tree | What | Where the code lives |
|---|---|---|
| **Tier 1 hook binaries** | Hook binary + persistent daemon for Claude Code PreToolUse integration. | `cmd/agentjail-hook/`, `cmd/agentjail-daemon/` |
| **Wrapper + per-session daemon** | Go binary with capture tracks, sync-DENY enforcement, OS peer-cred auth, OPA policy, cred TUI. | repo root + `cmd/agentjail/` |
| **Policy engine** | OPA/Rego decision engine; file/MCP/command rules; LRU cache. | `agentpolicy/` |
| **Containment substrate** | C PATH shim, Node/Bun runtime hook, mitmproxy addon, adversarial fixtures, microVM spikes. | `agentjail/` |

Each tree builds, tests, and ships independently.

## Prereqs

- macOS Apple Silicon (Linux/Intel support follows the same patterns but is deferred)
- Go 1.26+
- `brew install mitmproxy` for the proxy track (optional; needed only for HTTPS capture)
- `opa` on PATH for policy tests (`brew install opa`)

## Build

```sh
git clone https://github.com/LuD1161/agentjail.git
cd agentjail

# Build all binaries
go build ./...

# Build just the Tier 1 hook binaries
go build ./cmd/agentjail-hook ./cmd/agentjail-daemon

# Build the C PATH shim
make -C agentjail/native/shim build
```

## One-time setup (full-stack wrapper mode)

```sh
./bin/agentjail ca gen           # generate ~/.agentjail/ca/root.pem
./bin/agentjail ca install       # optional — installs CA to login keychain for curl/git/etc.
./bin/agentjail shim install     # symlinks ~/.agentjail/shims/{git,npm,rm,...} -> agentjail-shim
```

## Run an agent under agentjail (full wrapper)

```sh
AGENTJAIL_RUNTIME_DIR="$PWD/agentjail/runtime" \
AGENTJAIL_ADDON_PATH="$PWD/agentjail/addons/agentjail_addon.py" \
./bin/agentjail claude
```

Optionally bind an agent slug so every event in `events.jsonl` carries the principal identity:

```sh
./bin/agentjail --agent my-agent claude
# or via env (flag wins when both are set):
AGENTJAIL_AGENT_SLUG=my-agent ./bin/agentjail claude
```

## Inspect sessions

```sh
./bin/agentjail sessions list    # all sessions, newest first
./bin/agentjail tail             # live tail of the most recent session
./bin/agentjail tail <sid>       # tail a specific session (prefix OK)
./bin/agentjail bodies <sid>     # list captured req/res bodies (opt-in per host)
```

## Test

```sh
# Go unit tests
go build ./... && go vet ./... && go test ./... -race

# OPA policy unit tests (requires opa on PATH)
opa test agentpolicy/policies/

# Smoke fixtures
make smoke
```

The smoke runner skips fixtures whose prereq env vars are absent, so `make smoke` passes in a plain dev environment.

## Three independent capture tracks (full-stack mode)

When running `agentjail claude` (legacy full-wrapper mode), three capture tracks operate simultaneously to cover each other's blind spots:

| | Track A — Native | Track C — Runtime | Track P — Proxy |
|---|---|---|---|
| Catches | every shell-out by argv[0] basename | every `fs`/`child_process`/`fetch` call inside Node/Bun | every HTTPS request through `HTTPS_PROXY` |
| Mechanism | PATH shim binaries before `/usr/bin` | `NODE_OPTIONS=--require` (Node) + `BUN_OPTIONS=--preload` (Bun) | mitmproxy + per-session root CA |
| Blind spots | absolute paths to SIP-protected binaries invoked directly | direct syscalls / FFI that bypass JS APIs | non-HTTPS_PROXY-honoring clients |

The Tier 1 hook-only path (the current focus) works independently of these tracks.

### Bun preload note

Claude Code is a Bun-compiled single-file Mach-O. `NODE_OPTIONS` is ignored, and hardened runtime strips `DYLD_INSERT_LIBRARIES`. `BUN_OPTIONS=--preload` fires inside the compiled binary, giving in-process visibility without rebuild, sudo, or Apple-gated entitlements.

## Configuration

`~/.agentjail/config.yaml` (auto-created with safe defaults) controls body capture for full-stack mode:

```yaml
capture_bodies:
  enabled_hosts: []       # e.g. ["api.anthropic.com", "*.example.com"]
  max_bytes: 65536
```

Bodies are written to `~/.agentjail/sessions/<sid>/bodies/<n>.{req,res}.bin` only for matched hosts. Default: nothing captured.

## Policy rules

Policy rules live in `agentpolicy/policies/`. See [`agentpolicy/README.md`](./agentpolicy/README.md) for the full rule-authoring reference, including how to write custom Rego rules and the lib module pattern.

Policy decisions appear in session `events.jsonl` as `body: "policy.decision"` with `rule_id` and `action`.

## JIT credentials (Tier 1.5 — credential broker)

Once `~/.agentjail/capabilities.yaml` is in place, a wrapped agent can mint short-lived database credentials on demand. The daemon evaluates the `cred_use` action against `data.agentjail.caps`, issues a scoped credential, stores it in a file-backed AES-GCM store, tracks the lease, and registers the cred bytes with the mitmproxy redactor. On session end every lease is revoked.

See [ADR 0004](./docs/adr/0004-credential-broker-tier1.md) for the credential broker design.

## Engineering principles — non-negotiable

These are enforced by [`CLAUDE.md`](./CLAUDE.md), and apply equally to human contributors:

- **KISS.** The simplest thing that could possibly work. Three lines of duplication beats a premature abstraction.
- **Standard libraries only.** No ORMs, no DI containers, no custom retry frameworks. New libraries require an ADR.
- **Small atomic commits.** Conventional Commits format. One commit = one cohesive change. Sign off with `-s`. Do not bypass pre-commit hooks.
- **Update docs in the same commit.** README, ADRs all stay in sync with code. Drift is a bug.
- **Decision log.** Architecture decisions land as `docs/adr/NNNN-slug.md` with Context / Decision / Consequences.
- **Tests use `-race`.** Every test, every commit.

See [`CLAUDE.md`](./CLAUDE.md) for the full list and rationale.

## Workflow

1. Open an issue describing what you want to change and why (helps avoid duplicate work).
2. Branch off `main`. Branch name shape: `<type>/<short-slug>` (e.g. `feat/cred-broker-postgres`).
3. Make small commits as you go. Each commit:
   - builds (`go build ./...`)
   - passes vet (`go vet ./...`)
   - passes the relevant tree's tests (`go test ./<changed-pkg>/... -race`)
   - updates docs touching its scope
4. Open a PR against `main`. CI must be green before merge.
5. PR description should:
   - Name the affected component
   - Link the ADR if one was written
   - Include a "Test plan" checklist

## Developer Certificate of Origin (DCO)

Every commit must be signed off. This certifies that you wrote the code (or
otherwise have the right to submit it under the project's license) per the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).

Add the sign-off automatically with `-s`:

```sh
git commit -s -m "feat(cred): add postgres broker backend"
```

This appends a trailer to the message:

```
Signed-off-by: Your Name <you@example.com>
```

To never have to remember `-s`, enable the tracked auto-signoff hook once per
clone:

```sh
git config core.hooksPath .githooks
```

The name and email must be real and match your `git config user.name` /
`user.email`. CI (the **DCO** check) verifies every non-merge commit in a PR
carries this trailer and will fail the PR otherwise. To fix:

```sh
git commit --amend -s              # the latest commit
git rebase --signoff origin/main   # every commit on the branch
git push --force-with-lease
```

<details>
<summary>Full DCO 1.1 text</summary>

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
>     right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
>     knowledge, is covered under an appropriate open source license and I have
>     the right under that license to submit that work with modifications,
>     whether created in whole or in part by me, under the same open source
>     license (unless I am permitted to submit under a different license), as
>     indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who
>     certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
>     and that a record of the contribution (including all personal information
>     I submit with it, including my sign-off) is maintained indefinitely and
>     may be redistributed consistent with this project or the open source
>     license(s) involved.

</details>

## Architecture docs

- [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) — architecture overview and isolation tiers
- [`docs/ENGINEERING.md`](./docs/ENGINEERING.md) — engineering principles
- [`docs/adr/`](./docs/adr/) — Architecture Decision Records
- [`agentpolicy/README.md`](./agentpolicy/README.md) — policy engine + rule authoring

## Reporting security issues

agentjail is a security tool. If you find a vulnerability **do not** open a public issue. Email the maintainer privately. Disclosure policy will land alongside the v1.0 release.

## License

By contributing, you agree your work is licensed under the [Apache-2.0](./LICENSE).
