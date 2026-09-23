# Contributing to agentjail

This document covers build setup, workspace structure, dev workflows, and the engineering principles that govern all contributions. For the user-facing overview see [README.md](./README.md).

## Prerequisites

- macOS or Linux, on arm64 or amd64. Platform-specific enforcement needs its native OS.
- The Go version declared in [`go.mod`](./go.mod) and [`go.work`](./go.work) (currently 1.26.3).
- Bun at the version in [`cmd/agentjail/ui/frontend/.bun-version`](./cmd/agentjail/ui/frontend/.bun-version) when building the dashboard.
- OPA on PATH for Rego tests (`brew install opa` on macOS).
- Python 3, minisign, and fish for the isolated installer fixtures. Install these independently through your trusted package manager.

Read [`AGENTS.md`](./AGENTS.md), [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md), and [`docs/ENGINEERING.md`](./docs/ENGINEERING.md) before changing enforcement behavior.

## Build and test without installing

```sh
git clone https://github.com/LuD1161/agentjail.git
cd agentjail

# Build the embedded dashboard, then the two shipped executables.
make ui
mkdir -p bin
go build -o bin/agentjail ./cmd/agentjail
go build -o bin/agentjail-hook ./cmd/agentjail-hook

# Root module and nested workspace modules are checked explicitly.
go build ./...
go vet ./...
go test -race ./...
go test -race ./agentpolicy/...
go test -race ./agentjail/...
opa test agentpolicy/policies/
python3 test/installer/test_installer.py -v
make smoke
```

The released `agentjail` executable is a multicall binary: daemon, shield,
netproxy, and secrets roles dispatch through symlinks to it. `agentjail-hook`
is the separate lightweight executable. `go build ./...` checks packages; the
explicit `-o` commands above produce runnable development artifacts.

`make smoke` runs hook and OS-sandbox fixtures. A fixture may report SKIP when
its documented prerequisites are unavailable; review those skips before
claiming platform coverage. `make e2e-release` is the separate clean-VM release
gate with real agent authentication; see [`test/testbed/README.md`](./test/testbed/README.md).

## Repository layout

| Tree | Responsibility |
|---|---|
| `cmd/agentjail/` | Multicall CLI, install/diagnostic commands, and local dashboard |
| `cmd/agentjail-hook/` | Standalone hook adapter |
| `cmd/agentjail-daemon/`, `cmd/agentjail-shield/` | Policy daemon and OS sandbox role implementations |
| `internal/` | Typed domain services: agents, store, audit, credentials, network, updates |
| `agentpolicy/` | Nested Go module containing the OPA policy engine and Rego rules |
| `agentjail/` | Separate legacy/experimental workspace module and containment prototypes |
| `test/` | Installer fixtures, clean-VM release gate, and integration tests |

## Try your development build

Installing a development build changes your local agent hooks, binaries, and
supervised daemon. Run it deliberately from a normal terminal:

```sh
make dev-deploy
agentjail doctor
agentjail try --read ~/.ssh/id_rsa  # policy simulation; opens no file
agentjail run -- codex             # or claude / Cursor's agent
```

`make dev-deploy` rebuilds and reconciles the installed components. Restart
already-running agents to load updated hooks. Hooks are cooperative policy
checks; `agentjail run` adds OS sandbox enforcement. For network visibility,
see [`docs/SANDBOX.md`](./docs/SANDBOX.md); the supported path uses AgentJail's
tunnel/proxy components rather than a separately installed mitmproxy.

Inspect the resulting local records with:

```sh
agentjail logs
agentjail sessions
agentjail replay --session SESSION_ID
agentjail ui
```

## Configuration and policy

The active configuration is `~/.agentjail/policy.yaml`; decisions and audit
records use the unified SQLite store under `~/.agentjail`. Use the public store
interfaces instead of opening additional database connections.

Core policy source lives in `agentpolicy/policies/` and the CLI embeds the
corresponding bundle in `cmd/agentjail/policies/`. Keep both copies in sync.
See [`agentpolicy/README.md`](./agentpolicy/README.md) for rule authoring and the
README's credential commands for the current broker interface. Historical
`ca gen`, `shim install`, `tail`, and `bodies` wrapper examples are not the
current shipped CLI workflow.

## Engineering principles — non-negotiable

These are defined by [`AGENTS.md`](./AGENTS.md), and apply equally to human contributors:

- **KISS.** The simplest thing that could possibly work. Three lines of duplication beats a premature abstraction.
- **Standard libraries only.** No ORMs, no DI containers, no custom retry frameworks. New libraries require an ADR.
- **Small atomic commits.** Conventional Commits format. One commit = one cohesive change. Sign off with `-s`. Do not bypass pre-commit hooks.
- **Update docs in the same commit.** README, ADRs all stay in sync with code. Drift is a bug.
- **Decision log.** Architecture decisions land as `docs/adr/NNNN-slug.md` with Context / Decision / Consequences.
- **Tests use `-race`.** Every test, every commit.

See [`AGENTS.md`](./AGENTS.md) for the full list and rationale.

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

agentjail is a security tool. If you find a vulnerability **do not** open a public issue. Follow the private reporting instructions in [`SECURITY.md`](./SECURITY.md).

## License

By contributing, you agree your work is licensed under the [Apache-2.0](./LICENSE).
