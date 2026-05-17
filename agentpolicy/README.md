# agentpolicy

agentpolicy is the open-source policy decision engine for [agentjail](../README.md). It answers one question on every tool use: *given this operation — allow, ask, or deny?* Rules are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) and evaluated in-process by [OPA](https://www.openpolicyagent.org/) with a warm LRU cache that targets p95 < 1 ms per decision. No remote calls, no sidecar, no round-trip. The engine starts cold in < 100 ms and stays resident in the agentjail daemon for the lifetime of a coding-agent session.

## Install

```sh
go get github.com/LuD1161/agentjail/agentpolicy
```

Requires Go 1.21+. The only direct dependency is `github.com/open-policy-agent/opa`.

## Quickstart

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/LuD1161/agentjail/agentpolicy/policy"
)

func main() {
    ctx := context.Background()

    // Load all *.rego files from the policy directory and compile them.
    eng, err := policy.NewEngine(ctx, "policies/")
    if err != nil {
        log.Fatal(err)
    }

    // Build an input describing the operation to evaluate.
    in := policy.Input{
        Hook:          "exec",
        Program:       "rm",
        Flags:         []string{"-r", "-f"},
        PathsResolved: []string{"/Users/alice/.ssh"},
        Context:       map[string]any{"home": "/Users/alice"},
    }

    // Evaluate — returns a Decision with Action and RuleID.
    d, err := eng.Eval(ctx, in)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("action=%s rule_id=%s\n", d.Action, d.RuleID)
    // action=deny rule_id=no-recursive-delete-of-protected-paths
}
```

## Writing rules

### Hook-path rules (preferred — `package agentjail`)

The hook engine queries `data.agentjail.decision`. All core and user rules
live in `package agentjail` and contribute to the shared `candidate` partial
rule set. The `resolver.rego` file picks the most restrictive candidate
(deny > ask > allow) and produces the single `decision` output.

**Never declare `decision = ...` in your own rule files** — `resolver.rego`
is the only file that defines `decision`. User-authored rules must use the
`candidate contains r if { ... }` partial rule entry pattern.

A minimal example:

```rego
package agentjail

import future.keywords.if
import future.keywords.contains

# Block npm global installs — fires for any input that matches.
candidate contains r if {
    input.hook_event == "PreToolUse"
    input.tool_name == "Bash"
    regex.match(`\bnpm\s+(i|install)\b.*\s(-g|--global)\b`, input.tool_input.command)
    r := {
        "action":  "deny",
        "rule_id": "myorg/no-npm-global",
        "reason":  "global npm installs add binaries to PATH",
        "impact":  "would install a package globally with PATH/post-install side effects",
    }
}
```

The `candidate` partial rule set is a set of objects; each object must have:
- `action`: `"deny"` | `"ask"` | `"allow"`
- `rule_id`: a unique string (prefix with your org to avoid collisions)
- `reason`: a human-readable explanation
- `impact` (optional): what would happen if the action is not blocked

> **Installing via `agentjail policy add` (ADR 0014).** When you install a rule
> through the CLI, every `rule_id` it emits **must** use the reserved prefix
> `custom/<filename_stem>/<rule>` (e.g. `my_rule.rego` → `custom/my_rule/no-foo`).
> `policy add` validates the authoring contract and compiles the full bundle
> before installing; the daemon quarantines (skips + warns) any custom file that
> would break the bundle, so a bad rule never fails startup. Rules can be turned
> off with `agentjail policy disable <rule_id>` (which feeds `disabled_rules` in
> `policy.yaml`), except for the locked self-protection set. See the
> [authoring guide](../samples/README.md) and
> [ADR 0014](../docs/adr/0014-user-tunable-policy-surface.md).

### Legacy exec-hook rules (`package agentjail.default`)

The legacy engine queries `data.agentjail.default.decision`. These rules use
a different input shape (`input.hook`, `input.program`, `input.flags`, etc.)
and are separate from the hook-path rules above.

```rego
package agentjail.default

import future.keywords.in
import future.keywords.if

# Default — allow anything not matched by a deny or ask rule.
default decision := {"action": "allow"}

# Block recursive force-delete of sensitive paths.
decision := {"action": "deny", "rule_id": "no-rm-rf-home"} if {
    input.hook == "exec"
    input.program == "rm"
    "-r" in input.flags
    "-f" in input.flags
    some p in input.paths_resolved
    startswith(p, input.context.home)
}
```

Rules in `policies/lib/` use the package prefix `agentpolicy.lib.<surface>.<rule>` and can be imported into `default.rego` for composition (see [Writing a lib rule](#writing-a-lib-rule)).

### Input shape

`policy.Input` is the Go struct the engine receives. All fields are optional; the Rego rule checks only the fields it cares about.

| Field | Type | When set |
|---|---|---|
| `hook` | `string` | Always — `"exec"`, `"file"`, `"http"` |
| `op` | `string` | For `file` and `http` hooks — verb (`"write"`, `"GET"`) |
| `program` | `string` | `exec` hook — binary name (`"rm"`, `"curl"`) |
| `flags` | `[]string` | `exec` hook — parsed short + long flags |
| `argv_raw` | `[]string` | `exec` hook — raw argv[1:] |
| `paths_resolved` | `[]string` | `exec` hook — positional args expanded to absolute paths |
| `path` | `string` | `file` hook — the file path |
| `host` | `string` | `http` hook — hostname |
| `method` | `string` | `http` hook — HTTP method |
| `cwd` | `string` | When available — current working directory |
| `context` | `map[string]any` | Evaluator-injected ambient data: `home`, `session_id`, etc. |
| `principal` | `map[string]any` | Cerbos-shape principal (agent slug, user, trust tier) |
| `resource` | `map[string]any` | Cerbos-shape resource (kind, id, attrs) |
| `action` | `string` | Cerbos-shape action (e.g. `"cred_use"`, `"write"`) |

### Writing a lib rule

Place the rule in `policies/lib/<surface>/<name>.rego` with a `_test.rego` alongside it. The package name mirrors the path: `package agentpolicy.lib.exec.rm_rf`. Import it from `default.rego`:

```rego
import data.agentpolicy.lib.exec.rm_rf

decision := rm_rf.decision if rm_rf.decision else := {"action": "allow"}
```

Every lib rule must have a `_test.rego` with at least one deny and one allow case. A rule without tests is considered incomplete.

## Default rule library

agentpolicy ships core policy files under `policies/`:

### `resolver.rego` — `package agentjail`

The single file that owns `data.agentjail.decision`. It iterates over the
shared `candidate` partial rule set contributed by all other `package agentjail`
files and picks the most restrictive candidate: deny > ask > allow. Within each
priority tier, the candidate with the lexicographically smallest `rule_id` wins
(deterministic for cache hits and audit replay).

When no candidate fires, `resolver.rego` returns a safe default-ask rather than
silently allowing.

### `command_policy.rego` — dangerous Bash command patterns

Evaluates `input.tool_name == "Bash"` PreToolUse events. Each dangerous pattern
contributes a `candidate` entry. A safe `command_policy/default-allow` candidate
fires when no dangerous pattern matches, so benign commands like `git status` or
`ls` get `allow` without prompting.

### `file_policy.rego` — file access deny-list

Evaluates `input.tool_name` in `{"Write","Edit","Read"}` events. Contributes
`file_policy/sensitive_credential` (deny), `file_policy/project_allow` (allow),
and `file_policy/default` (ask) candidates.

### `mcp_policy.rego` — MCP server allowlist

Evaluates MCP tool calls (`input.tool_name` starts with `mcp__`). Contributes
`mcp_policy/blocked`, `mcp_policy/tool_not_allowed`, `mcp_policy/allowed`, and
`mcp_policy/unknown` candidates.

### `default.rego` — `package agentjail.default`

The production decision rules, evaluated on every tool use. Contains:

| Rule ID | Hook | What it does |
|---|---|---|
| `no-recursive-delete-of-protected-paths` | `exec` | Denies `rm -r -f` (any combination) targeting `$HOME`, `/`, `/Users/`, `/etc`, `/usr`, `/var`, `/opt` |
| `no-find-delete-in-home` | `exec` | Denies `find ... -delete` / `--delete` when any search root is under `$HOME` |
| `confirm-dotfile-write` | `file` | Asks before writing to `.env*`, `.ssh/**`, `**/credentials*` |
| `api-allowlist` | `http` | Denies outbound HTTP to hosts not in the explicit allowlist (Anthropic, GitHub, npm registry, etc.) |
| `cred-not-granted` | `cred_use` | Denies credential requests for capabilities not in the agent's catalog |
| `cred-auto-approve` | `cred_use` | Allows credential requests where `auto_approve: true` in capabilities.yaml |
| `cred-needs-approval` | `cred_use` | Asks for credentials needing human approval |
| `self-tamper-agentjail-dir` | `write` | Denies any write inside `~/.agentjail/` from a wrapped agent session |

### `policies/lib/exec/rm_rf.rego` — `package agentpolicy.lib.exec.rm_rf`

A composable library port of the `rm -rf` rule with an extended protected-path list (`/etc`, `/usr`, `/var`, `/opt` in addition to `$HOME` and `/`). Import this in custom policies to get the wider protection set without duplicating logic.

### `policies/experimental/principal_shape.rego` — `package agentjail.experimental`

Side-by-side rule package for testing new principal/resource/action shaped rules before promoting them to `default.rego`. The engine's `EvalQuery` method lets you compare experimental verdicts against default verdicts without flipping production traffic.

## Engine interface

The public surface is in `agentpolicy/policy/`:

```go
// NewEngine loads every *.rego file under policyDir (non-recursive, top-level
// only; test files ending in _test.rego are skipped) and compiles a PreparedEvalQuery
// for data.agentjail.default.decision.
func NewEngine(ctx context.Context, policyDir string) (*Engine, error)

// Input is the canonical policy input record.
type Input struct {
    Hook          string         `json:"hook"`
    Op            string         `json:"op,omitempty"`
    Program       string         `json:"program,omitempty"`
    Flags         []string       `json:"flags,omitempty"`
    Positional    []string       `json:"positional,omitempty"`
    ArgvRaw       []string       `json:"argv_raw,omitempty"`
    PathsResolved []string       `json:"paths_resolved,omitempty"`
    Path          string         `json:"path,omitempty"`
    Host          string         `json:"host,omitempty"`
    Port          int            `json:"port,omitempty"`
    Method        string         `json:"method,omitempty"`
    Cwd           string         `json:"cwd,omitempty"`
    Track         string         `json:"track,omitempty"`
    Context       map[string]any `json:"context,omitempty"`
    Principal     map[string]any `json:"principal,omitempty"`
    Resource      map[string]any `json:"resource,omitempty"`
    Action        string         `json:"action,omitempty"`
    Req           any            `json:"req,omitempty"`
}

// Decision is the verdict.
type Decision struct {
    Action string `json:"action"`  // "allow" | "deny" | "ask"
    RuleID string `json:"rule_id,omitempty"`
}

// Engine methods (warm after NewEngine; safe for concurrent use)
func (e *Engine) Eval(ctx context.Context, in Input) (Decision, error)
func (e *Engine) EvalQuery(ctx context.Context, query string, in Input) (Decision, error)
func (e *Engine) Reload(ctx context.Context) error   // re-reads policyDir atomically
func (e *Engine) ClearCache()
func (e *Engine) InvalidatePrincipal(staticKey string)
func (e *Engine) Stats() Stats
```

**Cache behaviour:** Eval uses a two-level LRU. When `Input.Principal` is populated the outer key is a hash of the slow-changing principal fields (agent slug, user, enforce flag) and the inner key covers the fast-changing resource+action. When `Principal` is nil the flat LRU is used. Cache capacity is 4096 entries (flat) or 64 buckets × 256 entries (bucketed). Both levels are safe for concurrent use.

**Reload:** On `SIGUSR1` the daemon calls `Reload`, which re-reads the policy directory and swaps the compiled query atomically. The decision cache is cleared on every reload so stale verdicts from the old rule set cannot survive.

**Fail-open:** If evaluation fails (bad rule, context cancelled) `Eval` returns `Decision{Action: "allow"}` plus the error. The enforcement point (PEP) decides whether to surface the error or proceed silently; the cred path is always fail-closed regardless.

## macOS hook integration

agentjail installs agentpolicy as the backend of a [Claude Code `PreToolUse` hook](https://docs.anthropic.com/en/docs/claude-code/hooks). Every tool call the agent makes is intercepted before execution:

```sh
# One-time setup (not yet released; planned for the agentjail-hook binary)
agentjail install --for claude-code
# → writes hook entry to ~/.claude/settings.json
# → starts agentjail-daemon (holds the OPA engine warm via launchd plist)
# → writes default ~/.agentjail/policy.yaml
```

On each tool call Claude Code writes a JSON event to the hook's stdin; `agentjail-hook` forwards it over a Unix socket to `agentjail-daemon` in < 1 ms; the daemon evaluates Rego and writes back `allow`, `deny`, or `ask`. The agent sees the decision and either proceeds or stops. See [`docs/DECISION_RPC.md`](docs/DECISION_RPC.md) for the full wire format.

## Building from source

```sh
cd agentpolicy
go build ./...
go vet ./...
go test ./... -race
opa test policies/   # requires opa on PATH
```

## Architecture

agentpolicy is the policy decision engine layer — sits above the containment substrate (agentjail) and provides the allow/deny/ask verdict for every tool use. The credential broker (ADR 0004) consults agentpolicy for cred-use decisions.

The wire contract between agentpolicy and its callers is frozen in `api/decision/v1/`. Additive evolution only; new fields require no migration. See [`docs/DECISION_RPC.md`](docs/DECISION_RPC.md) for semantics and evolution rules.

## License

Apache-2.0. See [LICENSE](LICENSE).
