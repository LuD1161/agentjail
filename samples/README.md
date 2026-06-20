# samples/

Drop-in examples for extending agentjail beyond the core policies and
7 library rules. Everything here is **optional** — copy what you want,
edit what you need.

```
samples/
├── policies/                       ← additional .rego rules
│   ├── mcp_filesystem_readonly.rego        deny mcp__filesystem__write_file
│   ├── mcp_filesystem_arg_aware.rego       inspect read_file's path arg
│   ├── mcp_github_writes_ask.rego          ask before PR creates/merges
│   ├── custom_no_npm_global.rego           block `npm i -g`
│   └── custom_no_kubectl_prod.rego         block kubectl against prod context
└── configs/                        ← drop-in policy.yaml fragments
    ├── policy-strict.yaml                  lock everything down (recommended for CI/CD)
    ├── policy-dev-permissive.yaml          loosened for daily local dev
    ├── policy-mcp-heavy.yaml               for teams using many MCP servers
    └── policy-aws.yaml                     AWS pack: per-account posture + AWS MCP allowlist
```

---

## How to load a custom policy

agentjail reads policies from **two places**:

1. **`agentpolicy/policies/`** (shipped with the binary, baked in via `go:embed`)
2. **`~/.agentjail/rules/`** (user-installed; you put files here)

The daemon loads both directories on startup and on `SIGHUP`. Anything you
drop in `~/.agentjail/rules/` is merged with the core policies — no rebuild
needed.

### Option A — `agentjail policy add` (recommended)

```sh
# Validates + installs in one step; SIGHUPs the daemon automatically.
agentjail policy add samples/policies/mcp_filesystem_readonly.rego

# Verify
agentjail policy list                           # shows your rule under Custom
agentjail logs                                  # watch denies in real time

# Remove when no longer needed
agentjail policy remove mcp_filesystem_readonly
```

`policy add` validates the file before installing it:
- `package agentjail` must be declared.
- Only `candidate contains r if { ... }` entries are allowed — NOT `decision = ...`.
- Every `rule_id` must use the prefix `custom/<filename_stem>/<rule>` (e.g. a
  file named `my_rule.rego` must emit ids like `custom/my_rule/no-something`).
- The full bundle (core + library + your file) must compile in OPA — a file that
  passes alone but breaks the bundle is rejected with a clear error.

### Option B — copy a sample and SIGHUP (manual, no validation)

```sh
# Copy whichever sample you want
cp samples/policies/mcp_filesystem_readonly.rego ~/.agentjail/rules/

# Tell the daemon to reload (zero-downtime — in-flight evals complete on the old engine)
kill -HUP $(pgrep -f agentjail-daemon)

# Verify
agentjail policy list                           # should show your rule
agentjail logs                                  # watch denies in real time
```

Note: the samples use `rule_id` prefixes like `samples/` — if you use them as
custom rules you should rename the rule_ids to `custom/<stem>/...` and then
use `agentjail policy add` for proper validation and lifecycle management.

### Option C — write your own from scratch

A minimum-viable .rego file (note the required `custom/<stem>/` rule_id prefix):

```rego
# ~/.agentjail/rules/my_rule.rego
#
# Required header for agentjail policy add validation:
# @rule_id: custom/my_rule/no-yolo-deploys
package agentjail

import future.keywords.if
import future.keywords.contains

# Use `candidate contains r if { ... }` — the partial rule set pattern.
# The resolver.rego picks the most restrictive candidate (deny > ask > allow).
candidate contains r if {
    input.hook_event == "PreToolUse"
    input.tool_name == "Bash"
    contains(input.tool_input.command, "kubectl apply -f")
    r := {
        "action":  "deny",                                    # or "ask" or "allow"
        "rule_id": "custom/my_rule/no-yolo-deploys",          # must start with custom/<stem>/
        "reason":  "deploys after 5pm are banned per the on-call agreement",
        "impact":  "would deploy outside business hours",     # shown in `agentjail logs`
    }
    # add a real time-of-day check via Rego's time package, or external eval
}
```

Then `agentjail policy add ~/.agentjail/rules/my_rule.rego`.  The `impact`
field shows up in `agentjail logs` automatically — no Go code changes needed.

### Option D — enable a built-in library rule via the CLI

For the 7 opt-in hardening rules that ship inside the binary:

```sh
agentjail policy list                               # see what's available
agentjail policy enable no_shell_init_write         # turn one on
agentjail policy enable no_history_read
agentjail policy disable no_shell_init_write        # turn one off
```

These are managed by the CLI — you don't copy files by hand.

### Bad rules are quarantined, not fatal

If a manually-edited custom rule breaks the bundle after the daemon starts,
the daemon will quarantine it (skip with a WARN log) on the next SIGHUP reload.
The baseline (core + valid rules) always loads — the daemon never goes open
because of a bad custom rule.

Fix the file and send SIGHUP to reload:

```sh
kill -HUP $(pgrep -f agentjail-daemon)
```

---

## How to load a custom config (policy.yaml)

`~/.agentjail/policy.yaml` is a single YAML file the daemon reads alongside
the .rego rules. Sample files are in `samples/configs/` — copy one as your
starting point:

```sh
cp samples/configs/policy-strict.yaml ~/.agentjail/policy.yaml
kill -HUP $(pgrep -f agentjail-daemon)
```

The Rego rules reference `data.agentjail.config.*` to read this YAML at
eval time — that's how MCP allowlists, network allow-hosts, and per-tool
restrictions plug in without writing more Rego.

### `policy-aws.yaml` — AWS pack

The AWS pack template wires up per-account posture (ADR 0017), an AWS MCP
server with a read-only per-tool allowlist, and a network allowlist for
typical AWS endpoints. Copy it and enable the destructive-CLI library rule:

```sh
cp samples/configs/policy-aws.yaml ~/.agentjail/policy.yaml
agentjail policy enable no_aws_destructive
kill -HUP $(pgrep -f agentjail-daemon)
```

Then edit the `aws.accounts` map with your real account ids (find them with
`aws sts get-caller-identity --profile <name>`). The daemon resolves the
account from `aws --profile <name>` via `~/.aws/config`; accounts not listed
fall back to `aws.default_posture` (fail-safe `prod` — delete denied).

## Authoring tips

- **Always use `candidate contains r if { ... }`** — not `decision = ...`.
  Since the resolver pattern was introduced, `resolver.rego` is the ONLY file that
  declares `decision`. Your custom rules contribute to the `candidate` partial
  rule set, and the resolver picks the most restrictive one (deny > ask > allow).
  Using `decision = ...` in your file will cause an `eval_conflict_error`.
- **Always test before shipping.** Drop your rule next to a `_test.rego`
  file with at least 3 cases (deny path, allow path, edge case), then
  `opa test ~/.agentjail/rules/`.
- **Use the `impact` field.** It's what the user sees in `agentjail logs`.
  Make it a sentence ending in a verb phrase: "would leak AWS credentials",
  "would force-push to a protected branch".
- **Prefix your `rule_id` with your org or your username.** e.g.
  `myorg/no-yolo-deploys` — keeps it from colliding with core rule IDs.
- **Stay in `package agentjail`** unless you specifically want your rule
  isolated — the daemon queries `data.agentjail.decision` and rules in
  other packages are ignored.
- **Add the right imports.** Each rule file needs at minimum:
  ```rego
  import future.keywords.if
  import future.keywords.contains
  ```

See `agentpolicy/README.md` for the full rule-authoring reference.
