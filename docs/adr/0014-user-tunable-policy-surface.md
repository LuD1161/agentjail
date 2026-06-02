# 0014 — User-tunable policy surface: disable any rule, first-class custom rules

Status: Proposed

Covers two launch work items that share one surface:
- **#3** — make rules (including most core rules) user-disableable.
- **#4** — let users author their own rules and enable/disable them easily.

## Context

Today agentjail has three rule sources with inconsistent control
(`cmd/agentjail/policy.go`):

- **Core** (`command_policy`, `file_policy`, `mcp_policy`, + `resolver`): whole
  `.rego` files in `~/.agentjail/rules/`, always loaded, re-installed on upgrade,
  and **cannot be disabled** — `policy disable` refuses them.
- **Library** (`no_shell_init_write`, `no_shell_eval`, …): opt-in. `enable`
  copies the embedded `.rego` in; `disable` removes it.
- **Custom**: a user can already drop a `.rego` into `~/.agentjail/rules/` and
  SIGHUP (`installCoreRules` preserves non-core files), but custom rules are
  **invisible to `policy list`** and have no validation or lifecycle.

There is no single view of everything in effect, no way to turn a core rule off,
and no supported authoring flow.

Two facts shape the decision:

1. The original driver for "let me disable core" was **file-policy noise on temp
   and the project dir** — already fixed in ADR 0013. So core-disable is now a
   deliberate **power-user escape hatch**, not a daily necessity: make it
   *possible and auditable*, not *frictionless*.
2. ADR 0012 wired `policy.yaml` into OPA as `data.agentjail.config` with SIGHUP
   hot-reload — the natural, file-deletion-free lever for disabling rules.

All rules already funnel through one mechanism: `resolver.rego` aggregates
`data.agentjail.candidate` and is the sole producer of `data.agentjail.decision`
(priority deny > ask > allow, lowest `rule_id` wins).

## Decision

### 0. Prerequisite cleanup (two parts, land first)

**0a — normalize core rule_ids to `<policy>/<rule>`.** `command_policy.rego`
today emits mostly *unprefixed* ids (`no-sudo`, `no-rm-rf-absolute`,
`confirm-git-push`, …; only `command_policy/default-allow` is namespaced —
`agentpolicy/policies/command_policy.rego:56,68,130,294,437`). `disabled_rules`
operates on emitted `rule_id` and globs like `command_policy/*`, so these must be
renamed to `command_policy/<rule>` (and `file_policy`/`mcp_policy` audited for the
same). Because emitted `rule_id`s appear in logs, the decision cache, and audit
replay, ship a **compat alias map** (old id → new id) so any pre-existing
`disabled_rules`/tooling referencing an old id still resolves; tests cover both
forms. This normalization is what makes the registry namespace coherent.

**0b — enforce "resolver is the only `decision` producer" on the hook path.**
`no_daemon_kill.rego` declares `decision = …` directly
(`cmd/agentjail/library/no_daemon_kill.rego` + mirror), contradicting the
candidate model and risking `eval_conflict`. Migrate it to a `candidate` entry.
Add a guard test that fails if any **hook-path** `.rego` (the candidate+resolver
tree under `agentpolicy/policies/` and its mirror, **excluding** the legacy
credential-broker `default.rego` and `experimental/` which are not loaded on the
hook path per ADR 0011) declares `decision`/`default decision` outside
`resolver.rego`. User custom files are held to the same contract (§5).

### 1. Rule-level disable via config (`disabled_rules`)

Add `disabled_rules: [<rule_id-or-glob>, …]` to `PolicyConfig`, injected (ADR
0012) as `data.agentjail.config.disabled_rules`. The unit is the **emitted
`rule_id`** (e.g. `file_policy/sensitive_in_project`, `command_policy/no-sudo`),
never the file name — a rule **registry** (see §4) maps source→rule_ids so the
namespace is well-defined.

`resolver.rego` is **fully rewired** to read an effective set everywhere it
currently reads `candidate` (all six references across the deny/ask/allow
branches and their id-sets):

```rego
disabled := object.get(data.agentjail.config, "disabled_rules", [])
effective_candidate[c] {
    some c in candidate
    not rule_disabled(c.rule_id)
}
rule_disabled(id) { some p in disabled; glob.match(p, ["/"], id) }   # "/"-segment-bounded
```

- **Glob is `/`-segment-bounded** (`glob.match(p, ["/"], id)`), so
  `file_policy/*` matches `file_policy/sensitive_in_project` but not a deeper
  `file_policy/x/y`. Invalid glob patterns are **rejected at config load**
  (compile each pattern once) so a bad pattern can't turn every eval into an
  error.
- **Self-protection rules are never suppressible** (see §2). The locked set is a
  **hardcoded constant in `resolver.rego`** (`locked_rules := {…}`), NOT config
  or Go state — the resolver can only read Rego/data, and baking it into the
  policy means no amount of `policy.yaml` editing can unlock it. `rule_disabled`
  is `glob.match(p, ["/"], id)` for some `p in disabled` AND `not id in
  locked_rules`. A `disabled_rules` entry that matches a locked id is ignored
  with a reload WARN. A required test feeds a hand-edited `policy.yaml` listing
  every locked id and asserts each still fires.
- `resolver/default` and `resolver/*` are in `locked_rules` (disabling them would
  remove the fail-safe default).
- **Hot-reloadable + auditable** — change `disabled_rules`, SIGHUP; the daemon
  logs every candidate it suppresses (`rule_id` + input summary) so a weakened
  guardrail is never silent.
- Fail-safe default: absent/empty ⇒ nothing suppressed.

### 2. Self-protection set stays locked (resolves the self-disable bypass)

Making rules disableable via a CLI that writes `policy.yaml` creates a bypass: a
compromised agent could run `agentjail policy disable <guard> --force` as a Bash
command and the CLI would write the config *outside* the hook-enforced file path.
`--force`/audit-logging do not stop an agent that can type `--force`. Therefore a
small **self-protection set is non-disableable**, defended on every vector:

| Vector | Defense (must stay on) |
|--|--|
| Edit `~/.agentjail/policy.yaml` directly | `file_policy` `is_protected_credential` already hard-denies `~/.agentjail/**` (locked) |
| Run any policy-mutating CLI via shell | `command_policy` gains an **always-on** rule that denies/asks the full set of config-mutating commands — `agentjail policy {disable,enable,add,remove}`, `agentjail mcp {allow,block}`, any future `policy`/`mcp` mutation subcommand, and shell writes/redirects into `~/.agentjail/` — so custom-rule install is not an alternate weakening route |
| Kill/stop the daemon | `no_daemon_kill` — promoted to **core, locked** |
| Remove the agent hooks | `no_hook_self_disable` — promoted to **core, locked** |
| Disable the resolver default | `resolver/*` locked |

The locked set is the **minimum that protects agentjail's own integrity** —
nothing about the *user's* files/commands/MCPs is locked; those are all
disableable. It is the `locked_rules` constant in `resolver.rego` (authoritative)
mirrored in the Go registry only for `policy list` display; the Rego copy is what
enforces. Disabling anything else (core or not) goes through §3.

### 3. `agentjail policy disable/enable` extended to rule_ids + non-locked core

- `policy disable <rule_id|source/*>` adds the id(s) to `disabled_rules` and
  SIGHUPs. Disabling a **core** (non-locked) rule requires `--force` **and** an
  interactive `/dev/tty` confirm that `--force` alone does not satisfy when no
  TTY is present (so a non-interactive agent invocation cannot complete it even
  with `--force`); prints a loud warning naming the dropped protection.
- A locked rule_id is refused with an explanation.
- `policy enable <rule_id>` removes the id from `disabled_rules`.
- **Audit:** config mutations write a structured event to `~/.agentjail/audit.log`
  opened `O_APPEND|O_CREATE` (0600): timestamp, action, rule_id, pid/ppid, cwd.
  If the append write fails, the **disable is aborted** (fail-closed on
  auditability). This is best-effort provenance, NOT tamper resistance — a
  same-user process can still rewrite the file; real tamper-proofing (daemon-owned
  append API or platform immutable flag) is future work, called out so we don't
  overclaim.
- Library enable/disable keeps its file-copy behavior for adding/removing the
  optional rule file; `disabled_rules` is the override layer on top.

### 4. Rule registry + unified `agentjail policy list`

Introduce a single in-binary **rule registry**: for each known rule_id, its
`source` (core / library / custom), human description, and `locked` flag. The
list, enable, disable, and resolver-lock paths all read it — no more scattered
`coreRuleNames()`/`libraryRuleNames()` string lists.

`policy list` becomes one view, three sections — **Core**, **Optional
Hardening**, **Custom** — each row showing `on` / `off` / `locked` (core rules
reflect `disabled_rules`; only the §2 set is `locked`), source, and
toggleability. Custom rule_ids are discovered from the registry built when a
custom rule is added (§5), not by evaluating inputs.

### 5. First-class custom rules

- **Authoring contract:** a custom rule file must be `package agentjail` and emit
  **only** `candidate contains r` / `candidate[r]` entries. It must NOT declare
  `decision`, `default …`, or redefine existing package symbols/helpers.
- **Reserved rule_id namespace.** Every custom rule_id MUST be
  `custom/<name>/<rule>` (where `<name>` is the file's basename). `policy add`
  **rejects** any id that omits the `custom/` prefix, collides with an existing
  registered id (core/library/custom), or targets a reserved prefix
  (`file_policy/`, `command_policy/`, `mcp_policy/`, `resolver/`, library names).
  This keeps disable/lock/list/audit semantics unambiguous.
- `agentjail policy add <file.rego>` — **validate by compiling the full bundle**
  (core + enabled library + the new file) via OPA, not the file in isolation,
  because the daemon compiles all `.rego` as one unit; reject on any compile
  error, `decision`/`default` declaration, symbol collision, or namespace
  violation. Register its rule_ids and copy into `~/.agentjail/rules/`, SIGHUP.
- **Daemon validate-on-load (deterministic quarantine).** A single failed
  bundle compile does not identify which custom file is at fault (two files may
  conflict only together). So the daemon compiles the **core + library baseline
  first**, then adds custom files **one at a time in sorted (deterministic)
  order**, keeping a file only if the accumulated bundle still compiles;
  each rejected file is logged with a WARN and skipped. The baseline always
  loads, so the daemon never fails startup and never goes open because of a bad
  custom rule.
- `agentjail policy remove <name>` deletes a custom rule and its registry entry.
- **Authoring format:** raw Rego (`candidate` pattern, already shown in
  `samples/`) is the V1 surface. A higher-level YAML rule-spec compiled to Rego,
  for non-Rego users, is **deferred to a future ADR** (named so it isn't lost).

## Consequences

- **Fail-closed becomes user-configurable, except for self-defense.** Disabling
  a (non-locked) core rule relaxes a guarantee that previously could not be
  turned off — deliberate for #3. Mitigations: a locked self-protection set,
  `--force` + non-bypassable TTY confirm, fail-closed audit, and visibility in
  `policy list`. No *default* is weakened; only an explicit, audited, human-only
  opt-out is added. This ADR is the record AGENTS.md requires for relaxing
  fail-closed on the cred path.
- **The self-disable bypass is closed** because the rules that protect
  agentjail's integrity (config, daemon, hooks) are exactly the locked set, and
  `command_policy` additionally gates the CLI mutation commands.
- **Custom rules are safe by construction** — bundle-composition validation on
  add + skip-bad-on-load mean broken Rego degrades gracefully and cannot cause
  `eval_conflict_error` against the resolver.
- The `locked`-everything-core concept is replaced by a *minimal* locked set;
  `disabled_rules` is the single disable mechanism; re-enable is removing the id.
- Gated on ADR 0012 (shipped). The YAML rule-spec authoring path is future work.

## Implementation sketch (task breakdown order)

1. **Prereq:** (0a) normalize `command_policy`/`file_policy`/`mcp_policy`
   rule_ids to `<policy>/<rule>` + ship the old→new alias map with tests; (0b)
   migrate `no_daemon_kill` to `candidate` and add the
   "only-resolver-declares-decision" hook-path guard test. Promote
   `no_daemon_kill` + `no_hook_self_disable` to locked core.
2. `resolver.rego`: `effective_candidate` + `/`-bounded `rule_disabled` honoring
   the locked set; route `decision` through it; daemon logs suppressions. Rego
   tests: disabled-deny-with-allow, all-disabled→`resolver/default`,
   locked-rule-cannot-be-disabled, glob boundary.
3. `PolicyConfig.DisabledRules` + glob-validate-on-load + `ToOPAData` +
   merge-over-default; strict-YAML unknown-key test.
4. `command_policy`: always-on guard for `agentjail policy disable` / `mcp` /
   `~/.agentjail/` mutation commands.
5. Rule registry (source/desc/locked) + unified `policy list`.
6. `policy disable/enable` for rule_ids + non-locked core (`--force` + TTY
   confirm) + append-only fail-closed audit log.
7. `policy add`/`remove` with full-bundle validate-on-install; daemon
   validate-on-load skip-with-WARN. Docs: README + `samples/README.md`.
