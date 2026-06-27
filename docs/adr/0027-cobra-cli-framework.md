# ADR 0027: Adopt Cobra for CLI Framework

**Status:** Accepted

## Context

agentjail's CLI surface has grown from 6 top-level commands at launch to 12+
subcommands with deep nesting:

```
agentjail mcp allow/block/list/scan/where/tools/tool
agentjail mcp tool allow/block/ask/clear
agentjail skill list/allow/block/ask/clear
agentjail help <topic>
agentjail policy enable/disable/list
```

The current implementation uses manual `switch` dispatch in `main.go`, `mcp.go`,
and `skill.go`. Each subcommand manually handles:

- `help` / `-h` / `--help` flag detection (repeated in every dispatcher)
- Argument parsing (mix of positional args, `flag.FlagSet`, and manual loops)
- Usage text formatting (hand-rolled in each `printXxxUsage` function)
- Error messages for missing/unknown subcommands

This works but has compounding costs:

1. **Help is inconsistent.** Some commands handle `--help`, others don't. The
   rtk hook rewriter can intercept `--help` before the binary sees it.
2. **No shell completions.** Users can't tab-complete `agentjail mcp t<TAB>`.
3. **Boilerplate per command.** Every new subcommand needs ~30 lines of dispatch
   scaffolding, help text, and flag parsing -- none of which is the actual logic.
4. **Deep nesting is fragile.** `mcp tool allow` is 3 levels deep; adding a 4th
   level (e.g. `mcp tool allow --scope project`) requires yet another manual
   parser.

## Decision

Adopt [spf13/cobra](https://github.com/spf13/cobra) as the CLI framework.

### Why Cobra

- De facto Go CLI standard (used by kubectl, docker, gh, hugo, etc.)
- Automatic `--help` on every command and subcommand
- Built-in shell completion (bash, zsh, fish, powershell)
- Persistent flags (e.g. `--project` propagates to all subcommands)
- Consistent error handling and usage formatting
- Single dependency tree: cobra + pflag (no transitive bloat beyond these)

### Why not alternatives

| Alternative | Reason to skip |
|-------------|---------------|
| urfave/cli | Less adoption, weaker completion support |
| kong | Struct-tag based -- doesn't fit the existing function-per-command style |
| stdlib only | Current approach; costs listed above |

### Migration approach

1. Add `github.com/spf13/cobra` dependency
2. Create a root command in `cmd/agentjail/root.go`
3. Migrate one subcommand tree at a time (mcp, skill, help, etc.)
4. Each command's `RunE` calls the existing `runXxx` function -- minimal logic change
5. Remove manual dispatch, help text, and flag parsing as each command migrates
6. Regenerate `THIRD_PARTY_LICENSES` after dependency addition

### What does NOT change

- Command names and behavior stay identical
- Policy evaluation, store, hook, daemon -- untouched
- No new runtime behavior (cobra is CLI scaffolding only)

## Consequences

### Positive

- `--help` works everywhere automatically, zero per-command effort
- Shell completions for free (`agentjail completion bash/zsh/fish`)
- New subcommands need ~10 lines instead of ~50
- Persistent flags (`--project`, `--json`) can be defined once
- Consistent error messages and usage formatting

### Negative

- New dependency: cobra v1.8+ (~2.5 MB compiled impact, ~6 transitive deps)
- Migration churn across `main.go`, `mcp.go`, `skill.go`, `help.go`, etc.
- Contributors need basic cobra familiarity (well-documented, widely known)
- `THIRD_PARTY_LICENSES` needs regeneration
