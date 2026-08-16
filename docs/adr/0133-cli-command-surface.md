# ADR 0133: Normalize the CLI command surface

**Status:** Accepted

## Context

The Cobra migration left several legacy parsers and parallel help paths behind.
Related operations were split between singular and plural nouns, some apparent
subcommands had no independent help or completion, compatibility flags remained
visible after losing their effect, and static help topics drifted from the live
command tree. The unfinished phantom-token workflow also exposed `agentjail
secret` beside the shipped static `agentjail credential` broker.

The daemon-only host approval path had already become persist-only, but the
request command still advertised a TTL and temporary current-session access.
The daemon never consumed that TTL when approving the project overlay.

## Decision

Use one canonical Cobra hierarchy for each user concept:

- `grant list|history|approve|deny`
- `mcp tool list|allow|block|ask|clear`
- `sessions [flags]`
- `telemetry status|enable|disable|view|reset`
- `trust add|remove|list`

Keep established irregular spellings as hidden compatibility commands or flags
when scripts may depend on them. Do not require examples on self-explanatory
commands; an example must teach a value, workflow, or non-default behavior.
Resolve command help from Cobra and retain only `getting-started` as a separate
cross-command guide.

Remove the public `secret` command until phantom HTTP credential substitution
is production-wired. The encrypted broker remains available through
`credential`, and the internal broker role remains intact.

Host requests are project-policy requests. Approval persists the host for
future project sessions and does not widen the running sandbox. Therefore the
public request surface does not advertise a TTL.

## Consequences

- Help, completion, and the executable command tree share one structure.
- Existing scripts using `grants`, `mcp tools`, `untrust`, `replay --list`,
  `--keep-secrets`, or `--allow-unsupported` continue to parse through hidden
  compatibility paths.
- Users must launch a new sandbox after an approved project host request.
- The phantom-token design remains documented but cannot be mistaken for a
  shipped credential workflow.
- A later removal of compatibility paths requires an explicit breaking-release
  decision.
