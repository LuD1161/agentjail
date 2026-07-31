# ADR 0118-codex-approval-broker

Status: Proposed

## Context

AgentJail's canonical `ask` requires a real user decision. Codex's
`PreToolUse` hook can rewrite a Bash input but cannot itself initiate a native
approval. ADR 0117-codex-ask-boundary consequently translated every Codex
PreToolUse `ask` to a fail-closed deny.

Codex CLI `0.146.0` was live-tested on 2026-07-30 against the current official
[Hooks documentation](https://learn.chatgpt.com/docs/hooks). A PreToolUse
`updatedInput` is evaluated by Codex execpolicy after the hook: an exact
`prefix_rule` can prompt for a rewritten command. The compatibility test also
showed that cancel emits no `PostToolUse`, `approval_policy=never` does not
create a prompt, and `--ignore-rules` executes the rewrite without a
`PermissionRequest`. The latter means an input rewrite alone can never prove
user intent.

The bridge must preserve the canonical policy action and must not weaken the
default Codex approval policy. It must also avoid putting original shell text
into the rewritten input, the broker command line, challenge audit data, or
structured logs. Existing decision persistence for the original PreToolUse
request remains the established redacted `RedactToolInput` behavior; this
bridge must not add another persistence path for the original command.

## Decision

For a Codex Bash `PreToolUse` canonical `ask`, and only when both hook and
daemon advertise `codex_approval_bridge_v1`, the daemon mints an in-memory,
cryptographically random, one-use challenge. It binds the challenge to the
Codex session, turn, tool-use correlation, working directory, policy rule,
current tool-call epoch, and the recorded Codex process. The hook returns a
supported PreToolUse allow with a rewritten broker input; no change is made to
Codex's default approval policy.

Installation owns one exact Codex execpolicy rule for that broker. It is
idempotent, refuses to overwrite a locally changed managed file, and removes
only its byte-for-byte owned file. A matching `PermissionRequest` records that
Codex reached the prompt path; it must match the challenge, session, turn,
working directory, and recorded Codex ancestry, then record a fresh
process-start boundary and defer its decision to Codex. Prompt observation is
not authorization by itself: redemption still requires the post-prompt fresh
process chain.

The broker may redeem only an armed challenge. The daemon verifies the
same-UID peer, active session, unchanged epoch, one-use state, expiry, and a
fresh process chain descended from the recorded Codex process before returning
the exact original command and working directory. Process-topology attestation
is deliberately conservative: any missing or unverifiable relationship denies.
Every redemption attempt burns the challenge. The daemon must fail closed for
mint, arm, capability, or redemption failures, including daemon restarts and
version skew; ordinary non-broker hook availability remains governed by the
standard fail-open policy.

Challenge audit events use a non-reversible reference only. Neither the
challenge nor original command may be placed in audit detail, structured logs,
or new persistent records. The broker transport must not expose original shell
text; an opaque one-use capability is carried only in the narrowly managed
broker argv and daemon socket request, and must never be reused as authority.

This amends ADR 0117-codex-ask-boundary for eligible Bash asks. All other Codex
PreToolUse asks remain fail-closed denies.

## Consequences

Codex can present its native approval UI for an AgentJail Bash `ask` without
changing its default permission policy. The prompt identifies the AgentJail
approval operation rather than displaying the original command, which is an
intentional confidentiality trade-off until Codex exposes a safe display-only
field. The bridge is not a general approval primitive for MCP, file tools, or
arbitrary direct invocations.

The daemon holds approval state only in memory, so restart or expiry invalidates
pending prompts. A policy decision still records the normal redacted original
input once; audit events add only a challenge reference. A direct broker call,
an ignored execpolicy rule, a canceled prompt, a stale agent process, or a
replayed challenge cannot authorize execution.

The opaque challenge is visible to same-user process inspection while the
broker starts. That exposure is bounded by its short lifetime and one use, and
the value is insufficient without the bound session, epoch, and fresh
process-topology attestation; it is not an approval token by itself.

The broker uses the session's absolute `SHELL` with login-shell semantics and
falls back to `/bin/sh` when that environment value is unavailable. Codex does
not expose the original per-call shell/login selection in the hook contract, so
the live compatibility matrix must cover shell syntax and initialization; an
unverified dialect is a release blocker rather than a reason to guess.

Bridge-capable Codex hook requests use a 250 ms daemon round-trip ceiling while
the 50 ms end-to-end latency target remains unchanged. A cold request combines
policy evaluation with process-ancestry work; treating a healthy response after
45 ms as an outage fails open and lets Codex evaluate the original command
instead of the opaque broker rewrite. Legacy clients and Codex hooks without
the bridge capability retain the 45 ms ceiling.

## Acceptance Criteria

1. A canonical Codex Bash `ask` such as `git push` yields Codex's native prompt
   without changing the default approval policy.
2. Approval executes the exact original command under the existing shield and
   working directory, preserving exit status, stdout, and stderr.
3. Cancel, pending state, replay, expiry, wrong session or PID, a later
   PreToolUse epoch, or stale pre-prompt process ancestry never executes.
4. `--ignore-rules`, `approval_policy=never`, and a missing managed rule cannot
   redeem a challenge.
5. Old hook/new daemon and new hook/old daemon combinations fail closed through
   the advertised capability gate.
6. Apart from the existing redacted PreToolUse decision record, the bridge adds
   no raw original command to rewritten argv, approval audit detail, broker
   logs, or new persistent storage. A live challenge appears only in the
   rewritten broker argv and daemon socket request, is never logged or audited
   (only a fingerprint is), and is insufficient without session, epoch, and
   fresh-process attestation.
7. The managed execpolicy rule is exact, idempotent, and ownership-safe.
8. Before merge, run the installed Codex `0.146` compatibility matrix for
   approve, cancel, and `--ignore-rules`, plus `go build ./...`, `go vet ./...`,
   `go test ./...`, `make smoke`, and `make adr-check`.
