# ADR 0118-codex-approval-broker

Status: Accepted

The Git-only transport eligibility in this ADR is broadened by
ADR 0119-command-approval-transport.

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

The 2026-07-31 matrix also verified the CLI boundary for noninteractive mode:
`-a never` is a top-level Codex option and must precede the `exec` subcommand.
The `exec` parser does not accept `-a`; an invalid invocation exits before any
tool call. Negative scenarios therefore require both an audit assertion that
the unique operation reached AgentJail policy and an unchanged remote.

The bridge must preserve the canonical policy action and must not weaken the
default Codex approval policy. It must also avoid putting original shell text
into the rewritten input, the broker command line, challenge audit data, or
structured logs. Existing decision persistence for the original PreToolUse
request remains the established redacted `RedactToolInput` behavior; this
bridge must not add another persistence path for the original command.

A live test on 2026-07-31 exposed an earlier boundary: the valid Git invocation
`git -C <repo> push ...` did not reach the bridge because command policy matched
only adjacent words in raw shell text. It selected
`command_policy/default-allow`, so Codex had no AgentJail approval to present.
The same raw scan also treated inert search arguments containing those words as
an operation. Git's documented CLI grammar permits global options before the
subcommand; the policy contract must therefore describe executable intent, not
surface spelling. The effect-boundary transport broker is tracked separately in
AGE-269.

The installed Codex `0.146.0` also maps
`--dangerously-bypass-approvals-and-sandbox` to `approval_policy=never`. That
mode auto-rejects every execpolicy prompt, including AgentJail's exact broker
rule. Broad `on-request` is not an equivalent replacement: it also enables
sandbox, MCP, request-permission, and skill-script approval categories.

## Decision

For a Codex Bash `PreToolUse` canonical `ask` from either Git-push confirmation
rule, and only when both hook and daemon advertise
`codex_approval_bridge_v1`, the daemon mints an in-memory,
cryptographically random, one-use challenge. It binds the challenge to the
Codex session, turn, tool-use correlation, working directory, policy rule,
current tool-call epoch, and the recorded Codex process. The hook returns a
supported PreToolUse allow with a rewritten broker input whose fixed
`--operation git-push` label tells the user what class of effect is awaiting
approval. The same hook response uses Codex's supported `systemMessage` field
to show `🔐 AgentJail approval required for:` and the redacted effective Git
command immediately before the native prompt. The display is bounded and strips
non-printable characters; it is not added to the executable broker input. Other Bash `ask` rules retain the
fail-closed Codex behavior until their approval labels and compatibility
scenarios are designed.

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
Every redemption attempt burns the challenge. The daemon and hook must fail
closed for mint, arm, capability, response timeout, or redemption failures,
including daemon restarts and version skew. An approval-capable Codex
`PreToolUse` cannot safely apply the ordinary hook fail-open policy: before
receiving the response, the hook cannot know whether the canonical decision
was `allow` or an approval-requiring `ask`.

Challenge audit events use a non-reversible reference only. Neither the
challenge nor original command may be placed in audit detail, structured logs,
or new persistent records. The broker transport must not expose original shell
text; an opaque one-use capability is carried only in the narrowly managed
broker argv and daemon socket request, and must never be reused as authority.
The user-visible command is produced through the existing store-boundary secret
redactor before it enters the hook response. It is intentionally visible in the
interactive Codex transcript, but raw credential values remain excluded.

This amends ADR 0117-codex-ask-boundary for eligible Bash asks. All other Codex
PreToolUse asks remain fail-closed denies.

When the opt-in AgentJail PATH shim receives Codex's bypass flag (or its legacy
`--yolo` spelling) as the leading global option, it keeps the Codex sandbox at
`danger-full-access` but replaces the all-or-nothing approval setting with a
granular policy. Only execpolicy-rule prompts remain interactive; sandbox, MCP
elicitation, `request_permissions`, and skill-script prompts auto-reject, and
the reviewer remains the user. This preserves the externally sandboxed launch
flow while leaving a native approval boundary for AgentJail's exact managed
rule.

The daemon parses Bash into executable invocations and classifies Git operations
before Rego evaluation. `command_intents` carries one of the typed remote-update
shapes: normal, forced default branch, forced explicit topic, or forced implicit
target. Classification consumes Git's documented global options (`-C`, `-c`,
and long forms), push options, and refspecs. Rego selects policy outcomes from
those intents and no longer scans raw command text for Git remote updates.

## Consequences

Codex can present its native approval UI for an AgentJail Git-push `ask`
without changing unrelated permission categories. The user sees the redacted
effective command beside the prompt and the broker argv visibly identifies
`git-push` without carrying the original command, paths, remote, or refspec as
executable metadata. Codex does not currently provide a display-only field
inside its native prompt box, so the command appears immediately before that
box rather than replacing the broker command. The bridge is not a general
approval primitive for other Bash asks, MCP, file tools, or arbitrary direct
invocations.

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

Bridge-capable Codex hook requests use a 2 second daemon round-trip ceiling
while the 50 ms end-to-end latency target remains unchanged. A cold request
combines policy evaluation, process-ancestry work, and the required approval
audit write. Codex CLI `0.147.0` was live-tested on 2026-08-13: an audit write
completed after the old 250 ms ceiling, so the hook timed out and Codex ran the
original command. The longer ceiling absorbs bounded cold-path work; a timeout
still denies instead of exposing the original command to Codex. Legacy clients
and Codex hooks without the bridge capability retain the 45 ms ceiling.

## Acceptance Criteria

1. A canonical Codex Git-push `ask` shows the redacted effective Git command
   immediately before Codex's native prompt, whose managed broker command
   contains `--operation git-push`, without changing unrelated approval
   categories.
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
   approve, cancel, `approval_policy=never`, and `--ignore-rules` using the
   valid `git -C <repo> push ...` form, plus `go build ./...`, `go vet ./...`,
   `go test ./...`, `make smoke`, and `make adr-check`.
9. Text-only mentions in another executable's arguments do not produce a Git
   remote-update intent, while repeated global options and branch-aware force
   forms preserve their deny/ask/allow outcomes.
10. Launching the AgentJail Codex shim with
    `--dangerously-bypass-approvals-and-sandbox` keeps Codex at
    `danger-full-access`, auto-rejects every non-rule approval category, and
    surfaces the broker's native execpolicy prompt to the user.
