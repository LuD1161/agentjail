# ADR 0111 — Shield-attested downgrade of sandbox-redundant deny rules

## Status
Accepted

## Context

The daemon's Bash text-heuristic deny rules (e.g.
`command_policy/no-bash-touch-sensitive-path`, `no-rm-rf-absolute`) match on
the raw command *string*. They exist because `file_policy` only sees the
Read/Write/Edit tool calls, so an agent could bypass it by shelling out —
`cat ~/.ssh/id_rsa`, `rm -rf ~`. The regex is over-broad on purpose: it denies
any command that *mentions* a sensitive path.

Inside a **shielded** session that heuristic is redundant. The OS sandbox
(seatbelt on macOS, Landlock on Linux) is `(allow default)` plus an explicit
deny-list: it read-denies `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.agentjail`,
`id_rsa`, `*.pem/.key`, `.netrc`, `.npmrc`, `.git-credentials`, and confines
writes to the session's own tree + `/tmp`. So `cat ~/.ssh/id_rsa` under the
shield gets EPERM at the syscall regardless of the policy verdict — the regex
deny only adds friction (it also trips on `echo`-ing a path, running the
`agentjail` CLI by full path, or a commit message that names one).

A project `.env` is deliberately NOT special-cased: it lives in the working
tree the agent is meant to read, real credential stores are sandbox-denied,
and leakage is stopped by the network egress allowlist, not by blocking a
`cat`. Treating `.env` as sacred is the same false-positive class as blocking
`.env.example`.

The naive fix — trust `AGENTJAIL_SHIELDED=1` — is unsound: env is
agent-influenced, so a prompt-injected agent could set it and disable the
rules. The switch must be something the sandboxed agent cannot forge.

## Decision

The shield **attests its own PID** to the daemon over the privileged,
sandbox-denied `daemon-ctl.sock`, gated by the `ctlauth` control token. The
sandboxed agent can neither read that token nor reach that socket
(network-outbound denied to the literal; path read-denied on Linux), so it
cannot self-attest.

For each decision the daemon downgrades a `deny` to `allow` (parking the real
verdict in `WouldAction`, exactly like monitor mode — ADR 0091) **iff both**:

1. `resp.RuleID` is in a fixed allowlist of **filesystem-scoped** rules the OS
   sandbox already enforces, AND
2. the command does **not** escalate privilege (`sudo`/`doas`/`su`/`run0` as a
   whole token), AND
3. `req.AgentPID` descends from a live attested shield PID
   (`procutil.FindAncestorPID`).

The privilege-escalation guard is load-bearing, not hygiene. The file sandbox
governs the *agent's* UID; `/etc` is read-allowed by default (only writes are
denied). Because `no-bash-touch-sensitive-path` outranks `no-sudo` in the
resolver, a command like `sudo cat /etc/master.passwd` resolves to the
downgradable rule — so without the guard the downgrade would let `sudo` read a
root-only file the sandbox does not protect. Escalating commands therefore
never downgrade, regardless of which rule matched.

Ancestry — not the session id — is the correlation key: the agent is always
the shield's descendant (spawned child) or the shield process itself
(`syscall.Exec` preserves the PID), on every platform and launch path, and it
is known from the first hook, with no dependency on Claude's session-id
resolution timing.

### Downgrade allowlist (filesystem-scoped only)

- `command_policy/no-bash-touch-sensitive-path`
- `command_policy/no-rm-rf-absolute`
- `command_policy/no-recursive-delete-of-protected-paths`
- `command_policy/no-find-delete-in-home`
- `command_policy/no-ssh-keygen-outside-tmp`

Everything else stays strict even when shielded, because its protection comes
from a *different* layer or none: privilege (`no-sudo`), service control
(`no-launchctl-remove`, `no-systemctl-disrupt`, `no-daemon-kill`), raw devices
(`no-dd-device-read`, `no-device-overwrite` — not reliably sandbox-covered and
catastrophic), remote-code exec (`no-pipe-to-shell`, `no-shell-eval/*`),
network exfil (`no-env-exfil`, `no-gpg-secret-export`), and the cloud/VCS
destructive rules. `file_policy/agentjail_self*` is left untouched: it is
locked-by-design and low-friction.

## Consequences

- Shielded sessions stop tripping on benign filesystem commands; the real
  protection (the sandbox) is unchanged. A genuinely dangerous read still
  fails — at the syscall (EPERM) instead of the policy wall — and the attempt
  is logged with `would_action=deny`, visible in the monitor UI.
- Unshielded sessions are byte-for-byte unchanged: no attestation, no
  downgrade, full strictness. The rules remain the only defense there.
- The downgrade list is a small, explicit, reviewable constant — widening it
  is a deliberate edit, never implicit.
- Attestation is best-effort: if it fails (daemon down, token unreadable), the
  session simply stays strict. Fail-safe by construction.
