# ADR 0001 — OS-native sandbox enforcement layer (agentjail-shield)

- **Status:** Accepted
- **Date:** 2026-05-23
- **Task:** (to be created)
- **Deciders:** agentjail-core
- **Supersedes:** none
- **Related:** ADR 0001 (three-tier model), [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)

## Context

Tier 1 enforcement is **cooperative**: Claude Code voluntarily calls our
PreToolUse hook before each tool call, and we decide allow/deny/ask. This
works as long as the agent (a) calls the hook reliably and (b) the rule we're
matching against captures the actual intent.

A dogfood test on 2026-05-23 surfaced a structural limitation. The user asked
Claude to write to `~/.ssh/id_rsa`. Instead of calling the `Write` tool (which
`file_policy.rego` would have denied), Claude issued:

```
printf 'null' > ~/.ssh/id_rsa
```

— a `Bash` tool call. The hook fired, but `command_policy.rego` had no rule
for "shell redirect to a sensitive path" and `file_policy.rego` only matches
on `Write`/`Edit`/`Read` tool inputs. Result: fall-through to the file_policy
default-`ask` — the user got prompted instead of being protected.

We patched it by adding `no-bash-touch-sensitive-path` to `command_policy.rego`.
But this is **whack-a-mole**:

- `printf 'x' > /Users/me/.ssh/id_rsa`            ← caught now
- `echo x | tee /Users/me/.ssh/id_rsa`            ← caught now
- `T=$HOME/.ssh/id_rsa; printf x > $T`            ← env-var expansion, not caught
- `eval $(echo "cHJpbnRmIHggPiB+Ly5zc2gv..." | base64 -d)` ← obfuscation, not caught
- `python -c "open('/Users/me/.ssh/id_rsa','w').write('x')"` ← Python, not caught
- `osascript -e 'do shell script "printf x > ~/.ssh/id_rsa"'` ← AppleScript, not caught

Pattern-matching a string is fundamentally unable to catch every way an agent
can describe "write to this path." We need enforcement *below* the agent —
something that holds regardless of what the agent or its subprocesses do.

## Decision

Build **`agentjail-shield`**, a small launcher that wraps the coding agent
(`claude`, `codex`, `cursor`) in the operating system's native sandbox before
exec'ing it. The hook layer stays; the sandbox is the trust anchor.

- **macOS:** generate a Seatbelt sbpl profile from the sensitive-path list in
  `~/.agentjail/policy.yaml` and exec the agent under `sandbox-exec -p
  <profile> ...`. Subprocesses inherit the sandbox; `printf > ~/.ssh/...` from
  any descendant returns `EPERM` regardless of any hook bypass.
- **Linux:** call `landlock_create_ruleset` + `landlock_restrict_self` with
  the same path list, then `execve` the agent. Landlock restrictions are
  inherited and irreversible.

Architecturally:

| Layer | Role | Bypassable? |
|---|---|---|
| Hook (Tier 1) | Policy logic + UX — explains *why* to Claude | Yes, by `Bash` patterns |
| Sandbox (Tier 1.5) | Enforcement — kernel says no, period | No (within scope of the sbpl/Landlock ruleset) |
| MicroVM (Tier 2) | Containment — agent only sees a virtio-fs view | No |
| Kernel module (Tier 3) | Fleet-wide visibility | No |

The hook does not become redundant: it still owns MCP allowlisting (no
filesystem analogue), command-intent rules (`git push --force` is not a file
op), and the UX of telling the agent *why* something was blocked. The
sandbox is the safety net that catches everything the hook missed.

### Why not jump straight to Tier 2 (microVM)?

- microVM adds a ~50 ms boot cost + virtio-fs cost on every tool call
- microVM requires Linux+KVM or libkrun+macOS (libkrun networking on macOS is
  still blocked on `socket_vmnet` sudo)
- Most users will not run their agent inside a VM; for them, sandbox-exec /
  Landlock is the strongest enforcement available without virtualization

Tier 2 remains the target for teams that want true isolation (different
filesystem, network, process namespace). Sandbox is the right next layer
because it bridges hook-only and full containment.

### Why not Endpoint Security framework on macOS / eBPF LSM on Linux?

These are Tier 3. They require:

- macOS: Apple Developer ID, `com.apple.developer.endpoint-security.client`
  entitlement (approval-gated by Apple), kernel-level system extension install
- Linux: CAP_SYS_ADMIN, kernel module loading, distro packaging concerns

That's a different product (system-wide EDR-style enforcement). It's out of
scope for the Tier 1 install path.

### Privilege model

Critically, **neither `sandbox-exec` nor Landlock require special privileges**:

- `sandbox-exec` ships on every macOS since 10.5; runs as the invoking user;
  no entitlement; no sudo; no developer ID. Apple deprecated the `.sb` DSL
  in 10.7 but the binary is still shipped on macOS 26 and used by Apple's own
  daemons. Risk of removal exists but has not materialized in 15+ years.
- Landlock was designed for unprivileged use; that's its design point versus
  AppArmor/SELinux. Available since Linux 5.13 (June 2021).

This means `agentjail install --for claude-code` can opt the user into
sandbox enforcement without ever asking for sudo, which keeps the install
story aligned with the rest of Tier 1.

## Consequences

**Positive:**

- Bash/Python/AppleScript/eval bypasses of `file_policy` are caught at the
  kernel level by inheritance. The hook no longer has to enumerate every way
  an agent could describe a write.
- Provides a defensible "enforcement" claim, not just "audit." Marketing-wise,
  "we use the macOS kernel sandbox" is meaningfully stronger than "we run a
  policy check before each tool call."
- Stays in Tier 1 (no microVM, no kernel module, no sudo, no entitlement).

**Negative:**

- Apple may eventually remove `sandbox-exec`. If they do, we fall back to
  hook-only on macOS until Tier 2 (microVM) lands.
- sbpl profile language is undocumented. We will lean on community references
  (Chromium's sandbox profiles, Apple's own `/System/Library/Sandbox/Profiles/`,
  the *Reverse Engineering Apple's Sandbox* paper by Dionysus Blazakis).
- Landlock's path-based deny does not catch every syscall — e.g., the
  `truncate` family is covered only as of Linux 6.2; symlink races have edge
  cases. We document the boundary in the user-facing README.
- Users who *want* Claude to touch sensitive paths for legitimate reasons
  (e.g., `ssh-keygen`) must add an allowlist entry in `policy.yaml` and
  reload the daemon + restart the shielded session. This is a UX cost we
  accept as the price of real enforcement.

**Implementation notes:**

- New binary `cmd/agentjail-shield/`
- Reads `~/.agentjail/policy.yaml` for the sensitive-path list
- macOS impl uses `os/exec` to invoke `sandbox-exec -p <profile> <agent-cmd>`
- Linux impl uses cgo to call `landlock_create_ruleset` + `landlock_restrict_self`
  (or `unix.LandlockCreateRuleset` from `golang.org/x/sys/unix` once available)
- Test: spawn `agentjail-shield -- sh -c "printf x > /Users/me/.ssh/id_rsa"`
  → assert exit non-zero and that the file is unchanged
- The hook continues to run on every PreToolUse regardless

## Rejected alternatives

| Alternative | Why rejected |
|---|---|
| chmod 000 + chown root on sensitive paths | Requires sudo; agent could chmod back if running as user; breaks legitimate use |
| chflags uchg / chattr +i | Same chmod-back-from-userland problem; user inconvenience high |
| TCC entitlement (~/Desktop, ~/Documents, etc.) | Only protects the four TCC-gated dirs; doesn't cover ~/.ssh, ~/.aws, /etc/, etc.; can't customize |
| seccomp-bpf syscall filter | Coarse — can deny `open()` entirely but not "open this path"; would break too many legitimate ops |
| Endpoint Security framework | Tier 3 only — entitlement-gated, Apple approval needed, different product |
| eBPF LSM module | Tier 3 only — CAP_SYS_ADMIN, kernel module loading |
| Polyfill the hook with more regex rules | What we just did for `no-bash-touch-sensitive-path`; not a structural fix; still bypassable by `eval`/obfuscation/non-shell interpreters |
| Wait for Tier 2 (microVM) | Right answer for full isolation but heavier than the problem requires today; sandbox-exec/Landlock is the 80% solution with 20% of the complexity |
