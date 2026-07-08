# ADR 0056: ssh-agent ready is not sufficient -- pinned IdentityFile blind spot

**Status:** Accepted

## Context

[ADR 0054](./0054-macos-shield-tempdir-afunix-parity.md) and the
ssh-agent advisory work on this branch established the model: the shield
blocks private-key FILE reads by design, `ssh` works through `ssh-agent`
(`SSH_AUTH_SOCK` passthrough + a socket connect carve-out), and if the
key is not loaded the fix is `ssh-add`, never a read hole for the key
file. `internal/sshagent` probes agent readiness, `agentjail doctor`
warns, and the hook prints a one-shot advisory -- all keyed on the
`NeedsRemediation()` predicate: *key on disk AND agent not Ready*.

Live testing on macOS (2026-07-08) found a failure mode this model does
NOT cover. With the key correctly loaded into the agent
(`ssh-add -l` exit 0, `ReadinessReady`), a `git clone` over SSH still
failed:

```
no such identity: /Users/you/.ssh/id_ed25519: Operation not permitted
git@github.com: Permission denied (publickey)
```

Root cause: the user's `~/.ssh/config` pins an explicit
`IdentityFile ~/.ssh/id_ed25519` (commonly with `IdentitiesOnly yes`).
Under that config `ssh` tries to read the on-disk key file **first** --
which the shield denies (`Operation not permitted`) -- and bails before
falling back to the agent socket, even though the agent holds a valid,
GitHub-authorized key (a *different* key than the pinned one). The
sandbox is behaving exactly as designed; the agent path works when
exercised directly. Two confirmations from the same session:

- `ssh -T -o IdentityFile=none -o IdentityAgent=$SSH_AUTH_SOCK git@github.com`
  authenticated successfully (agent key, distinct from the pinned file).
- The same `git clone` with
  `GIT_SSH_COMMAND="ssh -o IdentityFile=none -o IdentityAgent=$SSH_AUTH_SOCK"`
  succeeded (EXIT 0, full checkout).

The blind spot: `NeedsRemediation()` returns `false` in this case
(`Readiness == ReadinessReady`), so `doctor`, the hook advisory, and
`SANDBOX.md`'s current guidance all stay silent -- yet SSH auth fails
with the same cryptic `publickey` error the advisory exists to demystify.
A user following the current advice ("your key isn't loaded -- run
`ssh-add`") finds the key *is* loaded and is left with no next step.

A related but independent factor observed in the same session: the
user's global git config carries
`url.git@github.com:.insteadOf https://github.com/`, which silently
rewrites HTTPS GitHub URLs to SSH. So a command that looks like a plain
HTTPS clone (which the shield allows outright -- confirmed EXIT 0) is
actually taking the SSH path and hitting the above. This is user config,
not an agentjail concern, but it explains why "HTTPS should just work"
reports still surface the SSH failure.

## Decision (implemented -- both options shipped)

Both candidate responses landed, not as alternatives but as two layers of
the same fix:

1. **Option 2 -- shield-injected agent-only `GIT_SSH_COMMAND` (`feat(shield)`).**
   For shield-wrapped `git`, the shield now auto-injects

   ```
   GIT_SSH_COMMAND=ssh -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent='<sock>'
   ```

   where `<sock>` is the raw `SSH_AUTH_SOCK` value, single-quoted verbatim
   -- the exact, empirically verified recipe from the live repro above
   (`EXIT 0`, full checkout), not a theoretical simplification. This is
   injected only when `SSH_AUTH_SOCK` is set and non-empty, the user has
   not already set their own `GIT_SSH_COMMAND` (preserved verbatim if
   present), and `AGENTJAIL_NO_SSH_OVERRIDE` is not set. The shield marks
   the injection with `AGENTJAIL_SSH_OVERRIDE=1` so downstream advisory
   logic knows git was auto-handled. `<sock>` matches, byte-for-byte, the
   same `SSH_AUTH_SOCK` value the shield's ssh-agent socket carve-out
   grants, so the injected `IdentityAgent` and the sandbox's socket
   permission can never drift apart.

   **Why all three options (correction, 2026-07-08).** The recipe evolved
   under live testing, each step forced by an empirical failure:
   - `IdentityFile=none` alone is insufficient. OpenSSH *appends*
     command-line `IdentityFile` entries to the `ssh_config` ones rather
     than replacing them, so the pinned config entry stays active and the
     read still gets denied.
   - `IdentityAgent` alone is insufficient too. This was the FIRST shipped
     recipe (`-o IdentityFile=none -o IdentityAgent=<sock>`), and a
     conclusive end-to-end `git clone` UNDER the shield showed it still
     fails for the common real config: with `IdentitiesOnly yes`, OpenSSH
     only offers agent keys whose public half matches a CONFIGURED
     `IdentityFile`. When the agent holds a DIFFERENT key than the pinned
     one (e.g. pinned `id_ed25519` absent, agent holds a work key), that
     agent key is never offered -- `Permission denied (publickey)`. The
     verbose trace shows the agent key is simply never presented.
   - `IdentitiesOnly=no` is the decisive option, added in the correction.
     It lifts the "only offer configured identities" restriction so the
     agent's real key is offered and accepted. A/B under the real shield:
     the two-option recipe FAILS, the three-option recipe SUCCEEDS.

   **Honesty note on mechanism:** this fix does not prevent the on-disk
   read -- ssh may still probe the pinned file path, and the shield still
   denies it, exactly as designed. What changes is that `IdentitiesOnly=no`
   makes *all* agent identities eligible and `IdentityAgent` makes the
   agent socket available up front, so agent-backed auth succeeds before
   the denied on-disk read becomes fatal. We do not claim to "avoid" or
   "prevent" the denied read; we route auth around its consequence.

   **Why the first recipe's test did not catch this.** The Option 2
   acceptance fixture (`ssh-pinned-identity.sh`) originally loaded the SAME
   key into the agent that it pinned as `IdentityFile`. When pinned key ==
   agent key, `IdentitiesOnly yes` *does* offer it, so the fixture passed
   while the real world (agent holds a different key) failed. The fixture
   now generates two distinct keys -- pins an absent/unreadable key P,
   loads and authorizes only a different key Q -- and asserts the
   two-option recipe FAILS while the three-option recipe SUCCEEDS, so this
   class cannot regress silently again.

2. **Option 1 -- advisory detection (`feat(sshagent)`, `feat(hook,doctor)`).**
   `internal/sshagent` now parses the user's `~/.ssh/config` (conservative
   line scan, not a full `Host`/`Match`/`Include` resolver) for uncommented
   `IdentityFile` lines under `~/.ssh` that exist on disk (or EPERM under
   the shield, which counts as "exists" for this purpose) alongside an
   uncommented `IdentitiesOnly yes`, exposed as `Status.PinnedIdentityPaths`
   / `Status.PinnedBlindSpot()` / `Status.PinnedRemediation()`. The hook
   prints a one-shot pinned-config advisory to stderr for direct
   `ssh`/`scp`/`sftp`/`rsync` unconditionally when `PinnedBlindSpot()` is
   true, and for `git` only when the shield's `AGENTJAIL_SSH_OVERRIDE`
   marker is absent (i.e. Option 2 did not auto-handle this invocation --
   opt-out set, or the user supplied their own `GIT_SSH_COMMAND`).
   `agentjail doctor` warns on the same condition (`Ready` +
   `PinnedBlindSpot()`), ordered ahead of the existing `!KeysOnDisk` skip
   so a deploy-key-only user is not silently skipped.

**Non-goal, unchanged:** neither option punches a read hole for the key
file. SSH under the shield still goes through the agent; the fix is
always to route auth through the agent, never to grant the file. Option 2
makes that the automatic default for git; Option 1 is the advisory safety
net for everything Option 2 does not cover (direct ssh, the opt-out path,
a user-supplied `GIT_SSH_COMMAND`).

## Consequences

Shipping Option 2 means the shield now deliberately overrides part of the
user's ssh identity selection for git. These tradeoffs are intentional and
accepted, not accidental side effects:

- **`IdentitiesOnly=no` changes ALL shielded git SSH auth while the override
  is active, not only the broken pinned-identity cases.** Stated bluntly:
  whenever the shield injects this `GIT_SSH_COMMAND`, every git ssh
  connection now offers *every* key the agent holds to the server, instead
  of just the per-host configured identity. Consequences: the server can
  learn which key fingerprints the user holds (public-key probing that
  `IdentitiesOnly yes` is often set specifically to prevent); git may
  authenticate with a broader agent-resident key than the user's config
  intended; and offering many keys can trip a host's `MaxAuthTries`. This
  is accepted because under the shield on-disk-key auth is unavailable
  anyway (the pinned file read is denied), so the practical choice is
  "git fails entirely" vs "git succeeds by offering agent keys." The
  opt-out `AGENTJAIL_NO_SSH_OVERRIDE=1` restores exact `ssh_config`
  semantics for users who need them (at the cost of the pinned-file failure
  returning).
- **`IdentityAgent` is explicitly set, and that overrides a deliberate
  per-host `IdentityAgent none` or alternate-socket config.** An earlier
  draft of this ADR considered a "minimal" `IdentityFile=none`-only value
  that would have left `IdentityAgent` untouched -- that value was proven
  insufficient (see Decision) and rejected, so the override is present in
  what actually shipped. This is an accepted tradeoff, not something the
  design avoids. It is opt-outable per invocation via
  `AGENTJAIL_NO_SSH_OVERRIDE=1`, and that opt-out is documented prominently
  in `SANDBOX.md`.
- **Deploy-key host configs may be bypassed.** A host block scoped to a
  narrow deploy key (`IdentityFile ~/.ssh/deploy_key`,
  `IdentitiesOnly yes`) will, under the injected override, authenticate
  with whatever broader personal key is already loaded in the agent
  instead. This is acceptable because on-disk-key auth is unavailable
  under the shield regardless -- the deploy key's file read would be
  denied either way, so the choice is between "git fails" and
  "git succeeds with a different, already-agent-resident key."
- **Many loaded agent keys can trigger "too many authentication failures."**
  Forcing `IdentityAgent` offers every identity the agent holds to the
  server; a host with a low `MaxAuthTries` and a heavily loaded agent can
  reject the connection before reaching a valid key. `AGENTJAIL_NO_SSH_OVERRIDE`
  is the escape hatch here too.
- **The opt-out must stay visible.** `AGENTJAIL_NO_SSH_OVERRIDE` is
  documented in `SANDBOX.md` next to the auto-fix description, not buried
  -- a user who needs their exact `ssh_config` identity semantics for git
  has a one-line way to get them back (at the cost of the pinned-file
  failure this ADR describes returning).
- **The advisory heuristic (Option 1) is conservative and can miss or
  over-fire.** The `~/.ssh/config` line scan does not resolve `Host`,
  `Match`, or `Include` blocks -- it is advisory-only, so a miss produces
  at most a missing hint (no enforcement change) and a false positive
  produces at most one extra stderr line.
- The `insteadOf` HTTPS->SSH rewrite remains out of scope for agentjail to
  change; it is user config. It is documented here and in `SANDBOX.md`
  because it explains why an apparent HTTPS clone can still hit the SSH
  path described above.
- Tracked as shipped work on this branch; no Linear ticket number is
  asserted here.
