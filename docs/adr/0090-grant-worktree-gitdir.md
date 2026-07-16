# 0090 — Grant the worktree gitdir

Status: Accepted

## Context

On Linux, every git command failed inside a `git worktree` under
`agentjail-shield` (AGE-241):

```
$ agentjail-shield -- bash -c 'git status'
fatal: not a git repository: /path/to/main/.git/worktrees/<name>
```

In a worktree, `.git` is a regular *file* holding `gitdir: <path>`, and that
path lives in the **main** repo, outside the checkout. Landlock is allowlist-
based: it grants `/tmp`, cwd, and the home allowlist. The gitdir is under none
of them, so git follows its own pointer into a denied path. An ordinary clone
keeps `.git/` inside cwd, which is granted — which is why this never surfaced.
Submodules (`gitdir: ../.git/modules/x`) and an explicit `GIT_DIR` have the
same shape.

The bug was latent, not new. It became reachable when AGE-231 restored the
agent's working directory; before that the agent ran in `/` with no repo
context and the e2e git scenario passed by having nothing to do.

macOS does not reproduce it, and that is not evidence the Linux grant was
right: `shield_darwin.go` is denylist-based (`(allow default)` plus explicit
denies), so it permits the gitdir read for the same reason it permits most
reads. **"It works on macOS" cannot validate a Linux path grant**, and testing
there will not catch this class of bug. This is the deliberate backend
asymmetry documented at `shield_agentpaths.go:131`, not ADR 0034 drift — the
shared contract (`agentPaths()`) is about paths the *agent* needs; a gitdir is
discovered per-cwd at launch and cannot be a static list.

## Decision

Resolve the git directory at shield launch and grant it read-write, via
`gitDirGrants(cwd, home, gitDirEnv)` in `shield_linux.go`:

1. `GIT_DIR` if set; otherwise `<cwd>/.git` when it is a regular file, parsed
   for its `gitdir:` pointer. A `.git` *directory* returns no grants — the cwd
   grant already covers it, so the ordinary clone is untouched.
2. Relative pointers resolve against cwd; the result is symlink-resolved.
3. `<gitdir>/commondir` is followed and granted too. It points back at the main
   `.git`, where objects, refs and config live; the per-worktree gitdir alone
   does not run a single git command.

Read-**write**, because git writes `HEAD`, `index`, refs and logs — a read-only
grant would leave the worktree unusable in a subtler way than the original bug.

The grant is deliberately narrow, and the pointer is treated as untrusted
input: a `.git` file is writable by anything that can write the checkout, so
`safeGitGrant` refuses a target that is `$HOME`, an ancestor of it, the
filesystem root, or a credential directory (`~/.ssh`, `~/.aws`, `~/.gnupg`,
via the existing `isSensitiveMCPTarget`). Otherwise a poisoned `.git` would be
a self-service widening primitive of exactly the kind
`SensitiveMCPCommandDirs()` exists to stop.

## Consequences

- git works in worktrees and submodules under the shield on Linux. Verified
  end-to-end: `status`, `rev-parse --git-dir`, and a real `commit` all succeed.
- **The main repo's `.git` becomes agent-writable when working from a
  worktree.** This is inherent — that is where the worktree's objects and refs
  live, and git cannot function without it. The main repo's *working files*
  stay denied (verified: `cat <main>/secret.txt` → `Permission denied`), so the
  grant stops at the git database and does not widen to the checkout.
- A refused (poisoned or over-broad) pointer degrades honestly: the shield
  prints why on stderr and git fails, rather than silently widening the grant.
- Ordinary clones are unaffected — no extra syscalls, no extra grants.
- macOS needs no change and gets no test coverage for this. That asymmetry is
  now stated rather than assumed.
