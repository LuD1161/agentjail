# Shared-worktree Terra coordination protocol

This protocol is mandatory for plans 015–033. The user explicitly requested a
common worktree and local-only development. Git's index and HEAD are shared, so
source ownership and commit serialization are separate requirements.

## Non-negotiable rules

1. Stay on the current `main` worktree. Do not create/switch branches or
   worktrees, stash, rebase, merge, cherry-pick, push, open a PR, or create a
   GitHub issue.
2. Run every shell command through `rtk`.
3. Read `AGENTS.md` and its mandatory docs before editing.
4. Edit only the exact paths assigned by the plan. Reading outside scope is
   allowed. If another path is required, stop and ask the orchestrator.
5. Never use `git add -A`, `git add .`, or a directory broader than the assigned
   paths.
6. Every commit is conventional and signed: `git commit -s`.
7. The orchestrator alone updates `plans/macos-app/README.md`. Executors write
   only their unique `plans/macos-app/handoffs/NNN.md` record.
8. Do not install dependencies or add a library. A new dependency requires an
   ADR and explicit operator approval.

## Reserved pre-existing work

These paths were modified or untracked before this plan. They belong to the
user and are excluded from every task except plan 027 after the orchestrator
confirms the overlapping work is complete:

```text
README.md
cmd/agentjail/install.go
cmd/agentjail/install_test.go
cmd/agentjail/dev_deploy_test.go
scripts/dev-deploy.sh
scripts/collect-agentjail-debug.sh
assets/social/golden-circle.png
assets/social/golden-circle.svg
assets/social/pitch-hero.gif
assets/social/pitch-hero.mp4
assets/social/pitch-hero.png
assets/social/pitch-hero.svg
assets/social/pitch-hero@2x.png
assets/social/twitter-header-v4 copy 3.svg
assets/social/twitter-header-v4 copy.svg
```

Do not format, rename, stage, restore, or otherwise “clean up” these paths.

The planning set is orchestrator-owned and read-only to executors:
`plans/README.md`, every macOS approval plan from 015 through 033, and
`plans/macos-app/{README,DESIGN,COORDINATION,ORCHESTRATOR_LOG}.md`.

## Claim protocol

Before editing, send the orchestrator:

```text
CLAIM plan NNN
agent: <name>
owned paths: <exact paths>
starting HEAD: <sha>
owned-path status: <exact output of scoped status command>
```

Wait for an explicit claim acknowledgement. Only one agent can own a path at a
time. A dependency marked DONE means “reviewed by the orchestrator”, not merely
“another agent says it is done”.

Before sending the claim, run both checks against every exact owned product
path (not the whole repository):

```sh
rtk git diff -- <owned paths>
rtk git status --short --untracked-files=all -- <owned paths>
```

Committed prerequisite changes should produce no output. Any unstaged,
untracked, or staged product path is an ownership collision unless the plan
explicitly names it as the executor's own existing work. Save the output in the
handoff. Repeat the scoped status check immediately before staging; this catches
worktree edits that `BASE..HEAD` comparisons omit.

For a new ADR, the orchestrator reserves the number in the claim
acknowledgement. Recheck the number and run `rtk make adr-check` while holding
the commit lock immediately before staging. A reservation is local coordination,
not permission to ignore a number that has since landed.

## Commit lock

Agents can edit independent files concurrently, but staging and committing are
serialized. After tests pass:

1. Acquire the lock with `rtk mkdir .git/agentjail-terra-commit.lock`. If it
   already exists, report WAITING to the orchestrator; do not spin or delete it.
2. Run `rtk git diff --cached --quiet`. If it is non-zero, release the lock with
   `rtk rmdir .git/agentjail-terra-commit.lock` and stop: another owner left
   staged state.
3. Stage only explicit owned paths, for example
   `rtk git add -- internal/grantctl/review.go internal/grantctl/review_test.go`.
4. Inspect `rtk git diff --cached --name-only`. Every path must be owned by the
   current plan. If not, do not commit; report the list to the orchestrator.
5. Repeat `rtk git status --short --untracked-files=all -- <owned paths>` and
   compare it with the claim baseline plus the executor's intended files.
6. Commit with `rtk git commit -s -m "type(scope): description"`.
7. Release with `rtk rmdir .git/agentjail-terra-commit.lock`.

If an agent exits while holding the lock, only the orchestrator may remove it,
after confirming no commit/staging operation is live and inspecting the index.

## Handoff record

Every executor creates its unique `plans/macos-app/handoffs/NNN.md` in the same
local commit, containing:

```markdown
# Plan NNN handoff

- Agent:
- Work status: COMPLETE | PARTIAL | BLOCKED
- Acceptance verdict: PASS | PARTIAL | REWORK | NOT RUN
- Starting HEAD:
- Commit: this handoff is included in the task commit; SHA reported after commit
- Changed paths:
- Claim-time owned-path status:
- Verification commands and exact results:
- Acceptance criteria not exercised:
- Risks / follow-ups:
- No remote action taken: yes
```

After committing, send `HANDOFF plan NNN commit <sha>` to the orchestrator; a
file cannot contain the SHA of the commit that contains the file itself. Do not
claim COMPLETE/PASS when a required real-Mac or manual gate was skipped. Mark
it PARTIAL or BLOCKED and say exactly what remains. Board status remains the
orchestrator's `DONE | REWORK | BLOCKED` verdict after review.

## Orchestrator review gate

The orchestrator will, for every commit:

1. compare changed paths to the plan's ownership list;
2. read the diff and security-sensitive tests;
3. rerun the plan's machine-checkable gates;
4. verify DCO sign-off;
5. check that no secret/token/raw recording was added;
6. mark the central board DONE, REWORK, or BLOCKED;
7. dispatch dependent work only after DONE.

No push occurs during this project unless the user later gives a new,
unambiguous instruction to publish.
