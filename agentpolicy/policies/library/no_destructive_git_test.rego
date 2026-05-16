# Tests for agentpolicy/policies/library/no_destructive_git.rego
package agentjail_test

import future.keywords.if
import data.agentjail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

dgit_rule_id := "library/no-destructive-git"

bash_dgit(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git reset --hard (no ref)
# ---------------------------------------------------------------------------

test_no_destructive_git_reset_hard if {
	agentjail.decision.action == "deny" with input as bash_dgit("git reset --hard")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git reset --hard")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git reset --hard HEAD~3
# ---------------------------------------------------------------------------

test_no_destructive_git_reset_hard_ref if {
	agentjail.decision.action == "deny" with input as bash_dgit("git reset --hard HEAD~3")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git reset --hard HEAD~3")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git clean -fd (no path — whole tree)
# ---------------------------------------------------------------------------

test_no_destructive_git_clean_fd if {
	agentjail.decision.action == "deny" with input as bash_dgit("git clean -fd")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git clean -fd")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git clean -fdx (with -x, no path)
# ---------------------------------------------------------------------------

test_no_destructive_git_clean_fdx if {
	agentjail.decision.action == "deny" with input as bash_dgit("git clean -fdx")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git clean -fdx")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git clean -xdf . (explicit dot path)
# ---------------------------------------------------------------------------

test_no_destructive_git_clean_xdf_dot if {
	agentjail.decision.action == "deny" with input as bash_dgit("git clean -xdf .")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git clean -xdf .")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git checkout -- . (whole-tree discard)
# ---------------------------------------------------------------------------

test_no_destructive_git_checkout_dashdash_dot if {
	agentjail.decision.action == "deny" with input as bash_dgit("git checkout -- .")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git checkout -- .")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git checkout . (whole-tree discard)
# ---------------------------------------------------------------------------

test_no_destructive_git_checkout_dot if {
	agentjail.decision.action == "deny" with input as bash_dgit("git checkout .")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git checkout .")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git restore . (whole-tree discard)
# ---------------------------------------------------------------------------

test_no_destructive_git_restore_dot if {
	agentjail.decision.action == "deny" with input as bash_dgit("git restore .")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git restore .")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git stash clear
# ---------------------------------------------------------------------------

test_no_destructive_git_stash_clear if {
	agentjail.decision.action == "deny" with input as bash_dgit("git stash clear")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git stash clear")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git stash drop
# ---------------------------------------------------------------------------

test_no_destructive_git_stash_drop if {
	agentjail.decision.action == "deny" with input as bash_dgit("git stash drop")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git stash drop")
}

# ---------------------------------------------------------------------------
# POSITIVE deny: git stash drop stash@{0}
# ---------------------------------------------------------------------------

test_no_destructive_git_stash_drop_ref if {
	agentjail.decision.action == "deny" with input as bash_dgit("git stash drop stash@{0}")
	agentjail.decision.rule_id == dgit_rule_id with input as bash_dgit("git stash drop stash@{0}")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git reset --soft (NOT --hard; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_reset_soft_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git reset --soft HEAD~1")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git reset --mixed (NOT --hard; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_reset_mixed_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git reset --mixed HEAD~1")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git reset HEAD~1 (no mode flag; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_reset_no_flag_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git reset HEAD~1")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git checkout -- README.md (single-file; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_checkout_single_file_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git checkout -- README.md")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git checkout main (branch switch; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_checkout_branch_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git checkout main")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git restore README.md (single-file restore; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_restore_single_file_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git restore README.md")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git clean -fd build/ (narrowed path; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_clean_fd_path_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git clean -fd build/")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git stash (save — not destructive; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_stash_save_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git stash")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git stash list (read-only; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_stash_list_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git stash list")
}

# ---------------------------------------------------------------------------
# NEGATIVE: git status (read-only; must not deny)
# ---------------------------------------------------------------------------

test_no_destructive_git_status_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_dgit("git status")
}
