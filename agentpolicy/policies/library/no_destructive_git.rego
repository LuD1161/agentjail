# Package agentjail — library rule: no-destructive-git
#
# WHAT IT BLOCKS
# --------------
# Bash commands that irrecoverably wipe UNCOMMITTED work across the whole
# working tree.  Only whole-tree destructive forms are blocked; single-file
# operations (e.g. `git restore README.md`) are legitimate everyday work and
# are explicitly NOT denied.
#
#   git reset --hard [<ref>]
#       Moves HEAD and discards all staged and unstaged changes — unrecoverable
#       for any work that was not already committed.
#
#   git clean -f ... (with -d or -x/-X, no narrowing path or path == ".")
#       Removes untracked files from the whole tree.  Narrowed invocations such
#       as `git clean -fd build/` are allowed (path != ".").
#
#   git checkout -- .   and   git checkout .
#       Discards all unstaged changes across the whole working tree.
#
#   git restore .   and   git restore :/
#       Modern equivalent of `git checkout -- .`; wipes all unstaged changes.
#
#   git stash clear
#       Permanently deletes ALL saved stashes — cannot be undone.
#
#   git stash drop [<stash>]
#       Permanently drops a single stash ref — cannot be undone.
#
# WHY (attack scenario)
# ----------------------
# A prompt-injected or adversarial agent can silently erase hours of work with
# a single `git reset --hard` or `git clean -fd`.  Unlike file deletions (which
# leave traces in the filesystem), these git operations wipe content that was
# never committed and leave no recovery path outside of editor undo buffers.
#
# Example attack chain:
#   1. Agent is asked to "clean up the repo" by a prompt injection.
#   2. Agent runs: git clean -fdx && git reset --hard origin/main
#   3. All local uncommitted work (WIP code, secrets in .env, new files) is gone.
#   4. No git log entry exists — the work never made it into any commit.
#
# WHY OPT-IN (false-positive risks)
# -----------------------------------
# Legitimate developer uses:
#   - Intentional reset to a known-good state after a bad merge.
#   - CI pipelines that run `git clean -fd` to ensure a pristine build env.
#   - Stash management in complex rebase workflows.
# Enable this rule in unattended / autonomous agent sessions where the agent
# should never discard uncommitted developer work without human approval.
#
# EXAMPLE triggering input
# -------------------------
#   {"hook_event":"PreToolUse","tool_name":"Bash",
#    "tool_input":{"command":"git reset --hard HEAD~3"},
#    "session_id":"s1","cwd":"/Users/dev/project"}
#
# HOW TO ENABLE (MVP)
#   cp agentpolicy/policies/library/no_destructive_git.rego ~/.agentjail/rules/
#   kill -HUP $(pgrep -f agentjail-daemon)

package agentjail

import future.keywords.if
import future.keywords.contains

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_is_bash_event if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Bash"
}

_cmd := input.tool_input.command

# ---------------------------------------------------------------------------
# Candidate: deny `git reset --hard [<ref>]`
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\bgit\s+reset\s+.*--hard\b`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-destructive-git",
		"reason":  "git reset --hard is denied (library/no-destructive-git); irrecoverably discards all uncommitted work",
		"impact":  "would permanently discard all staged and unstaged changes",
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny `git clean` with -f AND (-d or -x/-X) AND no narrowing path
#   Allowed: git clean -fd build/   (has a non-"." path argument)
#   Denied:  git clean -fd          (no path)
#   Denied:  git clean -fdx .       (path is exactly ".")
#
# Strategy: require -f flag, require at least one of -d/-x/-X, then ensure the
# command does NOT end with a non-dot path argument.
# We parse this as: after stripping the git-clean invocation, if the remaining
# tokens are only flags (starting with -) or "." then it is a whole-tree clean.
# ---------------------------------------------------------------------------

# Matches: git clean followed by flags that include -f and (-d or -x or -X)
# with no trailing path argument (or only "." as path argument).
_is_whole_tree_git_clean if {
	# Must have -f in the flags
	regex.match(`\bgit\s+clean\b[^\n]*-[a-zA-Z]*f[a-zA-Z]*`, _cmd)
	# Must have -d or -x or -X in the flags
	regex.match(`\bgit\s+clean\b[^\n]*-[a-zA-Z]*[dxX][a-zA-Z]*`, _cmd)
	# Must NOT have a narrowing path (a non-dot, non-flag token after "git clean ...")
	# If the command ends with a path that is not "." (e.g. "build/", "src/"), allow it.
	not regex.match(`\bgit\s+clean\s+(?:-[a-zA-Z]+\s+)+[^-.\s][^\s]*`, _cmd)
}

# Separately: git clean ... <flags> . (explicit dot is also whole-tree)
_is_whole_tree_git_clean if {
	regex.match(`\bgit\s+clean\b[^\n]*-[a-zA-Z]*f[a-zA-Z]*`, _cmd)
	regex.match(`\bgit\s+clean\b[^\n]*-[a-zA-Z]*[dxX][a-zA-Z]*`, _cmd)
	regex.match(`\bgit\s+clean\s+(?:-[a-zA-Z]+\s+)+\.\s*$`, _cmd)
}

candidate contains r if {
	_is_bash_event
	_is_whole_tree_git_clean
	r := {
		"action":  "deny",
		"rule_id": "library/no-destructive-git",
		"reason":  "git clean with whole-tree flags is denied (library/no-destructive-git); irrecoverably removes all untracked files",
		"impact":  "would permanently delete all untracked files from the working tree",
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny `git checkout -- .` and `git checkout .`
# (whole working-tree discard; NOT single-file checkout)
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\bgit\s+checkout\s+(--\s+\.|\.)\s*$`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-destructive-git",
		"reason":  "git checkout . (whole-tree) is denied (library/no-destructive-git); irrecoverably discards all unstaged changes",
		"impact":  "would permanently discard all unstaged changes across the working tree",
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny `git restore .` and `git restore :/`
# (whole working-tree restore; NOT single-file restore)
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\bgit\s+restore\s+(\.|\:/)\s*$`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-destructive-git",
		"reason":  "git restore . (whole-tree) is denied (library/no-destructive-git); irrecoverably discards all unstaged changes",
		"impact":  "would permanently discard all unstaged changes across the working tree",
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny `git stash clear` (deletes ALL stashes permanently)
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\bgit\s+stash\s+clear\b`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-destructive-git",
		"reason":  "git stash clear is denied (library/no-destructive-git); permanently deletes all saved stashes",
		"impact":  "would permanently destroy all stashed uncommitted work",
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny `git stash drop [<stash>]` (drops a stash permanently)
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\bgit\s+stash\s+drop\b`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-destructive-git",
		"reason":  "git stash drop is denied (library/no-destructive-git); permanently discards a stash entry",
		"impact":  "would permanently discard stashed uncommitted work",
	}
}
