# Package agentjail — command policy (hook-wire-format Bash tool).
#
# Evaluates Claude Code PreToolUse events for the Bash tool. Input shape
# matches HookInput in agentpolicy/internal/policy/engine.go:
#
#   input.hook_event   == "PreToolUse"
#   input.tool_name    == "Bash"
#   input.tool_input   : {"command": "<shell command string>", ...}
#   input.session_id   : string
#   input.cwd          : string
#
# Each rule contributes a candidate entry to the shared partial rule set
# `candidate` (defined via resolver.rego). The resolver picks the most
# restrictive candidate (deny > ask > allow) and produces `decision`.
#
# Default: safe Bash commands that match no dangerous pattern contribute an
# explicit `command_policy/default-allow` candidate so benign commands like
# `git status` or `ls` still get "allow" without prompting the user.
#
# Note: rm_rf.rego (agentpolicy/policies/lib/exec/rm_rf.rego) operates on the
# legacy exec-hook input shape (input.hook == "exec", input.flags, etc.) and
# cannot be directly imported here. The rm -rf pattern is re-expressed as a
# regex match over the raw command string so this policy is self-contained on
# the hook-wire-format path. Deduplication of the protected-path predicate
# will be addressed when a unified hook-wire lib module lands.
package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# cmd is the raw shell command string from the Bash tool_input.
cmd := input.tool_input.command

# is_bash returns true when this is a Bash tool PreToolUse event.
is_bash if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Bash"
}

# ---------------------------------------------------------------------------
# DENY patterns — high-confidence dangerous
# ---------------------------------------------------------------------------

# Pipe to shell: curl <url> | bash   or  curl <url> | sh
# Also catches wget variants.
candidate contains r if {
	is_bash
	regex.match(`(curl|wget)\s+.*\|\s*(bash|sh)\b`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-pipe-to-shell",
		"reason":  "piping remote content directly into bash/sh allows arbitrary code execution from the internet",
		"impact":  "would execute remote script as shell",
	}
}

# sudo — privilege escalation via operator or chained command.
candidate contains r if {
	is_bash
	regex.match(`(^|;|&&|\|\|)\s*sudo\s+`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-sudo",
		"reason":  "agents must not escalate privileges via sudo",
		"impact":  "would escalate to root",
	}
}

# sudo as the first token (most common form).
candidate contains r if {
	is_bash
	startswith(trim_space(cmd), "sudo ")
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-sudo",
		"reason":  "agents must not escalate privileges via sudo",
		"impact":  "would escalate to root",
	}
}

# dd writing from a device node: dd if=/dev/...
candidate contains r if {
	is_bash
	regex.match(`\bdd\b.*\bif=/dev/`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-dd-device-read",
		"reason":  "reading from raw device nodes via dd risks disk exfiltration or system corruption",
		"impact":  "would read raw disk device",
	}
}

# chmod 777 or chmod -R 777 on any path (overly-permissive mode change).
candidate contains r if {
	is_bash
	regex.match(`\bchmod\b\s+(-[Rr]+\s+)?777\b`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-chmod-777",
		"reason":  "chmod 777 removes all access controls and is never appropriate in agent contexts",
		"impact":  "would remove all access controls",
	}
}

# Overwrite block device via redirect: > /dev/sda  or  > /dev/disk*
candidate contains r if {
	is_bash
	regex.match(`>\s*/dev/(disk|sd[a-z]|nvme|mmcblk)`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-device-overwrite",
		"reason":  "writing to raw device nodes may irrecoverably destroy disk data",
		"impact":  "would corrupt raw block device",
	}
}

# rm -rf on absolute paths (catches rm -rf / and rm -rf /anywhere).
# /tmp/agentjail is the only absolute-tmp exception (used by test fixtures).
candidate contains r if {
	is_bash
	regex.match(`\brm\s+(-[rRfF]{1,4}\s+|--recursive\s+|--force\s+)*/`, cmd)
	not regex.match(`\brm\s+(-[rRfF]{1,4}\s+|--recursive\s+|--force\s+)*/tmp/agentjail`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-rm-rf-absolute",
		"reason":  "recursive force-delete of absolute paths outside the project directory risks destroying the system",
		"impact":  "would recursively delete absolute path",
	}
}

# ---------------------------------------------------------------------------
# git force-push — branch-aware.
#
# Force-pushing a topic/feature branch is a normal rebase / PR-update workflow,
# so it should NOT be blocked. Force-pushing the default branch (main/master)
# rewrites shared history and can destroy others' commits, so it stays denied.
# When the target branch can't be read from the command (`git push -f` with no
# explicit refspec — it pushes the *current* branch, which the daemon can't see
# from the command string), we ask rather than guess.
#
# "Force" = -f / --force / --force-with-lease, or the `+<refspec>` push syntax.
# ---------------------------------------------------------------------------

# A force-push of any form.
_git_push_force if regex.match(`\bgit\s+push\b.*\s(-f\b|--force\b)`, cmd)

_git_push_force if regex.match(`\bgit\s+push\b.*\s\+\S+`, cmd) # git push origin +branch

# The command names a protected default branch (main/master) as a ref. Preceded
# by a space, "/", "+", or ":" so it matches `origin main`, `+main`, `HEAD:main`,
# `origin/main`. Over-broad on purpose (errs toward deny for a destructive op):
# any mention of a main/master ref token in a force-push command counts.
_git_push_default_branch if regex.match(`(^|[\s/+:])(main|master)\b`, cmd)

# The command carries an explicit `<remote> <refspec>` (≥2 non-flag args), so the
# branch IS named — as opposed to a bare `git push -f` that pushes the current
# branch implicitly.
_git_push_explicit_target if regex.match(`\bgit\s+push\b(\s+-{1,2}[\w-]+(=\S+)?)*\s+[^\s-]\S*\s+\+?\S+`, cmd)

# Force-push to the default branch → deny (rewrites shared history).
candidate contains r if {
	is_bash
	_git_push_force
	_git_push_default_branch
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-git-push-force",
		"reason":  "force-pushing the default branch (main/master) rewrites shared history and can destroy others' commits",
		"impact":  "would rewrite history on the default branch",
	}
}

# Force-push to an explicit non-default branch (your own topic branch) → allow.
candidate contains r if {
	is_bash
	_git_push_force
	_git_push_explicit_target
	not _git_push_default_branch
	r := {
		"action":  "allow",
		"rule_id": "command_policy/allow-git-push-force-topic",
		"reason":  "force-pushing a non-default (topic/feature) branch is a normal rebase / PR-update workflow",
		"impact":  "rewrites history on a non-default branch only",
	}
}

# Force-push with no explicit branch (`git push -f`) → ask: the target is the
# implicit current branch, which can't be read from the command, so confirm it
# isn't the default branch.
candidate contains r if {
	is_bash
	_git_push_force
	not _git_push_explicit_target
	not _git_push_default_branch
	r := {
		"action":  "ask",
		"rule_id": "command_policy/confirm-git-push-force",
		"reason":  "force-push target branch is implicit; confirm you are not force-pushing the default branch",
	}
}

# Environment variable exfiltration: env | curl  or  printenv | curl
candidate contains r if {
	is_bash
	regex.match(`\b(env|printenv)\b.*\|\s*curl\b`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-env-exfil",
		"reason":  "piping environment variables to curl risks leaking secrets to an external endpoint",
		"impact":  "would exfiltrate env vars",
	}
}

# GPG private key export.
candidate contains r if {
	is_bash
	regex.match(`\bgpg\b.*--export-secret-keys?\b`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-gpg-secret-export",
		"reason":  "exporting GPG private keys may expose long-term cryptographic credentials",
		"impact":  "would export GPG private key",
	}
}

# macOS launchd service removal (launchctl bootout / remove).
candidate contains r if {
	is_bash
	regex.match(`\blaunchctl\s+(bootout|remove)\b`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-launchctl-remove",
		"reason":  "removing launchd services can break system functionality and persistence mechanisms",
		"impact":  "would remove launchd service",
	}
}

# Linux systemctl stop / disable.
candidate contains r if {
	is_bash
	regex.match(`\bsystemctl\s+(stop|disable)\b`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-systemctl-disrupt",
		"reason":  "stopping or disabling systemd units can cause service outages",
		"impact":  "would stop systemd unit",
	}
}

# ssh-keygen with -f pointing outside /tmp (new key creation in sensitive dirs).
candidate contains r if {
	is_bash
	regex.match(`\bssh-keygen\b.*-f\s+[^/]*(/(?!tmp/)[^"'\s]+)`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-ssh-keygen-outside-tmp",
		"reason":  "generating SSH keys outside /tmp may overwrite existing credentials or create keys in unexpected locations",
		"impact":  "would create SSH key outside /tmp",
	}
}

# ---------------------------------------------------------------------------
# ALWAYS-ON mutation guard (LOCKED rule_id: command_policy/no-policy-mutation).
#
# Denies any Bash command that would mutate agentjail's own policy through the
# CLI or via shell writes/redirects into ~/.agentjail/. This is the second
# vector defense: even if an agent can type these commands, the hook will deny
# them before execution.
#
# Blocked subcommand patterns:
#   agentjail policy {disable,enable,add,remove}  — rule lifecycle mutations
#   agentjail mcp {allow,block}                   — MCP allowlist mutations
#   writes/redirects into ~/.agentjail/ (> ~/.agentjail/*, tee ~/.agentjail)
#   editing policy.yaml via sed/awk/perl/python in-place over agentjail paths
#
# NOT blocked (safe read-only operations):
#   agentjail policy list
#   agentjail mcp list
#   agentjail status
#   agentjail logs
#
# This rule_id is in locked_rules (resolver.rego), so it can NEVER be
# suppressed via disabled_rules.
# ---------------------------------------------------------------------------

# _mentions_agentjail is true when the command references the agentjail binary in
# ANY form: bare `agentjail`, an absolute/relative path ending in /agentjail, a
# quoted path ("…/agentjail"), or `$(which agentjail)`. Matching the binary token
# SEPARATELY from the subcommand verb is deliberate: a single
# `agentjail\s+<verb>` pattern is trivially evaded by a closing quote or path
# prefix right after the word (e.g. `"$HOME/.agentjail/bin/agentjail" mcp allow`,
# which has a `"` where the old regex required whitespace). The regex layer is a
# best-effort second line — the authoritative guard is the interactive-TTY
# confirmation enforced inside the agentjail binary itself.
_mentions_agentjail if {
	regex.match(`agentjail\b`, cmd)
}

# _is_policy_mutation returns true when the command invokes a config-mutating
# agentjail CLI subcommand (policy disable/enable/add/remove or mcp allow/block),
# regardless of how the binary is referenced.
_is_policy_mutation if {
	# agentjail … policy {disable,enable,add,remove} — mutation verbs only
	_mentions_agentjail
	regex.match(`\bpolicy\s+(disable|enable|add|remove)\b`, cmd)
}

_is_policy_mutation if {
	# agentjail … mcp {allow,block}
	_mentions_agentjail
	regex.match(`\bmcp\s+(allow|block)\b`, cmd)
}

_is_policy_mutation if {
	# Shell write/redirect directly into ~/.agentjail/ subtree
	# Covers: > ~/.agentjail/..., >> ~/.agentjail/..., tee ~/.agentjail/...
	# Also matches $HOME/.agentjail and /Users/<u>/.agentjail
	regex.match(`(>|>>|\btee\b)\s*(~|(\$HOME)|/Users/[^/\s'"]+)/\.agentjail\b`, cmd)
}

_is_policy_mutation if {
	# In-place editing tools targeting agentjail paths (sed -i, perl -i, etc.)
	regex.match(`\b(sed|awk|perl|python3?)\b[^\n]*(~|(\$HOME)|/Users/[^/\s'"]+)/\.agentjail\b`, cmd)
}

candidate contains r if {
	is_bash
	_is_policy_mutation
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-policy-mutation",
		"reason":  "commands that mutate agentjail policy or configuration are denied (self-protection; rule is permanently locked)",
		"impact":  "would modify agentjail policy or configuration",
	}
}

# ---------------------------------------------------------------------------
# Bash redirect / write to sensitive path. Catches commands like:
#   printf 'x' > ~/.ssh/id_rsa
#   echo y >> ~/.aws/credentials
#   tee ~/.ssh/id_rsa
#   cp foo ~/.gnupg/
# file_policy.rego catches Write/Edit/Read tool calls to these paths, but
# agents can bypass that by issuing the equivalent Bash command. This rule
# closes that loophole by denying any Bash command that mentions a known
# sensitive path. Over-broad on purpose — `cat ~/.ssh/known_hosts` also gets
# denied, which is the right default; users can explicitly use the Read tool.
# ---------------------------------------------------------------------------

candidate contains r if {
	is_bash
	contains_sensitive_path(cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-bash-touch-sensitive-path",
		"reason":  "Bash command references a sensitive path (SSH/cloud/GPG/credentials); use the Write, Edit, or Read tool so file_policy can audit",
		"impact":  "would touch sensitive path via Bash",
	}
}

# Sensitive path patterns — mirrors file_policy.rego's is_sensitive_path
# clauses but matches against the raw command string rather than tool_input.file_path.
contains_sensitive_path(c) if regex.match(`/Users/[^/\s'"]+/\.ssh\b`, c)

contains_sensitive_path(c) if regex.match(`/Users/[^/\s'"]+/\.aws\b`, c)

contains_sensitive_path(c) if regex.match(`/Users/[^/\s'"]+/\.gnupg\b`, c)

contains_sensitive_path(c) if regex.match(`/Users/[^/\s'"]+/\.agentjail\b`, c)

contains_sensitive_path(c) if regex.match(`\bid_(rsa|ed25519|ecdsa|dsa)\b`, c)

contains_sensitive_path(c) if regex.match(`(^|\s|=|>|<)/etc/`, c)

contains_sensitive_path(c) if regex.match(`(^|\s|/)\.env(\.[a-zA-Z0-9_-]+)?(\s|$|>)`, c)

contains_sensitive_path(c) if regex.match(`\.(pem|p12|pfx|jks|keystore)\b`, c)

# ~/.npmrc — npm registry auth tokens (matches ~/, $HOME/, and absolute /Users/<u>/ forms)
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.npmrc(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.npmrc$`, c)

# ~/.pypirc — PyPI upload credentials
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.pypirc(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.pypirc$`, c)

# ~/.git-credentials — git plaintext password store
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.git-credentials(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.git-credentials$`, c)

# ~/.docker/config.json — Docker registry auth tokens
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.docker/config\.json(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.docker/config\.json$`, c)

# ~/.kube/config — Kubernetes credentials
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.kube/config(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.kube/config$`, c)

# ~/.cargo/credentials and credentials.toml — Cargo registry tokens
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.cargo/credentials(\.toml)?(\s|$|"|')`, c)

contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/\.cargo/credentials(\.toml)?$`, c)

# ~/Library/Keychains/ — macOS Keychain files
contains_sensitive_path(c) if regex.match(`(~|(\$HOME)|/Users/[^/\s'"]+)/Library/Keychains/`, c)

# ---------------------------------------------------------------------------
# ASK rules — ambiguous; require operator confirmation
# ---------------------------------------------------------------------------

# git push without --force (could push to a protected branch or production remote).
candidate contains r if {
	is_bash
	regex.match(`\bgit\s+push\b`, cmd)
	not regex.match(`\bgit\s+push\b.*\s(-f\b|--force\b)`, cmd)
	r := {
		"action":  "ask",
		"rule_id": "command_policy/confirm-git-push",
		"reason":  "git push may affect remote branches; confirm intent before proceeding",
	}
}

# is_publish_cmd returns true when the command is a publish/push operation to a
# public registry.  Used by both the candidate block and any_dangerous_pattern so
# a single predicate is the source-of-truth (no drift between the two blocks).
#
# Coverage: npm publish, yarn publish, pnpm publish, cargo publish, pip upload/publish,
# twine upload, gem push, poetry publish, docker push, gh release create.
#
# Known gap: `docker buildx build --push` is NOT caught here.  Catching it would
# require distinguishing `docker build` from `docker buildx build --push` reliably
# via regex over the raw command string; the risk of false positives on `docker build`
# is too high.  The shield (OS sandbox network deny) is the safety net.
is_publish_cmd(c) if regex.match(`\b(npm\s+publish|yarn\s+publish|pnpm\s+publish)\b`, c)

is_publish_cmd(c) if regex.match(`\bcargo\s+publish\b`, c)

is_publish_cmd(c) if regex.match(`\bpip\s+(upload|publish)\b`, c)

is_publish_cmd(c) if regex.match(`\btwine\s+upload\b`, c)

is_publish_cmd(c) if regex.match(`\bgem\s+push\b`, c)

is_publish_cmd(c) if regex.match(`\bpoetry\s+publish\b`, c)

is_publish_cmd(c) if regex.match(`\bdocker\s+push\b`, c)

is_publish_cmd(c) if regex.match(`\bgh\s+release\s+create\b`, c)

# Publishing packages to public registries.
candidate contains r if {
	is_bash
	is_publish_cmd(cmd)
	r := {
		"action":  "ask",
		"rule_id": "command_policy/confirm-publish",
		"reason":  "publishing to a package registry is irreversible; confirm intent",
	}
}

# curl -O downloading executables to non-tmp paths.
candidate contains r if {
	is_bash
	regex.match(`\bcurl\b.*-O\b`, cmd)
	not regex.match(`\bcurl\b.*-O\b.*/tmp/`, cmd)
	r := {
		"action":  "ask",
		"rule_id": "command_policy/confirm-curl-download",
		"reason":  "downloading files with curl -O outside /tmp may place untrusted executables on the PATH or in the project",
	}
}

# ---------------------------------------------------------------------------
# ALLOW default: Bash fallback-allow for safe commands.
#
# Fires when the Bash tool is active but no dangerous pattern matched.
# This candidate ensures benign commands (git status, ls, cp /tmp/x /tmp/y,
# etc.) produce "allow" via the resolver rather than falling back to the
# resolver's default-ask, which is intended only for genuinely unknown tool
# types.
#
# The candidate has a deterministic rule_id so the resolver can pick it
# consistently when it wins the priority sort.
# ---------------------------------------------------------------------------

any_dangerous_pattern if {
	regex.match(`(curl|wget)\s+.*\|\s*(bash|sh)\b`, cmd)
}

any_dangerous_pattern if {
	regex.match(`(^|;|&&|\|\|)\s*sudo\s+`, cmd)
}

any_dangerous_pattern if {
	startswith(trim_space(cmd), "sudo ")
}

any_dangerous_pattern if {
	regex.match(`\bdd\b.*\bif=/dev/`, cmd)
}

any_dangerous_pattern if {
	regex.match(`\bchmod\b\s+(-[Rr]+\s+)?777\b`, cmd)
}

any_dangerous_pattern if {
	regex.match(`>\s*/dev/(disk|sd[a-z]|nvme|mmcblk)`, cmd)
}

any_dangerous_pattern if {
	regex.match(`\brm\s+(-[rRfF]{1,4}\s+|--recursive\s+|--force\s+)*/`, cmd)
	not regex.match(`\brm\s+(-[rRfF]{1,4}\s+|--recursive\s+|--force\s+)*/tmp/agentjail`, cmd)
}

any_dangerous_pattern if {
	regex.match(`\bgit\s+push\b.*\s(-f\b|--force\b)`, cmd)
}

any_dangerous_pattern if {
	regex.match(`\b(env|printenv)\b.*\|\s*curl\b`, cmd)
}

any_dangerous_pattern if {
	regex.match(`\bgpg\b.*--export-secret-keys?\b`, cmd)
}

any_dangerous_pattern if {
	regex.match(`\blaunchctl\s+(bootout|remove)\b`, cmd)
}

any_dangerous_pattern if {
	regex.match(`\bsystemctl\s+(stop|disable)\b`, cmd)
}

any_dangerous_pattern if {
	regex.match(`\bssh-keygen\b.*-f\s+[^/]*(/(?!tmp/)[^"'\s]+)`, cmd)
}

any_dangerous_pattern if {
	contains_sensitive_path(cmd)
}

any_dangerous_pattern if {
	regex.match(`\bgit\s+push\b`, cmd)
}

any_dangerous_pattern if {
	is_publish_cmd(cmd)
}

any_dangerous_pattern if {
	regex.match(`\bcurl\b.*-O\b`, cmd)
	not regex.match(`\bcurl\b.*-O\b.*/tmp/`, cmd)
}

any_dangerous_pattern if {
	_is_policy_mutation
}

candidate contains r if {
	is_bash
	not any_dangerous_pattern
	r := {
		"action":  "allow",
		"rule_id": "command_policy/default-allow",
		"reason":  "no dangerous-command pattern matched",
	}
}
