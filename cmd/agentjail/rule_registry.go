// rule_registry.go — single source of truth for all known policy rule_ids.
//
// For every known rule_id this file records its source (core, library, or
// custom), a human-readable description, and whether it is locked (cannot
// be suppressed by disabled_rules).
//
// IMPORTANT: The authoritative locked set lives in resolver.rego as the
// `locked_rules` constant. The Go copy here is used ONLY for:
//   - display in `agentjail policy list`
//   - early CLI refusal in `agentjail policy disable`
//
// Rego enforces; this is for display + early CLI refusal. A test
// (TestLockedSetMatchesRego) asserts that the two sets are identical so
// drift is caught at CI time.
package main

// RuleSource identifies where a rule originates.
type RuleSource string

const (
	RuleSourceCore    RuleSource = "core"
	RuleSourceLibrary RuleSource = "library"
	RuleSourceCustom  RuleSource = "custom"
)

// RuleEntry is the registry record for a single policy rule.
type RuleEntry struct {
	// ID is the canonical rule_id emitted by the Rego policy, e.g.
	// "command_policy/no-sudo" or "library/no-daemon-kill".
	ID string

	// Source indicates whether the rule is core, library, or custom.
	Source RuleSource

	// Description is a short human-readable summary.
	Description string

	// Locked, when true, means this rule_id can never be suppressed via
	// disabled_rules. The Rego resolver enforces this; Go duplicates it
	// only for display and early CLI refusal.
	Locked bool
}

// ruleRegistry is the complete list of known rule_ids.
// Authoritative locked set: resolver.rego locked_rules constant.
// ANY change to locked_rules in resolver.rego MUST be reflected here
// and TestLockedSetMatchesRego will catch it.
var ruleRegistry = []RuleEntry{
	// ------------------------------------------------------------------ //
	// Core — aws_policy/* (per-account posture, ADR 0017)
	// ------------------------------------------------------------------ //
	{
		ID:          "aws_policy/posture",
		Source:      RuleSourceCore,
		Description: "Per-account AWS posture: sandbox asks on delete, prod denies delete, locked denies CUD; fails safe to prod",
	},

	// ------------------------------------------------------------------ //
	// Core — command_policy/*
	// ------------------------------------------------------------------ //
	{
		ID:          "command_policy/no-sudo",
		Source:      RuleSourceCore,
		Description: "Block sudo invocations",
	},
	{
		ID:          "command_policy/no-rm-rf-absolute",
		Source:      RuleSourceCore,
		Description: "Block rm -rf on absolute paths",
	},
	{
		ID:          "command_policy/no-git-push-force",
		Source:      RuleSourceCore,
		Description: "Block git force-push to the default branch (main/master)",
	},
	{
		ID:          "command_policy/no-chmod-777",
		Source:      RuleSourceCore,
		Description: "Block chmod 777 / world-write operations",
	},
	{
		ID:          "command_policy/no-dd-device-read",
		Source:      RuleSourceCore,
		Description: "Block dd reads from raw block devices",
	},
	{
		ID:          "command_policy/no-device-overwrite",
		Source:      RuleSourceCore,
		Description: "Block writes to raw block/char devices",
	},
	{
		ID:          "command_policy/no-env-exfil",
		Source:      RuleSourceCore,
		Description: "Block environment-variable exfiltration via curl/wget",
	},
	{
		ID:          "command_policy/no-gpg-secret-export",
		Source:      RuleSourceCore,
		Description: "Block GPG secret key export",
	},
	{
		ID:          "command_policy/no-launchctl-remove",
		Source:      RuleSourceCore,
		Description: "Block launchctl remove / unload of system services",
	},
	{
		ID:          "command_policy/no-pipe-to-shell",
		Source:      RuleSourceCore,
		Description: "Block curl/wget | sh pipe-to-shell patterns",
	},
	{
		ID:          "command_policy/no-ssh-keygen-outside-tmp",
		Source:      RuleSourceCore,
		Description: "Block ssh-keygen writing keys outside /tmp",
	},
	{
		ID:          "command_policy/no-systemctl-disrupt",
		Source:      RuleSourceCore,
		Description: "Block systemctl stop/disable/mask on critical services",
	},
	{
		ID:          "command_policy/no-bash-touch-sensitive-path",
		Source:      RuleSourceCore,
		Description: "Block bash touch/truncation of sensitive paths",
	},
	{
		ID:          "command_policy/confirm-curl-download",
		Source:      RuleSourceCore,
		Description: "Ask before downloading via curl (non-pipe)",
	},
	{
		ID:          "command_policy/confirm-git-push",
		Source:      RuleSourceCore,
		Description: "Ask before git push to a remote",
	},
	{
		ID:          "command_policy/confirm-git-push-force",
		Source:      RuleSourceCore,
		Description: "Ask before a force-push whose target branch is implicit (bare git push -f)",
	},
	{
		ID:          "command_policy/confirm-publish",
		Source:      RuleSourceCore,
		Description: "Ask before npm/cargo/pip publish",
	},
	{
		ID:          "command_policy/default-allow",
		Source:      RuleSourceCore,
		Description: "Allow commands that match no other rule",
	},
	// Locked: protects against an agent disabling agentjail's own policy CLI.
	// See resolver.rego locked_rules.
	{
		ID:          "command_policy/no-policy-mutation",
		Source:      RuleSourceCore,
		Description: "Block agents from running agentjail policy/mcp mutation commands",
		Locked:      true,
	},

	// ------------------------------------------------------------------ //
	// Core — file_policy/*
	// ------------------------------------------------------------------ //
	// Locked: protects agentjail's own config directory from modification.
	{
		ID:          "file_policy/agentjail_self",
		Source:      RuleSourceCore,
		Description: "Block reads/writes to ~/.agentjail/ (agentjail self-protection)",
		Locked:      true,
	},
	{
		ID:          "file_policy/sensitive_credential",
		Source:      RuleSourceCore,
		Description: "Deny access to SSH keys, AWS credentials, GPG keyrings, etc.",
	},
	{
		ID:          "file_policy/sensitive_in_project",
		Source:      RuleSourceCore,
		Description: "Deny access to .env / secrets files found in the project tree",
	},
	{
		ID:          "file_policy/project_allow",
		Source:      RuleSourceCore,
		Description: "Allow reads/writes within the project working directory",
	},
	{
		ID:          "file_policy/temp_allow",
		Source:      RuleSourceCore,
		Description: "Allow reads/writes within the system temp directory",
	},
	{
		ID:          "file_policy/default",
		Source:      RuleSourceCore,
		Description: "Default ask for file paths not matched by a more specific rule",
	},

	// ------------------------------------------------------------------ //
	// Core — mcp_policy/*
	// ------------------------------------------------------------------ //
	{
		ID:          "mcp_policy/allowed",
		Source:      RuleSourceCore,
		Description: "Allow MCP tool calls to servers on the allow list",
	},
	{
		ID:          "mcp_policy/blocked",
		Source:      RuleSourceCore,
		Description: "Deny MCP tool calls to servers on the block list",
	},
	{
		ID:          "mcp_policy/tool_not_allowed",
		Source:      RuleSourceCore,
		Description: "Deny MCP tool calls not in the per-server allowed_tools list",
	},
	{
		ID:          "mcp_policy/unknown",
		Source:      RuleSourceCore,
		Description: "Deny MCP tool calls to servers not in the allow list",
	},

	// ------------------------------------------------------------------ //
	// Core — resolver/*
	// Locked: disabling the resolver default would remove the fail-safe.
	// ------------------------------------------------------------------ //
	{
		ID:          "resolver/default",
		Source:      RuleSourceCore,
		Description: "Fail-safe default-ask when no other candidate fires",
		Locked:      true,
	},

	// ------------------------------------------------------------------ //
	// Core — self-protection (promoted from library; rule_id prefix is historical)
	// ------------------------------------------------------------------ //
	// Locked: protects agentjail from being killed by the agent.
	// Note: rule_id retains "library/" prefix for historical reasons; the rule
	// is now always-on locked core — it is never opt-in.
	{
		ID:          "library/no-daemon-kill",
		Source:      RuleSourceCore,
		Description: "Block attempts to stop agentjail-daemon",
		Locked:      true,
	},
	// Locked: protects agentjail hooks from being removed.
	// Note: rule_id retains "library/" prefix for historical reasons; the rule
	// is now always-on locked core — it is never opt-in.
	{
		ID:          "library/no-hook-self-disable",
		Source:      RuleSourceCore,
		Description: "Block attempts to remove or modify agentjail agent hooks",
		Locked:      true,
	},

	// ------------------------------------------------------------------ //
	// Library — optional hardening rules
	// ------------------------------------------------------------------ //
	{
		ID:          "library/no-app-binary-write",
		Source:      RuleSourceLibrary,
		Description: "Block writes into application executable paths (/Applications, /usr/local/bin, …)",
	},
	{
		ID:          "library/no-aws-destructive",
		Source:      RuleSourceLibrary,
		Description: "Deny destructive AWS CLI (delete/terminate), ask on create/run/s3 cp; defers to per-account posture when configured",
	},
	{
		ID:          "library/no-destructive-git",
		Source:      RuleSourceLibrary,
		Description: "Block destructive git operations (reset --hard, clean -f, stash drop, …)",
	},
	{
		ID:          "library/no-history-read",
		Source:      RuleSourceLibrary,
		Description: "Block shell history reads (~/.bash_history, ~/.zsh_history, …)",
	},
	{
		ID:          "library/no-launchctl",
		Source:      RuleSourceLibrary,
		Description: "Block persistence and background job launchers (launchctl, osascript, crontab, …)",
	},
	{
		ID:          "library/no-shell-eval",
		Source:      RuleSourceLibrary,
		Description: "Block shell eval and obfuscation patterns",
	},
	{
		ID:          "library/no-shell-init-write",
		Source:      RuleSourceLibrary,
		Description: "Block writes to shell startup files (~/.bashrc, ~/.zshrc, …)",
	},
}

// LockedRuleIDs returns the set of rule_ids that are locked (cannot be
// suppressed by disabled_rules). This MUST match resolver.rego's
// locked_rules constant — TestLockedSetMatchesRego enforces this.
func LockedRuleIDs() map[string]bool {
	m := make(map[string]bool)
	for _, e := range ruleRegistry {
		if e.Locked {
			m[e.ID] = true
		}
	}
	return m
}

// RegistryByID looks up a rule entry by its rule_id. Returns the entry and
// true if found, or zero value and false if not found.
func RegistryByID(id string) (RuleEntry, bool) {
	for _, e := range ruleRegistry {
		if e.ID == id {
			return e, true
		}
	}
	return RuleEntry{}, false
}

// isRuleID reports whether s looks like a rule_id (contains a "/" separator)
// or is an exact match in the registry.
func isRuleID(s string) bool {
	// Anything with a "/" is treated as a rule_id (namespaced).
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	// Also accept exact registry matches even without "/" (shouldn't happen
	// with current naming but makes the check complete).
	_, ok := RegistryByID(s)
	return ok
}
