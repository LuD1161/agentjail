// logs_impact.go — impact text derivation for DENY rows in `agentjail logs`.
//
// impactFor translates a daemon evalLine into a one-line human-readable
// consequence string ("would overwrite SSH key") suitable for the IMPACT
// column in rich-display mode. Only called for DENY rows; ASK/ALLOW rows keep
// the rule_id column unchanged.
//
// All logic is a pure function — easy to unit-test without a terminal.
package main

import "strings"

// impactFor returns a short impact summary string for a denied eval line.
// Resolution order (highest priority first):
//  1. line.Impact — policy-declared; set by Rego rules that include an "impact" field
//  2. builtinImpact — hardcoded heuristics for the ~20 built-in rules
//  3. line.Reason — the rule author's human-readable reason, truncated to 50 chars
//  4. "—" — ultimate fallback
//
// New user-authored policies that declare an "impact" field in their decision
// object will have that text surfaced in agentjail logs without any code change.
func impactFor(line evalLine) string {
	// 1. Policy-declared impact — takes precedence over everything.
	if line.Impact != "" {
		return truncate(line.Impact, 50)
	}

	// 2. Hardcoded heuristics for built-in rules.
	if s := builtinImpact(line); s != "" {
		return s
	}

	// 3. Fall back to the rule's reason field (or rule_id if reason is absent).
	reason := line.Reason
	if reason == "" {
		reason = line.RuleID
	}
	if reason == "" {
		return "—"
	}
	// Keep the old truncation format (3-char ASCII "...") for backward-compat
	// with tests and log snapshots that match on "...".
	if len(reason) > 50 {
		return reason[:47] + "..."
	}
	return reason
}

// builtinImpact is the original impactFor body, preserved as a fallback for
// the built-in rules where we want richer context than the static reason text.
// Returns "" when no built-in pattern matches, so impactFor can continue to
// the reason-field fallback.
func builtinImpact(line evalLine) string {
	rule := line.RuleID
	summary := line.Summary
	tool := line.Tool

	switch rule {
	case "command_policy/no-bash-touch-sensitive-path",
		"no-bash-touch-sensitive-path": // backward-compat alias
		return sensitivePathImpact(summary)

	case "file_policy/sensitive_credential":
		return filePolicyImpact(tool, summary)

	case "command_policy/no-rm-rf-absolute",
		"no-rm-rf-absolute": // backward-compat alias
		return "would recursively delete absolute path"

	case "command_policy/no-pipe-to-shell",
		"no-pipe-to-shell": // backward-compat alias
		return "would execute remote script as shell"

	case "command_policy/no-sudo",
		"no-sudo": // backward-compat alias
		return "would escalate to root"

	case "command_policy/no-git-push-force",
		"no-git-push-force": // backward-compat alias
		return "would rewrite remote history"

	case "command_policy/no-env-exfil",
		"no-env-exfil": // backward-compat alias
		return "would exfiltrate env vars"

	case "command_policy/no-gpg-secret-export",
		"no-gpg-secret-export": // backward-compat alias
		return "would export GPG private key"

	case "command_policy/no-chmod-777",
		"no-chmod-777": // backward-compat alias
		return "would remove all access controls"

	case "command_policy/no-dd-device-read",
		"no-dd-device-read": // backward-compat alias
		return "would read raw disk device"

	case "command_policy/no-device-overwrite",
		"no-device-overwrite": // backward-compat alias
		return "would corrupt raw block device"

	case "command_policy/no-launchctl-remove",
		"no-launchctl-remove": // backward-compat alias
		return "would remove launchd service"

	case "command_policy/no-systemctl-disrupt",
		"no-systemctl-disrupt": // backward-compat alias
		return "would stop systemd unit"

	case "mcp_policy/blocked":
		return "would call blocked MCP server"

	case "mcp_policy/unknown":
		return "would call unallowlisted MCP server"
	}

	return ""
}

// sensitivePathImpact derives a write-vs-read impact string for the
// no-bash-touch-sensitive-path rule. The heuristic: if the command summary
// contains ">" or "tee" it's a write; otherwise a read.
func sensitivePathImpact(summary string) string {
	isWrite := strings.Contains(summary, ">") || strings.Contains(summary, "tee ")

	s := strings.ToLower(summary)
	switch {
	case strings.Contains(s, "/.ssh/"):
		if isWrite {
			return "would overwrite SSH key"
		}
		return "would read SSH key"

	case strings.Contains(s, "/.aws/"):
		if isWrite {
			return "would overwrite AWS credentials"
		}
		return "would leak AWS credentials"

	case strings.Contains(s, "/.gnupg/"):
		if isWrite {
			return "would expose GPG private key"
		}
		return "would expose GPG private key"

	case strings.Contains(s, ".env"):
		return "would expose env file secrets"

	case strings.Contains(s, "/etc/"):
		return "would tamper with system config"
	}

	// Generic sensitive-path impact.
	if isWrite {
		return "would overwrite sensitive file"
	}
	return "would read sensitive file"
}

// filePolicyImpact derives impact for the file_policy/sensitive_credential rule.
func filePolicyImpact(tool, summary string) string {
	s := strings.ToLower(summary)
	isWrite := tool == "Write" || tool == "Edit"

	switch {
	case strings.Contains(s, "/.ssh/"):
		if isWrite {
			return "would overwrite SSH private key"
		}
		return "would read SSH private key"

	case strings.Contains(s, "/.aws/credentials"):
		if isWrite {
			return "would overwrite AWS credentials"
		}
		return "would read AWS credentials"

	case strings.Contains(s, "/.aws/"):
		if isWrite {
			return "would overwrite AWS credentials"
		}
		return "would leak AWS credentials"

	case strings.Contains(s, "/.gnupg/"):
		return "would expose GPG private key"

	case strings.Contains(s, ".env"):
		return "would expose env file secrets"

	case strings.Contains(s, "/etc/"):
		return "would tamper with system config"
	}

	if isWrite {
		return "would overwrite sensitive credential"
	}
	return "would read sensitive credential"
}

// impactBucket categorizes an impact string for the "saved" counter in the
// status bar. Returns a short bucket name.
func impactBucket(impact string) string {
	s := strings.ToLower(impact)
	switch {
	case strings.Contains(s, "ssh") && strings.Contains(s, "write"),
		strings.Contains(s, "ssh") && strings.Contains(s, "overwrite"):
		return "SSH writes"
	case strings.Contains(s, "ssh"):
		return "SSH reads"
	case strings.Contains(s, "aws") && (strings.Contains(s, "overwrite") || strings.Contains(s, "write")):
		return "AWS creds"
	case strings.Contains(s, "aws") || strings.Contains(s, "credentials"):
		return "AWS reads"
	case strings.Contains(s, "gpg"):
		return "GPG"
	case strings.Contains(s, "env file"):
		return "env files"
	case strings.Contains(s, "system config"):
		return "system config"
	case strings.Contains(s, "recursive") || strings.Contains(s, "delete"):
		return "recursive delete"
	case strings.Contains(s, "remote script") || strings.Contains(s, "shell"):
		return "remote exec"
	case strings.Contains(s, "root") || strings.Contains(s, "sudo") || strings.Contains(s, "escalat"):
		return "sudo"
	case strings.Contains(s, "mcp") || strings.Contains(s, "blocked mcp") || strings.Contains(s, "unallowlist"):
		return "MCP block"
	default:
		return "other"
	}
}
