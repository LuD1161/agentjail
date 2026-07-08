package main

import (
	"strings"
	"testing"
)

// TestDenyRemediationHint is a table test for the "how to unblock"
// remediation line appended to file_policy/* and command_policy/* denies.
func TestDenyRemediationHint(t *testing.T) {
	tests := []struct {
		ruleID    string
		wantEmpty bool
		wantParts []string
	}{
		{"file_policy/sensitive_credential", false, []string{"file.extra_allow", "agentjail policy disable file_policy/sensitive_credential"}},
		{"file_policy/default", false, []string{"file.extra_allow"}},
		{"command_policy/no_rm_rf", false, []string{"agentjail policy disable command_policy/no_rm_rf"}},
		{"mcp_policy/unknown", true, nil},
		{"resolver/default", true, nil},
		{"", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := denyRemediationHint(tt.ruleID)
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("denyRemediationHint(%q) = %q, want empty", tt.ruleID, got)
				}
				return
			}
			for _, part := range tt.wantParts {
				if !strings.Contains(got, part) {
					t.Errorf("denyRemediationHint(%q) = %q, missing %q", tt.ruleID, got, part)
				}
			}
		})
	}
}

// TestMCPServerName covers extraction of the server component from an MCP
// tool name (mirrors mcp_policy.rego's mcp_server_name), including the
// double-underscore-in-tool-name and non-MCP fallback cases.
func TestMCPServerName(t *testing.T) {
	tests := []struct {
		toolName string
		want     string
	}{
		{"mcp__filesystem__read_file", "filesystem"},
		{"mcp__filesystem__read_multiple_files", "filesystem"},
		{"mcp__linear-server__get_issue", "linear-server"},
		{"mcp__claude_ai_Gmail__authenticate", "claude_ai_Gmail"},
		{"Bash", ""},
		{"Read", ""},
		{"mcp__incomplete", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			if got := mcpServerName(tt.toolName); got != tt.want {
				t.Errorf("mcpServerName(%q) = %q, want %q", tt.toolName, got, tt.want)
			}
		})
	}
}

// TestHook_Deny_UnknownMCPServerNamesServer verifies the end-to-end stderr for
// an mcp_policy/unknown deny names the exact server the agent tried to reach,
// so the user can copy-paste `agentjail mcp allow <server>` verbatim.
func TestHook_Deny_UnknownMCPServerNamesServer(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "deny", "MCP server not in allowlist", "mcp_policy/unknown"
	})

	stdin := makeStdinJSON("mcp__stripe__create_charge", map[string]interface{}{}, "session-mcp-deny")

	_, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + sockPath})

	if code != 2 {
		t.Fatalf("expected exit 2 on deny, got %d; stderr=%q", code, stderr)
	}
	stderrStr := string(stderr)
	if !strings.Contains(stderrStr, "agentjail mcp allow stripe") {
		t.Errorf("stderr missing server-specific 'agentjail mcp allow stripe' hint; got %q", stderrStr)
	}
	if strings.Contains(stderrStr, "<server-name>") {
		t.Errorf("stderr should name the server, not the placeholder; got %q", stderrStr)
	}
}

// TestHook_Deny_FilePolicyRemediationHint verifies the end-to-end stderr
// output for a file_policy/* deny includes the remediation hint naming
// file.extra_allow and the "agentjail policy disable" command.
func TestHook_Deny_FilePolicyRemediationHint(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "deny", "path is a sensitive credential file", "file_policy/sensitive_credential"
	})

	stdin := makeStdinJSON("Read", map[string]interface{}{
		"path": "/home/user/.ssh/id_rsa",
	}, "session-file-deny")

	_, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + sockPath})

	if code != 2 {
		t.Fatalf("expected exit 2 on deny, got %d; stderr=%q", code, stderr)
	}
	stderrStr := string(stderr)
	if !strings.Contains(stderrStr, "file.extra_allow") {
		t.Errorf("stderr missing file.extra_allow remediation hint; got %q", stderrStr)
	}
	if !strings.Contains(stderrStr, "agentjail policy disable file_policy/sensitive_credential") {
		t.Errorf("stderr missing 'agentjail policy disable' remediation hint; got %q", stderrStr)
	}
}

// TestHook_Deny_CommandPolicyRemediationHint verifies the end-to-end stderr
// output for a command_policy/* deny includes an analogous remediation hint.
func TestHook_Deny_CommandPolicyRemediationHint(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "deny", "rm -rf is blocked by default policy", "command_policy/no_rm_rf"
	})

	stdin := makeStdinJSON("Bash", map[string]interface{}{
		"command": "rm -rf /tmp/project",
	}, "session-cmd-deny")

	_, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + sockPath})

	if code != 2 {
		t.Fatalf("expected exit 2 on deny, got %d; stderr=%q", code, stderr)
	}
	stderrStr := string(stderr)
	if !strings.Contains(stderrStr, "agentjail policy disable command_policy/no_rm_rf") {
		t.Errorf("stderr missing 'agentjail policy disable' remediation hint; got %q", stderrStr)
	}
}
