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
