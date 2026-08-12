package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestLegacyCommandsExposeTheirRuntimeFlagsInHelp(t *testing.T) {
	tests := []struct {
		cmd   *cobra.Command
		flags []string
	}{
		{costCmd, []string{"period", "project", "json", "no-color"}},
		{logsCmd, []string{"log", "db", "no-follow", "action", "tool", "since", "json", "all", "no-color", "v", "session", "basic", "latest"}},
		{monitorCmd, []string{"db", "policy", "since", "json"}},
		{replayCmd, []string{"db", "session", "verbose", "follow", "list", "no-color", "basic"}},
		{sessionsCmd, []string{"db", "active", "json", "since", "no-color"}},
		{statsCmd, []string{"db", "json", "since", "top", "no-color"}},
		{tryCmd, []string{"read", "write", "json"}},
		{uiCmd, []string{"addr", "trusted-host", "log", "db", "insecure-bind", "edit-policy"}},
		{installCmd, []string{"for", "all", "yes", "allow-unsupported", "with-path-shim", "with-apparmor", "chain", "replace"}},
		{uninstallCmd, []string{"for", "path-shim-only", "keep-secrets", "force"}},
		{updateCmd, []string{"force"}},
		{runCmd, []string{"tunnel", "no-sandbox", "git-ssh", "no-git-ssh", "verbose", "credential"}},
		{claudeCmd, []string{"tunnel", "no-sandbox", "git-ssh", "no-git-ssh", "verbose", "credential"}},
		{mcpScanCmd, []string{"json"}},
		{mcpWhereCmd, []string{"json"}},
		{mcpToolsCmd, []string{"json"}},
		{skillListCmd, []string{"json"}},
		{skillAllowCmd, []string{"project"}},
		{skillBlockCmd, []string{"project"}},
		{skillAskCmd, []string{"project"}},
		{skillClearCmd, []string{"project"}},
	}

	for _, tt := range tests {
		for _, name := range tt.flags {
			if tt.cmd.Flags().Lookup(name) == nil && tt.cmd.InheritedFlags().Lookup(name) == nil {
				t.Errorf("%s help omits runtime flag --%s", tt.cmd.CommandPath(), name)
			}
		}
	}
}
