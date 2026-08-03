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
		{costCmd, []string{"period", "project", "json"}},
		{logsCmd, []string{"db", "action", "since", "latest"}},
		{monitorCmd, []string{"db", "policy", "since", "json"}},
		{replayCmd, []string{"session", "list", "follow", "basic"}},
		{sessionsCmd, []string{"active", "since", "json"}},
		{statsCmd, []string{"since", "top", "json"}},
		{tryCmd, []string{"read", "write", "json"}},
		{uiCmd, []string{"addr", "trusted-host", "edit-policy"}},
		{installCmd, []string{"for", "all", "yes", "with-path-shim"}},
		{uninstallCmd, []string{"for", "path-shim-only", "keep-secrets"}},
		{updateCmd, []string{"force"}},
		{runCmd, []string{"tunnel", "no-sandbox"}},
		{mcpScanCmd, []string{"json"}},
		{skillAllowCmd, []string{"project"}},
	}

	for _, tt := range tests {
		for _, name := range tt.flags {
			if tt.cmd.Flags().Lookup(name) == nil {
				t.Errorf("%s help omits runtime flag --%s", tt.cmd.CommandPath(), name)
			}
		}
	}
}
