//go:build darwin

package shieldapp

import (
	"strings"
	"testing"
)

func TestGenerateTunnelProfileCredentialMCPCapabilityIsExact(t *testing.T) {
	t.Parallel()
	home := "/Users/me"
	executable := home + "/.agentjail/bin/agentjail"
	profile := generateSBProfileTunnelWithCapabilities(nil, home, darwinProfileCapabilities{
		CredentialMCPExecutable: executable,
	})

	if !strings.Contains(profile, "(allow file-read*\n    (literal \""+executable+"\"))") {
		t.Fatalf("tunnel profile missing exact credential MCP read capability:\n%s", profile)
	}
	if strings.Contains(profile, "(allow file-read*\n    (subpath \""+home+"/.agentjail/bin\"))") {
		t.Fatal("tunnel profile broadly grants the AgentJail bin directory")
	}
}
