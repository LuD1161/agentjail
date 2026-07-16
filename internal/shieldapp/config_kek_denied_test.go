package shieldapp

import "testing"

// ~/.config is granted read-only so MCP configs stay reachable, so without the
// carve-out the agent reads the fallback KEK while doctor reports "encrypted".
// See ADR 0097-linux-kek-fallback.
func TestConfigKEKDirIsReadDenied(t *testing.T) {
	for _, d := range ConfigCredentialSubdirs() {
		if d == "agentjail" {
			return
		}
	}
	t.Error("SECURITY: \"agentjail\" is not in ConfigCredentialSubdirs() — a shielded " +
		"agent can read ~/.config/agentjail/kek and decrypt every recorded body, " +
		"while doctor still reports bodies as encrypted")
}
