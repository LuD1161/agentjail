package netpolicy

import (
	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredMatcherPreservesCanonicalVerdict(t *testing.T) {
	dir := t.TempDir()
	for _, verdict := range []string{"allow", "ask", "deny"} {
		t.Run(verdict, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("id: test\naction: "+verdict+"\nreason: test verdict\n"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []agentconfig.EnforcementMode{"", agentconfig.EnforcementMonitor, agentconfig.EnforcementEnforce} {
				m, err := NewMatcherForMode(mode, dir)
				if err != nil {
					t.Fatal(err)
				}
				got := m.Evaluate(&Operation{})
				action, would := verdict, ""
				if mode != agentconfig.EnforcementEnforce && verdict != "allow" {
					action, would = "allow", verdict
				}
				wantBlock := mode == agentconfig.EnforcementEnforce && verdict != "allow"
				if got.BlocksWithoutApproval() != wantBlock {
					t.Fatalf("mode %q verdict %q: blocking=%v", mode, verdict, got.BlocksWithoutApproval())
				}
				if got == nil || got.Action != action || got.WouldAction != would || got.Template.ID != "test" {
					t.Fatalf("mode %q verdict %q: %+v", mode, verdict, got)
				}
			}
		})
	}
}
