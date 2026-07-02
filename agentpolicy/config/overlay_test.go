package config

import (
	"slices"
	"testing"
)

func TestMergeProjectOverlay_WidensAllowLists(t *testing.T) {
	base := &PolicyConfig{
		Network: NetworkConfig{AllowedHosts: []string{"api.github.com"}},
		MCP:     MCPConfig{Allowed: []string{"linear-server"}, Blocked: []string{"evil-mcp"}},
	}
	overlay := &PolicyConfig{
		Network: NetworkConfig{AllowedHosts: []string{"internal.corp", "api.github.com"}}, // dup + new
		MCP:     MCPConfig{Allowed: []string{"postgres-mcp"}, Blocked: []string{"other-bad"}},
	}
	got := MergeProjectOverlay(base, overlay)

	wantHosts := []string{"api.github.com", "internal.corp"}
	if !slices.Equal(got.Network.AllowedHosts, wantHosts) {
		t.Errorf("allowed_hosts = %v; want %v (base first, deduped)", got.Network.AllowedHosts, wantHosts)
	}
	if !slices.Equal(got.MCP.Allowed, []string{"linear-server", "postgres-mcp"}) {
		t.Errorf("mcp.allowed = %v; want union", got.MCP.Allowed)
	}
	if !slices.Equal(got.MCP.Blocked, []string{"evil-mcp", "other-bad"}) {
		t.Errorf("mcp.blocked = %v; want union (add-only)", got.MCP.Blocked)
	}
}

func TestMergeProjectOverlay_NeverDropsBaseRestrictions(t *testing.T) {
	base := &PolicyConfig{
		MCP:           MCPConfig{Allowed: []string{"linear-server"}, Blocked: []string{"evil-mcp"}},
		Network:       NetworkConfig{AllowedHosts: []string{"api.github.com"}},
		DisabledRules: []string{"file_policy/x"},
	}
	// A hostile overlay tries to clear the block and the disabled rules.
	overlay := &PolicyConfig{
		MCP:           MCPConfig{Blocked: nil, Allowed: []string{"evil-mcp"}}, // try to "allow" a blocked MCP
		DisabledRules: nil,
	}
	got := MergeProjectOverlay(base, overlay)

	// The base block survives (union never shrinks); blocked still wins in rego.
	if !slices.Contains(got.MCP.Blocked, "evil-mcp") {
		t.Error("overlay must NOT be able to drop a base mcp.blocked entry")
	}
	// disabled_rules is taken from base unchanged (overlay cannot weaken it).
	if !slices.Equal(got.DisabledRules, []string{"file_policy/x"}) {
		t.Errorf("disabled_rules must come from base unchanged, got %v", got.DisabledRules)
	}
}

func TestMergeProjectOverlay_DoesNotMutateBase(t *testing.T) {
	base := &PolicyConfig{
		Network: NetworkConfig{AllowedHosts: []string{"api.github.com"}},
		MCP:     MCPConfig{Allowed: []string{"linear-server"}},
	}
	overlay := &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"evil.com"}}}
	_ = MergeProjectOverlay(base, overlay)

	if !slices.Equal(base.Network.AllowedHosts, []string{"api.github.com"}) {
		t.Errorf("base was mutated: %v", base.Network.AllowedHosts)
	}
}

func TestMergeProjectOverlay_NilOverlayIsBaseCopy(t *testing.T) {
	base := &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"api.github.com"}}}
	got := MergeProjectOverlay(base, nil)
	if !slices.Equal(got.Network.AllowedHosts, base.Network.AllowedHosts) {
		t.Errorf("nil overlay should copy base hosts, got %v", got.Network.AllowedHosts)
	}
	// Effective hosts still include the non-removable essentials.
	eff := got.EffectiveAllowedHosts()
	if !slices.Contains(eff, "api.anthropic.com") {
		t.Errorf("essentials must still be present after overlay merge, got %v", eff)
	}
}

func TestMergeProjectOverlay_EffectiveHostsIncludeOverlay(t *testing.T) {
	base := Default()
	overlay := &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"db.internal.corp"}}}
	got := MergeProjectOverlay(base, overlay)
	eff := got.EffectiveAllowedHosts()
	if !slices.Contains(eff, "db.internal.corp") {
		t.Errorf("overlay host must appear in EffectiveAllowedHosts, got %v", eff)
	}
	if !slices.Contains(eff, "api.anthropic.com") {
		t.Errorf("essentials must remain, got %v", eff)
	}
}
