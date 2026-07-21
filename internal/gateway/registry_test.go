package gateway

import "testing"

func TestLookup(t *testing.T) {
	tests := []struct {
		name         string
		agentBase    string
		wantFound    bool
		wantHost     string
		wantVerified bool
	}{
		{"claude code verified", "claude", true, "api.anthropic.com", true},
		{"codex inert", "codex", true, "api.openai.com", false},
		{"gemini inert", "gemini", true, "generativelanguage.googleapis.com", false},
		{"cursor not registered", "cursor", false, "", false},
		{"unknown agent", "some-other-agent", false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := Lookup(tt.agentBase)
			if ok != tt.wantFound {
				t.Fatalf("Lookup(%q) found=%v, want %v", tt.agentBase, ok, tt.wantFound)
			}
			if !tt.wantFound {
				return
			}
			if p.UpstreamHost != tt.wantHost {
				t.Errorf("UpstreamHost = %q, want %q", p.UpstreamHost, tt.wantHost)
			}
			if p.Caps.Verified != tt.wantVerified {
				t.Errorf("Caps.Verified = %v, want %v", p.Caps.Verified, tt.wantVerified)
			}
			if p.BaseURLEnvVar == "" {
				t.Errorf("BaseURLEnvVar is empty for %q", tt.agentBase)
			}
		})
	}
}

func TestLookupClaudeCodeCaps(t *testing.T) {
	p, ok := Lookup("claude")
	if !ok {
		t.Fatal("claude not found")
	}
	if !p.Caps.BaseURLEnv || !p.Caps.SupportsOAuth || !p.Caps.SupportsPathPrefix {
		t.Errorf("claude-code Caps missing expected flags: %+v", p.Caps)
	}
	if p.Caps.TunnelOnly {
		t.Errorf("claude-code should not be TunnelOnly: %+v", p.Caps)
	}
}
