package captureproxy

import "testing"

var testClaude = Provider{
	Name:          "claude-code",
	AgentBaseName: "claude",
	UpstreamHost:  "api.anthropic.com",
	BaseURLEnvVar: "ANTHROPIC_BASE_URL",
}

func TestResolveForwardTarget(t *testing.T) {
	tests := []struct {
		name       string
		inherited  string
		allowlist  []string
		wantErr    bool
		wantScheme string
		wantHost   string
		wantPath   string
	}{
		{
			name:       "empty inherited uses provider default",
			inherited:  "",
			wantScheme: "https",
			wantHost:   "api.anthropic.com",
			wantPath:   "",
		},
		{
			name:       "provider host allowed without allowlist",
			inherited:  "https://api.anthropic.com/some/prefix",
			wantScheme: "https",
			wantHost:   "api.anthropic.com",
			wantPath:   "/some/prefix",
		},
		{
			name:       "valid https chains and preserves path prefix when allowlisted",
			inherited:  "https://corp-proxy.internal/llm/anthropic",
			allowlist:  []string{"corp-proxy.internal"},
			wantScheme: "https",
			wantHost:   "corp-proxy.internal",
			wantPath:   "/llm/anthropic",
		},
		{
			name:      "userinfo rejected",
			inherited: "https://user:pass@api.anthropic.com",
			wantErr:   true,
		},
		{
			name:      "non-allowlisted host rejected",
			inherited: "https://evil.internal",
			wantErr:   true,
		},
		{
			name:      "unsupported scheme rejected",
			inherited: "ftp://api.anthropic.com",
			wantErr:   true,
		},
		{
			name:      "no host rejected",
			inherited: "https:///path-only",
			wantErr:   true,
		},
		{
			name:       "own gateway url not chained",
			inherited:  "http://127.0.0.1:54321/aj~deadbeef00000000",
			wantScheme: "https",
			wantHost:   "api.anthropic.com",
			wantPath:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveForwardTarget(tt.inherited, testClaude, tt.allowlist)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveForwardTarget(%q) = %v, want error", tt.inherited, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveForwardTarget(%q) unexpected error: %v", tt.inherited, err)
			}
			if got.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %q, want %q", got.Scheme, tt.wantScheme)
			}
			if got.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tt.wantPath)
			}
		})
	}
}

func TestIsOwnGatewayURLDoesNotFlagUnrelatedURLs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"real upstream", "https://api.anthropic.com/v1/messages", false},
		{"loopback but no nonce prefix", "http://127.0.0.1:8080/v1/messages", false},
		{"loopback with nonce prefix", "http://127.0.0.1:8080/aj~abc123", true},
		{"localhost with nonce prefix", "http://localhost:8080/aj~abc123", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := mustParseURL(t, tt.raw)
			if got := IsOwnGatewayURL(u); got != tt.want {
				t.Errorf("IsOwnGatewayURL(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
