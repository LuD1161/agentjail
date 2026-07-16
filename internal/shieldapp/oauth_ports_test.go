//go:build linux

package shieldapp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveOAuthCallbackPorts(t *testing.T) {
	tests := []struct {
		name string
		json string
		want []int
	}{
		{
			name: "extracts ports from redirect URIs",
			json: `{"mcpOAuth":{
				"linear|abc":{"redirectUri":"http://localhost:52819/callback"},
				"posthog|def":{"redirectUri":"http://localhost:3118/callback"}
			}}`,
			want: []int{52819, 3118},
		},
		{
			name: "deduplicates same port",
			json: `{"mcpOAuth":{
				"a|1":{"redirectUri":"http://localhost:8080/callback"},
				"b|2":{"redirectUri":"http://localhost:8080/callback"}
			}}`,
			want: []int{8080},
		},
		{
			name: "skips non-localhost",
			json: `{"mcpOAuth":{
				"a|1":{"redirectUri":"http://example.com:3000/callback"}
			}}`,
			want: nil,
		},
		{
			name: "skips empty redirect URI",
			json: `{"mcpOAuth":{
				"a|1":{"redirectUri":""}
			}}`,
			want: nil,
		},
		{
			name: "skips missing redirectUri field",
			json: `{"mcpOAuth":{
				"a|1":{"serverName":"test"}
			}}`,
			want: nil,
		},
		{
			name: "empty credentials file",
			json: `{}`,
			want: nil,
		},
		{
			name: "invalid JSON",
			json: `{not json`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".credentials.json")
			if err := os.WriteFile(path, []byte(tt.json), 0600); err != nil {
				t.Fatal(err)
			}
			got := resolveOAuthCallbackPorts(path)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			gotSet := make(map[int]bool)
			for _, p := range got {
				gotSet[p] = true
			}
			for _, w := range tt.want {
				if !gotSet[w] {
					t.Errorf("missing expected port %d in %v", w, got)
				}
			}
		})
	}
}

func TestResolveOAuthCallbackPorts_MissingFile(t *testing.T) {
	got := resolveOAuthCallbackPorts("/nonexistent/path/.credentials.json")
	if got != nil {
		t.Fatalf("expected nil for missing file, got %v", got)
	}
}
