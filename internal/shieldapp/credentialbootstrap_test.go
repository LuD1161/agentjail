package shieldapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/credentialaccess"
)

func TestCredentialSelectionsUseExactArbitraryIDs(t *testing.T) {
	t.Parallel()
	var selections credentialSelections
	for _, id := range []string{"aws-read-only-cred-prod", "slack-channel-read-token"} {
		if err := selections.Set(id); err != nil {
			t.Fatal(err)
		}
	}
	if got := selections.String(); got != "aws-read-only-cred-prod,slack-channel-read-token" {
		t.Fatalf("String() = %q", got)
	}
	if err := selections.Set("aws-read-only-cred-prod"); err == nil {
		t.Fatal("duplicate credential selection succeeded")
	}
	if err := selections.Set("  "); err == nil {
		t.Fatal("empty credential selection succeeded")
	}
}

func TestMergeCredentialSelectionsKeepsExplicitAndDiscovery(t *testing.T) {
	t.Parallel()
	explicit := credentialSelections{{Name: "aws-read-only-cred-prod"}}
	discovered := credentialSelections{{Discovery: true}}
	merged := mergeCredentialSelections(explicit, discovered)
	if len(merged) != 2 || merged[0].Name != "aws-read-only-cred-prod" || !merged[1].Discovery {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestCredentialSessionConfiguresCodexAndClaudeNatively(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	session := &credentialSession{dir: dir, sessionToken: "session-capability", mcpCommand: "/opt/agentjail/bin/agentjail"}
	codexArgs, err := session.configureAgent("/usr/bin/codex", []string{"exec", "inspect credentials"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(codexArgs, " ")
	if !strings.Contains(joined, "mcp_servers.agentjail_credentials.command") || !strings.HasSuffix(joined, "exec inspect credentials") {
		t.Fatalf("Codex args = %#v", codexArgs)
	}

	claudeArgs, err := session.configureAgent("/usr/bin/claude", []string{"-p", "inspect credential"})
	if err != nil {
		t.Fatal(err)
	}
	if len(claudeArgs) < 4 || claudeArgs[0] != "--mcp-config" || claudeArgs[2] != "--append-system-prompt" || !strings.Contains(claudeArgs[3], "does not infer") {
		t.Fatalf("Claude args = %#v", claudeArgs)
	}
	data, err := os.ReadFile(claudeArgs[1])
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Servers map[string]struct {
			Command string `json:"command"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.Servers["agentjail_credentials"].Command != session.mcpCommand {
		t.Fatalf("Claude MCP config = %s", data)
	}
}

func TestCredentialExecutableUnsafeRoot(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path  string
		roots []string
		want  bool
	}{
		{path: "/repo/bin/agentjail", roots: []string{"/repo", "/tmp"}, want: true},
		{path: "/tmp/tools/agentjail", roots: []string{"/repo", "/tmp"}, want: true},
		{path: "/repository/agentjail", roots: []string{"/repo", "/tmp"}, want: false},
		{path: "/usr/local/bin/agentjail", roots: []string{"/repo", "/tmp"}, want: false},
	}
	for _, tt := range tests {
		if _, got := credentialExecutableUnsafeRoot(tt.path, tt.roots...); got != tt.want {
			t.Errorf("unsafeRoot(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestCredentialSessionWritesProtectedFileAndAppliesEnv(t *testing.T) {
	t.Parallel()
	session := &credentialSession{dir: t.TempDir()}
	file := credentialaccess.SessionFile{EnvVar: "KUBECONFIG", Name: "credential-1", Content: []byte("secret config")}
	if err := session.writeFile(file); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(session.dir, file.Name)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("session file mode = %o, want 600", got)
	}
	env := session.applyEnv([]string{"PATH=/usr/bin", "KUBECONFIG=/host/config", "HOME=/home/test"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "/host/config") || !strings.Contains(joined, "KUBECONFIG="+path) {
		t.Fatalf("unexpected environment:\n%s", joined)
	}
}

func TestCredentialSessionRejectsUnsafeFileMetadata(t *testing.T) {
	t.Parallel()
	session := &credentialSession{dir: t.TempDir()}
	for _, file := range []credentialaccess.SessionFile{
		{EnvVar: "bad-name", Name: "credential", Content: []byte("x")},
		{EnvVar: "CONFIG", Name: "../escape", Content: []byte("x")},
		{EnvVar: "PATH", Name: "credential", Content: []byte("x")},
	} {
		if err := session.writeFile(file); err == nil {
			t.Fatalf("unsafe file metadata succeeded: %#v", file)
		}
	}
}

func TestCredentialSessionWritesProtectedDirectoryAndAppliesEnv(t *testing.T) {
	t.Parallel()
	session := &credentialSession{dir: t.TempDir()}
	directory := credentialaccess.SessionDirectory{EnvVar: "CLI_CONFIG_DIR", Name: "cli-config"}
	if err := session.writeDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(session.dir, directory.Name)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("session directory mode = %v", info.Mode())
	}
	if got := strings.Join(session.applyEnv([]string{"CLI_CONFIG_DIR=/host/config"}), "\n"); got != "CLI_CONFIG_DIR="+path {
		t.Fatalf("environment = %s", got)
	}
}

func TestPruneAbandonedCredentialSessions(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	for _, name := range []string{"agentjail-credentials-100-dead", "agentjail-credentials-200-live", "agentjail-credentials-invalid", "unrelated"} {
		if err := os.Mkdir(filepath.Join(tempDir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneAbandonedCredentialSessions(tempDir, func(pid int) bool { return pid == 200 }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tempDir, "agentjail-credentials-100-dead")); !os.IsNotExist(err) {
		t.Fatalf("dead session was not removed: %v", err)
	}
	for _, name := range []string{"agentjail-credentials-200-live", "agentjail-credentials-invalid", "unrelated"} {
		if _, err := os.Stat(filepath.Join(tempDir, name)); err != nil {
			t.Fatalf("%s should remain: %v", name, err)
		}
	}
}
