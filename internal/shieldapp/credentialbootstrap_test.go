package shieldapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/credentialtools"
)

func TestCredentialSelections(t *testing.T) {
	t.Parallel()
	var selections credentialSelections
	if err := selections.Set("aws=aws/default"); err != nil {
		t.Fatal(err)
	}
	if err := selections.Set("kubectl=kube/dev"); err != nil {
		t.Fatal(err)
	}
	if got := selections.String(); got != "aws=aws/default,kubectl=kube/dev" {
		t.Fatalf("String() = %q", got)
	}
	if got := selections.readyTools(); got != "aws,kubectl" {
		t.Fatalf("readyTools() = %q", got)
	}
	if err := selections.Set("aws=aws/other"); err == nil {
		t.Fatal("duplicate tool selection succeeded")
	}
	if err := selections.Set("unknown=value"); err == nil {
		t.Fatal("unknown tool selection succeeded")
	}
	if err := selections.Set("gh"); err == nil {
		t.Fatal("selection without name succeeded")
	}
}

func TestMergeCredentialSelectionsKeepsExplicitIdentity(t *testing.T) {
	t.Parallel()
	explicit := credentialSelections{{Tool: credentialtools.ToolAWS, Name: "aws/production"}}
	discovered := credentialSelections{{Tool: credentialtools.ToolAWS}, {Tool: credentialtools.ToolKubernetes}}
	merged := mergeCredentialSelections(explicit, discovered)
	if len(merged) != 2 || merged[0].Name != "aws/production" || merged[1].Tool != credentialtools.ToolKubernetes {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestCredentialSessionConfiguresCodexAndClaudeNatively(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	session := &credentialSession{dir: dir, sessionToken: "session-capability", mcpCommand: "/opt/agentjail/bin/agentjail"}
	codexArgs, err := session.configureAgent("/usr/bin/codex", []string{"exec", "inspect S3"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(codexArgs, " ")
	if !strings.Contains(joined, "mcp_servers.agentjail_credentials.command") || !strings.HasSuffix(joined, "exec inspect S3") {
		t.Fatalf("Codex args = %#v", codexArgs)
	}

	claudeArgs, err := session.configureAgent("/usr/bin/claude", []string{"-p", "inspect cluster"})
	if err != nil {
		t.Fatal(err)
	}
	if len(claudeArgs) < 4 || claudeArgs[0] != "--mcp-config" || claudeArgs[2] != "--append-system-prompt" || !strings.Contains(claudeArgs[3], "AgentJail never chooses") {
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

func TestResolveCredentialSelections(t *testing.T) {
	dir := t.TempDir()
	aws := filepath.Join(dir, "aws")
	if err := os.Symlink("/bin/sh", aws); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	resolved, err := resolveCredentialSelections(credentialSelections{{Tool: credentialtools.ToolAWS, Name: "aws/default"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].BinaryPath == aws || resolved[0].binaryInfo == nil {
		t.Fatalf("unexpected resolution: %#v", resolved)
	}
}

func TestResolveCredentialSelectionsRejectsMissingAndNonExecutable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	selection := credentialSelections{{Tool: credentialtools.ToolAWS, Name: "aws/default"}}
	if _, err := resolveCredentialSelections(selection); err == nil {
		t.Fatal("missing executable succeeded")
	}
	if err := os.WriteFile(filepath.Join(dir, "aws"), []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCredentialSelections(selection); err == nil {
		t.Fatal("non-executable file succeeded")
	}
}

func TestResolveCredentialSelectionsRejectsAgentWritableExecutable(t *testing.T) {
	workingDir := t.TempDir()
	toolDir := t.TempDir()
	aws := filepath.Join(toolDir, "aws")
	if err := os.WriteFile(aws, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workingDir)
	t.Setenv("PATH", toolDir)
	selection := credentialSelections{{Tool: credentialtools.ToolAWS, Name: "aws/default"}}
	if _, err := resolveCredentialSelections(selection); err == nil || !strings.Contains(err.Error(), "agent-writable") {
		t.Fatalf("agent-writable executable error = %v", err)
	}
}

func TestCredentialExecutableUnsafeRoot(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path  string
		roots []string
		want  bool
	}{
		{path: "/repo/bin/aws", roots: []string{"/repo", "/tmp"}, want: true},
		{path: "/tmp/tools/aws", roots: []string{"/repo", "/tmp"}, want: true},
		{path: "/repository/aws", roots: []string{"/repo", "/tmp"}, want: false},
		{path: "/usr/local/bin/aws", roots: []string{"/repo", "/tmp"}, want: false},
	}
	for _, tt := range tests {
		_, got := credentialExecutableUnsafeRoot(tt.path, tt.roots...)
		if got != tt.want {
			t.Errorf("credentialExecutableUnsafeRoot(%q, %v) = %v, want %v", tt.path, tt.roots, got, tt.want)
		}
	}
}

func TestCredentialSessionWritesProtectedFileAndAppliesEnv(t *testing.T) {
	t.Parallel()
	session := &credentialSession{dir: t.TempDir()}
	if err := session.writeFile(credentialtools.SessionFile{
		EnvVar:  "KUBECONFIG",
		Name:    "kubeconfig",
		Content: []byte("secret config"),
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(session.dir, "kubeconfig")
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
	for _, file := range []credentialtools.SessionFile{
		{EnvVar: "bad-name", Name: "kubeconfig", Content: []byte("x")},
		{EnvVar: "KUBECONFIG", Name: "../escape", Content: []byte("x")},
	} {
		if err := session.writeFile(file); err == nil {
			t.Fatalf("unsafe file metadata succeeded: %#v", file)
		}
	}
}

func TestCredentialSessionWritesProtectedDirectoryAndAppliesEnv(t *testing.T) {
	t.Parallel()
	session := &credentialSession{dir: t.TempDir()}
	if err := session.writeDirectory(credentialtools.SessionDirectory{
		EnvVar: "GH_CONFIG_DIR",
		Name:   "gh-config",
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(session.dir, "gh-config")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("session directory mode = %v, want directory 0700", info.Mode())
	}
	env := session.applyEnv([]string{"GH_CONFIG_DIR=/home/test/.config/gh"})
	if got := strings.Join(env, "\n"); got != "GH_CONFIG_DIR="+path {
		t.Fatalf("unexpected environment: %s", got)
	}
}

func TestCredentialSessionRejectsUnsafeDirectoryMetadata(t *testing.T) {
	t.Parallel()
	session := &credentialSession{dir: t.TempDir()}
	for _, directory := range []credentialtools.SessionDirectory{
		{EnvVar: "bad-name", Name: "gh-config"},
		{EnvVar: "GH_CONFIG_DIR", Name: "../escape"},
	} {
		if err := session.writeDirectory(directory); err == nil {
			t.Fatalf("unsafe directory metadata succeeded: %#v", directory)
		}
	}
}

func TestPruneAbandonedCredentialSessions(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	for _, name := range []string{
		"agentjail-credentials-100-dead",
		"agentjail-credentials-200-live",
		"agentjail-credentials-invalid",
		"unrelated",
	} {
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
