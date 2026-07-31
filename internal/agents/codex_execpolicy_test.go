package agents

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexExecPolicyUsesOnlyApprovalExecPrefix(t *testing.T) {
	if !strings.Contains(codexExecPolicy, `pattern = ["agentjail", "approval-exec"]`) {
		t.Fatalf("managed rule must prompt the approval-exec prefix:\n%s", codexExecPolicy)
	}
	if strings.Contains(codexExecPolicy, `pattern = ["*"]`) {
		t.Fatalf("managed rule must not use Codex's literal wildcard prefix:\n%s", codexExecPolicy)
	}
	if strings.Contains(codexExecPolicy, "agentjail approval-exec") {
		t.Fatalf("managed rule must use a tokenized prefix, not a shell string:\n%s", codexExecPolicy)
	}
}

func TestCodexExecPolicyInstallIsIdempotentAndPrivate(t *testing.T) {
	env := newCodexEnv(t)

	if err := ensureCodexExecPolicy(env); err != nil {
		t.Fatalf("first ensureCodexExecPolicy: %v", err)
	}
	path := codexExecPolicyPath(env)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read managed rule: %v", err)
	}
	if !bytes.Equal(first, []byte(codexExecPolicy)) {
		t.Fatalf("managed rule content differs\nwant:\n%s\ngot:\n%s", codexExecPolicy, first)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat managed rule: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("managed rule mode = %04o, want 0600", info.Mode().Perm())
	}

	if err := ensureCodexExecPolicy(env); err != nil {
		t.Fatalf("second ensureCodexExecPolicy: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read managed rule after second install: %v", err)
	}
	if !bytes.Equal(second, first) {
		t.Error("idempotent install changed the managed rule")
	}
}

func TestCodexExecPolicyInstallRefusesLocalChanges(t *testing.T) {
	env := newCodexEnv(t)
	path := codexExecPolicyPath(env)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	local := []byte("prefix_rule(pattern = [\"git\", \"push\"], decision = \"allow\")\n")
	if err := os.WriteFile(path, local, 0o600); err != nil {
		t.Fatalf("write local rule: %v", err)
	}

	err := ensureCodexExecPolicy(env)
	if err == nil || !strings.Contains(err.Error(), "local changes") {
		t.Fatalf("ensureCodexExecPolicy error = %v, want local changes error", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read local rule: %v", err)
	}
	if !bytes.Equal(got, local) {
		t.Errorf("locally changed rule was overwritten\nwant %q\ngot  %q", local, got)
	}
}

func TestCodexExecPolicyUninstallPreservesForeignRules(t *testing.T) {
	env := newCodexEnv(t)
	foreignPath := filepath.Join(env.Home, ".codex", "rules", "user.rules")
	foreign := []byte("prefix_rule(pattern = [\"go\", \"test\"], decision = \"allow\")\n")
	if err := os.MkdirAll(filepath.Dir(foreignPath), 0o700); err != nil {
		t.Fatalf("mkdir foreign rules: %v", err)
	}
	if err := os.WriteFile(foreignPath, foreign, 0o600); err != nil {
		t.Fatalf("write foreign rule: %v", err)
	}
	if err := ensureCodexExecPolicy(env); err != nil {
		t.Fatalf("ensureCodexExecPolicy: %v", err)
	}

	if err := removeCodexExecPolicy(env); err != nil {
		t.Fatalf("removeCodexExecPolicy: %v", err)
	}
	if _, err := os.Stat(codexExecPolicyPath(env)); !os.IsNotExist(err) {
		t.Fatalf("managed rule still exists after uninstall: %v", err)
	}
	got, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatalf("read foreign rule after uninstall: %v", err)
	}
	if !bytes.Equal(got, foreign) {
		t.Errorf("foreign rule changed\nwant %q\ngot  %q", foreign, got)
	}
}

func TestCodexExecPolicyUninstallPreservesLocalChanges(t *testing.T) {
	env := newCodexEnv(t)
	if err := ensureCodexExecPolicy(env); err != nil {
		t.Fatalf("ensureCodexExecPolicy: %v", err)
	}
	path := codexExecPolicyPath(env)
	local := []byte("# locally changed\n")
	if err := os.WriteFile(path, local, 0o600); err != nil {
		t.Fatalf("write local change: %v", err)
	}

	err := removeCodexExecPolicy(env)
	if err == nil || !strings.Contains(err.Error(), "preserving locally changed") {
		t.Fatalf("removeCodexExecPolicy error = %v, want preservation error", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read locally changed rule: %v", err)
	}
	if !bytes.Equal(got, local) {
		t.Errorf("locally changed rule was removed\nwant %q\ngot  %q", local, got)
	}
}

func TestCodexStatusRequiresManagedExecPolicy(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	if err := codexMergeHooksJSON(env); err != nil {
		t.Fatalf("codexMergeHooksJSON: %v", err)
	}

	status := (Codex{}).Status(env)
	if status.Installed {
		t.Fatal("Status.Installed = true without managed approval rule")
	}
	if !strings.Contains(strings.Join(status.Notes, "\n"), "approval rule") {
		t.Errorf("Status.Notes = %v, want approval-rule diagnostic", status.Notes)
	}
}
