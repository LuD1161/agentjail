package agents

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestEnsureHookRegistered_RestoresRemovedHook verifies that when the
// agentjail hook entry has been removed from an otherwise-populated
// settings.json, EnsureHookRegistered restores it and reports changed=true,
// while preserving unrelated keys already in the file (P11 acceptance
// criterion 1).
func TestEnsureHookRegistered_RestoresRemovedHook(t *testing.T) {
	env := newClaudeEnv(t)
	writeSettings(t, env, []byte(`{
  "someOtherSetting": "keep-me",
  "hooks": {
    "PreToolUse": []
  }
}`))

	changed, err := EnsureHookRegistered(ClaudeCode{}, env)
	if err != nil {
		t.Fatalf("EnsureHookRegistered returned error: %v", err)
	}
	if !changed {
		t.Errorf("changed = false, want true (hook was missing)")
	}

	data := readSettings(t, env)
	assertEntryCount(t, data, env.HookBin, 1)

	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal restored settings: %v", err)
	}
	if root["someOtherSetting"] != "keep-me" {
		t.Errorf("someOtherSetting = %v, want %q (must be preserved)", root["someOtherSetting"], "keep-me")
	}
}

// TestEnsureHookRegistered_NoopWhenAlreadyCorrect verifies idempotency: when
// the hook is already correctly registered, EnsureHookRegistered reports
// changed=false and leaves the file byte-for-byte unchanged (P11 acceptance
// criterion 2).
func TestEnsureHookRegistered_NoopWhenAlreadyCorrect(t *testing.T) {
	env := newClaudeEnv(t)

	// First call installs the hook.
	if _, err := EnsureHookRegistered(ClaudeCode{}, env); err != nil {
		t.Fatalf("first EnsureHookRegistered: %v", err)
	}
	before := readSettings(t, env)

	// Second call should be a pure no-op.
	changed, err := EnsureHookRegistered(ClaudeCode{}, env)
	if err != nil {
		t.Fatalf("second EnsureHookRegistered: %v", err)
	}
	if changed {
		t.Errorf("changed = true on second call, want false (already correct)")
	}

	after := readSettings(t, env)
	if string(before) != string(after) {
		t.Errorf("settings.json mutated on a no-op call:\nbefore: %s\nafter:  %s", before, after)
	}
}

// TestEnsureHookRegistered_CreatesFileWhenAbsent verifies that with no
// settings file at all, EnsureHookRegistered creates one containing just the
// hook (P11 acceptance criterion 3).
func TestEnsureHookRegistered_CreatesFileWhenAbsent(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)

	settingsPath := filepath.Join(env.Home, ".claude", "settings.json")
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		t.Fatalf("settings.json unexpectedly exists before test")
	}

	changed, err := EnsureHookRegistered(ClaudeCode{}, env)
	if err != nil {
		t.Fatalf("EnsureHookRegistered returned error: %v", err)
	}
	if !changed {
		t.Errorf("changed = false, want true (no file existed)")
	}

	data := readSettings(t, env)
	assertEntryCount(t, data, env.HookBin, 1)
}

// TestEnsureHookRegistered_CodexRestoresRemovedHook exercises the same
// restore-when-missing behavior for the Codex agent, which uses a different
// on-disk shape (~/.codex/hooks.json) than Claude Code, to confirm
// EnsureHookRegistered works generically across Agent implementations.
func TestEnsureHookRegistered_CodexRestoresRemovedHook(t *testing.T) {
	home := t.TempDir()
	env := Env{Home: home, HookBin: filepath.Join(home, ".agentjail", "bin", "agentjail-hook")}

	// Install once, then blow away the hooks.json entry to simulate tampering.
	if err := (Codex{}).Install(env); err != nil {
		t.Fatalf("initial Codex Install: %v", err)
	}
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatalf("simulate tamper: %v", err)
	}

	changed, err := EnsureHookRegistered(Codex{}, env)
	if err != nil {
		t.Fatalf("EnsureHookRegistered: %v", err)
	}
	if !changed {
		t.Errorf("changed = false, want true (hook was removed)")
	}

	status := (Codex{}).Status(env)
	if !status.Installed {
		t.Errorf("Codex Status.Installed = false after EnsureHookRegistered, want true")
	}
}

func TestEnsureHookRegistered_CodexDoesNotPrintInstallGuidance(t *testing.T) {
	home := t.TempDir()
	env := Env{Home: home, HookBin: filepath.Join(home, ".agentjail", "bin", "agentjail-hook")}

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = writePipe
	_, ensureErr := EnsureHookRegistered(Codex{}, env)
	_ = writePipe.Close()
	os.Stdout = originalStdout
	output, readErr := io.ReadAll(readPipe)
	_ = readPipe.Close()
	if ensureErr != nil {
		t.Fatal(ensureErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(output) != 0 {
		t.Fatalf("launch-time Codex hook reassertion printed setup guidance: %q", output)
	}
}
