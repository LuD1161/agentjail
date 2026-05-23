package agents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// newClaudeEnv builds an Env rooted at a fresh temp directory.
func newClaudeEnv(t *testing.T) Env {
	t.Helper()
	home := t.TempDir()
	return Env{
		Home:    home,
		HookBin: filepath.Join(home, ".agentjail", "bin", "agentjail-hook"),
	}
}

// mkClaudeDir creates ~/.claude/ inside env.Home.
func mkClaudeDir(t *testing.T, env Env) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(env.Home, ".claude"), 0o700); err != nil {
		t.Fatalf("mkClaudeDir: %v", err)
	}
}

// writeSettings writes content to ~/.claude/settings.json with mode 0600.
func writeSettings(t *testing.T, env Env, content []byte) {
	t.Helper()
	mkClaudeDir(t, env)
	p := filepath.Join(env.Home, ".claude", "settings.json")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}
}

// readSettings reads ~/.claude/settings.json.
func readSettings(t *testing.T, env Env) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(env.Home, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("readSettings: %v", err)
	}
	return b
}

// assertEntryCount counts how many times hookCmd appears in PreToolUse.
func assertEntryCount(t *testing.T, data []byte, hookCmd string, want int) {
	t.Helper()
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("assertEntryCount: unmarshal: %v", err)
	}
	hooks, _ := root["hooks"].(map[string]interface{})
	if hooks == nil && want == 0 {
		return
	}
	ptu, _ := hooks["PreToolUse"].([]interface{})
	count := 0
	for _, entry := range ptu {
		em, _ := entry.(map[string]interface{})
		if em == nil {
			continue
		}
		if claudeEntryHasCommand(em, hookCmd) {
			count++
		}
	}
	if count != want {
		t.Errorf("assertEntryCount: hookCmd %q appears %d times, want %d\ndata: %s",
			hookCmd, count, want, data)
	}
}

// ---- Detect -----------------------------------------------------------------

// TestClaudeDetectTrue verifies Detect returns Present=true when ~/.claude exists.
func TestClaudeDetectTrue(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)

	ag := ClaudeCode{}
	d := ag.Detect(env)
	if !d.Present {
		t.Errorf("Detect.Present = false, want true")
	}
	if d.Evidence == "" {
		t.Errorf("Detect.Evidence is empty, expected a non-empty string")
	}
}

// TestClaudeDetectFalse verifies Detect returns Present=false when ~/.claude
// does NOT exist.
func TestClaudeDetectFalse(t *testing.T) {
	env := newClaudeEnv(t) // temp dir exists, but no .claude subdir

	ag := ClaudeCode{}
	d := ag.Detect(env)
	if d.Present {
		t.Errorf("Detect.Present = true, want false")
	}
}

// ---- Install ----------------------------------------------------------------

// TestClaudeInstallAddsEntry verifies that Install creates settings.json with
// the hook entry when the file does not yet exist.
func TestClaudeInstallAddsEntry(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)

	ag := ClaudeCode{}
	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readSettings(t, env)
	assertEntryCount(t, data, env.HookBin, 1)
}

// TestClaudeInstallIdempotent verifies that running Install twice leaves
// exactly one entry in settings.json.
func TestClaudeInstallIdempotent(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)
	ag := ClaudeCode{}

	err := ag.Install(env)
	if err != nil {
		t.Fatalf("first Install: %v", err)
	}
	err = ag.Install(env)
	if err != nil {
		t.Fatalf("second Install: %v", err)
	}

	data := readSettings(t, env)
	assertEntryCount(t, data, env.HookBin, 1)
}

// TestClaudeInstallPreservesUnknownKeys verifies that existing top-level keys
// in settings.json survive a round-trip through Install.
func TestClaudeInstallPreservesUnknownKeys(t *testing.T) {
	env := newClaudeEnv(t)
	writeSettings(t, env, []byte(`{"theme":"dark","fontSize":14}`))

	ag := ClaudeCode{}
	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readSettings(t, env)

	var root map[string]interface{}
	if err2 := json.Unmarshal(data, &root); err2 != nil {
		t.Fatalf("unmarshal result: %v", err2)
	}
	if root["theme"] != "dark" {
		t.Errorf("theme key lost: got %v", root["theme"])
	}
	if root["fontSize"] == nil {
		t.Errorf("fontSize key lost")
	}
}

// TestClaudeInstallMalformedJSON verifies that Install returns an error and
// leaves the file byte-for-byte unchanged when settings.json contains
// malformed JSON.
func TestClaudeInstallMalformedJSON(t *testing.T) {
	env := newClaudeEnv(t)
	malformed := []byte(`{not valid json`)
	writeSettings(t, env, malformed)

	ag := ClaudeCode{}
	err := ag.Install(env)
	if err == nil {
		t.Fatal("Install should return an error for malformed JSON, got nil")
	}

	// File must be byte-for-byte unchanged.
	got := readSettings(t, env)
	if string(got) != string(malformed) {
		t.Errorf("file was modified despite malformed JSON\nwant: %q\ngot:  %q", malformed, got)
	}
}

// TestClaudeInstallMode verifies that settings.json is written with mode 0600
// when the file is created fresh.
func TestClaudeInstallMode(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)

	ag := ClaudeCode{}
	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	fi, err := os.Stat(filepath.Join(env.Home, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("settings.json mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// TestClaudeInstallPreservesMode verifies that if settings.json already exists
// with mode 0600, the mode is preserved after Install.
func TestClaudeInstallPreservesMode(t *testing.T) {
	env := newClaudeEnv(t)
	writeSettings(t, env, []byte(`{}`)) // written with 0600 via writeSettings

	ag := ClaudeCode{}
	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	fi, err := os.Stat(filepath.Join(env.Home, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("settings.json mode = %04o after Install, want 0600", fi.Mode().Perm())
	}
}

// ---- Uninstall --------------------------------------------------------------

// TestClaudeUninstallRemovesEntry verifies that Uninstall removes the hook
// entry from settings.json.
func TestClaudeUninstallRemovesEntry(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)
	ag := ClaudeCode{}

	// Install first.
	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	// Now uninstall.
	err = ag.Uninstall(env)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	data := readSettings(t, env)
	assertEntryCount(t, data, env.HookBin, 0)
}

// TestClaudeUninstallIdempotent verifies that Uninstall is idempotent: running
// it twice returns nil and makes no change.
func TestClaudeUninstallIdempotent(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)
	ag := ClaudeCode{}

	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	err = ag.Uninstall(env)
	if err != nil {
		t.Fatalf("first Uninstall: %v", err)
	}
	err = ag.Uninstall(env)
	if err != nil {
		t.Fatalf("second Uninstall: %v", err)
	}

	data := readSettings(t, env)
	assertEntryCount(t, data, env.HookBin, 0)
}

// TestClaudeUninstallNoFile verifies that Uninstall is a no-op when
// settings.json does not exist.
func TestClaudeUninstallNoFile(t *testing.T) {
	env := newClaudeEnv(t)
	// Do NOT create ~/.claude or settings.json.

	ag := ClaudeCode{}
	err := ag.Uninstall(env)
	if err != nil {
		t.Fatalf("Uninstall with no file: %v", err)
	}
}

// TestClaudeUninstallPreservesOtherEntries verifies that Uninstall only
// removes the agentjail entry and leaves other PreToolUse entries intact.
func TestClaudeUninstallPreservesOtherEntries(t *testing.T) {
	env := newClaudeEnv(t)
	const otherCmd = "/usr/local/bin/other-hook"
	initial := []byte(`{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "/usr/local/bin/other-hook"}]
      }
    ]
  }
}`)
	writeSettings(t, env, initial)

	ag := ClaudeCode{}

	// Install agentjail hook alongside the existing one.
	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	// Uninstall agentjail hook only.
	err = ag.Uninstall(env)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	data := readSettings(t, env)

	// agentjail hook must be gone.
	assertEntryCount(t, data, env.HookBin, 0)

	// Other hook must still be present.
	var root map[string]interface{}
	if err2 := json.Unmarshal(data, &root); err2 != nil {
		t.Fatalf("unmarshal: %v", err2)
	}
	hooks, _ := root["hooks"].(map[string]interface{})
	ptu, _ := hooks["PreToolUse"].([]interface{})
	found := false
	for _, entry := range ptu {
		em, _ := entry.(map[string]interface{})
		if claudeEntryHasCommand(em, otherCmd) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("other hook %q was removed by Uninstall", otherCmd)
	}
}

// ---- Status -----------------------------------------------------------------

// TestClaudeStatusInstalled verifies Status returns Installed=true after Install.
func TestClaudeStatusInstalled(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)
	ag := ClaudeCode{}

	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	s := ag.Status(env)
	if !s.Installed {
		t.Errorf("Status.Installed = false after Install, want true")
	}
}

// TestClaudeStatusNotInstalled verifies Status returns Installed=false when
// the hook entry is not present.
func TestClaudeStatusNotInstalled(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)
	// settings.json not created — hook is absent.

	ag := ClaudeCode{}
	s := ag.Status(env)
	if s.Installed {
		t.Errorf("Status.Installed = true when no settings.json, want false")
	}
}

// TestClaudeStatusAfterUninstall verifies Status returns Installed=false after
// Uninstall.
func TestClaudeStatusAfterUninstall(t *testing.T) {
	env := newClaudeEnv(t)
	mkClaudeDir(t, env)
	ag := ClaudeCode{}

	err := ag.Install(env)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	err = ag.Uninstall(env)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	s := ag.Status(env)
	if s.Installed {
		t.Errorf("Status.Installed = true after Uninstall, want false")
	}
}
