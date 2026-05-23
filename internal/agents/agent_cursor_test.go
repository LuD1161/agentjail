package agents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// newCursorEnv builds an Env rooted at a fresh temp directory.
func newCursorEnv(t *testing.T) Env {
	t.Helper()
	home := t.TempDir()
	return Env{
		Home:    home,
		HookBin: filepath.Join(home, ".agentjail", "bin", "agentjail-hook"),
	}
}

// mkCursorDir creates ~/.cursor/ inside env.Home.
func mkCursorDir(t *testing.T, env Env) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(env.Home, ".cursor"), 0o700); err != nil {
		t.Fatalf("mkCursorDir: %v", err)
	}
}

// writeCursorHooks writes content to ~/.cursor/hooks.json with the given mode.
func writeCursorHooks(t *testing.T, env Env, content []byte, mode os.FileMode) {
	t.Helper()
	mkCursorDir(t, env)
	p := filepath.Join(env.Home, ".cursor", "hooks.json")
	if err := os.WriteFile(p, content, mode); err != nil {
		t.Fatalf("writeCursorHooks: %v", err)
	}
}

// readCursorHooksFile reads ~/.cursor/hooks.json.
func readCursorHooksFile(t *testing.T, env Env) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(env.Home, ".cursor", "hooks.json"))
	if err != nil {
		t.Fatalf("readCursorHooksFile: %v", err)
	}
	return b
}

// assertCursorEntryCount counts the number of entries with command == hookCmd
// for the given event in the hooks.json data.
func assertCursorEntryCount(t *testing.T, data []byte, event, hookCmd string, want int) {
	t.Helper()
	var root cursorHooksJSON
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("assertCursorEntryCount: unmarshal: %v", err)
	}
	count := 0
	for _, e := range root.Hooks[event] {
		if e.Command == hookCmd {
			count++
		}
	}
	if count != want {
		t.Errorf("event %q: hookCmd %q appears %d time(s), want %d\ndata: %s",
			event, hookCmd, count, want, data)
	}
}

// ---- Detect ------------------------------------------------------------------

// TestCursorDetectTrue verifies Detect returns Present=true when ~/.cursor exists.
func TestCursorDetectTrue(t *testing.T) {
	env := newCursorEnv(t)
	mkCursorDir(t, env)

	ag := Cursor{}
	d := ag.Detect(env)
	if !d.Present {
		t.Errorf("Detect.Present = false, want true")
	}
	if d.Evidence == "" {
		t.Errorf("Detect.Evidence is empty, expected a non-empty string")
	}
}

// TestCursorDetectFalse verifies Detect returns Present=false when ~/.cursor
// does NOT exist.
func TestCursorDetectFalse(t *testing.T) {
	env := newCursorEnv(t)
	// no .cursor dir created

	ag := Cursor{}
	d := ag.Detect(env)
	if d.Present {
		t.Errorf("Detect.Present = true, want false")
	}
}

// ---- Install -----------------------------------------------------------------

// TestCursorInstallWritesThreeEvents verifies that Install creates hooks.json
// with entries for all three T0-confirmed events.
func TestCursorInstallWritesThreeEvents(t *testing.T) {
	env := newCursorEnv(t)
	mkCursorDir(t, env)

	ag := Cursor{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readCursorHooksFile(t, env)

	// Verify version field.
	var root cursorHooksJSON
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if root.Version != 1 {
		t.Errorf("version = %d, want 1", root.Version)
	}

	hookCmd := cursorHookCommand(env)
	for _, event := range cursorHookEvents {
		assertCursorEntryCount(t, data, event, hookCmd, 1)
	}
}

// TestCursorInstallMatchesFixture verifies the installed hooks.json structure
// matches the shape defined in testdata/cursor_hooks_sample.json.
func TestCursorInstallMatchesFixture(t *testing.T) {
	env := newCursorEnv(t)
	// Use the same hookBin as the fixture (adjusted for env).
	mkCursorDir(t, env)

	ag := Cursor{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readCursorHooksFile(t, env)
	var root cursorHooksJSON
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Fixture shape: version=1, hooks has exactly the 3 events, each with one entry.
	if root.Version != 1 {
		t.Errorf("version = %d, want 1", root.Version)
	}
	for _, event := range []string{"beforeShellExecution", "beforeMCPExecution", "beforeReadFile"} {
		entries, ok := root.Hooks[event]
		if !ok || len(entries) == 0 {
			t.Errorf("event %q missing from hooks.json", event)
			continue
		}
		wantCmd := cursorHookCommand(env)
		if entries[0].Command != wantCmd {
			t.Errorf("event %q command = %q, want %q", event, entries[0].Command, wantCmd)
		}
	}
}

// TestCursorInstallIdempotent verifies that running Install twice leaves
// exactly one entry per event in hooks.json.
func TestCursorInstallIdempotent(t *testing.T) {
	env := newCursorEnv(t)
	mkCursorDir(t, env)
	ag := Cursor{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	if err := ag.Install(env); err != nil {
		t.Fatalf("second Install: %v", err)
	}

	data := readCursorHooksFile(t, env)
	hookCmd := cursorHookCommand(env)
	for _, event := range cursorHookEvents {
		assertCursorEntryCount(t, data, event, hookCmd, 1)
	}
}

// TestCursorInstallPreservesUserHook verifies that a pre-existing user-defined
// hook entry is preserved after Install.
func TestCursorInstallPreservesUserHook(t *testing.T) {
	env := newCursorEnv(t)
	const userCmd = "/usr/local/bin/my-custom-hook"
	initial := []byte(`{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {"command": "/usr/local/bin/my-custom-hook"}
    ]
  }
}
`)
	writeCursorHooks(t, env, initial, 0o600)

	ag := Cursor{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readCursorHooksFile(t, env)

	// Our entry should be present.
	hookCmd := cursorHookCommand(env)
	assertCursorEntryCount(t, data, "beforeShellExecution", hookCmd, 1)

	// The user's entry should still be present.
	assertCursorEntryCount(t, data, "beforeShellExecution", userCmd, 1)
}

// TestCursorInstallMalformedJSON verifies that Install returns an error and
// leaves the file byte-for-byte unchanged when hooks.json is malformed.
func TestCursorInstallMalformedJSON(t *testing.T) {
	env := newCursorEnv(t)
	malformed := []byte(`{not valid json`)
	writeCursorHooks(t, env, malformed, 0o600)

	ag := Cursor{}
	err := ag.Install(env)
	if err == nil {
		t.Fatal("Install should return an error for malformed JSON, got nil")
	}

	// File must be byte-for-byte unchanged.
	got := readCursorHooksFile(t, env)
	if string(got) != string(malformed) {
		t.Errorf("file was modified despite malformed JSON\nwant: %q\ngot:  %q", malformed, got)
	}
}

// TestCursorInstallBakOnFirstMutation verifies that a .bak file is written on
// the first mutation of an existing hooks.json, and that re-running does NOT
// overwrite the .bak.
func TestCursorInstallBakOnFirstMutation(t *testing.T) {
	env := newCursorEnv(t)
	initial := []byte(`{"version":1,"hooks":{}}` + "\n")
	writeCursorHooks(t, env, initial, 0o600)

	hooksPath := filepath.Join(env.Home, ".cursor", "hooks.json")
	bakPath := hooksPath + ".bak"

	ag := Cursor{}

	// First Install — should create .bak with the original content.
	if err := ag.Install(env); err != nil {
		t.Fatalf("first Install: %v", err)
	}

	bak, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf(".bak not created after first Install: %v", err)
	}
	if string(bak) != string(initial) {
		t.Errorf(".bak content mismatch\nwant: %q\ngot:  %q", initial, bak)
	}

	// Second Install (idempotent — should not rewrite) must not overwrite .bak.
	// Modify .bak manually to detect overwrite.
	sentinel := []byte("sentinel-do-not-overwrite")
	if err := os.WriteFile(bakPath, sentinel, 0o600); err != nil {
		t.Fatalf("write sentinel .bak: %v", err)
	}

	if err := ag.Install(env); err != nil {
		t.Fatalf("second Install: %v", err)
	}

	bak2, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("read .bak after second Install: %v", err)
	}
	if string(bak2) != string(sentinel) {
		t.Errorf(".bak was overwritten on second Install; want %q got %q", sentinel, bak2)
	}
}

// TestCursorInstallPreservesMode verifies that the file mode of an existing
// hooks.json is preserved after Install.
func TestCursorInstallPreservesMode(t *testing.T) {
	env := newCursorEnv(t)
	initial := []byte(`{"version":1,"hooks":{}}` + "\n")
	writeCursorHooks(t, env, initial, 0o600)

	ag := Cursor{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	fi, err := os.Stat(filepath.Join(env.Home, ".cursor", "hooks.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("hooks.json mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// ---- Uninstall ---------------------------------------------------------------

// TestCursorUninstallRemovesEntries verifies that Uninstall removes the
// agentjail entries for all three events.
func TestCursorUninstallRemovesEntries(t *testing.T) {
	env := newCursorEnv(t)
	mkCursorDir(t, env)
	ag := Cursor{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	data := readCursorHooksFile(t, env)
	hookCmd := cursorHookCommand(env)
	for _, event := range cursorHookEvents {
		assertCursorEntryCount(t, data, event, hookCmd, 0)
	}
}

// TestCursorUninstallIdempotent verifies that Uninstall called twice is safe.
func TestCursorUninstallIdempotent(t *testing.T) {
	env := newCursorEnv(t)
	mkCursorDir(t, env)
	ag := Cursor{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("first Uninstall: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("second Uninstall: %v", err)
	}
}

// TestCursorUninstallNoFile verifies that Uninstall is a no-op when
// hooks.json does not exist.
func TestCursorUninstallNoFile(t *testing.T) {
	env := newCursorEnv(t)
	// No .cursor dir or hooks.json.

	ag := Cursor{}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall with no file: %v", err)
	}
}

// TestCursorUninstallPreservesOtherEntries verifies that Uninstall only removes
// the agentjail entry and leaves user-defined hooks untouched.
func TestCursorUninstallPreservesOtherEntries(t *testing.T) {
	env := newCursorEnv(t)
	const userCmd = "/usr/local/bin/user-hook"
	initial := []byte(`{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {"command": "/usr/local/bin/user-hook"}
    ]
  }
}
`)
	writeCursorHooks(t, env, initial, 0o600)

	ag := Cursor{}

	// Install then uninstall agentjail hook.
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	data := readCursorHooksFile(t, env)

	// agentjail entry must be gone.
	hookCmd := cursorHookCommand(env)
	assertCursorEntryCount(t, data, "beforeShellExecution", hookCmd, 0)

	// User's entry must remain.
	assertCursorEntryCount(t, data, "beforeShellExecution", userCmd, 1)
}

// ---- Status ------------------------------------------------------------------

// TestCursorStatusInstalled verifies Status returns Installed=true after Install.
func TestCursorStatusInstalled(t *testing.T) {
	env := newCursorEnv(t)
	mkCursorDir(t, env)
	ag := Cursor{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	s := ag.Status(env)
	if !s.Installed {
		t.Errorf("Status.Installed = false after Install, want true")
	}
}

// TestCursorStatusNotInstalled verifies Status returns Installed=false when
// hooks.json is absent.
func TestCursorStatusNotInstalled(t *testing.T) {
	env := newCursorEnv(t)
	mkCursorDir(t, env)

	ag := Cursor{}
	s := ag.Status(env)
	if s.Installed {
		t.Errorf("Status.Installed = true when no hooks.json, want false")
	}
}

// TestCursorStatusAfterUninstall verifies Status returns Installed=false after
// Uninstall.
func TestCursorStatusAfterUninstall(t *testing.T) {
	env := newCursorEnv(t)
	mkCursorDir(t, env)
	ag := Cursor{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	s := ag.Status(env)
	if s.Installed {
		t.Errorf("Status.Installed = true after Uninstall, want false")
	}
}

// TestCursorStatusPartialInstall verifies that Status returns Installed=false
// when only some (not all) events have our entry.
func TestCursorStatusPartialInstall(t *testing.T) {
	env := newCursorEnv(t)
	hookCmd := cursorHookCommand(env)

	// Write hooks.json with only one of the three events.
	partial := map[string]interface{}{
		"version": 1,
		"hooks": map[string]interface{}{
			"beforeShellExecution": []map[string]interface{}{
				{"command": hookCmd},
			},
			// beforeMCPExecution and beforeReadFile are absent
		},
	}
	b, _ := json.MarshalIndent(partial, "", "  ")
	writeCursorHooks(t, env, append(b, '\n'), 0o600)

	ag := Cursor{}
	s := ag.Status(env)
	if s.Installed {
		t.Errorf("Status.Installed = true for partial install, want false")
	}
}
