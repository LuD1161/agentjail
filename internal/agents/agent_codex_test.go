package agents

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- test helpers ------------------------------------------------------------

// newCodexEnv builds an Env rooted at a fresh temp directory.
func newCodexEnv(t *testing.T) Env {
	t.Helper()
	home := t.TempDir()
	return Env{
		Home:    home,
		HookBin: filepath.Join(home, ".agentjail", "bin", "agentjail-hook"),
	}
}

// mkCodexDir creates ~/.codex/ inside env.Home.
func mkCodexDir(t *testing.T, env Env) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(env.Home, ".codex"), 0o700); err != nil {
		t.Fatalf("mkCodexDir: %v", err)
	}
}

// writeHooksJSON writes content to ~/.codex/hooks.json with mode 0600.
func writeHooksJSON(t *testing.T, env Env, content []byte) {
	t.Helper()
	mkCodexDir(t, env)
	p := filepath.Join(env.Home, ".codex", "hooks.json")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("writeHooksJSON: %v", err)
	}
}

// readHooksJSON reads ~/.codex/hooks.json.
func readHooksJSON(t *testing.T, env Env) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(env.Home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatalf("readHooksJSON: %v", err)
	}
	return b
}

// writeConfigTOML writes content to ~/.codex/config.toml.
func writeConfigTOML(t *testing.T, env Env, content string, mode os.FileMode) {
	t.Helper()
	mkCodexDir(t, env)
	p := filepath.Join(env.Home, ".codex", "config.toml")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatalf("writeConfigTOML: %v", err)
	}
}

// readConfigTOML reads ~/.codex/config.toml as a string.
func readConfigTOML(t *testing.T, env Env) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(env.Home, ".codex", "config.toml"))
	if err != nil {
		t.Fatalf("readConfigTOML: %v", err)
	}
	return string(b)
}

// codexHookEntryCount counts how many PreToolUse matcher groups in hooks.json
// have hookCmd as one of their hook commands.
func codexHookEntryCount(t *testing.T, data []byte, hookCmd string) int {
	t.Helper()
	var root codexHooksRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("codexHookEntryCount: unmarshal: %v", err)
	}
	count := 0
	for _, g := range root.Hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if h.Command == hookCmd {
				count++
			}
		}
	}
	return count
}

// ---- Detect ------------------------------------------------------------------

// TestCodexDetectViaDir verifies Detect returns Present=true when ~/.codex/ exists.
func TestCodexDetectViaDir(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)

	ag := Codex{}
	d := ag.Detect(env)
	if !d.Present {
		t.Errorf("Detect.Present = false, want true (via dir)")
	}
	if !strings.Contains(d.Evidence, ".codex") {
		t.Errorf("Detect.Evidence %q should mention .codex", d.Evidence)
	}
}

// TestCodexDetectFalseNoDir verifies Detect returns Present=false when
// neither ~/.codex/ nor the binary exists.
func TestCodexDetectFalseNoDir(t *testing.T) {
	env := newCodexEnv(t)
	// No .codex dir; LookPath always fails.
	env.LookPath = func(name string) (string, error) {
		return "", errors.New("not found")
	}

	ag := Codex{}
	d := ag.Detect(env)
	if d.Present {
		t.Errorf("Detect.Present = true, want false")
	}
}

// TestCodexDetectViaLookPath verifies Detect returns Present=true when codex
// is found via an injected LookPath (no .codex dir required).
func TestCodexDetectViaLookPath(t *testing.T) {
	env := newCodexEnv(t)
	// No .codex dir.
	env.LookPath = func(name string) (string, error) {
		if name == "codex" {
			return "/usr/local/bin/codex", nil
		}
		return "", errors.New("not found")
	}

	ag := Codex{}
	d := ag.Detect(env)
	if !d.Present {
		t.Errorf("Detect.Present = false, want true (via LookPath)")
	}
	if !strings.Contains(d.Evidence, "/usr/local/bin/codex") {
		t.Errorf("Detect.Evidence %q should contain binary path", d.Evidence)
	}
}

// ---- Install: hooks.json -----------------------------------------------------

// TestCodexInstallCreatesHooksJSON verifies that Install creates hooks.json
// with the correct schema when the file does not yet exist.
func TestCodexInstallCreatesHooksJSON(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)

	ag := Codex{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readHooksJSON(t, env)

	// Verify schema.
	var root codexHooksRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("hooks.json is invalid JSON: %v\ncontent: %s", err, data)
	}
	groups := root.Hooks["PreToolUse"]
	if len(groups) == 0 {
		t.Fatalf("hooks.json has no PreToolUse groups")
	}
	wantCmd := env.HookBin + " --agent=codex"
	count := codexHookEntryCount(t, data, wantCmd)
	if count != 1 {
		t.Errorf("agentjail entry appears %d times, want 1", count)
	}

	// Verify the hook type is "command" and timeout is set.
	found := false
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Command == wantCmd {
				if h.Type != "command" {
					t.Errorf("hook type = %q, want \"command\"", h.Type)
				}
				if h.Timeout != 30 {
					t.Errorf("hook timeout = %d, want 30", h.Timeout)
				}
				if g.Matcher != ".*" {
					t.Errorf("hook matcher = %q, want \".*\"", g.Matcher)
				}
				found = true
			}
		}
	}
	if !found {
		t.Errorf("agentjail hook entry not found in hooks.json")
	}
}

// TestCodexInstallPreservesExistingUserHook verifies that a pre-existing user
// hook entry is preserved when Install merges the agentjail entry.
func TestCodexInstallPreservesExistingUserHook(t *testing.T) {
	env := newCodexEnv(t)
	const userCmd = "/usr/local/bin/my-custom-hook"
	initial := []byte(`{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/my-custom-hook",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
`)
	writeHooksJSON(t, env, initial)

	ag := Codex{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readHooksJSON(t, env)

	// agentjail entry present (new --agent=codex form).
	if codexHookEntryCount(t, data, env.HookBin+" --agent=codex") != 1 {
		t.Errorf("agentjail entry not found after Install")
	}

	// User hook still present.
	if codexHookEntryCount(t, data, userCmd) != 1 {
		t.Errorf("user hook %q lost after Install", userCmd)
	}
}

// TestCodexInstallIdempotent verifies that running Install twice leaves exactly
// one agentjail entry in hooks.json.
func TestCodexInstallIdempotent(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	if err := ag.Install(env); err != nil {
		t.Fatalf("second Install: %v", err)
	}

	data := readHooksJSON(t, env)
	count := codexHookEntryCount(t, data, env.HookBin+" --agent=codex")
	if count != 1 {
		t.Errorf("agentjail entry appears %d times after two Installs, want 1", count)
	}
}

// TestCodexInstallMalformedHooksJSON verifies that Install returns an error and
// leaves the file byte-for-byte unchanged when hooks.json is malformed.
func TestCodexInstallMalformedHooksJSON(t *testing.T) {
	env := newCodexEnv(t)
	malformed := []byte(`{not valid json`)
	writeHooksJSON(t, env, malformed)

	ag := Codex{}
	err := ag.Install(env)
	if err == nil {
		t.Fatal("Install should return an error for malformed hooks.json")
	}

	// File must be byte-for-byte unchanged.
	got := readHooksJSON(t, env)
	if string(got) != string(malformed) {
		t.Errorf("hooks.json was modified despite malformed JSON\nwant: %q\ngot:  %q",
			malformed, got)
	}
}

// TestCodexInstallMalformedConfigTOML verifies that a malformed/truncated
// config.toml (e.g. a "[features" header with no closing bracket) is treated as
// ambiguous: Install does NOT error (hooks.json still wires), but config.toml is
// left byte-for-byte unchanged and Status reports the config-ambiguous note.
func TestCodexInstallMalformedConfigTOML(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)

	// Truncated table header — not valid TOML, and not a complete [features].
	malformed := "[features\nhooks = true\n"
	writeConfigTOML(t, env, malformed, 0o644)

	ag := Codex{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install should not error on ambiguous config.toml, got: %v", err)
	}

	// config.toml must be byte-for-byte unchanged.
	got, err := os.ReadFile(filepath.Join(env.Home, ".codex", "config.toml"))
	if err != nil {
		t.Fatalf("read config.toml: %v", err)
	}
	if string(got) != malformed {
		t.Errorf("config.toml was modified despite malformed content\nwant: %q\ngot:  %q",
			malformed, got)
	}

	// Status should surface the config.toml-specific ambiguous note.
	st := ag.Status(env)
	foundAmbiguous := false
	for _, n := range st.Notes {
		if strings.Contains(n, "config.toml") && strings.Contains(n, "ambiguous") {
			foundAmbiguous = true
		}
	}
	if !foundAmbiguous {
		t.Errorf("Status notes missing config.toml ambiguous note; got %v", st.Notes)
	}
}

// TestCodexTomlEnsureHooksMalformedHeader verifies the scanner reports ambiguity
// (and proposes no mutation) for a truncated table header.
func TestCodexTomlEnsureHooksMalformedHeader(t *testing.T) {
	mutated, ambiguous, reason := codexTomlEnsureHooks([]byte("[features\nhooks = true\n"))
	if !ambiguous {
		t.Errorf("expected ambiguous=true for truncated header, got false (reason=%q)", reason)
	}
	if mutated != nil {
		t.Errorf("expected no mutation for ambiguous input, got %q", mutated)
	}
}

// TestCodexInstallHooksJSONMode verifies that hooks.json is written with mode
// 0600 when created fresh, and that the mode is preserved on subsequent writes.
func TestCodexInstallHooksJSONMode(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)

	ag := Codex{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	fi, err := os.Stat(filepath.Join(env.Home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("hooks.json mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// TestCodexInstallHooksJSONBak verifies that a .bak file is created on the
// first mutation of an existing hooks.json.
func TestCodexInstallHooksJSONBak(t *testing.T) {
	env := newCodexEnv(t)
	initial := []byte(`{"hooks":{"PreToolUse":[]}}` + "\n")
	writeHooksJSON(t, env, initial)

	ag := Codex{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	bakPath := filepath.Join(env.Home, ".codex", "hooks.json.bak")
	bak, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("hooks.json.bak not created: %v", err)
	}
	if string(bak) != string(initial) {
		t.Errorf("hooks.json.bak content mismatch\nwant: %q\ngot:  %q", initial, bak)
	}

	// Second install must NOT overwrite the .bak.
	if err := ag.Install(env); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	bak2, _ := os.ReadFile(bakPath)
	if string(bak2) != string(bak) {
		t.Errorf(".bak was overwritten by second Install")
	}
}

// ---- Install: config.toml strict safe-mode -----------------------------------

// tomlSafeCase describes one config.toml strict safe-mode test case.
type tomlSafeCase struct {
	name          string
	input         string // "" means absent file
	wantSubstring string // must be present in resulting file (safe cases)
	wantUnchanged bool   // true means file must be byte-for-byte unchanged (ambiguous)
	wantDegraded  bool   // true means Status must have degraded note
}

// TestCodexConfigTOMLStrictSafeMode is the definitive table test covering
// every safe and ambiguous config.toml case.
func TestCodexConfigTOMLStrictSafeMode(t *testing.T) {
	cases := []tomlSafeCase{
		// -----------------------------------------------------------------------
		// SAFE CASES — file should be mutated correctly
		// -----------------------------------------------------------------------
		{
			name:          "absent_file_created",
			input:         "", // absent
			wantSubstring: "[features]\nhooks = true\n",
		},
		{
			name:          "empty_file_created",
			input:         "   \n  \n",
			wantSubstring: "[features]\nhooks = true\n",
		},
		{
			name: "clean_features_no_hooks_inserted",
			input: `model = "gpt-4o"

[features]
shell = true
`,
			wantSubstring: "hooks = true",
		},
		{
			name: "no_features_table_appended",
			input: `model = "gpt-4o"

[projects."/foo"]
trust_level = "trusted"
`,
			wantSubstring: "[features]\nhooks = true\n",
		},
		{
			name: "already_hooks_true_no_change",
			input: `[features]
hooks = true
`,
			// File should not be mutated (no change needed).
			// We verify by checking no .bak is created (file unchanged).
			wantSubstring: "[features]\nhooks = true\n",
			wantUnchanged: true,
		},

		// -----------------------------------------------------------------------
		// AMBIGUOUS CASES — file must be byte-for-byte unchanged + degraded note
		// -----------------------------------------------------------------------
		{
			name: "existing_hooks_false_unchanged",
			input: `[features]
hooks = false
`,
			wantUnchanged: true,
			wantDegraded:  true,
		},
		{
			name: "existing_hooks_other_value_unchanged",
			input: `[features]
hooks = "maybe"
`,
			wantUnchanged: true,
			wantDegraded:  true,
		},
		{
			name: "duplicate_features_tables_unchanged",
			input: `[features]
shell = true

[other]
x = 1

[features]
network = true
`,
			wantUnchanged: true,
			wantDegraded:  true,
		},
		{
			name:          "inline_table_unchanged",
			input:         "features = {hooks = true}\n",
			wantUnchanged: true,
			wantDegraded:  true,
		},
		{
			name:          "inline_table_no_hooks_unchanged",
			input:         "features = {shell = true}\n",
			wantUnchanged: true,
			wantDegraded:  true,
		},
		{
			name:          "array_of_tables_unchanged",
			input:         "[[features]]\nhooks = false\n",
			wantUnchanged: true,
			wantDegraded:  true,
		},
		{
			name: "multiline_value_in_features_unchanged",
			input: `[features]
description = "line one \
line two"
`,
			wantUnchanged: true,
			wantDegraded:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newCodexEnv(t)
			mkCodexDir(t, env)

			tomlPath := filepath.Join(env.Home, ".codex", "config.toml")

			// Write input file (or leave absent if input == "").
			var originalBytes []byte
			if tc.input != "" {
				originalBytes = []byte(tc.input)
				if err := os.WriteFile(tomlPath, originalBytes, 0o644); err != nil {
					t.Fatalf("write toml: %v", err)
				}
			}

			ag := Codex{}
			// We only test config.toml handling; call codexEnsureFeaturesHooks directly.
			err := codexEnsureFeaturesHooks(env)
			if err != nil {
				t.Fatalf("codexEnsureFeaturesHooks: %v", err)
			}

			// For absent file case, check file was created.
			if tc.input == "" {
				got := readConfigTOML(t, env)
				if !strings.Contains(got, tc.wantSubstring) {
					t.Errorf("created file missing %q\ngot: %q", tc.wantSubstring, got)
				}
				return
			}

			got := readConfigTOML(t, env)

			if tc.wantUnchanged && !tc.wantDegraded {
				// "already_hooks_true" — file is either unchanged or has same content.
				if !strings.Contains(got, tc.wantSubstring) {
					t.Errorf("file missing %q\ngot: %q", tc.wantSubstring, got)
				}
				// Verify no .bak was created (unchanged → no mutation).
				bakPath := tomlPath + ".bak"
				if _, err2 := os.Stat(bakPath); err2 == nil {
					t.Errorf(".bak created even though file was already correct (no mutation expected)")
				}
				return
			}

			if tc.wantUnchanged && tc.wantDegraded {
				// Ambiguous case — file must be byte-for-byte unchanged.
				if got != string(originalBytes) {
					t.Errorf("ambiguous case: file was modified\nwant (unchanged): %q\ngot: %q",
						originalBytes, got)
				}
				// No .bak should be created for ambiguous cases (no mutation).
				bakPath := tomlPath + ".bak"
				if _, err2 := os.Stat(bakPath); err2 == nil {
					t.Errorf(".bak created for ambiguous case (no mutation should have occurred)")
				}
				// Verify degraded status note.
				s := ag.Status(env)
				hasTrustNote := false
				for _, n := range s.Notes {
					if n == codexTrustDegradedNote {
						hasTrustNote = true
					}
				}
				if !hasTrustNote {
					t.Errorf("Status.Notes missing trust degraded note %q, got %v",
						codexTrustDegradedNote, s.Notes)
				}
				return
			}

			// Safe mutation case.
			if !strings.Contains(got, tc.wantSubstring) {
				t.Errorf("safe case: file missing %q\ngot: %q", tc.wantSubstring, got)
			}
		})
	}
}

// TestCodexConfigTOMLIdempotent verifies that running Install twice on a
// config.toml that gets mutated on the first run does not duplicate anything.
func TestCodexConfigTOMLIdempotent(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	// Start with no config.toml.
	ag := Codex{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	got1 := readConfigTOML(t, env)

	if err := ag.Install(env); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	got2 := readConfigTOML(t, env)

	// Count occurrences of "hooks = true" — must be exactly 1.
	count := strings.Count(got2, "hooks = true")
	if count != 1 {
		t.Errorf("'hooks = true' appears %d times after two Installs, want 1\nfile:\n%s", count, got2)
	}

	// Content should be stable after the second run.
	if got1 != got2 {
		t.Errorf("config.toml changed between first and second Install\nafter 1: %q\nafter 2: %q",
			got1, got2)
	}
}

// TestCodexConfigTOMLInsertedIntoCleanFeatures verifies the specific case where
// [features] exists without hooks — hooks = true is inserted after the header.
func TestCodexConfigTOMLInsertedIntoCleanFeatures(t *testing.T) {
	env := newCodexEnv(t)
	input := "model = \"gpt-4o\"\n\n[features]\nshell = true\n"
	writeConfigTOML(t, env, input, 0o644)

	if err := codexEnsureFeaturesHooks(env); err != nil {
		t.Fatalf("codexEnsureFeaturesHooks: %v", err)
	}

	got := readConfigTOML(t, env)
	if !strings.Contains(got, "hooks = true") {
		t.Errorf("hooks = true not inserted\ngot: %q", got)
	}
	// Verify shell = true is still present (other keys preserved).
	if !strings.Contains(got, "shell = true") {
		t.Errorf("shell = true was lost\ngot: %q", got)
	}
	// Verify model key is preserved.
	if !strings.Contains(got, "model = \"gpt-4o\"") {
		t.Errorf("model key was lost\ngot: %q", got)
	}
}

// TestCodexConfigTOMLModePreserved verifies that config.toml mode is preserved
// when the file is mutated by codexEnsureFeaturesHooks.
func TestCodexConfigTOMLModePreserved(t *testing.T) {
	env := newCodexEnv(t)
	writeConfigTOML(t, env, "[other]\nkey = 1\n", 0o640)

	if err := codexEnsureFeaturesHooks(env); err != nil {
		t.Fatalf("codexEnsureFeaturesHooks: %v", err)
	}

	fi, err := os.Stat(filepath.Join(env.Home, ".codex", "config.toml"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("config.toml mode = %04o, want 0640", fi.Mode().Perm())
	}
}

// ---- Uninstall ---------------------------------------------------------------

// TestCodexUninstallRemovesEntry verifies that Uninstall removes the agentjail
// hooks.json entry.
func TestCodexUninstallRemovesEntry(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	data := readHooksJSON(t, env)
	count := codexHookEntryCount(t, data, env.HookBin+" --agent=codex")
	if count != 0 {
		t.Errorf("agentjail entry still present after Uninstall (count=%d)", count)
	}
}

// TestCodexUninstallIdempotent verifies that Uninstall is idempotent.
func TestCodexUninstallIdempotent(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("first Uninstall: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("second Uninstall: %v", err)
	}

	data := readHooksJSON(t, env)
	if codexHookEntryCount(t, data, env.HookBin+" --agent=codex") != 0 {
		t.Errorf("agentjail entry present after two Uninstalls")
	}
}

// TestCodexUninstallNoFile verifies Uninstall is a no-op when hooks.json
// does not exist.
func TestCodexUninstallNoFile(t *testing.T) {
	env := newCodexEnv(t)

	ag := Codex{}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall with no file: %v", err)
	}
}

// TestCodexUninstallPreservesUserHook verifies that Uninstall only removes the
// agentjail entry and leaves other PreToolUse entries intact.
func TestCodexUninstallPreservesUserHook(t *testing.T) {
	env := newCodexEnv(t)
	const userCmd = "/usr/local/bin/my-custom-hook"
	initial := []byte(`{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "/usr/local/bin/my-custom-hook"}]
      }
    ]
  }
}
`)
	writeHooksJSON(t, env, initial)

	ag := Codex{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	data := readHooksJSON(t, env)
	if codexHookEntryCount(t, data, env.HookBin+" --agent=codex") != 0 {
		t.Errorf("agentjail hook still present after Uninstall")
	}
	if codexHookEntryCount(t, data, userCmd) != 1 {
		t.Errorf("user hook %q lost after Uninstall", userCmd)
	}
}

// TestCodexUninstallMalformedHooksJSON verifies that Uninstall returns an error
// and leaves the file unchanged when hooks.json is malformed.
func TestCodexUninstallMalformedHooksJSON(t *testing.T) {
	env := newCodexEnv(t)
	malformed := []byte(`{bad json`)
	writeHooksJSON(t, env, malformed)

	ag := Codex{}
	err := ag.Uninstall(env)
	if err == nil {
		t.Fatal("Uninstall should error on malformed hooks.json")
	}

	got := readHooksJSON(t, env)
	if string(got) != string(malformed) {
		t.Errorf("hooks.json was modified despite malformed JSON")
	}
}

// ---- Status ------------------------------------------------------------------

// TestCodexStatusTrustDegradedNote verifies that Status always includes the
// trust degraded note regardless of other state.
func TestCodexStatusTrustDegradedNote(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	// Even with no hooks.json, trust note must appear.
	s := ag.Status(env)
	found := false
	for _, n := range s.Notes {
		if n == codexTrustDegradedNote {
			found = true
		}
	}
	if !found {
		t.Errorf("Status.Notes missing %q, got %v", codexTrustDegradedNote, s.Notes)
	}
}

// TestCodexStatusAfterInstall verifies that Status reports Installed=true after
// Install and still includes the trust degraded note.
func TestCodexStatusAfterInstall(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	s := ag.Status(env)
	if !s.Installed {
		t.Errorf("Status.Installed = false after Install, want true")
	}

	trustFound := false
	for _, n := range s.Notes {
		if n == codexTrustDegradedNote {
			trustFound = true
		}
	}
	if !trustFound {
		t.Errorf("Status.Notes missing trust note after Install, got %v", s.Notes)
	}
}

// TestCodexStatusAfterUninstall verifies that Status reports Installed=false
// after Uninstall.
func TestCodexStatusAfterUninstall(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

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

// TestCodexStatusIndependentComponents verifies that Status reports hooks.json
// and features.hooks independently.
func TestCodexStatusIndependentComponents(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	// Install hook but leave config.toml absent.
	if err := codexMergeHooksJSON(env); err != nil {
		t.Fatalf("codexMergeHooksJSON: %v", err)
	}
	// Don't call codexEnsureFeaturesHooks.

	s := ag.Status(env)

	// hooks.json entry present → Installed should be true.
	if !s.Installed {
		t.Errorf("Status.Installed = false even though hooks.json entry is present")
	}

	// features.hooks status note should mention config.toml unknown/absent.
	hasTomlNote := false
	for _, n := range s.Notes {
		if strings.Contains(n, "config.toml") {
			hasTomlNote = true
		}
	}
	if !hasTomlNote {
		t.Errorf("Status.Notes should mention config.toml absent, got %v", s.Notes)
	}
}

// TestCodexStatusNoHooksJSON verifies that Status reports not installed when
// hooks.json is missing.
func TestCodexStatusNoHooksJSON(t *testing.T) {
	env := newCodexEnv(t)
	ag := Codex{}

	s := ag.Status(env)
	if s.Installed {
		t.Errorf("Status.Installed = true when hooks.json absent, want false")
	}
}

// ---- writeFileAtomic integration: mode preservation -------------------------

// TestCodexHooksJSONModePreserved verifies that writeFileAtomic preserves an
// existing hooks.json mode after Install mutates it.
func TestCodexHooksJSONModePreserved(t *testing.T) {
	env := newCodexEnv(t)
	// Write an initial hooks.json with mode 0600.
	initial := []byte(`{"hooks":{}}` + "\n")
	writeHooksJSON(t, env, initial) // writeHooksJSON uses 0600

	ag := Codex{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	fi, err := os.Stat(filepath.Join(env.Home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("hooks.json mode = %04o after Install, want 0600", fi.Mode().Perm())
	}
}

// ---- corruption-recovery -----------------------------------------------------

// TestCodexInstallCorruptedHooksJSON verifies that Install returns an error
// and leaves a corrupted hooks.json untouched.
func TestCodexInstallCorruptedHooksJSON(t *testing.T) {
	env := newCodexEnv(t)
	corrupted := []byte(`{"hooks":{"PreToolUse": [CORRUPTED`)
	writeHooksJSON(t, env, corrupted)

	ag := Codex{}
	err := ag.Install(env)
	if err == nil {
		t.Fatal("Install should error on corrupted hooks.json, got nil")
	}

	got := readHooksJSON(t, env)
	if string(got) != string(corrupted) {
		t.Errorf("corrupted hooks.json was modified\nwant: %q\ngot:  %q", corrupted, got)
	}
}

// ---- Migration matrix (--agent=codex replace-in-place) -----------------------

// buildBareHooksJSON returns hooks.json content with a legacy bare-command entry.
func buildBareHooksJSON(hookBin string) []byte {
	return []byte(`{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "` + hookBin + `",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
`)
}

// TestCodexMigrationInstallFromScratch verifies that a fresh install creates
// exactly one entry with the new --agent=codex form (no legacy bare form).
func TestCodexMigrationInstallFromScratch(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readHooksJSON(t, env)
	newCmd := env.HookBin + " --agent=codex"

	// Exactly one new-form entry.
	if codexHookEntryCount(t, data, newCmd) != 1 {
		t.Errorf("new-form entry count != 1 after fresh install")
	}
	// No bare-form entry.
	if codexHookEntryCount(t, data, env.HookBin) != 0 {
		t.Errorf("legacy bare-form entry unexpectedly present after fresh install")
	}
}

// TestCodexMigrationUpgradeFromBare verifies that installing over a legacy
// bare-command entry replaces it in place: exactly one entry, new form.
func TestCodexMigrationUpgradeFromBare(t *testing.T) {
	env := newCodexEnv(t)
	writeHooksJSON(t, env, buildBareHooksJSON(env.HookBin))

	ag := Codex{}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data := readHooksJSON(t, env)
	newCmd := env.HookBin + " --agent=codex"

	// Exactly one new-form entry.
	if codexHookEntryCount(t, data, newCmd) != 1 {
		t.Errorf("new-form entry count != 1 after upgrade from bare")
	}
	// No bare-form entry — it must have been replaced.
	if codexHookEntryCount(t, data, env.HookBin) != 0 {
		t.Errorf("legacy bare-form entry still present after upgrade (duplicate!)")
	}
}

// TestCodexMigrationIdempotentNewForm verifies that installing when the new
// form is already present leaves exactly one entry (no duplicate).
func TestCodexMigrationIdempotentNewForm(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	// Install once to get the new form.
	if err := ag.Install(env); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	// Install again — must be idempotent.
	if err := ag.Install(env); err != nil {
		t.Fatalf("second Install: %v", err)
	}

	data := readHooksJSON(t, env)
	newCmd := env.HookBin + " --agent=codex"

	if codexHookEntryCount(t, data, newCmd) != 1 {
		t.Errorf("new-form entry count != 1 after idempotent install, got %d",
			codexHookEntryCount(t, data, newCmd))
	}
}

// TestCodexMergeHookEntryIdempotentNoRewrite verifies that merging into a
// document that already contains exactly the canonical entry reports no change
// (changed == false), so an idempotent install does not rewrite hooks.json.
func TestCodexMergeHookEntryIdempotentNoRewrite(t *testing.T) {
	hookBin := "/usr/local/bin/agentjail-hook"

	// First merge into an empty doc to produce the canonical document.
	out, changed, err := codexMergeHookEntry(nil, hookBin)
	if err != nil {
		t.Fatalf("first merge: %v", err)
	}
	if !changed {
		t.Fatalf("first merge into empty doc should report changed=true")
	}

	// Second merge into the canonical document must be a no-op.
	out2, changed2, err := codexMergeHookEntry(out, hookBin)
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if changed2 {
		t.Errorf("merge into already-canonical doc reported changed=true (would rewrite); want false")
	}
	if string(out2) != string(out) {
		t.Errorf("merge into already-canonical doc mutated content")
	}
}

// TestCodexMigrationUninstallBare verifies that Uninstall recognises and
// removes the legacy bare-form entry.
func TestCodexMigrationUninstallBare(t *testing.T) {
	env := newCodexEnv(t)
	writeHooksJSON(t, env, buildBareHooksJSON(env.HookBin))

	ag := Codex{}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	data := readHooksJSON(t, env)
	if codexHookEntryCount(t, data, env.HookBin) != 0 {
		t.Errorf("bare-form entry still present after Uninstall")
	}
}

// TestCodexMigrationUninstallNew verifies that Uninstall removes the new
// --agent=codex form.
func TestCodexMigrationUninstallNew(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	data := readHooksJSON(t, env)
	newCmd := env.HookBin + " --agent=codex"
	if codexHookEntryCount(t, data, newCmd) != 0 {
		t.Errorf("new-form entry still present after Uninstall")
	}
}

// TestCodexMigrationStatusBare verifies that Status reports Installed=true
// when the legacy bare-form entry is present.
func TestCodexMigrationStatusBare(t *testing.T) {
	env := newCodexEnv(t)
	writeHooksJSON(t, env, buildBareHooksJSON(env.HookBin))

	ag := Codex{}
	s := ag.Status(env)
	if !s.Installed {
		t.Errorf("Status.Installed = false for legacy bare-form entry, want true")
	}
}

// TestCodexMigrationStatusNew verifies that Status reports Installed=true
// when the new --agent=codex form is present.
func TestCodexMigrationStatusNew(t *testing.T) {
	env := newCodexEnv(t)
	mkCodexDir(t, env)
	ag := Codex{}

	if err := ag.Install(env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	s := ag.Status(env)
	if !s.Installed {
		t.Errorf("Status.Installed = false after installing new-form entry, want true")
	}
}
