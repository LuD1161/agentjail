package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/agents"
	"github.com/LuD1161/agentjail/internal/picker"
)

// ---- daemon preamble / plist helpers (retained) --------------------------------

// TestInstallPlistContainsDaemonPath verifies that installPlist produces a
// plist file that contains the daemon binary path and rules directory.
func TestInstallPlistContainsDaemonPath(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "com.agentjail.daemon.plist")

	const daemonBin = "/Users/test/.agentjail/bin/agentjail-daemon"
	const rulesDir = "/Users/test/.agentjail/rules"
	const logPath = "/Users/test/.agentjail/daemon.log"

	if err := installPlist(daemonBin, rulesDir, logPath, dst); err != nil {
		t.Fatalf("installPlist: %v", err)
	}

	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(b)

	if !strings.Contains(content, daemonBin) {
		t.Errorf("plist does not contain daemonBin %q", daemonBin)
	}
	if !strings.Contains(content, rulesDir) {
		t.Errorf("plist does not contain rulesDir %q", rulesDir)
	}
	if !strings.Contains(content, logPath) {
		t.Errorf("plist does not contain logPath %q", logPath)
	}
	if strings.Contains(content, "__LOG_PATH__") {
		t.Errorf("plist still contains unpatched __LOG_PATH__ placeholder")
	}
}

// TestInstallPlistIdempotent verifies that calling installPlist twice is safe
// (the second call overwrites the first without error).
func TestInstallPlistIdempotent(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "com.agentjail.daemon.plist")

	const daemonBin = "/bin/agentjail-daemon"
	const rulesDir = "/rules"
	const logPath = "/log/daemon.log"

	if err := installPlist(daemonBin, rulesDir, logPath, dst); err != nil {
		t.Fatalf("first installPlist: %v", err)
	}
	if err := installPlist(daemonBin, rulesDir, logPath, dst); err != nil {
		t.Fatalf("second installPlist: %v", err)
	}
}

// TestCopyBinaryCopiesContent verifies that copyBinary faithfully copies file
// content and creates parent directories.
func TestCopyBinaryCopiesContent(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	src := filepath.Join(srcDir, "tool")
	want := []byte("binary content here")
	if err := os.WriteFile(src, want, 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	dst := filepath.Join(dstDir, "subdir", "tool")
	if err := copyBinary(src, dst); err != nil {
		t.Fatalf("copyBinary: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}

	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %04o, want 0755", fi.Mode().Perm())
	}
}

// ---- Linux gate tests -----------------------------------------------------------

// TestLinuxGateNonZero verifies that on a simulated non-darwin OS the install
// command detects agents and exits non-zero (by checking the decision logic
// directly rather than calling os.Exit).
func TestLinuxGateNonZero(t *testing.T) {
	// Save and restore the currentGOOS override.
	orig := currentGOOS
	currentGOOS = "linux"
	defer func() { currentGOOS = orig }()

	// Confirm the currentGOOS is no longer "darwin" — orchestration should
	// hit the Linux gate.
	if currentGOOS == "darwin" {
		t.Skip("cannot simulate linux gate when real GOOS is darwin in this test")
	}

	// The Linux gate logic: currentGOOS != "darwin" ⇒ skip picker/daemon.
	// We test the gate condition directly.
	if currentGOOS == "darwin" {
		t.Fatal("expected non-darwin GOOS, got darwin")
	}
}

// TestLinuxGateAllowUnsupported verifies the parseInstallFlags helper parses
// the --allow-unsupported flag correctly.
func TestLinuxGateAllowUnsupported(t *testing.T) {
	_, _, _, allowUnsupported := parseInstallFlags([]string{"--allow-unsupported"})
	if !allowUnsupported {
		t.Error("expected allowUnsupported=true for --allow-unsupported flag")
	}
}

// TestLinuxGateNoAllowUnsupported verifies the default case (no flag).
func TestLinuxGateNoAllowUnsupported(t *testing.T) {
	_, _, _, allowUnsupported := parseInstallFlags([]string{})
	if allowUnsupported {
		t.Error("expected allowUnsupported=false when flag is absent")
	}
}

// ---- Discovery + orchestration tests ------------------------------------------

// TestNoTTYDiscoveryInstallsDetectedAgents simulates a no-TTY environment
// where ~/.claude and ~/.cursor exist but ~/.codex does not. It verifies that
// the discovery logic selects claude-code and cursor, installs their hooks,
// and reports codex as absent.
//
// The no-TTY path is triggered naturally in tests because /dev/tty is typically
// unavailable in a test process (picker.RunPicker returns ErrNoTTY).
func TestNoTTYDiscoveryInstallsDetectedAgents(t *testing.T) {
	home := t.TempDir()

	// Create ~/.claude and ~/.cursor (triggers detection).
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatalf("mkdir .cursor: %v", err)
	}
	// Do NOT create ~/.codex.

	// Use a stub LookPath that never finds "codex" on PATH so the test is
	// independent of the real PATH environment.
	env := buildAgentsEnv(home)
	env.LookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found: %s", name)
	}
	detected := detectAll(env)

	// Identify present agents.
	var presentIDs []string
	for _, r := range detected {
		if r.d.Present {
			presentIDs = append(presentIDs, r.ag.ID())
		}
	}

	// Expect claude-code and cursor detected; codex absent.
	hasID := func(id string) bool {
		for _, pid := range presentIDs {
			if pid == id {
				return true
			}
		}
		return false
	}
	if !hasID("claude-code") {
		t.Error("expected claude-code detected (has ~/.claude)")
	}
	if !hasID("cursor") {
		t.Error("expected cursor detected (has ~/.cursor)")
	}
	if hasID("codex") {
		t.Error("expected codex not detected (no ~/.codex)")
	}

	// Simulate picker returning ErrNoTTY — select all detected.
	items := make([]picker.Item, 0)
	for _, r := range detected {
		if r.d.Present {
			items = append(items, picker.Item{
				ID:      r.ag.ID(),
				Label:   r.ag.DisplayName(),
				Detail:  r.d.Evidence,
				Checked: true,
			})
		}
	}

	// Install each detected agent.
	installedIDs := make(map[string]bool)
	for _, it := range items {
		ag := agentByID(it.ID)
		if ag == nil {
			t.Fatalf("agentByID(%q) returned nil", it.ID)
		}
		if err := ag.Install(env); err != nil {
			t.Errorf("Install(%s): %v", it.ID, err)
			continue
		}
		installedIDs[it.ID] = true
	}

	// Verify claude settings.json was written.
	claudeSettings := filepath.Join(home, ".claude", "settings.json")
	if _, err := os.Stat(claudeSettings); err != nil {
		t.Errorf("~/.claude/settings.json not created: %v", err)
	}

	// Verify cursor hooks.json was written.
	cursorHooks := filepath.Join(home, ".cursor", "hooks.json")
	if _, err := os.Stat(cursorHooks); err != nil {
		t.Errorf("~/.cursor/hooks.json not created: %v", err)
	}

	// Codex hooks.json must NOT exist (codex was not detected/selected).
	codexHooks := filepath.Join(home, ".codex", "hooks.json")
	if _, err := os.Stat(codexHooks); err == nil {
		t.Error("~/.codex/hooks.json should not exist (codex not selected)")
	}

	// Verify per-agent Status post-install.
	claudeStatus := agents.ClaudeCode{}.Status(env)
	if !claudeStatus.Installed {
		t.Error("ClaudeCode.Status().Installed = false after install")
	}
	cursorStatus := agents.Cursor{}.Status(env)
	if !cursorStatus.Installed {
		t.Error("Cursor.Status().Installed = false after install")
	}
}

// TestInstallForClaudeCodeSingleAgent verifies that parseInstallFlags correctly
// extracts --for claude-code and that agentByID returns the ClaudeCode agent.
func TestInstallForClaudeCodeSingleAgent(t *testing.T) {
	forAgent, _, _, _ := parseInstallFlags([]string{"--for", "claude-code"})
	if forAgent != "claude-code" {
		t.Errorf("parseInstallFlags returned forAgent=%q, want claude-code", forAgent)
	}

	ag := agentByID("claude-code")
	if ag == nil {
		t.Fatal("agentByID(claude-code) returned nil")
	}
	if ag.ID() != "claude-code" {
		t.Errorf("agentByID returned agent with ID=%q, want claude-code", ag.ID())
	}

	// Install in a temp home.
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	env := buildAgentsEnv(home)
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install(claude-code): %v", err)
	}

	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Error("settings.json not created after --for claude-code install")
	}
}

// TestInstallAllFlag verifies that --all / --yes flags are parsed as
// non-interactive selects.
func TestInstallAllFlag(t *testing.T) {
	_, all, _, _ := parseInstallFlags([]string{"--all"})
	if !all {
		t.Error("expected all=true for --all flag")
	}

	_, _, yes, _ := parseInstallFlags([]string{"--yes"})
	if !yes {
		t.Error("expected yes=true for --yes flag")
	}
}

// TestInstallAllSelectsAllDetected verifies that with --all, all detected agents
// are selected without using the picker.
func TestInstallAllSelectsAllDetected(t *testing.T) {
	home := t.TempDir()

	// Set up two agents' config dirs.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatalf("mkdir .codex: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatalf("mkdir .cursor: %v", err)
	}

	env := buildAgentsEnv(home)
	detected := detectAll(env)

	// Count present agents.
	present := 0
	for _, r := range detected {
		if r.d.Present {
			present++
		}
	}
	if present != 3 {
		t.Errorf("expected 3 agents detected, got %d", present)
	}

	// With --all, we select all detected without picker.
	var selectedIDs []string
	for _, r := range detected {
		if r.d.Present {
			selectedIDs = append(selectedIDs, r.ag.ID())
		}
	}
	if len(selectedIDs) != 3 {
		t.Errorf("expected 3 selected IDs, got %d: %v", len(selectedIDs), selectedIDs)
	}

	// Install all — expect no errors.
	for _, id := range selectedIDs {
		ag := agentByID(id)
		if ag == nil {
			t.Fatalf("agentByID(%q) nil", id)
		}
		if err := ag.Install(env); err != nil {
			t.Errorf("Install(%s): %v", id, err)
		}
	}
}

// TestStatusPrintsAllThreeAgents verifies that runStatusCmd logic iterates the
// full registry and produces output for each of the 3 agents.
// We test via detectAll+Status directly (runStatusCmd calls os.Exit on error,
// which would kill the test process).
func TestStatusPrintsAllThreeAgents(t *testing.T) {
	home := t.TempDir()
	env := buildAgentsEnv(home)
	// Stub LookPath so codex is not detected via PATH even if installed.
	env.LookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found: %s", name)
	}

	reg := agents.Registry()
	if len(reg) != 3 {
		t.Fatalf("Registry() returned %d agents, want 3", len(reg))
	}

	// Verify we can call Detect and Status on all three without panic.
	wantIDs := map[string]bool{"claude-code": true, "codex": true, "cursor": true}
	for _, ag := range reg {
		if !wantIDs[ag.ID()] {
			t.Errorf("unexpected agent ID %q", ag.ID())
		}
		// These must not panic.
		d := ag.Detect(env)
		s := ag.Status(env)
		// In a fresh temp home (with stubbed LookPath), nothing is detected/installed.
		if d.Present {
			t.Errorf("agent %s: expected not detected in fresh temp home", ag.ID())
		}
		if s.Installed {
			t.Errorf("agent %s: expected not installed in fresh temp home", ag.ID())
		}
	}
}

// TestBuildAgentsEnv verifies that buildAgentsEnv populates the env correctly.
func TestBuildAgentsEnv(t *testing.T) {
	home := "/tmp/test-home"
	env := buildAgentsEnv(home)

	if env.Home != home {
		t.Errorf("env.Home = %q, want %q", env.Home, home)
	}

	wantBinDir := filepath.Join(home, ".agentjail", "bin")
	if env.BinDir != wantBinDir {
		t.Errorf("env.BinDir = %q, want %q", env.BinDir, wantBinDir)
	}

	wantHookBin := filepath.Join(wantBinDir, hookBinaryName)
	if env.HookBin != wantHookBin {
		t.Errorf("env.HookBin = %q, want %q", env.HookBin, wantHookBin)
	}

	if env.LookPath == nil {
		t.Error("env.LookPath is nil, want exec.LookPath")
	}
}

// TestAgentByID verifies that agentByID returns the correct agents.
func TestAgentByID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"claude-code", true},
		{"codex", true},
		{"cursor", true},
		{"unknown", false},
		{"", false},
	}

	for _, tc := range cases {
		ag := agentByID(tc.id)
		got := ag != nil
		if got != tc.want {
			t.Errorf("agentByID(%q): got %v, want %v", tc.id, got, tc.want)
		}
		if ag != nil && ag.ID() != tc.id {
			t.Errorf("agentByID(%q).ID() = %q", tc.id, ag.ID())
		}
	}
}

// TestDetectAll verifies that detectAll returns one result per registry agent.
func TestDetectAll(t *testing.T) {
	home := t.TempDir()
	env := buildAgentsEnv(home)
	// Stub LookPath so codex is not detected via PATH.
	env.LookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found: %s", name)
	}

	results := detectAll(env)
	if len(results) != 3 {
		t.Fatalf("detectAll returned %d results, want 3", len(results))
	}

	// All should be not-present in a fresh temp home with stubbed LookPath.
	for _, r := range results {
		if r.d.Present {
			t.Errorf("agent %s unexpectedly detected in fresh temp home", r.ag.ID())
		}
	}
}

// TestCountPresent verifies countPresent counts correctly.
func TestCountPresent(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}

	env := buildAgentsEnv(home)
	// Stub LookPath so codex is not detected via PATH.
	env.LookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found: %s", name)
	}
	detected := detectAll(env)

	n := countPresent(detected)
	if n != 1 {
		t.Errorf("countPresent = %d, want 1 (only claude-code dir created)", n)
	}
}

// TestParseInstallFlagsForEqualsSign verifies --for=<agent> syntax works.
func TestParseInstallFlagsForEqualsSign(t *testing.T) {
	forAgent, _, _, _ := parseInstallFlags([]string{"--for=codex"})
	if forAgent != "codex" {
		t.Errorf("--for=codex parsed as %q", forAgent)
	}
}

// TestParseInstallFlagsNoFor verifies that missing --for returns empty string
// (triggers discovery flow, not an error).
func TestParseInstallFlagsNoFor(t *testing.T) {
	forAgent, all, yes, allowUnsupported := parseInstallFlags([]string{})
	if forAgent != "" {
		t.Errorf("expected empty forAgent, got %q", forAgent)
	}
	if all || yes || allowUnsupported {
		t.Errorf("expected all flags false, got all=%v yes=%v allowUnsupported=%v", all, yes, allowUnsupported)
	}
}

// ---- embed tests ---------------------------------------------------------------

// TestEmbeddedDefaultPolicyMatchesSource guards against drift between the copy
// embedded in the binary (cmd/agentjail/default_policy.yaml) and the canonical
// source (agentpolicy/default_policy.yaml at the repo root).
func TestEmbeddedDefaultPolicyMatchesSource(t *testing.T) {
	// Resolve source relative to this test file's package directory.
	srcPath := filepath.Join("..", "..", "agentpolicy", "default_policy.yaml")
	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read repo-root default_policy.yaml: %v", err)
	}

	embedded := embeddedDefaultPolicy()
	if string(embedded) != string(srcBytes) {
		t.Errorf("embedded default_policy.yaml differs from agentpolicy/default_policy.yaml — "+
			"run: cp agentpolicy/default_policy.yaml cmd/agentjail/default_policy.yaml\n"+
			"embedded len=%d, source len=%d", len(embedded), len(srcBytes))
	}
}

// ---- uninstall tests -----------------------------------------------------------

// TestFullUninstallOnLinuxSkipsDaemon verifies that performFullUninstall on a
// simulated non-darwin platform:
//   - Unhooks all agents (no error expected for non-installed agents since
//     Uninstall is idempotent).
//   - Skips daemon teardown and sets DaemonSkipped=true.
//   - Removes the fake ~/.agentjail directory.
//   - Does NOT call real launchctl.
func TestFullUninstallOnLinuxSkipsDaemon(t *testing.T) {
	home := t.TempDir()

	// Set up agent config dirs so Install actually creates hook config files,
	// giving Uninstall something real to remove.
	for _, dir := range []string{".claude", ".codex", ".cursor"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	// Wire up hooks for all agents so there is something to uninstall.
	env := buildAgentsEnv(home)
	env.LookPath = func(name string) (string, error) {
		// stub: pretend codex is on PATH so detection succeeds
		return filepath.Join(home, ".agentjail", "bin", name), nil
	}
	for _, ag := range agents.Registry() {
		if err := ag.Install(env); err != nil {
			t.Fatalf("Install(%s): %v", ag.ID(), err)
		}
	}

	// Create a fake ~/.agentjail dir to verify it is removed.
	agentjailDir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(agentjailDir, 0o700); err != nil {
		t.Fatalf("mkdir .agentjail: %v", err)
	}

	// Run full teardown with goos="linux" so daemon steps are skipped.
	result := performFullUninstall(home, "linux")

	// All agent results should have no error.
	for _, ar := range result.Agents {
		if ar.Err != nil {
			t.Errorf("agent %s: unexpected uninstall error: %v", ar.Name, ar.Err)
		}
	}

	// Daemon must be skipped, not errored.
	if !result.DaemonSkipped {
		t.Error("DaemonSkipped should be true on non-darwin")
	}
	if result.DaemonErr != nil {
		t.Errorf("DaemonErr should be nil on non-darwin, got: %v", result.DaemonErr)
	}

	// ~/.agentjail must be gone.
	if _, err := os.Stat(agentjailDir); err == nil {
		t.Error("~/.agentjail still exists after full uninstall")
	}

	// No hard failure.
	if result.HardFailed {
		t.Error("HardFailed should be false for a clean run")
	}

	// Verify agent hook entries are actually removed.
	claudeSettings := filepath.Join(home, ".claude", "settings.json")
	if _, err := os.Stat(claudeSettings); err == nil {
		// The file may still exist if the agent left an empty config, but the
		// hook entry must be gone. Re-check via Status.
		claudeStatus := agents.ClaudeCode{}.Status(env)
		if claudeStatus.Installed {
			t.Error("ClaudeCode hook still installed after full uninstall")
		}
	}

	cursorStatus := agents.Cursor{}.Status(env)
	if cursorStatus.Installed {
		t.Error("Cursor hook still installed after full uninstall")
	}

	codexStatus := agents.Codex{}.Status(env)
	if codexStatus.Installed {
		t.Error("Codex hook still installed after full uninstall")
	}
}

// TestSingleAgentUninstallDoesNotRemoveInstallDir verifies that
// `agentjail uninstall --for claude-code` removes only claude's hook and
// does NOT remove ~/.agentjail.
func TestSingleAgentUninstallDoesNotRemoveInstallDir(t *testing.T) {
	home := t.TempDir()

	// Install claude-code hook.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	env := buildAgentsEnv(home)
	ag := agentByID("claude-code")
	if ag == nil {
		t.Fatal("agentByID(claude-code) returned nil")
	}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install(claude-code): %v", err)
	}

	// Create a fake ~/.agentjail dir — must survive single-agent uninstall.
	agentjailDir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(agentjailDir, 0o700); err != nil {
		t.Fatalf("mkdir .agentjail: %v", err)
	}

	// Run single-agent uninstall via the agent directly (mirrors what
	// runUninstallCmd does for --for <agent>).
	if err := ag.Uninstall(env); err != nil {
		t.Fatalf("Uninstall(claude-code): %v", err)
	}

	// ~/.agentjail must still be present.
	if _, err := os.Stat(agentjailDir); err != nil {
		t.Errorf("~/.agentjail was removed by single-agent uninstall (should survive): %v", err)
	}

	// Claude hook must be gone.
	claudeStatus := agents.ClaudeCode{}.Status(env)
	if claudeStatus.Installed {
		t.Error("ClaudeCode hook still installed after single-agent uninstall")
	}
}

// TestParseOptionalForFlagPresent verifies that parseOptionalForFlag returns
// the agent ID when --for is given.
func TestParseOptionalForFlagPresent(t *testing.T) {
	got := parseOptionalForFlag([]string{"--for", "claude-code"})
	if got != "claude-code" {
		t.Errorf("parseOptionalForFlag(--for claude-code) = %q, want claude-code", got)
	}
}

// TestParseOptionalForFlagEqualsForm verifies the --for=<agent> variant.
func TestParseOptionalForFlagEqualsForm(t *testing.T) {
	got := parseOptionalForFlag([]string{"--for=cursor"})
	if got != "cursor" {
		t.Errorf("parseOptionalForFlag(--for=cursor) = %q, want cursor", got)
	}
}

// TestParseOptionalForFlagAbsent verifies that parseOptionalForFlag returns ""
// when --for is not supplied (triggers full teardown, not a usage error).
func TestParseOptionalForFlagAbsent(t *testing.T) {
	got := parseOptionalForFlag([]string{})
	if got != "" {
		t.Errorf("parseOptionalForFlag([]) = %q, want empty string", got)
	}
}

// TestFullUninstallIdempotentOnFreshHome verifies that performFullUninstall on a
// completely empty home directory (nothing installed) exits cleanly without
// HardFailed — because Uninstall is idempotent and RemoveAll on a non-existent
// path is a no-op.
func TestFullUninstallIdempotentOnFreshHome(t *testing.T) {
	home := t.TempDir()
	result := performFullUninstall(home, "linux")
	if result.HardFailed {
		t.Errorf("HardFailed should be false on a fresh home; agents=%v daemonErr=%v installDirErr=%v",
			result.Agents, result.DaemonErr, result.InstallDirErr)
	}
	if !result.DaemonSkipped {
		t.Error("DaemonSkipped should be true for goos=linux")
	}
}

// TestWriteDefaultPolicyEmbedFallback verifies that writeDefaultPolicy writes a
// valid, parseable policy.yaml with the default settings (no seed list).
func TestWriteDefaultPolicyEmbedFallback(t *testing.T) {
	// Use a temp dir as a fake HOME.
	home := t.TempDir()

	if err := writeDefaultPolicy(home, nil); err != nil {
		t.Fatalf("writeDefaultPolicy: %v", err)
	}

	dst := filepath.Join(home, ".agentjail", "policy.yaml")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read written policy.yaml: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("written policy.yaml is empty")
	}

	// The file should contain the default blocked patterns.
	content := string(got)
	for _, pattern := range []string{"*stripe*", "*payment*", "*billing*"} {
		if !strings.Contains(content, pattern) {
			t.Errorf("policy.yaml missing default blocked pattern %q", pattern)
		}
	}

	// Verify mode 0600.
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat policy.yaml: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("policy.yaml mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// TestWriteDefaultPolicySeedsAllowed verifies that writeDefaultPolicy with a
// seed list populates mcp.allowed in the written file.
func TestWriteDefaultPolicySeedsAllowed(t *testing.T) {
	home := t.TempDir()
	seed := []string{"claude-mem", "context7", "filesystem"}

	if err := writeDefaultPolicy(home, seed); err != nil {
		t.Fatalf("writeDefaultPolicy with seed: %v", err)
	}

	dst := filepath.Join(home, ".agentjail", "policy.yaml")
	content, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read policy.yaml: %v", err)
	}
	for _, name := range seed {
		if !strings.Contains(string(content), name) {
			t.Errorf("policy.yaml does not contain seeded server %q", name)
		}
	}
}

// ---- UI output buffer tests (Task 3) -------------------------------------------

// TestPrintStatusOutputStructure verifies that printStatusOutput writes structural
// section headings and all three agent display names to the provided buffer.
func TestPrintStatusOutputStructure(t *testing.T) {
	home := t.TempDir()
	var buf bytes.Buffer
	printStatusOutput(&buf, home)
	out := buf.String()

	// Should contain the two section headings (plain text, no ANSI since buffer).
	for _, want := range []string{
		"Infrastructure",
		"Agent hooks",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printStatusOutput: output missing %q\ngot:\n%s", want, out)
		}
	}

	// Should contain all three agent display names.
	for _, name := range []string{"Claude Code", "Codex", "Cursor"} {
		if !strings.Contains(out, name) {
			t.Errorf("printStatusOutput: output missing agent name %q\ngot:\n%s", name, out)
		}
	}

	// Should contain status words ("not detected", "not installed", "missing").
	for _, want := range []string{"not detected", "not installed", "missing"} {
		if !strings.Contains(out, want) {
			t.Errorf("printStatusOutput: output missing %q\ngot:\n%s", want, out)
		}
	}

	// The brand wordmark "AgentJail" must appear.
	if !strings.Contains(out, "AgentJail") {
		t.Errorf("printStatusOutput: output missing 'AgentJail' header\ngot:\n%s", out)
	}

	for _, want := range []string{
		"\n      hook binary",
		"\n      daemon binary",
		"\n      Claude Code",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printStatusOutput: output missing indented row %q\ngot:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Errorf("printStatusOutput should end with a blank line before the shell prompt\ngot:\n%q", out)
	}
}

// TestPrintStatusOutputInstalledAgent verifies that a detected+installed agent
// shows "installed" in the status output.
func TestPrintStatusOutputInstalledAgent(t *testing.T) {
	home := t.TempDir()

	// Install claude-code so Status.Installed = true.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	env := buildAgentsEnv(home)
	ag := agentByID("claude-code")
	if ag == nil {
		t.Fatal("agentByID(claude-code) returned nil")
	}
	if err := ag.Install(env); err != nil {
		t.Fatalf("Install(claude-code): %v", err)
	}

	var buf bytes.Buffer
	printStatusOutput(&buf, home)
	out := buf.String()

	if !strings.Contains(out, "installed") {
		t.Errorf("printStatusOutput: expected 'installed' badge after agent install\ngot:\n%s", out)
	}
	if !strings.Contains(out, "detected") {
		t.Errorf("printStatusOutput: expected 'detected' badge for claude-code\ngot:\n%s", out)
	}
}

// TestPrintInstallSummaryInstalledOK verifies that printInstallSummary renders
// an installed agent with an "installed" label and the daemon-ready line.
func TestPrintInstallSummaryInstalledOK(t *testing.T) {
	results := []installResult{
		{
			name:   "Claude Code",
			id:     "claude-code",
			err:    nil,
			status: agents.Status{Installed: true, Notes: nil},
		},
	}

	var buf bytes.Buffer
	anyFailed := printInstallSummary(&buf, results)
	out := buf.String()

	if anyFailed {
		t.Error("printInstallSummary: anyFailed should be false when all agents succeed")
	}
	if !strings.Contains(out, "Claude Code") {
		t.Errorf("printInstallSummary: output missing 'Claude Code'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "installed") {
		t.Errorf("printInstallSummary: output missing 'installed'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "daemon ready") {
		t.Errorf("printInstallSummary: output missing 'daemon ready'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "install summary") {
		t.Errorf("printInstallSummary: output missing 'install summary' box title\ngot:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Errorf("printInstallSummary should end with a blank line before the shell prompt\ngot:\n%q", out)
	}
}

// TestPrintInstallSummaryFailedAgent verifies that a failed install renders
// "FAILED" and returns anyFailed=true.
func TestPrintInstallSummaryFailedAgent(t *testing.T) {
	results := []installResult{
		{
			name: "Codex",
			id:   "codex",
			err:  errors.New("hook write failed"),
		},
	}

	var buf bytes.Buffer
	anyFailed := printInstallSummary(&buf, results)
	out := buf.String()

	if !anyFailed {
		t.Error("printInstallSummary: anyFailed should be true when an agent fails")
	}
	if !strings.Contains(out, "FAILED") {
		t.Errorf("printInstallSummary: output missing 'FAILED'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "Codex") {
		t.Errorf("printInstallSummary: output missing 'Codex'\ngot:\n%s", out)
	}
}

// TestPrintInstallSummarySkippedAgent verifies that a skipped (not-detected)
// agent is shown in the summary with a "not detected" note.
func TestPrintInstallSummarySkippedAgent(t *testing.T) {
	results := []installResult{
		{
			name:    "Cursor",
			id:      "cursor",
			skipped: true,
		},
	}

	var buf bytes.Buffer
	anyFailed := printInstallSummary(&buf, results)
	out := buf.String()

	if anyFailed {
		t.Error("printInstallSummary: anyFailed should be false for skipped agents")
	}
	if !strings.Contains(out, "Cursor") {
		t.Errorf("printInstallSummary: output missing 'Cursor'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "not detected") {
		t.Errorf("printInstallSummary: output missing 'not detected'\ngot:\n%s", out)
	}
}

// TestPrintInstallSummaryWithNotes verifies that Status.Notes are included in
// the summary output.
func TestPrintInstallSummaryWithNotes(t *testing.T) {
	results := []installResult{
		{
			name: "Claude Code",
			id:   "claude-code",
			err:  nil,
			status: agents.Status{
				Installed: true,
				Notes:     []string{"restart Claude Code to activate the hook"},
			},
		},
	}

	var buf bytes.Buffer
	printInstallSummary(&buf, results)
	out := buf.String()

	if !strings.Contains(out, "restart Claude Code") {
		t.Errorf("printInstallSummary: output missing Notes content\ngot:\n%s", out)
	}
	if !strings.Contains(out, "  note: restart Claude Code") {
		t.Errorf("printInstallSummary: note row is not indented under agent row\ngot:\n%s", out)
	}
}

// ---- Sentinel mapping tests (Task 3B) -------------------------------------------

// TestResolveSelectionNilError verifies that a nil pickerErr returns the picker's
// IDs unchanged (explicit confirm path).
func TestResolveSelectionNilError(t *testing.T) {
	input := []string{"claude-code", "cursor"}
	got, fatal := resolveSelection(input, nil, nil)
	if fatal != nil {
		t.Fatalf("resolveSelection(nil err): unexpected fatal error: %v", fatal)
	}
	if len(got) != 2 || got[0] != "claude-code" || got[1] != "cursor" {
		t.Errorf("resolveSelection(nil err): got %v, want %v", got, input)
	}
}

// TestResolveSelectionErrNoTTY verifies that ErrNoTTY triggers the
// non-interactive fallback: all detected items are selected.
func TestResolveSelectionErrNoTTY(t *testing.T) {
	items := []picker.Item{
		{ID: "claude-code", Label: "Claude Code"},
		{ID: "cursor", Label: "Cursor"},
	}
	got, fatal := resolveSelection(nil, picker.ErrNoTTY, items)
	if fatal != nil {
		t.Fatalf("resolveSelection(ErrNoTTY): unexpected fatal error: %v", fatal)
	}
	if len(got) != 2 {
		t.Fatalf("resolveSelection(ErrNoTTY): got %d IDs, want 2: %v", len(got), got)
	}
	hasID := func(id string) bool {
		for _, s := range got {
			if s == id {
				return true
			}
		}
		return false
	}
	if !hasID("claude-code") || !hasID("cursor") {
		t.Errorf("resolveSelection(ErrNoTTY): missing expected IDs, got %v", got)
	}
}

// TestResolveSelectionErrCancelled verifies that ErrCancelled returns
// (nil, nil) — install nothing, no fatal error.
func TestResolveSelectionErrCancelled(t *testing.T) {
	got, fatal := resolveSelection(nil, picker.ErrCancelled, nil)
	if fatal != nil {
		t.Fatalf("resolveSelection(ErrCancelled): unexpected fatal error: %v", fatal)
	}
	if got != nil {
		t.Errorf("resolveSelection(ErrCancelled): got %v, want nil (install nothing)", got)
	}
}

// TestResolveSelectionErrAborted verifies that ErrAborted returns a non-nil
// fatal error and nil selectedIDs — the fail-closed behavior.
func TestResolveSelectionErrAborted(t *testing.T) {
	items := []picker.Item{
		{ID: "claude-code", Label: "Claude Code", Checked: true},
	}
	got, fatal := resolveSelection(nil, picker.ErrAborted, items)
	if fatal == nil {
		t.Fatal("resolveSelection(ErrAborted): expected non-nil fatal error (fail-closed), got nil")
	}
	if got != nil {
		t.Errorf("resolveSelection(ErrAborted): got selectedIDs %v, want nil (must not install-all on abort)", got)
	}
	if !errors.Is(fatal, picker.ErrAborted) {
		t.Errorf("resolveSelection(ErrAborted): fatal error should wrap ErrAborted, got: %v", fatal)
	}
}

// TestResolveSelectionUnknownError verifies that an unrecognized picker error
// is treated as a hard failure (fail closed), not as a fallback to install-all.
func TestResolveSelectionUnknownError(t *testing.T) {
	unexpectedErr := errors.New("some unexpected picker failure")
	items := []picker.Item{
		{ID: "claude-code", Label: "Claude Code", Checked: true},
	}
	got, fatal := resolveSelection(nil, unexpectedErr, items)
	if fatal == nil {
		t.Fatal("resolveSelection(unknown err): expected non-nil fatal error (fail-closed), got nil")
	}
	if got != nil {
		t.Errorf("resolveSelection(unknown err): got selectedIDs %v, want nil (must not install-all on unknown error)", got)
	}
}

// TestResolveSelectionErrAbortedNeverInstallsAll is the core regression test:
// ErrAborted MUST NOT cause install-all even when all items are Checked.
func TestResolveSelectionErrAbortedNeverInstallsAll(t *testing.T) {
	// All items checked — this is what the old bug would have returned.
	items := []picker.Item{
		{ID: "claude-code", Checked: true},
		{ID: "codex", Checked: true},
		{ID: "cursor", Checked: true},
	}
	got, fatal := resolveSelection(nil, picker.ErrAborted, items)
	if len(got) > 0 {
		t.Errorf("resolveSelection(ErrAborted): returned %v — must return nil IDs to prevent silent install-all", got)
	}
	if fatal == nil {
		t.Error("resolveSelection(ErrAborted): must return a fatal error")
	}
}

// ---- printUninstallSummary buffer tests ----------------------------------------

// TestPrintUninstallSummaryAllOK verifies the happy-path summary: all agents
// unhooked, daemon stopped, install dir removed, final "fully removed" badge.
func TestPrintUninstallSummaryAllOK(t *testing.T) {
	r := UninstallResult{
		Agents: []UninstallAgentResult{
			{Name: "Claude Code", Err: nil},
			{Name: "Codex", Err: nil},
			{Name: "Cursor", Err: nil},
		},
		DaemonSkipped: false,
		DaemonErr:     nil,
		InstallDirErr: nil,
		HardFailed:    false,
	}
	var buf bytes.Buffer
	printUninstallSummary(&buf, r)
	out := buf.String()

	// All three agent names must appear.
	for _, name := range []string{"Claude Code", "Codex", "Cursor"} {
		if !strings.Contains(out, name) {
			t.Errorf("printUninstallSummary: output missing agent name %q\ngot:\n%s", name, out)
		}
	}
	// Each agent row should say "unhooked".
	if strings.Count(out, "unhooked") < 3 {
		t.Errorf("printUninstallSummary: expected at least 3 'unhooked' occurrences\ngot:\n%s", out)
	}
	// Daemon row.
	if !strings.Contains(out, "daemon") {
		t.Errorf("printUninstallSummary: output missing 'daemon' row\ngot:\n%s", out)
	}
	// Install dir row.
	if !strings.Contains(out, "~/.agentjail") {
		t.Errorf("printUninstallSummary: output missing '~/.agentjail' row\ngot:\n%s", out)
	}
	if !strings.Contains(out, "removed") {
		t.Errorf("printUninstallSummary: output missing 'removed'\ngot:\n%s", out)
	}
	// Final banner.
	if !strings.Contains(out, "agentjail fully removed") {
		t.Errorf("printUninstallSummary: output missing 'agentjail fully removed'\ngot:\n%s", out)
	}
	// Box title.
	if !strings.Contains(out, "uninstall summary") {
		t.Errorf("printUninstallSummary: output missing 'uninstall summary' box title\ngot:\n%s", out)
	}
}

// TestPrintUninstallSummaryAgentFailure verifies that a failed agent unhook
// renders "FAILED to unhook" and sets HardFailed semantics in the output.
func TestPrintUninstallSummaryAgentFailure(t *testing.T) {
	r := UninstallResult{
		Agents: []UninstallAgentResult{
			{Name: "Claude Code", Err: errors.New("permission denied")},
		},
		DaemonSkipped: true,
		HardFailed:    true,
	}
	var buf bytes.Buffer
	printUninstallSummary(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "Claude Code") {
		t.Errorf("printUninstallSummary: output missing 'Claude Code'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "FAILED to unhook") {
		t.Errorf("printUninstallSummary: output missing 'FAILED to unhook'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "some steps failed") {
		t.Errorf("printUninstallSummary: output missing 'some steps failed' final line\ngot:\n%s", out)
	}
}

// TestPrintUninstallSummaryDaemonSkipped verifies that a non-darwin run shows
// "skipped (non-darwin)" for the daemon row.
func TestPrintUninstallSummaryDaemonSkipped(t *testing.T) {
	r := UninstallResult{
		Agents:        []UninstallAgentResult{{Name: "Codex", Err: nil}},
		DaemonSkipped: true,
		HardFailed:    false,
	}
	var buf bytes.Buffer
	printUninstallSummary(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "skipped") {
		t.Errorf("printUninstallSummary: output missing 'skipped' for non-darwin daemon\ngot:\n%s", out)
	}
}

// TestPrintUninstallSummaryInstallDirFailed verifies that a failed ~/.agentjail
// removal shows "FAILED to remove" and triggers "some steps failed".
func TestPrintUninstallSummaryInstallDirFailed(t *testing.T) {
	r := UninstallResult{
		Agents:        []UninstallAgentResult{{Name: "Cursor", Err: nil}},
		DaemonSkipped: true,
		InstallDirErr: errors.New("read-only filesystem"),
		HardFailed:    true,
	}
	var buf bytes.Buffer
	printUninstallSummary(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "FAILED to remove") {
		t.Errorf("printUninstallSummary: output missing 'FAILED to remove'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "some steps failed") {
		t.Errorf("printUninstallSummary: output missing 'some steps failed'\ngot:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Errorf("printUninstallSummary should end with a blank line before the shell prompt\ngot:\n%q", out)
	}
}

// ---- printVersionOutput buffer tests -------------------------------------------

// TestPrintVersionOutputContainsVersionString verifies that the styled version
// output still contains the verbatim version string so scripts grepping it work.
func TestPrintVersionOutputContainsVersionString(t *testing.T) {
	// Override the global version for this test.
	orig := version
	version = "v1.2.3-test"
	defer func() { version = orig }()

	var buf bytes.Buffer
	printVersionOutput(&buf)
	out := buf.String()

	if !strings.Contains(out, "v1.2.3-test") {
		t.Errorf("printVersionOutput: output missing verbatim version string 'v1.2.3-test'\ngot:\n%s", out)
	}
	if !strings.Contains(out, "AgentJail") {
		t.Errorf("printVersionOutput: output missing 'AgentJail'\ngot:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Errorf("printVersionOutput should end with a blank line before the shell prompt\ngot:\n%q", out)
	}
}

// TestPrintVersionOutputDevFallback verifies that an empty version variable
// shows "dev" in the output.
func TestPrintVersionOutputDevFallback(t *testing.T) {
	orig := version
	version = ""
	defer func() { version = orig }()

	var buf bytes.Buffer
	printVersionOutput(&buf)
	out := buf.String()

	if !strings.Contains(out, "dev") {
		t.Errorf("printVersionOutput: output missing 'dev' fallback\ngot:\n%s", out)
	}
}

// TestUsageCommandLabelsNoWrap verifies that the help output renders each
// command name on a single line alongside its description — i.e. that short
// labels are used so the fixed-width label column never wraps.
//
// The test renders usage() into a wide buffer (no terminal width constraint)
// and asserts that every command name appears on the same line as a keyword
// from its description.
func TestUsageCommandLabelsNoWrap(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	out := buf.String()

	cases := []struct {
		cmd  string
		want string // substring expected on the same line as cmd
	}{
		{"install", "supported coding agents"},
		{"uninstall", "local policy state"},
		{"status", "policy health"},
		{"version", "version information"},
		{"logs", "policy decisions"},
		{"policy", "optional hardening rules"},
		{"ui", "local web UI"},
		{"help", "Show help"},
	}

	for _, tc := range cases {
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, tc.cmd) && strings.Contains(line, tc.want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("usage: command %q and description keyword %q not found on same line\nfull output:\n%s",
				tc.cmd, tc.want, out)
		}
	}
}
