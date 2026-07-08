package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/wire"
)

// ---------------------------------------------------------------------------
// Unit tests: loadHookFallback
// ---------------------------------------------------------------------------

// writeSidecar writes fb as the hook-fallback sidecar under home, mirroring
// what the daemon would have written.
func writeSidecar(t *testing.T, home string, fb wire.HookFallback) {
	t.Helper()
	dir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	b, err := json.Marshal(fb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hook-fallback.json"), b, 0o600); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
}

func TestLoadHookFallback_MissingSidecarDefaultsAllow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fb, ok := loadHookFallback()
	if ok {
		t.Error("expected ok=false for missing sidecar")
	}
	if fb.Level != levelAllow {
		t.Errorf("Level = %q, want %q", fb.Level, levelAllow)
	}
}

func TestLoadHookFallback_UnparseableJSONDefaultsAllow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hook-fallback.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	fb, ok := loadHookFallback()
	if ok {
		t.Error("expected ok=false for unparseable sidecar")
	}
	if fb.Level != levelAllow {
		t.Errorf("Level = %q, want %q", fb.Level, levelAllow)
	}
}

func TestLoadHookFallback_WrongVersionDefaultsAllow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeSidecar(t, home, wire.HookFallback{Version: 99, Level: levelDeny})
	fb, ok := loadHookFallback()
	if ok {
		t.Error("expected ok=false for wrong version")
	}
	if fb.Level != levelAllow {
		t.Errorf("Level = %q, want %q", fb.Level, levelAllow)
	}
}

func TestLoadHookFallback_UnknownLevelDefaultsAllow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeSidecar(t, home, wire.HookFallback{Version: wire.HookFallbackVersion, Level: "bogus"})
	fb, ok := loadHookFallback()
	if ok {
		t.Error("expected ok=false for unknown level")
	}
	if fb.Level != levelAllow {
		t.Errorf("Level = %q, want %q", fb.Level, levelAllow)
	}
}

func TestLoadHookFallback_ValidSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeSidecar(t, home, wire.HookFallback{Version: wire.HookFallbackVersion, Level: levelDegraded})
	fb, ok := loadHookFallback()
	if !ok {
		t.Fatal("expected ok=true for valid sidecar")
	}
	if fb.Level != levelDegraded {
		t.Errorf("Level = %q, want %q", fb.Level, levelDegraded)
	}
}

// ---------------------------------------------------------------------------
// Unit tests: path normalization + offline rule matching
// ---------------------------------------------------------------------------

func TestNormalizeOfflinePath_TildeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got := normalizeOfflinePath("~/.agentjail/policy.yaml", "")
	want := filepath.Join(home, ".agentjail", "policy.yaml")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeOfflinePath_DollarHomeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got := normalizeOfflinePath("$HOME/.agentjail/secrets.key", "")
	want := filepath.Join(home, ".agentjail", "secrets.key")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeOfflinePath_RelativeResolvedAgainstCWD(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	got := normalizeOfflinePath("foo.txt", "/tmp/project")
	want := filepath.Join("/tmp/project", "foo.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPathUnderPrefix(t *testing.T) {
	cases := []struct {
		p, prefix string
		want      bool
	}{
		{"/home/dev/.agentjail", "/home/dev/.agentjail", true},
		{"/home/dev/.agentjail/policy.yaml", "/home/dev/.agentjail", true},
		{"/home/dev/.agentjail-decoy/x", "/home/dev/.agentjail", false},
		{"/home/dev/other", "/home/dev/.agentjail", false},
	}
	for _, c := range cases {
		if got := pathUnderPrefix(c.p, c.prefix); got != c.want {
			t.Errorf("pathUnderPrefix(%q, %q) = %v, want %v", c.p, c.prefix, got, c.want)
		}
	}
}

func TestMatchesCommandMutationRule(t *testing.T) {
	rule := wire.OfflineRule{
		Binaries: []string{"agentjail"},
		Patterns: []string{`\bpolicy\s+(disable|enable|add|remove)\b`},
	}
	cases := []struct {
		cmd  string
		want bool
	}{
		{"agentjail policy disable no-sudo", true},
		{"sh -c 'agentjail policy disable no-sudo'", true},
		{"agentjail policy list", false},
		{"echo hi", false},
		{"/usr/local/bin/agentjail policy disable foo", true},
	}
	for _, c := range cases {
		got := matchesCommandMutationRule(rule, map[string]interface{}{"command": c.cmd})
		if got != c.want {
			t.Errorf("matchesCommandMutationRule(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// resolveFailOpenDecision decision table
// ---------------------------------------------------------------------------

func offlineRulesFixture(home string) []wire.OfflineRule {
	return []wire.OfflineRule{
		{
			Kind:         wire.OfflineRuleKindPathPrefixWrite,
			RuleID:       "file_policy/agentjail_self",
			Reason:       "self-protection",
			PathPrefixes: []string{filepath.Join(home, ".agentjail")},
		},
		{
			Kind:   wire.OfflineRuleKindPathRead,
			RuleID: "file_policy/agentjail_secrets",
			Reason: "secrets protection",
			PathPrefixes: []string{
				filepath.Join(home, ".agentjail", "secrets.key"),
				filepath.Join(home, ".agentjail", "secrets"),
			},
		},
		{
			Kind:     wire.OfflineRuleKindCommandMutation,
			RuleID:   "command_policy/no-policy-mutation",
			Reason:   "no self-mutation",
			Binaries: []string{"agentjail"},
			Patterns: []string{`\bpolicy\s+(disable|enable|add|remove)\b`},
		},
	}
}

func TestResolveFailOpenDecision_Allow(t *testing.T) {
	fb := wire.HookFallback{Level: levelAllow}
	d := resolveFailOpenDecision(fb, "Write", map[string]interface{}{"file_path": "/tmp/x"}, "/tmp")
	if d.Deny {
		t.Errorf("expected allow at level=allow, got deny (%s)", d.Reason)
	}
}

func TestResolveFailOpenDecision_Deny(t *testing.T) {
	fb := wire.HookFallback{Level: levelDeny}
	d := resolveFailOpenDecision(fb, "Read", map[string]interface{}{"file_path": "/etc/hostname"}, "/tmp")
	if !d.Deny {
		t.Error("expected deny at level=deny")
	}
	if !strings.Contains(d.Reason, "agentjail daemon restart") {
		t.Errorf("deny reason missing restart instructions: %q", d.Reason)
	}
}

func TestResolveFailOpenDecision_DegradedDeniesWriteToPolicyYAML(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fb := wire.HookFallback{Level: levelDegraded, OfflineRules: offlineRulesFixture(home)}
	d := resolveFailOpenDecision(fb, "Write", map[string]interface{}{
		"file_path": "~/.agentjail/policy.yaml",
	}, "/tmp/project")
	if !d.Deny {
		t.Fatal("expected deny for Write to ~/.agentjail/policy.yaml under degraded")
	}
	if d.RuleID != "file_policy/agentjail_self" {
		t.Errorf("RuleID = %q, want file_policy/agentjail_self", d.RuleID)
	}
}

func TestResolveFailOpenDecision_DegradedDeniesReadOfSecretsKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fb := wire.HookFallback{Level: levelDegraded, OfflineRules: offlineRulesFixture(home)}
	d := resolveFailOpenDecision(fb, "Read", map[string]interface{}{
		"file_path": "$HOME/.agentjail/secrets.key",
	}, "/tmp/project")
	if !d.Deny {
		t.Fatal("expected deny for Read of ~/.agentjail/secrets.key under degraded")
	}
	if d.RuleID != "file_policy/agentjail_secrets" {
		t.Errorf("RuleID = %q, want file_policy/agentjail_secrets", d.RuleID)
	}
}

func TestResolveFailOpenDecision_DegradedDeniesPolicyMutationBash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fb := wire.HookFallback{Level: levelDegraded, OfflineRules: offlineRulesFixture(home)}
	d := resolveFailOpenDecision(fb, "Bash", map[string]interface{}{
		"command": "sh -c 'agentjail policy disable no-sudo'",
	}, "/tmp/project")
	if !d.Deny {
		t.Fatal("expected deny for policy-mutation Bash under degraded")
	}
	if d.RuleID != "command_policy/no-policy-mutation" {
		t.Errorf("RuleID = %q, want command_policy/no-policy-mutation", d.RuleID)
	}
}

func TestResolveFailOpenDecision_DegradedAllowsBenignCalls(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fb := wire.HookFallback{Level: levelDegraded, OfflineRules: offlineRulesFixture(home)}

	readCase := resolveFailOpenDecision(fb, "Read", map[string]interface{}{"file_path": "/etc/hostname"}, "/tmp/project")
	if readCase.Deny {
		t.Errorf("expected allow for benign Read, got deny (%s)", readCase.Reason)
	}

	bashCase := resolveFailOpenDecision(fb, "Bash", map[string]interface{}{"command": "echo hi"}, "/tmp/project")
	if bashCase.Deny {
		t.Errorf("expected allow for benign Bash, got deny (%s)", bashCase.Reason)
	}
}

func TestResolveFailOpenDecision_UnknownToolNameAllowsUnderDegraded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	fb := wire.HookFallback{Level: levelDegraded, OfflineRules: offlineRulesFixture(home)}
	// toolName == "" simulates a read-stdin/parse-input failure: the hook has
	// no idea what the call was, so degraded cannot match anything.
	d := resolveFailOpenDecision(fb, "", nil, "")
	if d.Deny {
		t.Error("expected allow when tool identity is unknown under degraded")
	}
}

func TestResolveFailOpenDecision_UnknownToolNameStillDeniesUnderDeny(t *testing.T) {
	fb := wire.HookFallback{Level: levelDeny}
	d := resolveFailOpenDecision(fb, "", nil, "")
	if !d.Deny {
		t.Error("expected deny unconditionally under deny, even with unknown tool identity")
	}
}

// ---------------------------------------------------------------------------
// Banner text
// ---------------------------------------------------------------------------

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = orig

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	_ = r.Close()
	return string(buf[:n])
}

func TestPrintFailOpenBanner_Allow(t *testing.T) {
	out := captureStderr(t, func() { printFailOpenBanner(levelAllow) })
	if !strings.Contains(out, "daemon not running - policy enforcement disabled") {
		t.Errorf("allow banner missing friendly message: %q", out)
	}
	if !strings.Contains(out, "agentjail daemon restart") {
		t.Errorf("allow banner missing restart instructions: %q", out)
	}
}

func TestPrintFailOpenBanner_Degraded(t *testing.T) {
	out := captureStderr(t, func() { printFailOpenBanner(levelDegraded) })
	if !strings.Contains(out, "REDUCED protection") {
		t.Errorf("degraded banner missing REDUCED protection text: %q", out)
	}
	if !strings.Contains(out, "degraded") {
		t.Errorf("degraded banner missing level name: %q", out)
	}
	if !strings.Contains(out, "agentjail daemon restart") {
		t.Errorf("degraded banner missing restart instructions: %q", out)
	}
}

func TestPrintFailOpenBanner_Deny(t *testing.T) {
	out := captureStderr(t, func() { printFailOpenBanner(levelDeny) })
	if !strings.Contains(out, "deny") {
		t.Errorf("deny banner missing level name: %q", out)
	}
	if !strings.Contains(out, "agentjail daemon restart") {
		t.Errorf("deny banner missing restart instructions: %q", out)
	}
}

// ---------------------------------------------------------------------------
// End-to-end subprocess tests: {allow, deny, degraded} x daemon-down
// ---------------------------------------------------------------------------

// TestHookE2E_DenyLevelDeniesWhenDaemonDown verifies the full subprocess
// binary denies (exit 2, Claude convention) when daemon_unreachable: deny is
// in effect and the daemon socket does not exist.
func TestHookE2E_DenyLevelDeniesWhenDaemonDown(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeSidecar(t, home, wire.HookFallback{Version: wire.HookFallbackVersion, Level: levelDeny})

	nonexistentSock := filepath.Join(shortSockDir(t), "no-daemon.sock")
	stdin := makeStdinJSON("Read", map[string]interface{}{"file_path": "/etc/hostname"}, "session-deny")

	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + nonexistentSock})

	if code != 2 {
		t.Errorf("expected exit 2 (deny), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(string(stderr), "agentjail daemon restart") {
		t.Errorf("deny stderr missing restart instructions: %q", stderr)
	}
}

// TestHookE2E_DegradedDeniesLockedRuleAttacks verifies the three locked-rule
// attack classes are denied offline under degraded, while a benign call is
// allowed, all with the daemon socket absent.
func TestHookE2E_DegradedDeniesLockedRuleAttacks(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeSidecar(t, home, wire.HookFallback{
		Version:      wire.HookFallbackVersion,
		Level:        levelDegraded,
		OfflineRules: offlineRulesFixture(home),
	})
	nonexistentSock := filepath.Join(shortSockDir(t), "no-daemon.sock")

	t.Run("write policy.yaml denied", func(t *testing.T) {
		stdin := makeStdinJSON("Write", map[string]interface{}{
			"file_path": filepath.Join(home, ".agentjail", "policy.yaml"),
			"content":   "mcp: {}",
		}, "session-degraded-1")
		_, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + nonexistentSock})
		if code != 2 {
			t.Errorf("expected exit 2 (deny), got %d; stderr=%q", code, stderr)
		}
		if !strings.Contains(string(stderr), "REDUCED protection") {
			t.Errorf("stderr missing degraded banner: %q", stderr)
		}
	})

	t.Run("read secrets.key denied", func(t *testing.T) {
		stdin := makeStdinJSON("Read", map[string]interface{}{
			"file_path": filepath.Join(home, ".agentjail", "secrets.key"),
		}, "session-degraded-2")
		_, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + nonexistentSock})
		if code != 2 {
			t.Errorf("expected exit 2 (deny), got %d; stderr=%q", code, stderr)
		}
	})

	t.Run("bash policy disable denied", func(t *testing.T) {
		stdin := makeStdinJSON("Bash", map[string]interface{}{
			"command": "sh -c 'agentjail policy disable no-sudo'",
		}, "session-degraded-3")
		_, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + nonexistentSock})
		if code != 2 {
			t.Errorf("expected exit 2 (deny), got %d; stderr=%q", code, stderr)
		}
	})

	t.Run("benign read allowed", func(t *testing.T) {
		stdin := makeStdinJSON("Read", map[string]interface{}{"file_path": "/etc/hostname"}, "session-degraded-4")
		stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + nonexistentSock})
		if code != 0 {
			t.Errorf("expected exit 0 (allow), got %d; stdout=%q stderr=%q", code, stdout, stderr)
		}
		var out claudeHookOutput
		if err := json.Unmarshal(stdout, &out); err != nil {
			t.Fatalf("decode stdout: %v (stdout=%q)", err, stdout)
		}
		if out.HookSpecificOutput.PermissionDecision != "allow" {
			t.Errorf("permissionDecision = %q, want allow", out.HookSpecificOutput.PermissionDecision)
		}
	})

	t.Run("benign bash allowed", func(t *testing.T) {
		stdin := makeStdinJSON("Bash", map[string]interface{}{"command": "echo hi"}, "session-degraded-5")
		stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + nonexistentSock})
		if code != 0 {
			t.Errorf("expected exit 0 (allow), got %d; stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
}

// TestHookE2E_AllowLevelUnchangedWhenDaemonDown verifies the "allow" level
// (explicit sidecar, not just a missing one) behaves exactly like today.
func TestHookE2E_AllowLevelUnchangedWhenDaemonDown(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeSidecar(t, home, wire.HookFallback{Version: wire.HookFallbackVersion, Level: levelAllow})

	nonexistentSock := filepath.Join(shortSockDir(t), "no-daemon.sock")
	stdin := makeStdinJSON("Write", map[string]interface{}{
		"path":    filepath.Join(home, ".agentjail", "policy.yaml"),
		"content": "x",
	}, "session-allow")

	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + nonexistentSock})
	if code != 0 {
		t.Errorf("expected exit 0 (allow), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
}
