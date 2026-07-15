package daemonapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/wire"
)

// withTempHome points $HOME at a fresh temp dir for the duration of the test
// so wire.HookFallbackPath() (and compileOfflineRules' os.UserHomeDir() call)
// resolve to an isolated location instead of the real user's home.
func withTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestCompileOfflineRulesUsesHomeDir(t *testing.T) {
	home := withTempHome(t)

	rules, err := compileOfflineRules()
	if err != nil {
		t.Fatalf("compileOfflineRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 offline rules, got %d", len(rules))
	}

	byRuleID := map[string]wire.OfflineRule{}
	for _, r := range rules {
		byRuleID[r.RuleID] = r
	}

	selfRule, ok := byRuleID["file_policy/agentjail_self"]
	if !ok {
		t.Fatal("missing file_policy/agentjail_self offline rule")
	}
	if selfRule.Kind != wire.OfflineRuleKindPathPrefixWrite {
		t.Errorf("agentjail_self kind = %q, want path_prefix_write", selfRule.Kind)
	}
	wantPrefix := filepath.Join(home, ".agentjail")
	if len(selfRule.PathPrefixes) != 1 || selfRule.PathPrefixes[0] != wantPrefix {
		t.Errorf("agentjail_self PathPrefixes = %v, want [%s]", selfRule.PathPrefixes, wantPrefix)
	}

	secretsRule, ok := byRuleID["file_policy/agentjail_secrets"]
	if !ok {
		t.Fatal("missing file_policy/agentjail_secrets offline rule")
	}
	if secretsRule.Kind != wire.OfflineRuleKindPathRead {
		t.Errorf("agentjail_secrets kind = %q, want path_read", secretsRule.Kind)
	}
	wantSecretsKey := filepath.Join(home, ".agentjail", "secrets.key")
	found := false
	for _, p := range secretsRule.PathPrefixes {
		if p == wantSecretsKey {
			found = true
		}
	}
	if !found {
		t.Errorf("agentjail_secrets PathPrefixes = %v, want to include %s", secretsRule.PathPrefixes, wantSecretsKey)
	}

	mutationRule, ok := byRuleID["command_policy/no-policy-mutation"]
	if !ok {
		t.Fatal("missing command_policy/no-policy-mutation offline rule")
	}
	if mutationRule.Kind != wire.OfflineRuleKindCommandMutation {
		t.Errorf("no-policy-mutation kind = %q, want command_mutation", mutationRule.Kind)
	}
	if len(mutationRule.Binaries) == 0 || mutationRule.Binaries[0] != "agentjail" {
		t.Errorf("no-policy-mutation Binaries = %v, want [agentjail]", mutationRule.Binaries)
	}
	if len(mutationRule.Patterns) == 0 {
		t.Error("no-policy-mutation Patterns should be non-empty")
	}
}

func TestWriteHookFallbackAllowLevelHasNoOfflineRules(t *testing.T) {
	withTempHome(t)
	cfg := agentconfig.Default()
	cfg.DaemonUnreachable = agentconfig.DaemonUnreachableAllow

	if err := writeHookFallback(cfg); err != nil {
		t.Fatalf("writeHookFallback: %v", err)
	}

	fb := readHookFallback(t)
	if fb.Version != wire.HookFallbackVersion {
		t.Errorf("Version = %d, want %d", fb.Version, wire.HookFallbackVersion)
	}
	if fb.Level != "allow" {
		t.Errorf("Level = %q, want allow", fb.Level)
	}
	if len(fb.OfflineRules) != 0 {
		t.Errorf("expected no offline rules at allow level, got %d", len(fb.OfflineRules))
	}
}

func TestWriteHookFallbackDegradedLevelHasOfflineRules(t *testing.T) {
	withTempHome(t)
	cfg := agentconfig.Default()
	cfg.DaemonUnreachable = agentconfig.DaemonUnreachableDegraded

	if err := writeHookFallback(cfg); err != nil {
		t.Fatalf("writeHookFallback: %v", err)
	}

	fb := readHookFallback(t)
	if fb.Level != "degraded" {
		t.Errorf("Level = %q, want degraded", fb.Level)
	}
	if len(fb.OfflineRules) != 3 {
		t.Errorf("expected 3 offline rules at degraded level, got %d", len(fb.OfflineRules))
	}
}

func TestWriteHookFallbackDenyLevel(t *testing.T) {
	withTempHome(t)
	cfg := agentconfig.Default()
	cfg.DaemonUnreachable = agentconfig.DaemonUnreachableDeny

	if err := writeHookFallback(cfg); err != nil {
		t.Fatalf("writeHookFallback: %v", err)
	}

	fb := readHookFallback(t)
	if fb.Level != "deny" {
		t.Errorf("Level = %q, want deny", fb.Level)
	}
}

// TestWriteHookFallbackIsAtomicAndPrivate verifies the sidecar is written via
// temp+rename (no leftover temp file) with 0600 permissions.
func TestWriteHookFallbackIsAtomicAndPrivate(t *testing.T) {
	home := withTempHome(t)
	cfg := agentconfig.Default()

	if err := writeHookFallback(cfg); err != nil {
		t.Fatalf("writeHookFallback: %v", err)
	}

	path := wire.HookFallbackPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat sidecar: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("sidecar permissions = %o, want 0600", perm)
	}

	entries, err := os.ReadDir(filepath.Join(home, ".agentjail"))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "hook-fallback.json" {
			t.Errorf("unexpected leftover file in .agentjail: %s", e.Name())
		}
	}
}

// TestWriteHookFallbackEmptyLevelDefaultsToDegraded covers a zero-value
// PolicyConfig (as if daemon_unreachable were never set): the sidecar must say
// "degraded" (ADR 0074), never an empty/unknown string the hook can't parse.
//
// This is the last of the three places an unset level resolves, and the one
// that reaches an existing install: a policy.yaml written before ADR 0074 has
// no daemon_unreachable key, so this coercion — not config.Default() — is what
// their daemon actually applies.
func TestWriteHookFallbackEmptyLevelDefaultsToDegraded(t *testing.T) {
	withTempHome(t)
	cfg := &agentconfig.PolicyConfig{}

	if err := writeHookFallback(cfg); err != nil {
		t.Fatalf("writeHookFallback: %v", err)
	}

	fb := readHookFallback(t)
	if fb.Level != "degraded" {
		t.Errorf("Level = %q, want degraded for zero-value config", fb.Level)
	}
	// A degraded sidecar with no rules is indistinguishable from allow, so the
	// level alone is not the assertion that matters.
	if len(fb.OfflineRules) == 0 {
		t.Error("degraded sidecar carries no offline rules; enforcement would be vacuous")
	}
}

func readHookFallback(t *testing.T) wire.HookFallback {
	t.Helper()
	b, err := os.ReadFile(wire.HookFallbackPath())
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	var fb wire.HookFallback
	if err := json.Unmarshal(b, &fb); err != nil {
		t.Fatalf("unmarshal sidecar: %v", err)
	}
	return fb
}
