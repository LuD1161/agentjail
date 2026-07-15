package daemonapp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/wire"
)

// writeHookFallback serializes the current config's daemon_unreachable level
// (and, for "degraded", the compiled offline critical-denylist) into the
// hook-fallback sidecar (internal/wire.HookFallbackPath) atomically
// (temp file + rename, 0600) — see ADR 0050.
//
// This is best-effort by design: a write failure is logged (and audited, if
// possible) but never blocks daemon startup or a SIGHUP reload. Startup
// order matters for the caller: call this AFTER the daemon has successfully
// started listening (or successfully reloaded), never before, so the
// sidecar never reflects a config the daemon itself failed to adopt.
func writeHookFallback(cfg *agentconfig.PolicyConfig) error {
	level := string(cfg.DaemonUnreachable)
	if level == "" {
		level = string(agentconfig.DaemonUnreachableDegraded)
	}

	fb := wire.HookFallback{
		Version:      wire.HookFallbackVersion,
		Level:        level,
		OfflineRules: []wire.OfflineRule{},
	}
	if level == string(agentconfig.DaemonUnreachableDegraded) {
		rules, err := compileOfflineRules()
		if err != nil {
			// Non-fatal: ship the sidecar with an empty offline_rules list
			// rather than not writing it at all — "degraded" then behaves
			// like "allow" offline until the next successful reload, which
			// is logged loudly here so it is not silent.
			slog.Warn("compile offline rules for hook-fallback sidecar failed; writing with empty offline_rules", "err", err)
		} else {
			fb.OfflineRules = rules
		}
	}

	path := wire.HookFallbackPath()
	if err := writeJSONAtomic(path, fb); err != nil {
		return fmt.Errorf("write hook-fallback sidecar %s: %w", path, err)
	}
	slog.Info("hook-fallback sidecar written", "path", path, "level", level, "offline_rules", len(fb.OfflineRules))
	return nil
}

// writeJSONAtomic marshals v to JSON and writes it to path via temp file +
// rename with 0600 permissions, so a concurrent hook read of path never
// observes a partially-written file.
func writeJSONAtomic(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".hook-fallback-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// Best-effort cleanup if we fail before rename.
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}
	return nil
}

// compileOfflineRules translates the locked-rule set (the source of truth
// lives in agentpolicy/policies/resolver.rego's locked_rules constant, plus
// the dedicated secrets-store protection alongside it — see ADR 0050 and
// ADR 0032) into the stdlib-matchable OfflineRule shape the hook enforces
// offline under "degraded". The daemon is the only place these are defined;
// the hook only matches.
//
// Kept in sync by hand with:
//   - agentpolicy/policies/file_policy.rego (is_agentjail_self,
//     file_policy/agentjail_self — LOCKED)
//   - the secrets-store key/dir (~/.agentjail/secrets.key,
//     ~/.agentjail/secrets/) protected by the phantom-credential broker
//     (ADR 0032, ADR 0048)
//   - agentpolicy/policies/command_policy.rego (_is_policy_mutation,
//     command_policy/no-policy-mutation — LOCKED)
//
// A change to any of the above should be mirrored here; drift means
// "degraded" offline enforcement quietly stops matching what OPA enforces
// online.
func compileOfflineRules() ([]wire.OfflineRule, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}
	agentjailDir := filepath.Join(home, ".agentjail")

	return []wire.OfflineRule{
		{
			Kind:         wire.OfflineRuleKindPathPrefixWrite,
			RuleID:       "file_policy/agentjail_self",
			Reason:       "writes under ~/.agentjail are denied offline (daemon unreachable, self-protection is permanently locked)",
			PathPrefixes: []string{agentjailDir},
		},
		{
			Kind:   wire.OfflineRuleKindPathRead,
			RuleID: "file_policy/agentjail_secrets",
			Reason: "reads of the agentjail secrets store are denied offline (daemon unreachable, secrets protection is permanently locked)",
			PathPrefixes: []string{
				filepath.Join(agentjailDir, "secrets.key"),
				filepath.Join(agentjailDir, "secrets"),
			},
		},
		{
			Kind:     wire.OfflineRuleKindCommandMutation,
			RuleID:   "command_policy/no-policy-mutation",
			Reason:   "commands that mutate agentjail policy or configuration are denied offline (daemon unreachable, self-protection is permanently locked)",
			Binaries: []string{"agentjail"},
			// Simplified, offline-matchable mirror of command_policy.rego's
			// _is_policy_mutation. Not a full reimplementation (no shell
			// redirect-into-~/.agentjail check, which needs a Bash-specific
			// path scan) — see the rego file for the authoritative rule.
			Patterns: []string{
				`\bpolicy\s+(disable|enable|add|remove)\b`,
				`\bmcp\s+(allow|block)\b`,
				`\bgrant\s+(approve|deny)\b`,
				`\b(trust|untrust)\b`,
				`--persist\b`,
				`\bupdate\b`,
			},
		},
	}, nil
}
