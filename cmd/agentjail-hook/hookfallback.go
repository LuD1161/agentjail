// Offline daemon-unreachable handling (ADR 0050).
//
// The hook is stdlib-only (see the package doc in main.go): it cannot read
// policy.yaml or run OPA. Instead, the daemon serializes the resolved
// daemon_unreachable level (and, for "degraded", a compiled offline
// critical-denylist) into a small JSON sidecar (internal/wire.HookFallback)
// which this file reads and matches with plain stdlib string/path/regexp
// operations — no new external dependency.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/LuD1161/agentjail/internal/shellparse"
	"github.com/LuD1161/agentjail/internal/wire"
)

// Level string constants mirror agentpolicy/config.DaemonUnreachableLevel's
// values without importing that package (which pulls in OPA, violating the
// hook's stdlib-only contract). wire.HookFallback.Level carries these as a
// plain string on the wire for exactly this reason.
const (
	levelAllow    = "allow"
	levelDegraded = "degraded"
	levelDeny     = "deny"
)

// restartInstructions is appended to every fail-open banner/deny reason so a
// human reading the terminal always sees the exact recovery command.
const restartInstructions = "Restart: agentjail daemon restart    (diagnose: agentjail doctor)"

// loadHookFallback reads and parses the daemon-written hook-fallback sidecar
// (wire.HookFallbackPath()). The second return value reports whether a
// valid, current-version sidecar was found.
//
// ANY failure mode — file missing, unreadable, unparseable JSON, or a
// Version that doesn't match wire.HookFallbackVersion — returns
// (wire.HookFallback{Level: levelAllow}, false). This is the
// backward-compatible safe fallback from ADR 0050: a fresh install or an old
// daemon that never wrote a sidecar behaves exactly like today (fail-open
// allow). The hook must never block a tool call because the sidecar is
// absent.
func loadHookFallback() (wire.HookFallback, bool) {
	fallback := wire.HookFallback{Level: levelAllow}

	b, err := os.ReadFile(wire.HookFallbackPath())
	if err != nil {
		return fallback, false
	}
	var fb wire.HookFallback
	if err := json.Unmarshal(b, &fb); err != nil {
		return fallback, false
	}
	if fb.Version != wire.HookFallbackVersion {
		return fallback, false
	}
	switch fb.Level {
	case levelAllow, levelDegraded, levelDeny:
		return fb, true
	default:
		// Unknown level value (e.g. a future daemon version's new level
		// talking to an older hook binary) — fail open rather than guess.
		return fallback, false
	}
}

// printFailOpenBanner writes a loud, per-occurrence stderr notice naming the
// current protection level and the exact restart command. Unlike the old
// one-shot warning (gated by the fail-open-warned sentinel and shown only
// once per "session"), this prints on EVERY fail-open occurrence — the
// silent-drift problem ADR 0050 exists to fix. The fail_open telemetry event
// already fires every occurrence (unchanged); this brings the human-visible
// notice to parity with it.
func printFailOpenBanner(level string) {
	switch level {
	case levelDegraded:
		fmt.Fprintln(os.Stderr, "⚠ agentjail: daemon unreachable — running at REDUCED protection (degraded).")
		fmt.Fprintln(os.Stderr, "  Critical self-protection rules still enforced; other policy is OFF.")
		fmt.Fprintln(os.Stderr, "  "+restartInstructions)
	case levelDeny:
		fmt.Fprintln(os.Stderr, "⚠ agentjail: daemon unreachable — DENYING by policy (deny).")
		fmt.Fprintln(os.Stderr, "  "+restartInstructions)
	default: // levelAllow, or any fallback value
		fmt.Fprintln(os.Stderr, failOpenFriendlyMessage)
		fmt.Fprintln(os.Stderr, "  "+restartInstructions)
	}
}

// failOpenDecision is the resolved allow/deny outcome for a fail-open
// occurrence, given the sidecar's level and (if known) the tool call.
type failOpenDecision struct {
	Deny   bool
	Reason string
	RuleID string
}

// resolveFailOpenDecision determines what the hook should do when the
// daemon is unreachable, given the sidecar and (if known) the tool call.
//
// toolName == "" means the tool identity is not known at this call site
// (e.g. the hook failed to read/parse its own stdin before a request could
// ever be built) — "degraded" cannot match an unknown call so it allows;
// "deny" still denies unconditionally regardless of what the call was.
func resolveFailOpenDecision(fb wire.HookFallback, toolName string, toolInput map[string]interface{}, cwd string) failOpenDecision {
	switch fb.Level {
	case levelDeny:
		return failOpenDecision{
			Deny:   true,
			Reason: "daemon unreachable — failing closed (policy.yaml: daemon_unreachable: deny). " + restartInstructions,
			RuleID: "daemon_unreachable/deny",
		}
	case levelDegraded:
		if toolName != "" {
			if rule, ok := matchOfflineRules(fb, toolName, toolInput, cwd); ok {
				return failOpenDecision{
					Deny:   true,
					Reason: rule.Reason + " (offline degraded enforcement — daemon unreachable; " + restartInstructions + ")",
					RuleID: rule.RuleID,
				}
			}
		}
		return failOpenDecision{
			Deny:   false,
			Reason: "daemon unreachable — degraded mode, no offline critical rule matched",
		}
	default: // levelAllow
		return failOpenDecision{
			Deny:   false,
			Reason: "daemon unreachable - fail-open",
		}
	}
}

// matchOfflineRules checks a tool call against the sidecar's compiled
// offline critical-denylist. Returns the first matching rule, or ok=false if
// nothing matched ("degraded" is allow-the-rest by design).
func matchOfflineRules(fb wire.HookFallback, toolName string, toolInput map[string]interface{}, cwd string) (rule wire.OfflineRule, ok bool) {
	for _, r := range fb.OfflineRules {
		switch r.Kind {
		case wire.OfflineRuleKindPathPrefixWrite:
			if toolName == "Write" || toolName == "Edit" {
				if matchesPathPrefixRule(r, toolInput, cwd) {
					return r, true
				}
			}
		case wire.OfflineRuleKindPathRead:
			if toolName == "Read" {
				if matchesPathPrefixRule(r, toolInput, cwd) {
					return r, true
				}
			}
		case wire.OfflineRuleKindCommandMutation:
			if toolName == "Bash" {
				if matchesCommandMutationRule(r, toolInput) {
					return r, true
				}
			}
		}
	}
	return wire.OfflineRule{}, false
}

// matchesPathPrefixRule checks every path-shaped tool_input field
// (file_path/path/old_path — same fields internal/policyeval.NormalizeToolInput
// canonicalizes online) against the rule's PathPrefixes after stdlib-only
// tilde/$HOME expansion.
func matchesPathPrefixRule(r wire.OfflineRule, toolInput map[string]interface{}, cwd string) bool {
	for _, field := range []string{"file_path", "path", "old_path"} {
		raw, ok := toolInput[field].(string)
		if !ok || raw == "" {
			continue
		}
		p := normalizeOfflinePath(raw, cwd)
		if p == "" {
			continue
		}
		for _, prefix := range r.PathPrefixes {
			if prefix != "" && pathUnderPrefix(p, prefix) {
				return true
			}
		}
	}
	return false
}

// normalizeOfflinePath expands a leading "~"/"~/" or embedded "$HOME" token
// and resolves a relative path against cwd, then filepath.Clean's the
// result. This is a stdlib-only mirror of the tilde/$HOME handling in
// internal/policyeval.CanonicalizePath / ExpandCommandPaths (that package is
// off-limits to the hook — it transitively imports OPA via agentpolicy/policy,
// which would break the hook's stdlib-only contract).
//
// Unlike the daemon's online canonicalization, this does NOT call
// filepath.EvalSymlinks: the fail-open path has no meaningful time/IO budget
// and no daemon to fall back on if a symlink walk is slow or fails. Prefix
// matching against the daemon's already home-resolved absolute prefixes is
// exact enough for the locked, offline critical-denylist.
func normalizeOfflinePath(raw, cwd string) string {
	if raw == "" {
		return ""
	}
	p := raw
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if p == "~" {
			p = home
		} else if strings.HasPrefix(p, "~/") {
			p = filepath.Join(home, p[2:])
		}
		p = strings.ReplaceAll(p, "$HOME", home)
	}
	if !filepath.IsAbs(p) {
		if cwd != "" {
			p = filepath.Join(cwd, p)
		} else if wd, err := os.Getwd(); err == nil {
			p = filepath.Join(wd, p)
		}
	}
	return filepath.Clean(p)
}

// pathUnderPrefix reports whether p equals prefix or is nested under it
// (never a bare string-prefix match, so "~/.agentjail-decoy" does not match
// a "~/.agentjail" rule).
func pathUnderPrefix(p, prefix string) bool {
	prefix = filepath.Clean(prefix)
	if p == prefix {
		return true
	}
	return strings.HasPrefix(p, prefix+string(filepath.Separator))
}

// matchesCommandMutationRule parses tool_input.command via internal/shellparse
// (stdlib-only, hardened to unwrap sh -c/$(...)/wrappers) and checks both
// that one of the rule's Binaries is present AND the raw command string
// matches one of the rule's regexp Patterns — mirroring
// command_policy.rego's _mentions_agentjail + _is_policy_mutation gate.
func matchesCommandMutationRule(r wire.OfflineRule, toolInput map[string]interface{}) bool {
	cmd, ok := toolInput["command"].(string)
	if !ok || cmd == "" {
		return false
	}
	parsed := shellparse.Parse(cmd)
	binMatch := len(r.Binaries) == 0 // no Binaries listed means "any command"
	for _, want := range r.Binaries {
		for _, got := range parsed.Binaries {
			if got == want {
				binMatch = true
			}
		}
	}
	if !binMatch {
		return false
	}
	for _, pat := range r.Patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue // a malformed pattern from the daemon never panics the hook
		}
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}
