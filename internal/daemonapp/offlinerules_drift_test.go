package daemonapp

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/wire"
)

// The ADR 0074 default (daemon_unreachable: degraded) rests on one property:
// everything degraded denies offline is already denied online by a permanently
// locked rule, so it can never refuse a call a healthy daemon would have
// allowed. compileOfflineRules mirrors the rego BY HAND, so that property is a
// convention, not a mechanism — and a convention that silently stops holding
// takes the default's justification with it.
//
// These tests make the drift a build-time failure instead. They read the rego
// source rather than the compiled bundle deliberately: locked_rules is a Rego
// constant precisely so it lives outside anything Go/config can influence, and
// the whole point here is to compare against that source of truth.

// regoPoliciesDir walks up to the repo's agentpolicy/policies directory.
// Worktree layouts make a relative path fragile, hence the walk (same approach
// as agentpolicy/internal/policy's tests).
//
// Fatal, not Skip: a drift test that quietly skips when it cannot find its
// input is exactly the green-but-vacuous test this file exists to prevent.
func regoPoliciesDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for dir := cwd; ; {
		cand := filepath.Join(dir, "agentpolicy", "policies", "resolver.rego")
		if _, err := os.Stat(cand); err == nil {
			return filepath.Join(dir, "agentpolicy", "policies")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate agentpolicy/policies/resolver.rego walking up from %s", cwd)
		}
		dir = parent
	}
}

func readRego(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(regoPoliciesDir(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

var (
	lockedRulesBlockRe = regexp.MustCompile(`(?s)locked_rules\s*:=\s*\{(.*?)\}`)
	quotedRe           = regexp.MustCompile(`"([^"]+)"`)
	policyMutationRe   = regexp.MustCompile("(?s)_is_policy_mutation if \\{(.*?)\\n\\}")
	regexMatchRe       = regexp.MustCompile("regex\\.match\\(`([^`]+)`")
)

// parseLockedRules extracts resolver.rego's locked_rules constant.
func parseLockedRules(t *testing.T) map[string]bool {
	t.Helper()
	block := lockedRulesBlockRe.FindStringSubmatch(readRego(t, "resolver.rego"))
	if block == nil {
		t.Fatal("could not find the locked_rules constant in resolver.rego; the drift test can no longer see its source of truth")
	}
	out := map[string]bool{}
	for _, m := range quotedRe.FindAllStringSubmatch(block[1], -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("parsed locked_rules as empty; refusing to pass vacuously")
	}
	return out
}

// parseOnlineMutationPatterns extracts every regex used by command_policy.rego's
// _is_policy_mutation rule bodies.
func parseOnlineMutationPatterns(t *testing.T) map[string]bool {
	t.Helper()
	src := readRego(t, "command_policy.rego")
	blocks := policyMutationRe.FindAllStringSubmatch(src, -1)
	if len(blocks) == 0 {
		t.Fatal("could not find any _is_policy_mutation rule bodies in command_policy.rego")
	}
	out := map[string]bool{}
	for _, b := range blocks {
		for _, m := range regexMatchRe.FindAllStringSubmatch(b[1], -1) {
			out[m[1]] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no patterns out of _is_policy_mutation; refusing to pass vacuously")
	}
	return out
}

// offlineOnlyLockedRuleExceptions are locked rule IDs with no offline
// counterpart, each for a stated reason. A locked rule missing from
// compileOfflineRules and absent here fails the test — an omission has to be
// named, never silent (the habit ADR 0034 pushes for platform backends).
var offlineOnlyLockedRuleExceptions = map[string]string{
	// resolver/default is the resolver's own fallthrough verdict, not a
	// matchable tool-call rule; there is nothing for the hook to pattern-match.
	"resolver/default": "resolver fallthrough, not a tool-call rule",
}

// TestOfflineRuleIDsMatchLockedRules is the containment half of the ADR 0074
// argument: offline may not deny anything that is not locked online.
func TestOfflineRuleIDsMatchLockedRules(t *testing.T) {
	withTempHome(t)
	locked := parseLockedRules(t)

	rules, err := compileOfflineRules()
	if err != nil {
		t.Fatalf("compileOfflineRules: %v", err)
	}

	offline := map[string]bool{}
	for _, r := range rules {
		offline[r.RuleID] = true
	}

	// No offline rule may deny something the online policy does not lock. If
	// this fires, degraded can refuse a call a healthy daemon would allow and
	// the default's justification is gone.
	for id := range offline {
		if !locked[id] {
			t.Errorf("offline rule %q is not in resolver.rego's locked_rules: degraded would deny what online may allow (ADR 0074)", id)
		}
	}

	// Every locked rule must be mirrored offline or named as an exception.
	for id := range locked {
		if offline[id] || offlineOnlyLockedRuleExceptions[id] != "" {
			continue
		}
		t.Errorf("locked rule %q has no offline counterpart in compileOfflineRules and is not a named exception: degraded silently stopped enforcing it", id)
	}
}

// TestOfflineCommandPatternsMatchRego is the same argument for the command
// rule, where the mirroring is regex-by-regex.
func TestOfflineCommandPatternsMatchRego(t *testing.T) {
	withTempHome(t)
	online := parseOnlineMutationPatterns(t)

	rules, err := compileOfflineRules()
	if err != nil {
		t.Fatalf("compileOfflineRules: %v", err)
	}

	var offline []string
	for _, r := range rules {
		if r.Kind == wire.OfflineRuleKindCommandMutation {
			offline = append(offline, r.Patterns...)
		}
	}
	if len(offline) == 0 {
		t.Fatal("no offline command-mutation patterns compiled")
	}

	// Every offline pattern must exist verbatim online. A pattern that drifted
	// (loosened, or edited on one side only) over-matches relative to OPA.
	for _, p := range offline {
		if !online[p] {
			t.Errorf("offline pattern %q has no verbatim match in command_policy.rego's _is_policy_mutation: it may deny what online allows", p)
		}
	}

	// The reverse gap is allowed but must stay deliberate. Offline omits the
	// shell-redirect rule (it needs a Bash-specific path scan the hook does not
	// do), so it under-matches — safe for the subset argument, but a NEW
	// unmirrored online pattern should be a decision, not an accident.
	onlineOnly := map[string]bool{}
	for p := range online {
		if strings.Contains(p, `\.agentjail`) && strings.Contains(p, "tee") {
			continue // the known, documented redirect carve-out
		}
		onlineOnly[p] = true
	}
	for _, p := range offline {
		delete(onlineOnly, p)
	}
	for p := range onlineOnly {
		t.Errorf("online pattern %q is enforced by OPA but not mirrored offline and is not the documented redirect exception: degraded under-enforces a locked rule (safe, but undecided — mirror it or name it here)", p)
	}
}
