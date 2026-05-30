// decision_producer_guard_test.go — enforces that resolver.rego is the ONLY
// file on the hook path that declares `decision`/`default decision`.
//
// Background (ADR 0014 §0b): all policy files contribute `candidate` entries;
// resolver.rego aggregates them and is the sole producer of
// data.agentjail.decision. A direct `decision = ...` declaration in any other
// hook-path file would either cause an eval_conflict_error (if it maps to the
// same package) or silently diverge from the resolver's priority logic.
//
// Scope of the walk:
//   - agentpolicy/policies/**/*.rego (source of truth)
//   - cmd/agentjail/policies/**/*.rego (embedded mirror for core rules)
//   - cmd/agentjail/library/**/*.rego (embedded mirror for library rules)
//
// Exclusions (not on the hook path per ADR 0011 + ADR 0014):
//   - resolver.rego — the one file that IS allowed to declare decision
//   - default.rego — legacy credential-broker path (package agentjail.default)
//   - agentpolicy/policies/experimental/ — not loaded on the hook path
//   - agentpolicy/policies/lib/ — utility packages in different package namespaces
//   - *_test.rego — OPA unit tests; reference decision in assertions, not declarations
//
// What counts as a declaration (vs. a reference):
//   A line matches if it starts (after optional leading whitespace) with one of:
//     decision =    (complete rule assignment, e.g. old-style decision = {...} if)
//     decision :=   (local-variable assignment used as a rule head)
//     default decision  (default rule)
//   A line like `agentjail.decision.action` or `data.agentjail.decision` or
//   `decision ==` (comparison in a test) does NOT match — those are references.
package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// reDeclaration matches lines that declare a top-level `decision` rule.
// It intentionally does NOT match:
//   - `decision ==` (equality comparison in tests/conditions)
//   - `data.agentjail.decision` or `agentjail.decision` (qualified references)
//   - `rm_rf.decision` or any prefixed reference
//
// The pattern anchors to the start of a trimmed line to catch rule heads,
// and uses a negative lookbehind equivalent (character-class check) to ensure
// "decision" is not preceded by a dot or alphanumeric (which would make it a
// field access or qualified reference).
var reDeclaration = regexp.MustCompile(`^(default\s+)?decision\s*(:=|=)`)

// reComment matches lines that are pure Rego comments (after trimming).
var reComment = regexp.MustCompile(`^#`)

// containsDecisionDeclaration returns true if the file at path has at least
// one line that is a top-level `decision` rule declaration (not a reference).
func containsDecisionDeclaration(path string) (bool, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if reComment.MatchString(line) {
			continue
		}
		if reDeclaration.MatchString(line) {
			return true, lineNum, nil
		}
	}
	return false, 0, scanner.Err()
}

// repoRoot returns the absolute repo root path relative to this test file.
func repoRootFromGuard(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = .../cmd/agentjail/decision_producer_guard_test.go
	// repo root = ../..
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// TestOnlyResolverDeclaresDecision walks the hook-path rego tree and fails if
// any file other than resolver.rego declares `decision`/`default decision`.
func TestOnlyResolverDeclaresDecision(t *testing.T) {
	t.Parallel()

	root := repoRootFromGuard(t)

	// Directories to walk, relative to repo root.
	walkRoots := []string{
		filepath.Join(root, "agentpolicy", "policies"),
		filepath.Join(root, "cmd", "agentjail", "policies"),
		filepath.Join(root, "cmd", "agentjail", "library"),
	}

	for _, walkRoot := range walkRoots {
		walkRoot := walkRoot
		if _, err := os.Stat(walkRoot); os.IsNotExist(err) {
			// Mirror directories are optional (e.g. policies/ mirror may not
			// exist in all CI environments), skip rather than fail.
			continue
		}

		err := filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Skip excluded subtrees.
				name := d.Name()
				if name == "experimental" || name == "lib" {
					return filepath.SkipDir
				}
				return nil
			}

			name := d.Name()

			// Only inspect .rego files.
			if !strings.HasSuffix(name, ".rego") {
				return nil
			}

			// Exclude test files — they reference decision in assertions.
			if strings.HasSuffix(name, "_test.rego") {
				return nil
			}

			// Exclude resolver.rego — the one allowed producer.
			if name == "resolver.rego" {
				return nil
			}

			// Exclude default.rego — legacy credential-broker path.
			if name == "default.rego" {
				return nil
			}

			// Check for a declaration.
			found, lineNum, walkErr := containsDecisionDeclaration(path)
			if walkErr != nil {
				t.Errorf("read %s: %v", path, walkErr)
				return nil
			}
			if found {
				// Make the path relative to the repo root for readability.
				rel, _ := filepath.Rel(root, path)
				t.Errorf(
					"%s:%d declares `decision` directly — only resolver.rego may produce data.agentjail.decision.\n"+
						"Migrate this rule to a `candidate contains r if { ... }` entry instead.\n"+
						"See ADR 0014 §0b.",
					rel, lineNum,
				)
			}
			return nil
		})
		if err != nil {
			t.Errorf("walk %s: %v", walkRoot, err)
		}
	}
}
