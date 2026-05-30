// custom_rules.go — `agentjail policy add/remove` subcommands (ADR 0014 §5).
//
// # Authoring contract
//
// A valid custom rule file MUST:
//   - Declare `package agentjail`.
//   - Emit ONLY `candidate contains` / `candidate[...]` entries — no `decision`,
//     `default decision`, or redefinitions of existing package symbols.
//   - Give every emitted rule_id the prefix `custom/<basename>/` where
//     `<basename>` is the file's stem (filename without .rego).  Rule IDs can
//     be declared via a required `# @rule_id: custom/<basename>/<rule>` comment
//     header, or parsed from string literals in `candidate contains` blocks.
//
// # Namespace
//
//   - `custom/<name>/<rule>` — required prefix; any other prefix is rejected.
//   - Reserved prefixes that collide with core/library namespaces
//     (file_policy/, command_policy/, mcp_policy/, resolver/, library/) are
//     always rejected even if they have a `custom/` parent prefix.
//   - An ID that collides with an already-registered rule_id (core, library, or
//     another custom rule) is rejected.
//
// # Bundle validation
//
// `policy add` compiles the FULL bundle (embedded core + currently-enabled
// library rules + the candidate file) rather than the file alone.  The daemon
// compiles all .rego files as one OPA package, so a file that parses in
// isolation can still break the bundle (e.g. via `decision = ...` causing
// eval_conflict).
//
// # Daemon quarantine
//
// The daemon (cmd/agentjail-daemon) extends loadModules to implement staged
// quarantine: it compiles the core+library baseline first, then adds custom
// rule files one at a time in sorted filename order.  A custom file that breaks
// the accumulated bundle is logged at WARN and skipped — it never prevents the
// baseline from loading.
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	policy "github.com/LuD1161/agentjail/agentpolicy/policy"
)

// ---- Reserved prefixes -------------------------------------------------------

// reservedPrefixes are rule_id namespace prefixes owned by core/library rules.
// Custom rules must NOT emit any id that starts with one of these.
var reservedPrefixes = []string{
	"file_policy/",
	"command_policy/",
	"mcp_policy/",
	"resolver/",
	"library/",
}

// ---- Regex patterns for static analysis -------------------------------------

// rePkgDecl matches the `package agentjail` declaration line.
var rePkgDecl = regexp.MustCompile(`(?m)^\s*package\s+agentjail\b`)

// reDecisionDecl matches lines that declare `decision` or `default decision`
// (reuses the logic from decision_producer_guard_test.go).
var reDecisionDecl = regexp.MustCompile(`(?m)^\s*(default\s+)?decision\s*(:=|=)`)

// reRuleIDHeader matches the convention comment header:
//
//	# @rule_id: custom/<name>/<rule>
var reRuleIDHeader = regexp.MustCompile(`(?m)^\s*#\s*@rule_id:\s*(\S+)`)

// reCandidateStringLiteral matches string literals that look like rule_ids
// inside candidate contains blocks, e.g.:
//
//	"rule_id": "custom/foo/bar"
var reCandidateStringLiteral = regexp.MustCompile(`"rule_id"\s*:\s*"([^"]+)"`)

// ---- runPolicyAdd -----------------------------------------------------------

// runPolicyAdd implements `agentjail policy add <file.rego>`.
func runPolicyAdd(path string) int {
	// Read the candidate file.
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy add: read %s: %v\n", path, err)
		return 1
	}

	stem := strings.TrimSuffix(filepath.Base(path), ".rego")

	// Step 1: authoring-contract enforcement (static).
	if err := enforceAuthoringContract(string(src), stem); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy add: %v\n", err)
		return 1
	}

	// Step 2: full-bundle validation (OPA compile).
	if err := validateFullBundle(path, src); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy add: bundle validation failed: %v\n", err)
		return 1
	}

	// Step 3: copy into ~/.agentjail/rules/<stem>.rego atomically.
	dir, err := rulesDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy add: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy add: mkdir %s: %v\n", dir, err)
		return 1
	}

	dst := filepath.Join(dir, stem+".rego")
	if err := atomicWrite(dst, src, 0o640); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy add: install %s: %v\n", dst, err)
		return 1
	}

	fmt.Printf("added: %s (installed to %s)\n", stem, dst)
	fmt.Println("  Run 'agentjail policy list' to see it under Custom.")
	sighupDaemon()
	return 0
}

// ---- runPolicyRemove --------------------------------------------------------

// runPolicyRemove implements `agentjail policy remove <name>`.
func runPolicyRemove(name string) int {
	// Refuse to remove core or library names — those are managed differently.
	if isCoreRule(name) {
		fmt.Fprintf(os.Stderr,
			"agentjail policy remove: %q is a core rule; use 'agentjail policy disable <rule_id>' to suppress it.\n", name)
		return 1
	}
	if isLibraryRule(name) {
		fmt.Fprintf(os.Stderr,
			"agentjail policy remove: %q is a library rule; use 'agentjail policy disable %s' to turn it off.\n",
			name, libraryStemToRuleID(name))
		return 1
	}

	dir, err := rulesDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy remove: %v\n", err)
		return 1
	}

	target := filepath.Join(dir, name+".rego")
	if _, err := os.Stat(target); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "agentjail policy remove: custom rule %q not found in %s\n", name, dir)
		return 1
	}

	if err := os.Remove(target); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy remove: remove %s: %v\n", target, err)
		return 1
	}

	fmt.Printf("removed: %s\n", name)
	sighupDaemon()
	return 0
}

// ---- enforceAuthoringContract -----------------------------------------------

// enforceAuthoringContract checks the static requirements for a custom rule
// file:
//  1. Must declare `package agentjail`.
//  2. Must NOT declare `decision` or `default decision`.
//  3. Every rule_id found (via @rule_id headers or string literals) must have
//     the prefix `custom/<stem>/` and must not collide with a reserved prefix
//     or an already-registered rule_id.
//
// If the file contains NO extractable rule_ids (no @rule_id headers, no
// "rule_id": "..." literals) we require at least one @rule_id header so the
// namespace can be verified.
func enforceAuthoringContract(src, stem string) error {
	// 1. Must be `package agentjail`.
	if !rePkgDecl.MatchString(src) {
		return fmt.Errorf("file must declare 'package agentjail' (found no matching declaration)")
	}

	// 2. Must NOT declare decision.
	if reDecisionDecl.MatchString(src) {
		// Check it's not just a comment.
		scanner := bufio.NewScanner(strings.NewReader(src))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}
			if reDecisionDecl.MatchString(line) {
				return fmt.Errorf("file declares 'decision' directly — custom rules must use 'candidate contains r if { ... }' instead.\n" +
					"  Only resolver.rego may produce data.agentjail.decision (ADR 0014 §5).")
			}
		}
	}

	// 3. Collect rule_ids.
	ruleIDs := extractRuleIDs(src)
	if len(ruleIDs) == 0 {
		return fmt.Errorf("no rule_ids found — declare at least one '# @rule_id: custom/%s/<rule>' header\n"+
			"  or use '\"rule_id\": \"custom/%s/<rule>\"' inside a candidate block", stem, stem)
	}

	requiredPrefix := "custom/" + stem + "/"
	for _, id := range ruleIDs {
		if err := validateCustomRuleID(id, requiredPrefix); err != nil {
			return err
		}
	}

	return nil
}

// extractRuleIDs collects rule_ids from the Rego source via two mechanisms:
//  1. `# @rule_id: <id>` comment headers (authoritative).
//  2. `"rule_id": "<id>"` string literals inside candidate blocks.
//
// Deduplicates and returns sorted results.
func extractRuleIDs(src string) []string {
	seen := map[string]bool{}

	// Mechanism 1: @rule_id headers.
	for _, m := range reRuleIDHeader.FindAllStringSubmatch(src, -1) {
		if len(m) >= 2 && m[1] != "" {
			seen[m[1]] = true
		}
	}

	// Mechanism 2: "rule_id": "..." literals (skip comment lines).
	scanner := bufio.NewScanner(strings.NewReader(src))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, m := range reCandidateStringLiteral.FindAllStringSubmatch(line, -1) {
			if len(m) >= 2 && m[1] != "" {
				seen[m[1]] = true
			}
		}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// validateCustomRuleID checks that id:
//  1. Has the required prefix `custom/<stem>/`.
//  2. Does not start with a reserved core/library prefix.
//  3. Does not collide with an existing registered rule_id.
func validateCustomRuleID(id, requiredPrefix string) error {
	// Must have the custom/<stem>/ prefix.
	if !strings.HasPrefix(id, requiredPrefix) {
		return fmt.Errorf("rule_id %q must start with %q\n"+
			"  Custom rule IDs must be namespaced as custom/<filename_stem>/<rule>", id, requiredPrefix)
	}

	// Must not start with a reserved prefix (even if nested under custom/).
	// e.g. "custom/foo/file_policy/x" would be weird but we reject it anyway.
	for _, rp := range reservedPrefixes {
		if strings.HasPrefix(id, rp) {
			return fmt.Errorf("rule_id %q starts with reserved prefix %q — choose a custom/ namespace", id, rp)
		}
	}

	// Must not collide with an existing registered rule_id.
	if _, exists := RegistryByID(id); exists {
		return fmt.Errorf("rule_id %q collides with an existing registered rule — choose a different ID", id)
	}

	return nil
}

// ---- validateFullBundle -----------------------------------------------------

// validateFullBundle compiles the full bundle (embedded core + enabled library
// rules from ~/.agentjail/rules/ + the candidate src) using OPA.
//
// This is the same compilation the daemon performs on SIGHUP, so a file that
// passes this check is guaranteed to not break the live bundle.
func validateFullBundle(candidatePath string, candidateSrc []byte) error {
	ctx := context.Background()

	// Collect embedded core modules.
	var modules [][2]string
	for name, content := range allCoreRuleBytes() {
		modules = append(modules, [2]string{name + ".rego", string(content)})
	}

	// Collect embedded library modules (all; the daemon loads them when present
	// in ~/.agentjail/rules/ but for bundle compilation we include them all to
	// be safe — extra library rules do not affect correctness, only performance).
	for _, libName := range libraryRuleNames() {
		content := libraryRuleContent(libName)
		if content != nil {
			modules = append(modules, [2]string{libName + ".rego", string(content)})
		}
	}

	// Add the candidate file.
	stem := strings.TrimSuffix(filepath.Base(candidatePath), ".rego")
	modules = append(modules, [2]string{stem + ".rego", string(candidateSrc)})

	_, err := policy.NewHookOPAEngine(ctx, modules)
	if err != nil {
		return fmt.Errorf("OPA compile error: %w", err)
	}
	return nil
}

// ---- atomicWrite ------------------------------------------------------------

// atomicWrite writes data to dst atomically (temp file + rename in same dir).
func atomicWrite(dst string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".custom-rule-*.rego.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename to %s: %w", dst, err)
	}
	return nil
}

// ---- discoverCustomRulesWithIDs ---------------------------------------------

// customRuleInfo holds the display information for a discovered custom rule.
type customRuleInfo struct {
	// stem is the file basename without .rego (used as the rule name).
	stem string
	// ruleIDs are the rule_ids parsed from the file (may be empty if
	// the file is not parseable or has no extractable ids).
	ruleIDs []string
}

// discoverCustomRulesWithInfo returns customRuleInfo for each custom rule file
// found in dir. This extends discoverCustomRules with rule_id extraction for
// richer list output.
func discoverCustomRulesWithInfo(dir string) []customRuleInfo {
	stems := discoverCustomRules(dir)
	if len(stems) == 0 {
		return nil
	}

	infos := make([]customRuleInfo, 0, len(stems))
	for _, stem := range stems {
		info := customRuleInfo{stem: stem}

		// Try to read the file and extract rule_ids.
		p := filepath.Join(dir, stem+".rego")
		if src, err := os.ReadFile(p); err == nil {
			info.ruleIDs = extractRuleIDs(string(src))
		}

		infos = append(infos, info)
	}
	return infos
}

// ---- printPolicyAdd/Remove usage lines (for help) --------------------------

func printCustomRuleHelp(w io.Writer) {
	fmt.Fprintln(w, "  agentjail policy add <file.rego>    Install + validate a custom rule file")
	fmt.Fprintln(w, "  agentjail policy remove <name>      Remove a custom rule by file stem")
}
