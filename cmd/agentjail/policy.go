// policy.go — `agentjail policy {list,enable,disable,help}` subcommand.
//
// # Rules directory
//
// Core rules (command_policy, file_policy, mcp_policy, resolver) are always
// loaded by the daemon; they live in ~/.agentjail/rules/ after install, are
// never disabled, and are ALWAYS refreshed on upgrade so stale versions never
// survive an update.  resolver.rego is the single producer of
// data.agentjail.decision — all other files contribute candidates only.
//
// Library rules (no_shell_init_write, no_hook_self_disable, …) are opt-in.
// Enabling copies the embedded .rego to ~/.agentjail/rules/<name>.rego.
// Disabling removes it. Both operations SIGHUP the daemon for zero-restart reload.
//
// # Daemon reload
//
// After enable/disable the command tries to SIGHUP agentjail-daemon via pgrep.
// If the daemon is not running, we warn but do not fail — the rule is correctly
// persisted and takes effect on the next daemon start.
//
// # Disable/enable semantics (ADR 0014)
//
// disable and enable now accept EITHER:
//   - a bare library file name (e.g. no_history_read) — file-copy/removal path
//   - a rule_id containing "/" (e.g. command_policy/no-sudo) — disabled_rules path
//
// Locked rule_ids (see rule_registry.go + resolver.rego) are refused.
// Disabling a non-locked CORE rule_id requires --force AND an interactive TTY
// confirm. Non-interactive invocations (no /dev/tty) are refused even with
// --force so that agents cannot bypass the guard.
//
// Every disable/enable mutation appends a structured event to
// ~/.agentjail/audit.log. If the append fails, the mutation is ABORTED
// (fail-closed on auditability).
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/ui"
)

// runPolicy is the top-level dispatcher for `agentjail policy <sub>`.
// It returns an exit code so the caller can os.Exit without capturing errors
// in the switch.
func runPolicy(args []string) int {
	if len(args) == 0 {
		printPolicyUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "list":
		return runPolicyList()
	case "enable":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail policy enable <name|rule_id>")
			return 2
		}
		return runPolicyEnable(args[1])
	case "disable":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail policy disable <name|rule_id> [--force]")
			return 2
		}
		// Scan args[1:] for --force and the rule name (order-independent).
		force := false
		var target string
		for _, a := range args[1:] {
			if a == "--force" || a == "-force" {
				force = true
			} else if target == "" {
				target = a
			}
		}
		if target == "" {
			fmt.Fprintln(os.Stderr, "usage: agentjail policy disable <name|rule_id> [--force]")
			return 2
		}
		return runPolicyDisableWithForce(target, force)
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail policy add <file.rego>")
			return 2
		}
		return runPolicyAdd(args[1])
	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail policy remove <name>")
			return 2
		}
		return runPolicyRemove(args[1])
	case "help", "-h", "--help":
		printPolicyUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "agentjail policy: unknown subcommand %q\n", args[0])
		printPolicyUsage(os.Stderr)
		return 2
	}
}

// rulesDir returns the path to the user's active rules directory.
func rulesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home dir: %w", err)
	}
	return filepath.Join(home, ".agentjail", "rules"), nil
}

// auditLogPath returns the path to ~/.agentjail/audit.log.
func auditLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home dir: %w", err)
	}
	return filepath.Join(home, ".agentjail", "audit.log"), nil
}

// matchGlob reports whether id matches pattern using path.Match with "/"
// as the segment separator (mirrors OPA's glob.match(p, ["/"], id)).
// Returns false on pattern errors (invalid patterns are rejected at config
// load time, so this should not happen in practice).
func matchGlob(pattern, id string) bool {
	ok, err := path.Match(pattern, id)
	return err == nil && ok
}

// isDisabledByConfig reports whether rule_id is suppressed by the
// disabled_rules list in cfg (uses the same /-bounded glob semantics
// as OPA's glob.match(p, ["/"], id)).
func isDisabledByConfig(cfg *config.PolicyConfig, id string) bool {
	if cfg == nil {
		return false
	}
	for _, p := range cfg.DisabledRules {
		if matchGlob(p, id) {
			return true
		}
	}
	return false
}

// runPolicyList prints a table of all known policy rules with their status.
func runPolicyList() int {
	return runPolicyListOutput(os.Stdout)
}

func runPolicyListOutput(w io.Writer) int {
	dir, err := rulesDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy list: %v\n", err)
		return 1
	}

	// Load config to read disabled_rules.
	cfgPath, err := policyConfigPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy list: %v\n", err)
		return 1
	}
	cfg, err := config.LoadOrDefault(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy list: load policy: %v\n", err)
		return 1
	}

	u := ui.New(w)
	const bodyIndent = "  "
	locked := LockedRuleIDs()

	// ------------------------------------------------------------------ //
	// Section 1: Core Rules — emit one row per rule_id in the registry
	// ------------------------------------------------------------------ //
	fmt.Fprintln(w, u.Section("Core Rules"))
	for _, entry := range ruleRegistry {
		if entry.Source != RuleSourceCore {
			continue
		}
		status := "on"
		if locked[entry.ID] {
			status = "locked"
		} else if isDisabledByConfig(cfg, entry.ID) {
			status = "off"
		}
		fmt.Fprintln(w, bodyIndent+policyRuleRow(u, status, entry.ID, entry.Description))
	}

	// ------------------------------------------------------------------ //
	// Section 2: Optional Hardening — library rules
	// ------------------------------------------------------------------ //
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Optional Hardening"))
	for _, entry := range ruleRegistry {
		if entry.Source != RuleSourceLibrary {
			continue
		}
		// Library file name is derived from the rule_id: "library/no-foo-bar"
		// → file name uses underscores: "no_foo_bar.rego".
		stem := ruleIDToLibraryStem(entry.ID)
		target := filepath.Join(dir, stem+".rego")
		fileInstalled := false
		if _, err := os.Stat(target); err == nil {
			fileInstalled = true
		}

		status := "off"
		if locked[entry.ID] {
			// Locked rule — show as locked regardless of file presence.
			status = "locked"
		} else if !fileInstalled {
			status = "off (not installed)"
		} else if isDisabledByConfig(cfg, entry.ID) {
			status = "off"
		} else {
			status = "on"
		}
		fmt.Fprintln(w, bodyIndent+policyRuleRow(u, status, entry.ID, entry.Description))
	}

	// ------------------------------------------------------------------ //
	// Section 3: Custom — rules discovered in ~/.agentjail/rules/ that are
	// not core or library files.
	// ------------------------------------------------------------------ //
	customInfos := discoverCustomRulesWithInfo(dir)
	if len(customInfos) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, u.Section("Custom"))
		for _, info := range customInfos {
			if len(info.ruleIDs) == 0 {
				// No extractable rule_ids — fall back to stem display.
				status := "on"
				if isDisabledByConfig(cfg, info.stem) {
					status = "off"
				}
				fmt.Fprintln(w, bodyIndent+policyRuleRow(u, status, info.stem, "User-defined custom rule"))
			} else {
				for _, id := range info.ruleIDs {
					status := "on"
					if isDisabledByConfig(cfg, id) {
						status = "off"
					}
					fmt.Fprintln(w, bodyIndent+policyRuleRow(u, status, id, "User-defined custom rule ("+info.stem+")"))
				}
			}
		}
	}

	fmt.Fprintln(w)
	return 0
}

// discoverCustomRules returns the base names (without .rego) of rego files
// in dir that are neither core nor library rules.
func discoverCustomRules(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	// Build a set of known core stems.
	coreStemSet := make(map[string]bool, len(coreRuleNames()))
	for _, n := range coreRuleNames() {
		coreStemSet[n] = true
	}
	// Build a set of known library stems.
	libStemSet := make(map[string]bool, len(libraryRuleNames()))
	for _, n := range libraryRuleNames() {
		libStemSet[n] = true
	}

	var customs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".rego") || strings.HasSuffix(n, "_test.rego") {
			continue
		}
		stem := strings.TrimSuffix(n, ".rego")
		if !coreStemSet[stem] && !libStemSet[stem] {
			customs = append(customs, stem)
		}
	}
	return customs
}

// ruleIDToLibraryStem converts a library rule_id like "library/no-foo-bar"
// to the file stem "no_foo_bar" (used for the .rego file in rules/).
func ruleIDToLibraryStem(ruleID string) string {
	// Strip "library/" prefix.
	name := strings.TrimPrefix(ruleID, "library/")
	// Replace hyphens with underscores to match the file naming convention.
	return strings.ReplaceAll(name, "-", "_")
}

// libraryStemToRuleID is the inverse of ruleIDToLibraryStem.
func libraryStemToRuleID(stem string) string {
	return "library/" + strings.ReplaceAll(stem, "_", "-")
}

func policyRuleRow(u *ui.UI, status, id, desc string) string {
	// Truncate status for badge to the simple keyword before any " (" suffix.
	badgeStatus := strings.SplitN(status, " ", 2)[0]
	return fmt.Sprintf("%-22s %-40s %s", policyStatusBadge(u, badgeStatus), id, desc)
}

func policyStatusBadge(u *ui.UI, status string) string {
	switch status {
	case "locked":
		return u.Badge("info", "locked")
	case "on":
		return u.Badge("ok", "on")
	default:
		return u.Badge("dim", "off")
	}
}

// runPolicyEnable enables the named library rule OR removes a rule_id from
// disabled_rules (re-enabling a previously disabled rule).
//
// Precedence:
//  1. If arg is a rule_id (contains "/" or is in the registry as a rule_id):
//     remove it from disabled_rules in policy.yaml, Save, SIGHUP, audit.
//  2. If arg is a bare library file stem (e.g. no_history_read):
//     copy the embedded .rego into ~/.agentjail/rules/, SIGHUP.
func runPolicyEnable(arg string) int {
	// Path 1: rule_id-based re-enable.
	if isRuleID(arg) {
		return runPolicyEnableRuleID(arg)
	}

	// Path 2: library file-stem enable (existing behavior).
	if !isLibraryRule(arg) {
		if isCoreRule(arg) {
			fmt.Fprintf(os.Stderr, "agentjail policy enable: %q is a core rule file; use the rule_id to re-enable a disabled rule_id (e.g. 'agentjail policy enable command_policy/no-sudo').\n", arg)
			return 1
		}
		fmt.Fprintf(os.Stderr, "error: unknown rule %q — run 'agentjail policy list' to see available rules.\n", arg)
		return 1
	}

	return runPolicyEnableLibraryFile(arg)
}

// runPolicyEnableRuleID removes ruleID from disabled_rules in policy.yaml.
func runPolicyEnableRuleID(ruleID string) int {
	cfgPath, err := policyConfigPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: %v\n", err)
		return 1
	}

	cfg, err := config.LoadOrDefault(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: load policy: %v\n", err)
		return 1
	}

	// Remove the ruleID from disabled_rules (exact match only — patterns are
	// not expanded back; the user added an exact id or a glob to disable).
	found := false
	filtered := cfg.DisabledRules[:0]
	for _, existing := range cfg.DisabledRules {
		if existing == ruleID {
			found = true
		} else {
			filtered = append(filtered, existing)
		}
	}
	cfg.DisabledRules = filtered

	if !found {
		fmt.Printf("note: %s was not in disabled_rules (already enabled or was suppressed via a glob pattern)\n", ruleID)
	}

	// Write audit log BEFORE Save — fail-closed on auditability.
	logPath, err := auditLogPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: audit log path: %v\n", err)
		return 1
	}
	if err := appendAuditEvent(logPath, "enable", ruleID); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: audit log write failed — aborting: %v\n", err)
		return 1
	}

	if err := config.Save(cfg, cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: save policy: %v\n", err)
		return 1
	}

	fmt.Printf("enabled: %s (removed from disabled_rules)\n", ruleID)
	sighupDaemon()
	return 0
}

// runPolicyEnableLibraryFile copies the embedded .rego for the named library
// rule into ~/.agentjail/rules/ (existing "file copy" behavior).
func runPolicyEnableLibraryFile(name string) int {
	content := libraryRuleContent(name)
	if content == nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: internal error: embedded content missing for %q\n", name)
		return 1
	}

	dir, err := rulesDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: mkdir %s: %v\n", dir, err)
		return 1
	}

	target := filepath.Join(dir, name+".rego")
	if err := os.WriteFile(target, content, 0o640); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy enable: write %s: %v\n", target, err)
		return 1
	}

	fmt.Printf("enabled: %s\n", name)
	sighupDaemon()
	return 0
}

// runPolicyDisable is the public entry point called from runPolicy (no --force).
func runPolicyDisable(arg string) int {
	return runPolicyDisableWithForce(arg, false)
}

// runPolicyDisableWithForce disables the named rule.
//
// Dispatch logic:
//  1. If arg is a rule_id (contains "/"):
//     - locked → refuse
//     - unknown → error
//     - library rule_id → add to disabled_rules (suppresses even installed files)
//     - core rule_id (non-locked) → require --force AND interactive TTY confirm
//  2. If arg is a bare library file stem (no "/"):
//     - existing file-removal behavior (removes the .rego file)
//
// In all rule_id cases: write audit before Save; abort if audit fails.
func runPolicyDisableWithForce(arg string, force bool) int {
	if isRuleID(arg) {
		return runPolicyDisableRuleID(arg, force)
	}

	// Bare library name — existing file-removal behavior.
	if isCoreRule(arg) {
		fmt.Fprintf(os.Stderr, "agentjail policy disable: %q is a core rule file. Use the rule_id to suppress it (e.g. 'agentjail policy disable command_policy/no-sudo --force').\n", arg)
		return 1
	}
	if !isLibraryRule(arg) {
		fmt.Fprintf(os.Stderr, "error: unknown rule %q — run 'agentjail policy list' to see available rules.\n", arg)
		return 1
	}

	return runPolicyDisableLibraryFile(arg)
}

// runPolicyDisableRuleID adds ruleID to disabled_rules in policy.yaml.
func runPolicyDisableRuleID(ruleID string, force bool) int {
	locked := LockedRuleIDs()

	// --- Check 1: locked set ---
	if locked[ruleID] {
		fmt.Fprintf(os.Stderr,
			"agentjail policy disable: %q is in the locked rule set and can NEVER be disabled.\n"+
				"  Locked rules protect agentjail's own integrity. This restriction is\n"+
				"  enforced in resolver.rego and cannot be overridden by policy.yaml.\n",
			ruleID)
		return 1
	}

	// Also check the resolver/* namespace (always locked).
	if strings.HasPrefix(ruleID, "resolver/") {
		fmt.Fprintf(os.Stderr,
			"agentjail policy disable: all resolver/* rules are locked (fail-safe default protection).\n")
		return 1
	}

	// --- Check 2: rule_id must be known (in registry) ---
	entry, known := RegistryByID(ruleID)
	if !known {
		fmt.Fprintf(os.Stderr,
			"agentjail policy disable: unknown rule_id %q — run 'agentjail policy list' to see available rules.\n",
			ruleID)
		return 1
	}

	// --- Check 3: core (non-locked) requires --force + interactive TTY ---
	if entry.Source == RuleSourceCore {
		if !force {
			fmt.Fprintf(os.Stderr,
				"agentjail policy disable: %q is a core rule. Disabling it weakens a security guarantee.\n"+
					"  Re-run with --force and confirm interactively to proceed.\n"+
					"  Example: agentjail policy disable %s --force\n",
				ruleID, ruleID)
			return 1
		}

		// --force is set: require interactive TTY confirm.
		if !confirmDisableInteractive(ruleID) {
			return 1
		}
	}

	// --- Perform the mutation ---
	cfgPath, err := policyConfigPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy disable: %v\n", err)
		return 1
	}

	cfg, err := config.LoadOrDefault(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy disable: load policy: %v\n", err)
		return 1
	}

	// Idempotent: skip if already present.
	for _, existing := range cfg.DisabledRules {
		if existing == ruleID {
			fmt.Printf("disabled: %s (was already in disabled_rules)\n", ruleID)
			return 0
		}
	}
	cfg.DisabledRules = append(cfg.DisabledRules, ruleID)

	// Write audit log BEFORE Save — fail-closed on auditability.
	logPath, err := auditLogPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy disable: audit log path: %v\n", err)
		return 1
	}
	if err := appendAuditEvent(logPath, "disable", ruleID); err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail policy disable: AUDIT LOG WRITE FAILED — aborting disable to maintain auditability.\n"+
				"  Error: %v\n"+
				"  Fix the audit log path (%s) and retry.\n",
			err, logPath)
		return 1
	}

	if err := config.Save(cfg, cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy disable: save policy: %v\n", err)
		return 1
	}

	fmt.Printf("disabled: %s (added to disabled_rules)\n", ruleID)
	sighupDaemon()
	return 0
}

// confirmDisableInteractive opens /dev/tty and prompts the user to confirm
// disabling a core rule. Returns true if the user confirms.
//
// If /dev/tty cannot be opened (non-interactive context, e.g. agent-invoked),
// the function prints a clear refusal and returns false — so even with
// --force, a non-interactive invocation cannot bypass the TTY guard.
func confirmDisableInteractive(ruleID string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail policy disable: REFUSED — no interactive terminal detected.\n"+
				"  Disabling core rule %q requires interactive confirmation.\n"+
				"  Even with --force, this command must be run in a terminal by a human.\n"+
				"  This restriction prevents agents from bypassing safety guardrails.\n",
			ruleID)
		return false
	}
	defer tty.Close()

	fmt.Fprintf(tty,
		"\n"+
			"  ⚠  WARNING: You are about to disable a core policy rule.\n"+
			"\n"+
			"  Rule:        %s\n"+
			"  Effect:      The protection enforced by this rule will be DROPPED.\n"+
			"  Reversible:  Yes — run 'agentjail policy enable %s' to re-enable.\n"+
			"  Audit:       This action is logged to ~/.agentjail/audit.log.\n"+
			"\n"+
			"  Type 'y' to confirm, anything else to cancel: ",
		ruleID, ruleID)

	reader := bufio.NewReader(tty)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if strings.ToLower(line) != "y" {
		fmt.Fprintln(tty, "Cancelled.")
		return false
	}
	return true
}

// runPolicyDisableLibraryFile removes the .rego file for a library rule
// (the original file-deletion behavior for bare library names).
func runPolicyDisableLibraryFile(name string) int {
	dir, err := rulesDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail policy disable: %v\n", err)
		return 1
	}

	target := filepath.Join(dir, name+".rego")
	removeErr := os.Remove(target)
	if removeErr != nil && !os.IsNotExist(removeErr) {
		fmt.Fprintf(os.Stderr, "agentjail policy disable: remove %s: %v\n", target, removeErr)
		return 1
	}

	if os.IsNotExist(removeErr) {
		fmt.Printf("disabled: %s (was already disabled)\n", name)
	} else {
		fmt.Printf("disabled: %s\n", name)
	}
	sighupDaemon()
	return 0
}

// isLibraryRule reports whether name is a known library rule file stem.
func isLibraryRule(name string) bool {
	for _, n := range libraryRuleNames() {
		if n == name {
			return true
		}
	}
	return false
}

// isCoreRule reports whether name is a known core rule file stem.
func isCoreRule(name string) bool {
	for _, n := range coreRuleNames() {
		if n == name {
			return true
		}
	}
	return false
}

// sighupDaemon finds the agentjail-daemon process and sends SIGHUP.
// Warns (but does not fail) if the daemon is not running.
func sighupDaemon() {
	pid, err := findDaemonPID()
	if err != nil || pid == 0 {
		fmt.Fprintln(os.Stderr, "warning: agentjail-daemon not running; rule will take effect on next start.")
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot find daemon process (pid %d): %v\n", pid, err)
		return
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		fmt.Fprintf(os.Stderr, "warning: SIGHUP daemon (pid %d): %v\n", pid, err)
	}
}

// findDaemonPID uses pgrep to find the agentjail-daemon PID.
// Returns 0 if not found or on error.
func findDaemonPID() (int, error) {
	out, err := exec.Command("pgrep", "-f", "agentjail-daemon").Output()
	if err != nil {
		return 0, nil // not running
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return 0, nil
	}
	// pgrep may return multiple lines; take the first
	parts := strings.Fields(line)
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("parse pgrep output: %w", err)
	}
	return pid, nil
}

func printPolicyUsage(w io.Writer) {
	u := ui.New(w)
	const bodyIndent = "  "

	fmt.Fprintln(w, u.Header("agentjail policy"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Usage"))
	fmt.Fprintln(w, bodyIndent+"agentjail policy <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Commands"))
	cmds := []struct {
		name string
		desc string
	}{
		{"list", "Show core, optional, and custom policy rules with status"},
		{"enable <name|rule_id>", "Enable a library rule or re-enable a disabled rule_id"},
		{"disable <name|rule_id> [--force]", "Disable a rule (rule_ids require --force + TTY for core rules)"},
		{"add <file.rego>", "Validate + install a custom rule file into ~/.agentjail/rules/"},
		{"remove <name>", "Remove a custom rule by file stem (refuses core/library names)"},
		{"help", "Show policy help"},
	}
	for _, c := range cmds {
		fmt.Fprintln(w, bodyIndent+u.KeyValue(c.name, c.desc, ""))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Examples"))
	examples := []string{
		"agentjail policy list",
		"agentjail policy enable no_history_read",
		"agentjail policy enable command_policy/no-sudo",
		"agentjail policy disable no_history_read",
		"agentjail policy disable command_policy/no-sudo --force",
		"agentjail policy add ~/my_rule.rego",
		"agentjail policy remove my_rule",
	}
	for _, ex := range examples {
		fmt.Fprintln(w, bodyIndent+ex)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Notes"))
	notes := []string{
		"Locked rules (file_policy/agentjail_self, library/no-daemon-kill, library/no-hook-self-disable,",
		"  command_policy/no-policy-mutation, resolver/default) can NEVER be disabled — they protect",
		"  agentjail's own integrity.",
		"Core rules require --force AND interactive terminal confirmation to disable.",
		"Non-interactive invocations (scripts, agents) are refused even with --force.",
		"Every disable/enable is logged to ~/.agentjail/audit.log.",
	}
	for _, n := range notes {
		fmt.Fprintln(w, bodyIndent+n)
	}
	fmt.Fprintln(w)
}

// installCoreRules copies all embedded core .rego files to the rules directory,
// REPLACING any stale versions that already exist.  Core rules are
// agentjail-managed and must always match the embedded version shipped with the
// binary — replacing them on upgrade is the critical fix for the fail-open bug
// where a stale else-chain command_policy.rego would silently ignore library
// rule candidates.
//
// Non-core files (enabled library rules, user-authored rules) are never
// touched by this function: allCoreRuleBytes() only returns files from the
// embedded policies/ directory, so custom *.rego files in the rules dir are
// preserved unchanged.
//
// Each file is written atomically (temp file in the same directory + os.Rename)
// so a crash cannot leave a half-written core rule.
func installCoreRules(rulesDir string) error {
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", rulesDir, err)
	}
	for name, content := range allCoreRuleBytes() {
		dst := filepath.Join(rulesDir, name+".rego")
		// Write atomically: temp file in same dir, then rename.
		tmp, err := os.CreateTemp(rulesDir, ".core-rule-*.rego.tmp")
		if err != nil {
			return fmt.Errorf("create temp file for %s: %w", name, err)
		}
		tmpName := tmp.Name()
		if _, err := tmp.Write(content); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("write temp file for %s: %w", name, err)
		}
		if err := tmp.Chmod(0o640); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("chmod temp file for %s: %w", name, err)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpName)
			return fmt.Errorf("close temp file for %s: %w", name, err)
		}
		if err := os.Rename(tmpName, dst); err != nil {
			os.Remove(tmpName)
			return fmt.Errorf("rename temp to %s: %w", dst, err)
		}
	}
	return nil
}

// policyRuleDescription returns a human-readable description for legacy
// file-stem based display. Kept for backward compatibility with any callers
// that use it. For rule_id based display, use RuleEntry.Description.
func policyRuleDescription(name string) string {
	switch name {
	case "command_policy":
		return "Shell command guardrails"
	case "file_policy":
		return "Sensitive file protection"
	case "mcp_policy":
		return "MCP server allowlist"
	case "no_app_binary_write":
		return "Block writes into app executable paths"
	case "no_daemon_kill":
		return "Block attempts to stop agentjail-daemon"
	case "no_history_read":
		return "Block shell history reads"
	case "no_hook_self_disable":
		return "Block attempts to remove agent hooks"
	case "no_launchctl":
		return "Block persistence and background job launchers"
	case "no_shell_eval":
		return "Block shell eval and obfuscation patterns"
	case "no_shell_init_write":
		return "Block writes to shell startup files"
	default:
		return "Optional hardening rule"
	}
}
