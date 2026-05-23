package agents

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
)

// defaultLookPath is the package-level fallback for env.LookPath when it is nil.
// It delegates to exec.LookPath so production code never calls exec.LookPath
// directly (tests can inject a replacement via Env.LookPath).
var defaultLookPath = exec.LookPath

// Codex is the agent implementation for OpenAI's Codex CLI.
// It wires the agentjail PreToolUse hook into ~/.codex/hooks.json,
// enables features.hooks in ~/.codex/config.toml (strict safe-mode only),
// and prints the manual trust instruction (hook trust cannot be persisted).
type Codex struct{}

// ID returns "codex".
func (Codex) ID() string { return "codex" }

// DisplayName returns "Codex".
func (Codex) DisplayName() string { return "Codex" }

// Detect reports whether ~/.codex/ exists under env.Home OR the codex binary
// is resolvable via env.LookPath (falling back to exec.LookPath when nil).
func (Codex) Detect(env Env) Detection {
	codexDir := filepath.Join(env.Home, ".codex")
	if _, err := os.Stat(codexDir); err == nil {
		return Detection{Present: true, Evidence: "~/.codex/ exists"}
	}

	lp := env.LookPath
	if lp == nil {
		// Default to os/exec lookup — imported lazily to avoid a hard import
		// in the production binary for the trivial no-codex case.
		lp = defaultLookPath
	}
	if p, err := lp("codex"); err == nil && p != "" {
		return Detection{Present: true, Evidence: "codex on PATH at " + p}
	}

	return Detection{Present: false}
}

// Install wires the agentjail hook into ~/.codex/hooks.json, enables
// features.hooks in ~/.codex/config.toml (strict safe-mode), and prints the
// manual trust instruction.
//
// The operation is idempotent. All file mutations go through writeFileAtomic.
func (Codex) Install(env Env) error {
	if err := os.MkdirAll(filepath.Join(env.Home, ".codex"), 0o700); err != nil {
		return fmt.Errorf("install codex: mkdir ~/.codex: %w", err)
	}

	// Step 1 — merge hooks.json entry.
	if err := codexMergeHooksJSON(env); err != nil {
		return fmt.Errorf("install codex: hooks.json: %w", err)
	}

	// Step 2 — ensure features.hooks = true in config.toml (strict safe-mode).
	if err := codexEnsureFeaturesHooks(env); err != nil {
		return fmt.Errorf("install codex: config.toml: %w", err)
	}

	// Step 3 — trust cannot be persisted; print manual instruction.
	printCodexTrustInstruction(codexHookCommand(env))

	return nil
}

// Uninstall removes the agentjail hooks.json entry (command == env.HookBin).
// It leaves features.hooks and trust state untouched. Idempotent.
func (Codex) Uninstall(env Env) error {
	hooksPath := filepath.Join(env.Home, ".codex", "hooks.json")

	existing, err := os.ReadFile(hooksPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("uninstall codex: read hooks.json: %w", err)
	}

	updated, changed, err := codexRemoveHookEntry(existing, env.HookBin)
	if err != nil {
		return fmt.Errorf("uninstall codex: parse hooks.json: %w", err)
	}
	if !changed {
		return nil
	}

	return writeFileAtomic(hooksPath, updated, 0o600)
}

// Status reports hooks.json entry presence, features.hooks enablement, and the
// permanent trust degraded note (trust cannot be persisted by an installer).
func (Codex) Status(env Env) Status {
	var notes []string
	installed := true

	// Check hooks.json.
	hooksPath := filepath.Join(env.Home, ".codex", "hooks.json")
	b, err := os.ReadFile(hooksPath)
	if err != nil {
		installed = false
		notes = append(notes, "hooks.json not found or unreadable")
	} else {
		_, found, _ := codexHookEntryPresent(b, env.HookBin)
		if !found {
			installed = false
			notes = append(notes, "agentjail entry not in hooks.json")
		}
	}

	// Check features.hooks in config.toml.
	tomlPath := filepath.Join(env.Home, ".codex", "config.toml")
	tb, err2 := os.ReadFile(tomlPath)
	if err2 != nil {
		notes = append(notes, "config.toml not found (features.hooks unknown)")
	} else {
		enabled, ambiguous := codexFeaturesHooksState(tb)
		if ambiguous {
			notes = append(notes, "features.hooks state ambiguous in config.toml (manual check required)")
		} else if !enabled {
			notes = append(notes, "features.hooks not enabled in config.toml")
		}
	}

	// Trust is always degraded — cannot be persisted.
	notes = append(notes, codexTrustDegradedNote)

	return Status{Installed: installed, Notes: notes}
}

// ---- hooks.json helpers -------------------------------------------------------

// codexHooksRoot is the JSON schema for ~/.codex/hooks.json.
type codexHooksRoot struct {
	Hooks map[string][]codexMatcherGroup `json:"hooks"`
}

type codexMatcherGroup struct {
	Matcher string      `json:"matcher"`
	Hooks   []codexHook `json:"hooks"`
}

type codexHook struct {
	Type          string `json:"type"`
	Command       string `json:"command"`
	Timeout       int    `json:"timeout,omitempty"`
	StatusMessage string `json:"statusMessage,omitempty"`
}

// codexHookCommand returns the canonical registered hook command for Codex:
// env.HookBin + " --agent=codex". This mirrors cursorHookCommand in agent_cursor.go.
func codexHookCommand(env Env) string {
	return env.HookBin + " --agent=codex"
}

// codexHookCmdMatches reports whether cmd matches EITHER the legacy bare form
// (env.HookBin) OR the canonical new form (env.HookBin + " --agent=codex").
// This two-form matcher is used by all read paths (Status, Uninstall, MergeHookEntry)
// so that existing installs with the legacy command are recognised after upgrade.
func codexHookCmdMatches(cmd, hookBin string) bool {
	return cmd == hookBin || cmd == hookBin+" --agent=codex"
}

// codexMergeHooksJSON reads (or creates) ~/.codex/hooks.json and merges a
// PreToolUse entry for the canonical codex hook command. Idempotent. If the
// file exists but is malformed JSON, returns an error and leaves it untouched.
func codexMergeHooksJSON(env Env) error {
	hooksPath := filepath.Join(env.Home, ".codex", "hooks.json")

	var raw []byte
	if b, err := os.ReadFile(hooksPath); err == nil {
		raw = b
	}

	updated, changed, err := codexMergeHookEntry(raw, env.HookBin)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	return writeFileAtomic(hooksPath, updated, 0o600)
}

// codexMergeHookEntry merges a PreToolUse entry for the canonical codex hook
// command (hookBin + " --agent=codex") into raw hooks.json content.
// Returns (newJSON, changed, error).
//
// Migration algorithm (replace-in-place, no duplicates):
//  1. Remove any entry matching EITHER the legacy bare form OR the new form.
//  2. Insert the canonical new form.
//
// This ensures that an upgrade from a legacy bare-command install results in
// exactly one entry with the new form (idempotent on re-run).
// If raw is nil/empty a fresh document is created.
// If raw is malformed JSON, returns an error (file must be left untouched).
func codexMergeHookEntry(raw []byte, hookBin string) ([]byte, bool, error) {
	canonicalCmd := hookBin + " --agent=codex"

	var root codexHooksRoot

	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &root); err != nil {
			return nil, false, fmt.Errorf("hooks.json is malformed JSON: %w", err)
		}
	}

	if root.Hooks == nil {
		root.Hooks = make(map[string][]codexMatcherGroup)
	}

	// Replace-in-place: drop any entry matching either form (legacy bare or new
	// --agent=codex), then append exactly one canonical new-form entry. This makes
	// upgrades idempotent and never produces duplicates.
	ptu := root.Hooks["PreToolUse"]
	var filtered []codexMatcherGroup
	for _, g := range ptu {
		if groupContainsCmdMatcher(g, hookBin) {
			continue // drop our entry (either form)
		}
		filtered = append(filtered, g)
	}

	desired := append(filtered, codexMatcherGroup{
		Matcher: ".*",
		Hooks: []codexHook{
			{
				Type:    "command",
				Command: canonicalCmd,
				Timeout: 30,
			},
		},
	})

	// Idempotent: if the document already equals the desired end-state (foreign
	// groups preserved in order, our single canonical entry last), don't rewrite.
	if reflect.DeepEqual(ptu, desired) {
		return raw, false, nil
	}

	root.Hooks["PreToolUse"] = desired

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return raw, false, fmt.Errorf("marshal hooks.json: %w", err)
	}
	out = append(out, '\n')
	return out, true, nil
}

// codexHookEntryPresent checks whether any agentjail hook entry (either form)
// appears in any PreToolUse matcher group. Returns (parsed_ok, found, error).
func codexHookEntryPresent(raw []byte, hookBin string) (bool, bool, error) {
	var root codexHooksRoot
	if err := json.Unmarshal(raw, &root); err != nil {
		return false, false, err
	}
	return true, codexHookCmdExists(root.Hooks["PreToolUse"], hookBin), nil
}

// codexHookCmdExists reports whether any hook in any matcher group in groups
// matches the agentjail hook command (either legacy bare or new --agent=codex form).
func codexHookCmdExists(groups []codexMatcherGroup, hookBin string) bool {
	for _, g := range groups {
		if groupContainsCmdMatcher(g, hookBin) {
			return true
		}
	}
	return false
}

// codexRemoveHookEntry removes any matcher group whose hooks list matches the
// agentjail hook command (either legacy bare or new --agent=codex form).
// Returns (newJSON, changed, error).
func codexRemoveHookEntry(raw []byte, hookBin string) ([]byte, bool, error) {
	var root codexHooksRoot
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, false, fmt.Errorf("hooks.json is malformed JSON: %w", err)
	}

	ptu := root.Hooks["PreToolUse"]
	var filtered []codexMatcherGroup
	for _, g := range ptu {
		if groupContainsCmdMatcher(g, hookBin) {
			continue // drop this group
		}
		filtered = append(filtered, g)
	}

	if len(filtered) == len(ptu) {
		return raw, false, nil
	}

	root.Hooks["PreToolUse"] = filtered
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return raw, false, fmt.Errorf("marshal hooks.json: %w", err)
	}
	out = append(out, '\n')
	return out, true, nil
}


// groupContainsCmdMatcher reports whether any hook in the matcher group matches
// the agentjail command in either the legacy bare form or the new --agent=codex form.
func groupContainsCmdMatcher(g codexMatcherGroup, hookBin string) bool {
	for _, h := range g.Hooks {
		if codexHookCmdMatches(h.Command, hookBin) {
			return true
		}
	}
	return false
}

// ---- config.toml strict safe-mode --------------------------------------------

// codexTrustDegradedNote is a fixed informational note added by Status. agentjail
// cannot read Codex's hook trust state, so this is always shown for Codex as a
// reminder rather than a live check — it is not a failure indicator.
const codexTrustDegradedNote = "grant trust once in Codex: run /hooks (agentjail can't read Codex trust state)"

// codexEnsureFeaturesHooks ensures [features] hooks = true is set in
// ~/.codex/config.toml using the strict safe-mode scanner. On any ambiguity
// the file is left byte-for-byte unchanged and a degraded note is printed.
func codexEnsureFeaturesHooks(env Env) error {
	tomlPath := filepath.Join(env.Home, ".codex", "config.toml")

	raw, err := os.ReadFile(tomlPath)
	if os.IsNotExist(err) {
		// Safe case 1: file absent — create minimal file.
		content := "[features]\nhooks = true\n"
		return writeFileAtomic(tomlPath, []byte(content), 0o644)
	}
	if err != nil {
		return fmt.Errorf("read config.toml: %w", err)
	}

	if len(strings.TrimSpace(string(raw))) == 0 {
		// Safe case 1b: file exists but is empty.
		content := "[features]\nhooks = true\n"
		return writeFileAtomic(tomlPath, []byte(content), 0o644)
	}

	mutated, ambiguous, reason := codexTomlEnsureHooks(raw)
	if ambiguous {
		fmt.Printf("\nagentjail: config.toml not modified (%s)\n", reason)
		fmt.Printf("To enable Codex hooks, add the following line to ~/.codex/config.toml:\n")
		fmt.Printf("  [features]\n  hooks = true\n\n")
		// Degraded — but not an error; Install will still record the trust note.
		return nil
	}

	if mutated == nil {
		// Already set — nothing to do.
		return nil
	}

	return writeFileAtomic(tomlPath, mutated, 0o644)
}

// codexTomlEnsureHooks scans raw config.toml content with the strict safe-mode
// scanner. It returns:
//   - (newContent, false, "") when a safe mutation was made
//   - (nil, false, "") when hooks = true is already present (no change needed)
//   - (nil, true, reason) when any ambiguous case is detected (file untouched)
//
// Safe mutation cases:
//  1. File has exactly one clean [features] table with NO hooks key → insert
//     "hooks = true" after the [features] header line.
//  2. No [features] table anywhere → append a new [features]\nhooks = true block.
//
// Ambiguous cases (leave file unchanged):
//   - existing hooks key (any value, including hooks = true already handled → return nil,false,"")
//   - duplicate [features] tables
//   - inline table form: features = {...}
//   - array-of-tables: [[features]]
//   - multi-line values (value continuation on next line)
//   - comments between [features] and hooks key that make insertion uncertain
func codexTomlEnsureHooks(raw []byte) (newContent []byte, ambiguous bool, reason string) {
	lines := splitLines(raw)

	type tableSpan struct {
		headerIdx int    // line index of the [features] header
		name      string // normalised table name
		isInline  bool   // features = {...}
		isArray   bool   // [[features]]
	}

	var spans []tableSpan
	// Also track whether any line looks like a bare `features = {` (inline).
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect [[table]] array-of-tables.
		if strings.HasPrefix(trimmed, "[[") && strings.HasSuffix(trimmed, "]]") {
			name := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
			if name == "features" {
				spans = append(spans, tableSpan{headerIdx: i, name: "features", isArray: true})
			}
			continue
		}

		// Detect [table] standard tables.
		if strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "[[") &&
			strings.HasSuffix(trimmed, "]") && !strings.HasSuffix(trimmed, "]]") {
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if name == "features" {
				spans = append(spans, tableSpan{headerIdx: i, name: "features"})
			}
			continue
		}

		// Detect inline table: features = { ... }
		// This handles lines like: features = {hooks=true} or features={hooks = true}
		bare := strings.TrimSpace(trimmed)
		if isInlineTableAssignment(bare, "features") {
			spans = append(spans, tableSpan{headerIdx: i, name: "features", isInline: true})
			continue
		}

		// Strict safe-mode: a line that opens with '[' but is not a complete
		// [table] or [[array]] header (handled+continued above) is a malformed or
		// truncated header — e.g. "[features" with no closing bracket — or an
		// array-value continuation line we cannot reason about. Either way the
		// file is not something we can mutate with certainty, so treat the whole
		// file as ambiguous and leave it byte-for-byte unchanged.
		if strings.HasPrefix(bare, "[") {
			return nil, true, "malformed or unrecognized bracket line in config.toml — manual edit required"
		}
	}

	// Ambiguous: any inline or array-of-tables.
	for _, s := range spans {
		if s.isInline {
			return nil, true, "inline table 'features = {...}' detected — manual edit required"
		}
		if s.isArray {
			return nil, true, "array-of-tables '[[features]]' detected — manual edit required"
		}
	}

	// Ambiguous: duplicate [features] tables.
	featCount := 0
	for _, s := range spans {
		if s.name == "features" {
			featCount++
		}
	}
	if featCount > 1 {
		return nil, true, fmt.Sprintf("%d [features] tables found — manual edit required", featCount)
	}

	// Case: no [features] table anywhere → safe to append.
	if featCount == 0 {
		// Append a new [features] block at EOF.
		var sb strings.Builder
		// Write original content, ensuring it ends with a newline.
		sb.Write(raw)
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			sb.WriteByte('\n')
		}
		sb.WriteString("\n[features]\nhooks = true\n")
		return []byte(sb.String()), false, ""
	}

	// Exactly one clean [features] table.
	featSpan := spans[0]
	headerIdx := featSpan.headerIdx

	// Scan the body of this [features] table (lines after the header until
	// the next table header or EOF).
	bodyStart := headerIdx + 1
	bodyEnd := len(lines) // exclusive
	for i := bodyStart; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if isTableHeader(t) {
			bodyEnd = i
			break
		}
	}

	// Within the body, look for a hooks key.
	for i := bodyStart; i < bodyEnd; i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}

		// Check for hooks key (any value).
		if isKeyLine(t, "hooks") {
			// Check if it's already hooks = true.
			val := extractValueAfterEquals(t)
			if strings.TrimSpace(val) == "true" {
				// Already set — no change needed.
				return nil, false, ""
			}
			// hooks key exists with a different value — ambiguous.
			return nil, true, fmt.Sprintf("existing 'hooks = %s' in [features] — manual edit required", strings.TrimSpace(val))
		}

		// Multi-line value detection: if a value ends with a backslash or
		// if the next non-blank line starts with whitespace (indented continuation),
		// we treat it as ambiguous.
		if strings.HasSuffix(t, "\\") {
			return nil, true, "multi-line value detected in [features] body — manual edit required"
		}
	}

	// Safe case: [features] exists, no hooks key — insert after the header line.
	// We insert "hooks = true" immediately after the [features] line.
	var out strings.Builder
	for i, line := range lines {
		out.WriteString(line)
		if i < len(lines)-1 || line != "" {
			out.WriteByte('\n')
		}
		if i == headerIdx {
			out.WriteString("hooks = true\n")
		}
	}
	return []byte(out.String()), false, ""
}

// codexFeaturesHooksState scans config.toml and reports whether features.hooks
// is set to true. Returns (enabled, ambiguous).
// ambiguous is true when the scanner cannot determine the value with certainty.
func codexFeaturesHooksState(raw []byte) (enabled bool, ambiguous bool) {
	_, isAmbiguous, _ := codexTomlEnsureHooks(raw)
	if isAmbiguous {
		return false, true
	}

	// Check if hooks = true is already present by seeing if codexTomlEnsureHooks
	// returns nil (meaning no change needed, i.e., already set or nothing to do).
	// We need to actually check the content for the presence of hooks = true.
	lines := splitLines(raw)
	inFeatures := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if isTableHeader(t) {
			inFeatures = (t == "[features]")
			continue
		}
		if inFeatures && isKeyLine(t, "hooks") {
			val := extractValueAfterEquals(t)
			return strings.TrimSpace(val) == "true", false
		}
	}
	return false, false
}

// ---- TOML scanner helpers ----------------------------------------------------

// splitLines splits content into lines WITHOUT the trailing newline.
// An empty final line (from a trailing newline) is preserved as an empty string.
func splitLines(data []byte) []string {
	s := string(data)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\n")
	// If the string ends with \n, Split produces a trailing empty string.
	// We keep it so that reassembly preserves the trailing newline.
	return parts
}

// isTableHeader reports whether a trimmed line is a table or array-of-tables header.
func isTableHeader(trimmed string) bool {
	return (strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"))
}

// isKeyLine reports whether a trimmed line starts with "key" followed by optional
// whitespace and "=". This is a strict prefix check to avoid false positives
// (e.g., "hooks_mode" matching "hooks").
func isKeyLine(trimmed, key string) bool {
	rest := strings.TrimPrefix(trimmed, key)
	if rest == trimmed {
		return false // key is not a prefix
	}
	return strings.HasPrefix(strings.TrimLeft(rest, " \t"), "=")
}

// extractValueAfterEquals returns the portion of a key = value line after the
// first '='. It does NOT handle quoted strings, multi-line values, or comments.
// That is intentional — the caller treats any uncertain value as ambiguous.
func extractValueAfterEquals(trimmed string) string {
	idx := strings.Index(trimmed, "=")
	if idx < 0 {
		return ""
	}
	return trimmed[idx+1:]
}

// isInlineTableAssignment reports whether a line is an inline table assignment
// for the given key, e.g. "features = { ... }" or "features={...}".
func isInlineTableAssignment(trimmed, key string) bool {
	if !strings.HasPrefix(trimmed, key) {
		return false
	}
	rest := strings.TrimLeft(trimmed[len(key):], " \t")
	if !strings.HasPrefix(rest, "=") {
		return false
	}
	val := strings.TrimSpace(rest[1:])
	return strings.HasPrefix(val, "{")
}

// ---- trust instruction -------------------------------------------------------

// printCodexTrustInstruction prints the manual trust instruction to stdout.
// Lines are indented to sit under the "Wiring hooks" section (aligning with the
// per-agent "wiring …" progress lines) so the block reads as Codex's follow-up
// rather than a flush-left dump. Codex is wired last (see agents.Registry) so
// this block lands at the end of the section.
func printCodexTrustInstruction(hookCmd string) {
	const indent = "      " // matches emojiSectionBodyIndent in cmd/agentjail/install.go
	fmt.Printf(`
%[1]sagentjail-hook has been registered in ~/.codex/hooks.json.
%[1]sTo trust the hook, start Codex and run: /hooks
%[1]sSelect the agentjail-hook entry and press 't' to trust it.

%[1]sHook command: %[2]s
`, indent, hookCmd)
}
