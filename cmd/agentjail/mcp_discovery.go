// mcp_discovery.go — discover installed MCP server names from the three
// supported agent config formats at install time.
//
// Sources (global only; project-level .mcp.json is out of scope for V1):
//   - Claude Code: ~/.claude.json → top-level "mcpServers" object; keys are names.
//   - Codex CLI:   ~/.codex/config.toml → [mcp_servers.<name>] section headers.
//   - Cursor:      ~/.cursor/mcp.json → "mcpServers" object; keys are names.
//
// Missing files are silently skipped (not errors).
// Results are de-duplicated and sorted.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// globMetaChars lists the characters that have special meaning in glob patterns.
// A server name containing any of these is rejected with a warning because it
// would otherwise become a broad allow pattern in mcp.allowed (AC2.7 / R6).
const globMetaChars = `*?[]{}!`

// containsGlobMeta reports whether s contains any glob metacharacter.
func containsGlobMeta(s string) bool {
	return strings.ContainsAny(s, globMetaChars)
}

// discoverInstalledMCPServers reads MCP server names from all known agent
// config files under home. Results are de-duplicated and sorted alphabetically.
// Missing or unreadable files are silently skipped.
func discoverInstalledMCPServers(home string) []string {
	seen := make(map[string]struct{})

	for _, name := range claudeGlobalMCPServers(home) {
		seen[name] = struct{}{}
	}
	for _, name := range codexMCPServers(home) {
		seen[name] = struct{}{}
	}
	for _, name := range cursorMCPServers(home) {
		seen[name] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// claudeGlobalMCPServers reads ~/.claude.json and returns the keys of its
// top-level "mcpServers" object. Missing file → empty list, not error.
func claudeGlobalMCPServers(home string) []string {
	path := filepath.Join(home, ".claude.json")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return jsonMCPServerKeys(f)
}

// jsonMCPServerKeys decodes a JSON object from r and returns the keys of the
// top-level "mcpServers" sub-object. Any parse error returns nil (no names).
func jsonMCPServerKeys(r io.Reader) []string {
	var top map[string]json.RawMessage
	if err := json.NewDecoder(r).Decode(&top); err != nil {
		return nil
	}
	raw, ok := top["mcpServers"]
	if !ok {
		return nil
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(raw, &servers); err != nil {
		return nil
	}
	names := make([]string, 0, len(servers))
	for k := range servers {
		names = append(names, k)
	}
	return names
}

// cursorMCPServers reads ~/.cursor/mcp.json and returns the keys of its
// top-level "mcpServers" object. Missing file → empty list, not error.
func cursorMCPServers(home string) []string {
	path := filepath.Join(home, ".cursor", "mcp.json")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return jsonMCPServerKeys(f)
}

// codexMCPServers scans ~/.codex/config.toml with a line-scanner (no TOML
// dependency) and returns the names of all [mcp_servers.<name>] sections.
// Missing file → empty list, not error.
//
// The scanner follows the same conservative line-scanner style used throughout
// agent_codex.go. It only matches complete [mcp_servers.<name>] lines where
// the name portion is non-empty and contains no whitespace or reserved chars.
func codexMCPServers(home string) []string {
	path := filepath.Join(home, ".codex", "config.toml")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseCodexMCPSections(b)
}

// parseCodexMCPSections extracts MCP server names from TOML content without
// a TOML parser dependency. It scans for lines matching [mcp_servers.<name>].
func parseCodexMCPSections(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	var names []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Must be a complete [table] header (not [[array]])
		if !strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "[[") {
			continue
		}
		if !strings.HasSuffix(trimmed, "]") || strings.HasSuffix(trimmed, "]]") {
			continue
		}
		inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
		// Must start with mcp_servers.
		const prefix = "mcp_servers."
		if !strings.HasPrefix(inner, prefix) {
			continue
		}
		name := strings.TrimPrefix(inner, prefix)
		// Name must be non-empty, have no sub-keys (no dot), no whitespace.
		if name == "" || strings.ContainsAny(name, ". \t") {
			continue
		}
		names = append(names, name)
	}
	return names
}

// filterAndWarnMCPNames filters discovered names through the default blocked
// glob patterns and the glob-safety check. It writes warnings to w for any
// name that is excluded.
//
//   - A name matching a blocked pattern is excluded (AC2.2).
//   - A name containing glob metacharacters is rejected (AC2.7 / R6).
//
// Returns the safe, non-blocked subset in the original order.
func filterAndWarnMCPNames(names []string, blocked []string, w io.Writer) []string {
	var safe []string
	for _, name := range names {
		if containsGlobMeta(name) {
			fmt.Fprintf(w, "warning: MCP server name %q contains glob metacharacters — skipping (would create unsafe allow pattern)\n", name)
			continue
		}
		if matchesAnyGlob(name, blocked) {
			fmt.Fprintf(w, "warning: discovered MCP server %q matches a blocked pattern — not added to allowed list\n", name)
			continue
		}
		safe = append(safe, name)
	}
	return safe
}

// matchesAnyGlob reports whether name matches any of the provided glob patterns.
// It uses the same path.Match semantics as the mcp_policy.rego rule.
func matchesAnyGlob(name string, patterns []string) bool {
	for _, pat := range patterns {
		matched, err := filepath.Match(pat, name)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// discoverMCPSeedList discovers installed MCP servers under home, filters them
// through the default blocklist and glob-safety check, and prints a summary to
// w (Q-B transparency). It is safe to call before policy.yaml exists.
//
// Returns the filtered, sorted list ready for seeding into mcp.allowed.
func discoverMCPSeedList(home string, w io.Writer) []string {
	raw := discoverInstalledMCPServers(home)
	if len(raw) == 0 {
		return nil
	}

	defaultBlocked := []string{
		"*stripe*",
		"*payment*",
		"*billing*",
		"*twilio*",
		"*sendgrid*",
	}

	safe := filterAndWarnMCPNames(raw, defaultBlocked, w)
	if len(safe) == 0 {
		return nil
	}

	// Q-B: print transparency summary.
	fmt.Fprintf(w, "trusted %d existing MCP server(s): %s\n", len(safe), strings.Join(safe, ", "))
	return safe
}
