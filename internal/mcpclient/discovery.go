package mcpclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MCPServerEntry combines a server config with provenance metadata.
type MCPServerEntry struct {
	Name    string          // display name (e.g. "fff", "plugin_claude-mem_mcp-search")
	Source  string          // "claude", "cursor", "codex", "plugin"
	Scope   string          // "global" or "project"
	Trust   string          // "official-marketplace", "third-party-marketplace", "user-installed"
	Package string          // package identifier (e.g. "claude-plugins-official/linear", binary path, npm pkg)
	Config  MCPServerConfig // connection parameters
}

// DiscoverServersWithConfig reads all MCP server configs from known agent
// config files and returns entries with enough info to connect. Missing or
// unreadable files are silently skipped. projectDir, if non-empty, is checked
// for project-level .claude/settings.json and .claude/settings.local.json.
func DiscoverServersWithConfig(home string, projectDirs ...string) []MCPServerEntry {
	seen := make(map[string]MCPServerEntry)

	for _, e := range claudeGlobalServers(home) {
		seen[e.Name] = e
	}
	for _, e := range cursorServers(home) {
		if _, exists := seen[e.Name]; !exists {
			seen[e.Name] = e
		}
	}
	for _, e := range claudePluginServers(home) {
		if _, exists := seen[e.Name]; !exists {
			seen[e.Name] = e
		}
	}
	for _, dir := range projectDirs {
		for _, e := range claudeProjectServers(dir) {
			if _, exists := seen[e.Name]; !exists {
				seen[e.Name] = e
			}
		}
	}

	entries := make([]MCPServerEntry, 0, len(seen))
	for _, e := range seen {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return entries
}

// --------------------------------------------------------------------------
// Claude Code: ~/.claude.json
// --------------------------------------------------------------------------

// serverJSON is the JSON shape for one MCP server entry in config files.
type serverJSON struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

func claudeGlobalServers(home string) []MCPServerEntry {
	path := filepath.Join(home, ".claude.json")
	entries := parseJSONMCPServers(path, "claude")
	for i := range entries {
		entries[i].Scope = "global"
		entries[i].Trust = "user-installed"
		entries[i].Package = entries[i].Config.Command
	}
	return entries
}

// claudeProjectServers reads .claude/settings.json and .claude/settings.local.json
// from a project directory.
func claudeProjectServers(projectDir string) []MCPServerEntry {
	var entries []MCPServerEntry
	for _, name := range []string{"settings.json", "settings.local.json"} {
		path := filepath.Join(projectDir, ".claude", name)
		for _, e := range parseJSONMCPServers(path, "claude") {
			e.Scope = "project"
			e.Trust = "project-local"
			e.Package = e.Config.Command
			entries = append(entries, e)
		}
	}
	return entries
}

// --------------------------------------------------------------------------
// Cursor: ~/.cursor/mcp.json
// --------------------------------------------------------------------------

func cursorServers(home string) []MCPServerEntry {
	path := filepath.Join(home, ".cursor", "mcp.json")
	entries := parseJSONMCPServers(path, "cursor")
	for i := range entries {
		entries[i].Scope = "global"
		entries[i].Trust = "user-installed"
		entries[i].Package = entries[i].Config.Command
	}
	return entries
}

// parseJSONMCPServers reads a JSON file with a top-level "mcpServers" object
// and returns entries with full connection config.
func parseJSONMCPServers(path, source string) []MCPServerEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var top struct {
		MCPServers map[string]serverJSON `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &top); err != nil {
		return nil
	}

	entries := make([]MCPServerEntry, 0, len(top.MCPServers))
	for name, srv := range top.MCPServers {
		cfg := MCPServerConfig{
			Name:    name,
			Type:    srv.Type,
			Command: srv.Command,
			Args:    srv.Args,
			Env:     srv.Env,
			URL:     srv.URL,
			Headers: srv.Headers,
		}
		// Default type to stdio if a command is present.
		if cfg.Type == "" && cfg.Command != "" {
			cfg.Type = "stdio"
		}
		entries = append(entries, MCPServerEntry{
			Name:   name,
			Source: source,
			Config: cfg,
		})
	}
	return entries
}

// --------------------------------------------------------------------------
// Claude Code plugins: ~/.claude/plugins/installed_plugins.json
// --------------------------------------------------------------------------

func claudePluginServers(home string) []MCPServerEntry {
	registryPath := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	data, err := os.ReadFile(registryPath)
	if err != nil {
		return nil
	}

	var registry struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil
	}

	var entries []MCPServerEntry
	seen := make(map[string]struct{})

	for registryKey, installs := range registry.Plugins {
		pluginName, _, ok := strings.Cut(registryKey, "@")
		if !ok || pluginName == "" {
			continue
		}
		// Determine trust level from the registry key.
		// Format: "<plugin>@<marketplace>" e.g. "linear@claude-plugins-official"
		// "claude-plugins-official" marketplace = official; anything else = third-party.
		trust := "third-party-marketplace"
		if strings.HasSuffix(registryKey, "@claude-plugins-official") {
			trust = "official-marketplace"
		}
		for _, inst := range installs {
			if !filepath.IsAbs(inst.InstallPath) {
				continue
			}
			mcpPath := filepath.Join(inst.InstallPath, ".mcp.json")
			servers := parsePluginMCPFile(mcpPath, pluginName)
			for _, e := range servers {
				if _, dup := seen[e.Name]; dup {
					continue
				}
				seen[e.Name] = struct{}{}
				e.Scope = "global"
				e.Trust = trust
				e.Package = registryKey
				entries = append(entries, e)
			}
		}
	}
	return entries
}

// parsePluginMCPFile reads a plugin's .mcp.json and returns server entries.
// Handles both wrapped {"mcpServers": {...}} and flat {"name": {"command":...}} formats.
func parsePluginMCPFile(path, pluginName string) []MCPServerEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil
	}

	// Try wrapped format first.
	if raw, ok := top["mcpServers"]; ok {
		var servers map[string]serverJSON
		if err := json.Unmarshal(raw, &servers); err != nil {
			return nil
		}
		entries := make([]MCPServerEntry, 0, len(servers))
		for key, srv := range servers {
			entryName := "plugin_" + pluginName + "_" + key
			cfg := MCPServerConfig{
				Name:    entryName,
				Type:    srv.Type,
				Command: srv.Command,
				Args:    srv.Args,
				Env:     srv.Env,
				URL:     srv.URL,
				Headers: srv.Headers,
			}
			if cfg.Type == "" && cfg.Command != "" {
				cfg.Type = "stdio"
			}
			entries = append(entries, MCPServerEntry{
				Name:   entryName,
				Source: "plugin",
				Config: cfg,
			})
		}
		return entries
	}

	// Flat format: top-level keys whose values look like server configs.
	mcpFields := map[string]bool{"command": true, "url": true, "type": true, "args": true, "env": true}
	var entries []MCPServerEntry
	for key, raw := range top {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		isMCP := false
		for field := range obj {
			if mcpFields[field] {
				isMCP = true
				break
			}
		}
		if !isMCP {
			continue
		}
		var srv serverJSON
		if err := json.Unmarshal(raw, &srv); err != nil {
			continue
		}
		entryName := "plugin_" + pluginName + "_" + key
		cfg := MCPServerConfig{
			Name:    entryName,
			Type:    srv.Type,
			Command: srv.Command,
			Args:    srv.Args,
			Env:     srv.Env,
			URL:     srv.URL,
			Headers: srv.Headers,
		}
		if cfg.Type == "" && cfg.Command != "" {
			cfg.Type = "stdio"
		}
		entries = append(entries, MCPServerEntry{
			Name:   entryName,
			Source: "plugin",
			Config: cfg,
		})
	}
	return entries
}
