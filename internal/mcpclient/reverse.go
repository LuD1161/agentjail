// reverse.go — reverse MCP index: given a server name, find which projects use it.
package mcpclient

import (
	"sort"
)

// ProjectMCPInfo describes which MCP servers a project uses.
type ProjectMCPInfo struct {
	ProjectDir string   `json:"project_dir"` // project root directory
	Servers    []string `json:"servers"`      // MCP server names configured in this project
	Source     string   `json:"source"`       // "claude-project", "claude-local", "global"
}

// ReverseMCPIndex maps MCP server names to the projects that use them.
type ReverseMCPIndex map[string][]ProjectMCPInfo

// BuildReverseIndex scans all projectDirs for MCP server configs and
// builds an inverted index: server name -> list of projects using it.
// Also includes global servers (from DiscoverServersWithConfig) tagged
// as global.
func BuildReverseIndex(home string, projectDirs []string) ReverseMCPIndex {
	idx := make(ReverseMCPIndex)

	// 1. Global servers from DiscoverServersWithConfig (no project dirs passed).
	globalEntries := DiscoverServersWithConfig(home)
	for _, e := range globalEntries {
		info := ProjectMCPInfo{
			ProjectDir: home,
			Servers:    []string{e.Name},
			Source:     "global",
		}
		idx[e.Name] = append(idx[e.Name], info)
	}

	// 2. Per-project: parse .claude/settings.json and .claude/settings.local.json.
	for _, dir := range projectDirs {
		for _, item := range []struct {
			file   string
			source string
		}{
			{"settings.json", "claude-project"},
			{"settings.local.json", "claude-local"},
		} {
			path := dir + "/.claude/" + item.file
			entries := parseJSONMCPServers(path, "claude")
			if len(entries) == 0 {
				continue
			}
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name)
			}
			sort.Strings(names)
			for _, name := range names {
				info := ProjectMCPInfo{
					ProjectDir: dir,
					Servers:    names,
					Source:     item.source,
				}
				idx[name] = append(idx[name], info)
			}
		}
	}

	return idx
}

// ServerNames returns the sorted list of all server names in the index.
func (idx ReverseMCPIndex) ServerNames() []string {
	names := make([]string, 0, len(idx))
	for name := range idx {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
