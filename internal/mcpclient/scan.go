// scan.go -- package manager + Docker scanner for MCP server discovery.
//
// ScanNPMGlobal, ScanPipPackages, and ScanDocker probe the local machine for
// MCP-related packages and containers. FullScan orchestrates all scanners
// concurrently and cross-references results against configured servers.
package mcpclient

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // register sqlite driver for audit queries
)

// ScanResult is the full inventory of MCP servers found on the machine.
type ScanResult struct {
	Configured []MCPServerEntry    `json:"configured"`      // from config files
	NPM        []PackageEntry      `json:"npm"`             // from npm ls -g
	Pip        []PackageEntry      `json:"pip"`             // from pip list
	Docker     []DockerEntry       `json:"docker"`          // from docker ps + docker images
	Audit      map[string][]string `json:"audit,omitempty"` // server -> [tools]
}

// PackageEntry represents an MCP-related package found by a package manager.
type PackageEntry struct {
	Name    string `json:"name"`    // package name e.g. "@modelcontextprotocol/server-filesystem"
	Version string `json:"version"`
	Source  string `json:"source"` // "npm" or "pip"
	Status  string `json:"status"` // "installed-not-configured", "configured"
}

// DockerEntry represents an MCP-related Docker container or image.
type DockerEntry struct {
	Name   string `json:"name"`   // container/image name
	Image  string `json:"image"`
	Status string `json:"status"` // "running", "stopped", "image"
	Ports  string `json:"ports"`  // exposed ports
	Source string `json:"source"` // "docker"
}

// npmMCPPatterns are the patterns used to identify MCP-related npm packages.
var npmMCPPatterns = []string{
	"@modelcontextprotocol/",
	"mcp-server-",
	"-mcp-server",
	"mcp_server_",
}

// pipMCPPatterns are the patterns used to identify MCP-related pip packages.
var pipMCPPatterns = []string{
	"mcp-server-",
	"mcp_server_",
	"-mcp",
}

// matchesMCPPattern reports whether name matches any of the given patterns.
func matchesMCPPattern(name string, patterns []string) bool {
	lower := strings.ToLower(name)
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ScanNPMGlobal runs `npm ls -g --json --depth=0` and returns MCP-related packages.
// Returns empty (not error) if npm is not installed or the command fails.
func ScanNPMGlobal() []PackageEntry {
	if _, err := exec.LookPath("npm"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "npm", "ls", "-g", "--json", "--depth=0").Output()
	if err != nil {
		// npm ls exits non-zero when there are peer dep warnings; still parse.
		if len(out) == 0 {
			return nil
		}
	}

	var result struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil
	}

	var entries []PackageEntry
	for name, info := range result.Dependencies {
		if matchesMCPPattern(name, npmMCPPatterns) {
			entries = append(entries, PackageEntry{
				Name:    name,
				Version: info.Version,
				Source:  "npm",
				Status:  "installed-not-configured",
			})
		}
	}
	return entries
}

// ScanPipPackages runs `pip list --format=json` (tries pip3 first, then pip)
// and returns MCP-related packages. Returns empty if pip is not installed.
func ScanPipPackages() []PackageEntry {
	var pipCmd string
	if _, err := exec.LookPath("pip3"); err == nil {
		pipCmd = "pip3"
	} else if _, err := exec.LookPath("pip"); err == nil {
		pipCmd = "pip"
	} else {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, pipCmd, "list", "--format=json").Output()
	if err != nil {
		return nil
	}

	var packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &packages); err != nil {
		return nil
	}

	var entries []PackageEntry
	for _, pkg := range packages {
		if matchesMCPPattern(pkg.Name, pipMCPPatterns) {
			entries = append(entries, PackageEntry{
				Name:    pkg.Name,
				Version: pkg.Version,
				Source:  "pip",
				Status:  "installed-not-configured",
			})
		}
	}
	return entries
}

// ScanDocker checks for running MCP containers and installed MCP images.
// Returns empty if Docker is not installed or the daemon is not running.
func ScanDocker() []DockerEntry {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}

	var entries []DockerEntry

	// Running containers.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "ps", "--format", "{{json .}}").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			var container struct {
				Names  string `json:"Names"`
				Image  string `json:"Image"`
				Status string `json:"Status"`
				Ports  string `json:"Ports"`
			}
			if err := json.Unmarshal([]byte(line), &container); err != nil {
				continue
			}
			combined := strings.ToLower(container.Names + " " + container.Image)
			if strings.Contains(combined, "mcp") {
				status := "running"
				if !strings.HasPrefix(strings.ToLower(container.Status), "up") {
					status = "stopped"
				}
				entries = append(entries, DockerEntry{
					Name:   container.Names,
					Image:  container.Image,
					Status: status,
					Ports:  container.Ports,
					Source: "docker",
				})
			}
		}
	}

	// Images (separate timeout).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	out2, err := exec.CommandContext(ctx2, "docker", "images", "--format", "{{json .}}").Output()
	if err == nil {
		// Track names already seen from running containers.
		seen := make(map[string]bool)
		for _, e := range entries {
			seen[e.Image] = true
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out2)), "\n") {
			if line == "" {
				continue
			}
			var img struct {
				Repository string `json:"Repository"`
				Tag        string `json:"Tag"`
			}
			if err := json.Unmarshal([]byte(line), &img); err != nil {
				continue
			}
			fullName := img.Repository
			if img.Tag != "" && img.Tag != "<none>" {
				fullName += ":" + img.Tag
			}
			if !strings.Contains(strings.ToLower(img.Repository), "mcp") {
				continue
			}
			if seen[fullName] || seen[img.Repository] {
				continue
			}
			entries = append(entries, DockerEntry{
				Name:   img.Repository,
				Image:  fullName,
				Status: "image",
				Source: "docker",
			})
		}
	}

	return entries
}

// auditToolsFromDB queries the decisions table for distinct MCP tool names
// grouped by server. Returns nil if the database is unavailable.
func auditToolsFromDB(dbPath string) map[string][]string {
	if dbPath == "" {
		return nil
	}

	dsn := fmt.Sprintf(
		"file:%s?mode=ro&_pragma=busy_timeout(3000)",
		strings.NewReplacer("?", "%3f", "#", "%23").Replace(dbPath),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT tool_name FROM decisions WHERE tool_name LIKE 'mcp__%' ORDER BY tool_name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var toolName string
		if err := rows.Scan(&toolName); err != nil {
			continue
		}
		rest := strings.TrimPrefix(toolName, "mcp__")
		idx := strings.Index(rest, "__")
		var server, tool string
		if idx > 0 {
			server = rest[:idx]
			tool = rest[idx+2:]
		} else {
			server = rest
			tool = rest
		}
		result[server] = append(result[server], tool)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// FullScan orchestrates all scanners concurrently and cross-references results.
// home is the user's home directory; dbPath is the path to the agentjail SQLite
// database (empty string to skip audit history).
func FullScan(home string, dbPath string) *ScanResult {
	var (
		configured []MCPServerEntry
		npmPkgs    []PackageEntry
		pipPkgs    []PackageEntry
		dockerEnts []DockerEntry
		auditTools map[string][]string
		wg         sync.WaitGroup
	)

	wg.Add(5)

	go func() {
		defer wg.Done()
		configured = DiscoverServersWithConfig(home)
	}()

	go func() {
		defer wg.Done()
		npmPkgs = ScanNPMGlobal()
	}()

	go func() {
		defer wg.Done()
		pipPkgs = ScanPipPackages()
	}()

	go func() {
		defer wg.Done()
		dockerEnts = ScanDocker()
	}()

	go func() {
		defer wg.Done()
		auditTools = auditToolsFromDB(dbPath)
	}()

	wg.Wait()

	// Cross-reference: mark npm/pip packages as "configured" if they appear
	// in any configured server's command or package field.
	configuredNames := make(map[string]bool)
	for _, e := range configured {
		configuredNames[strings.ToLower(e.Name)] = true
		configuredNames[strings.ToLower(e.Config.Command)] = true
		configuredNames[strings.ToLower(e.Package)] = true
		// Also match on the base name of the command (e.g. "mcp-server-sqlite"
		// from "/usr/bin/mcp-server-sqlite").
		if e.Config.Command != "" {
			parts := strings.Split(e.Config.Command, "/")
			configuredNames[strings.ToLower(parts[len(parts)-1])] = true
		}
	}

	crossRef := func(entries []PackageEntry) []PackageEntry {
		for i := range entries {
			lower := strings.ToLower(entries[i].Name)
			if configuredNames[lower] {
				entries[i].Status = "configured"
			}
		}
		return entries
	}

	npmPkgs = crossRef(npmPkgs)
	pipPkgs = crossRef(pipPkgs)

	// Ensure nil slices become empty for clean JSON.
	if configured == nil {
		configured = []MCPServerEntry{}
	}
	if npmPkgs == nil {
		npmPkgs = []PackageEntry{}
	}
	if pipPkgs == nil {
		pipPkgs = []PackageEntry{}
	}
	if dockerEnts == nil {
		dockerEnts = []DockerEntry{}
	}

	return &ScanResult{
		Configured: configured,
		NPM:        npmPkgs,
		Pip:        pipPkgs,
		Docker:     dockerEnts,
		Audit:      auditTools,
	}
}
