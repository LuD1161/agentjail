// mcp.go — `agentjail mcp {allow,block,list,help}` subcommand.
//
// This subcommand manages the MCP server allow/block lists in
// ~/.agentjail/policy.yaml and signals the daemon to reload on each change.
//
// Usage:
//
//	agentjail mcp allow <server>   # add server to allowed list (idempotent)
//	agentjail mcp block <server>   # add server to blocked list, remove from allowed
//	agentjail mcp list             # print current allowed + blocked lists
//	agentjail mcp help             # show this help
//
// The "allow" and "block" subcommands reject server names that contain glob
// metacharacters (*?[]{}!) to prevent accidental broad allow patterns.
// After each mutation, SIGHUP is sent to agentjail-daemon to reload policy.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/ui"
)

// policyConfigPath returns ~/.agentjail/policy.yaml.
func policyConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home dir: %w", err)
	}
	return filepath.Join(home, ".agentjail", "policy.yaml"), nil
}

// runMCP is the top-level dispatcher for `agentjail mcp <sub>`.
// It returns an exit code so the caller can os.Exit without capturing errors.
func runMCP(args []string) int {
	if len(args) == 0 {
		printMCPUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "allow":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail mcp allow <server>")
			return 2
		}
		return runMCPAllow(args[1])
	case "block":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentjail mcp block <server>")
			return 2
		}
		return runMCPBlock(args[1])
	case "list":
		return runMCPList()
	case "help", "-h", "--help":
		printMCPUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "agentjail mcp: unknown subcommand %q\n", args[0])
		printMCPUsage(os.Stderr)
		return 2
	}
}

// runMCPAllow adds server to MCP.Allowed in policy.yaml (idempotent).
// Rejects names with glob metacharacters. Sends SIGHUP to daemon on success.
func runMCPAllow(server string) int {
	if containsGlobMeta(server) {
		fmt.Fprintf(os.Stderr, "error: server name %q contains glob metacharacters (%s) — rejected to prevent broad allow patterns\n", server, globMetaChars)
		fmt.Fprintln(os.Stderr, "hint: use an exact server name without wildcards")
		return 1
	}

	path, err := policyConfigPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail mcp allow: %v\n", err)
		return 1
	}

	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail mcp allow: load policy: %v\n", err)
		return 1
	}

	// Idempotent: skip if already present.
	for _, existing := range cfg.MCP.Allowed {
		if existing == server {
			fmt.Printf("already allowed: %s\n", server)
			return 0
		}
	}

	cfg.MCP.Allowed = append(cfg.MCP.Allowed, server)

	if err := config.Save(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail mcp allow: save policy: %v\n", err)
		return 1
	}

	fmt.Printf("allowed: %s\n", server)
	sighupDaemon()
	return 0
}

// runMCPBlock adds server to MCP.Blocked in policy.yaml and removes it from
// MCP.Allowed (Q-D: no contradictory intent). Sends SIGHUP to daemon on success.
func runMCPBlock(server string) int {
	if containsGlobMeta(server) {
		fmt.Fprintf(os.Stderr, "error: server name %q contains glob metacharacters (%s) — rejected\n", server, globMetaChars)
		return 1
	}

	path, err := policyConfigPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail mcp block: %v\n", err)
		return 1
	}

	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail mcp block: load policy: %v\n", err)
		return 1
	}

	// Add to blocked if not already present.
	alreadyBlocked := false
	for _, b := range cfg.MCP.Blocked {
		if b == server {
			alreadyBlocked = true
			break
		}
	}
	if !alreadyBlocked {
		cfg.MCP.Blocked = append(cfg.MCP.Blocked, server)
	}

	// Remove from allowed to keep the file honest (Q-D).
	filtered := cfg.MCP.Allowed[:0]
	for _, a := range cfg.MCP.Allowed {
		if a != server {
			filtered = append(filtered, a)
		}
	}
	cfg.MCP.Allowed = filtered

	if err := config.Save(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail mcp block: save policy: %v\n", err)
		return 1
	}

	fmt.Printf("blocked: %s\n", server)
	sighupDaemon()
	return 0
}

// runMCPList prints the current MCP.Allowed and MCP.Blocked lists.
func runMCPList() int {
	return runMCPListOutput(os.Stdout, os.Stderr)
}

func runMCPListOutput(out, errOut io.Writer) int {
	path, err := policyConfigPath()
	if err != nil {
		fmt.Fprintf(errOut, "agentjail mcp list: %v\n", err)
		return 1
	}

	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		fmt.Fprintf(errOut, "agentjail mcp list: load policy: %v\n", err)
		return 1
	}

	u := ui.New(out)
	fmt.Fprintln(out, u.Section("MCP allowed"))
	if len(cfg.MCP.Allowed) == 0 {
		fmt.Fprintln(out, "  (none — all MCP calls denied)")
	} else {
		for _, a := range cfg.MCP.Allowed {
			fmt.Fprintln(out, "  "+a)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, u.Section("MCP blocked"))
	if len(cfg.MCP.Blocked) == 0 {
		fmt.Fprintln(out, "  (none)")
	} else {
		for _, b := range cfg.MCP.Blocked {
			fmt.Fprintln(out, "  "+b)
		}
	}
	fmt.Fprintln(out)
	return 0
}

func printMCPUsage(w io.Writer) {
	u := ui.New(w)
	const bodyIndent = "  "

	fmt.Fprintln(w, u.Header("agentjail mcp"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Usage"))
	fmt.Fprintln(w, bodyIndent+"agentjail mcp <command> [server]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Commands"))
	cmds := []struct {
		name string
		desc string
	}{
		{"allow <server>", "Add a server to the MCP allowed list"},
		{"block <server>", "Add a server to the MCP blocked list (and remove from allowed)"},
		{"list", "Show current allowed and blocked MCP servers"},
		{"help", "Show MCP help"},
	}
	for _, c := range cmds {
		fmt.Fprintln(w, bodyIndent+u.KeyValue(c.name, c.desc, ""))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Examples"))
	examples := []string{
		"agentjail mcp allow claude-mem",
		"agentjail mcp allow filesystem",
		"agentjail mcp block my-payment-bot",
		"agentjail mcp list",
	}
	for _, ex := range examples {
		fmt.Fprintln(w, bodyIndent+ex)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Notes"))
	notes := []string{
		"Server names must be exact (no wildcards). Glob metacharacters (*?[]{}!) are rejected.",
		"After each change, agentjail-daemon is signaled to reload policy (SIGHUP).",
		"If the daemon is not running, the change takes effect on the next daemon start.",
		"Denial message: run 'agentjail mcp allow <server>' to grant access.",
	}
	for _, n := range notes {
		fmt.Fprintln(w, bodyIndent+strings.TrimSpace(n))
	}
	fmt.Fprintln(w)
}
