package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run -- <command> [args...]",
	Short: "Run a command inside the agentjail shield",
	Long: `Run any coding agent inside the agentjail OS-native sandbox.
The agent inherits Landlock (Linux) or Seatbelt (macOS) restrictions
that prevent access to credentials, host processes, and unrestricted network.

Examples:
  agentjail run -- claude
  agentjail run -- codex --approval-mode full-auto
  agentjail run -- cursor`,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		// Handle --help before passing to runRunCmd.
		for _, a := range args {
			if a == "--help" || a == "-h" {
				fmt.Fprintln(os.Stdout, cmd.Long)
				return
			}
		}
		os.Exit(runRunCmd(args))
	},
}

var claudeCmd = &cobra.Command{
	Use:   "claude [args...]",
	Short: "Run Claude Code inside the agentjail shield",
	Long: `Launch Claude Code inside the agentjail OS-native sandbox.

This is equivalent to: agentjail run -- claude [args...]

The session is protected by Landlock (Linux) or Seatbelt (macOS).
Credential paths, host processes, and unrestricted network access
are blocked at the kernel level.`,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runClaudeCmd(args))
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(claudeCmd)
}

func runClaudeCmd(args []string) int {
	return runRunCmd(append([]string{"claude"}, args...))
}

func runRunCmd(args []string) int {
	// Strip leading "--" if present (cobra passes it through with DisableFlagParsing).
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "agentjail run: no command given")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  usage: agentjail run -- <command> [args...]")
		fmt.Fprintln(os.Stderr, "  usage: agentjail claude [args...]")
		return 2
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail run: cannot determine home directory: %v\n", err)
		return 1
	}

	// 1. Locate the shield binary.
	shieldBin, err := findShieldBinary(home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Run: agentjail install")
		fmt.Fprintln(os.Stderr, "  to install the shield binary.")
		return 1
	}

	// 2. Ensure the daemon is running.
	if err := ensureDaemon(home); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: agentjail daemon is not running: %v\n", err)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  The daemon evaluates policy for every tool call.")
		fmt.Fprintln(os.Stderr, "  Start it with: agentjail install")
		return 1
	}

	// 3. Ensure hooks are installed for the agent (best-effort, don't block on failure).
	agentName := args[0]
	if agentName == "claude" {
		ensureHooksInstalled(home, "claude-code")
	}

	// 4. Resolve the agent binary.
	agentPath, err := exec.LookPath(agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %q not found in PATH: %v\n", agentName, err)
		return 127
	}

	// Guard: if the resolved path is our own PATH shim, that's a loop.
	shimPath := filepath.Join(home, ".agentjail", "bin", agentName)
	if resolvedShim, err := filepath.EvalSymlinks(shimPath); err == nil {
		if resolvedAgent, err := filepath.EvalSymlinks(agentPath); err == nil {
			if resolvedShim == resolvedAgent {
				fmt.Fprintf(os.Stderr, "ERROR: %q resolved to the agentjail PATH shim at %s\n", agentName, shimPath)
				fmt.Fprintln(os.Stderr, "  This would cause an infinite loop.")
				fmt.Fprintln(os.Stderr, "  Ensure the real binary is on PATH before ~/.agentjail/bin.")
				return 1
			}
		}
	}

	// 5. Exec through shield. This replaces the current process.
	shieldArgs := []string{shieldBin, "--", agentPath}
	shieldArgs = append(shieldArgs, args[1:]...)

	fmt.Fprintf(os.Stderr, "agentjail: starting shielded session for %s\n", agentName)

	if err := syscall.Exec(shieldBin, shieldArgs, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to exec shield: %v\n", err)
		return 1
	}

	return 0 // unreachable after exec
}

// findShieldBinary locates the agentjail-shield binary. It checks:
//  1. ~/.agentjail/bin/agentjail-shield (installed location)
//  2. Next to the current executable (co-located build)
//  3. PATH
func findShieldBinary(home string) (string, error) {
	// Installed location.
	installed := filepath.Join(home, ".agentjail", "bin", "agentjail-shield")
	if _, err := os.Stat(installed); err == nil {
		return installed, nil
	}

	// Co-located with agentjail binary.
	if self, err := os.Executable(); err == nil {
		colocated := filepath.Join(filepath.Dir(self), "agentjail-shield")
		if _, err := os.Stat(colocated); err == nil {
			return colocated, nil
		}
	}

	// PATH.
	if p, err := exec.LookPath("agentjail-shield"); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("agentjail-shield binary not found at %s or in PATH", installed)
}

// ensureDaemon checks if the daemon is reachable. It does NOT start it —
// that's the install command's job. It just verifies connectivity so the
// user gets a clear error before the session starts.
func ensureDaemon(home string) error {
	sockPath := filepath.Join(home, ".agentjail", "daemon.sock")
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		return fmt.Errorf("daemon socket not found at %s", sockPath)
	}

	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("cannot connect to daemon at %s: %v", sockPath, err)
	}
	conn.Close()
	return nil
}

// ensureHooksInstalled is best-effort: if hooks are not installed for the
// given agent, print a warning but don't block the session.
func ensureHooksInstalled(home, agentID string) {
	if agentID != "claude-code" {
		return
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")
	hookBin := filepath.Join(home, ".agentjail", "bin", "agentjail-hook")

	b, err := os.ReadFile(settingsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentjail: warning: could not read ~/.claude/settings.json — hooks may not be installed")
		fmt.Fprintln(os.Stderr, "  Run: agentjail install --for claude-code")
		return
	}

	// Check if hook is already present (reuse the merge check).
	var root map[string]interface{}
	if err := parseJSON(b, &root); err != nil {
		return
	}

	hooks, _ := root["hooks"].(map[string]interface{})
	if hooks == nil {
		fmt.Fprintln(os.Stderr, "agentjail: warning: no hooks configured in ~/.claude/settings.json")
		fmt.Fprintln(os.Stderr, "  Run: agentjail install --for claude-code")
		return
	}

	preToolUse, _ := hooks["PreToolUse"].([]interface{})
	for _, entry := range preToolUse {
		em, _ := entry.(map[string]interface{})
		if em == nil {
			continue
		}
		inner, _ := em["hooks"].([]interface{})
		for _, h := range inner {
			hm, _ := h.(map[string]interface{})
			if hm != nil && hm["command"] == hookBin {
				return // hook is present
			}
		}
	}

	fmt.Fprintln(os.Stderr, "agentjail: warning: agentjail hook not found in ~/.claude/settings.json")
	fmt.Fprintln(os.Stderr, "  Policy decisions won't be enforced until hooks are installed.")
	fmt.Fprintln(os.Stderr, "  Run: agentjail install --for claude-code")
}

// parseJSON is a thin wrapper for json.Unmarshal that avoids importing
// encoding/json at package scope (it's already imported in install.go).
func parseJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
