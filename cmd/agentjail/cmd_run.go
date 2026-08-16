package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command inside the agentjail shield",
	Long: `Run any coding agent inside the agentjail OS-native sandbox.
The agent inherits Landlock (Linux) or Seatbelt (macOS) restrictions
that prevent access to credentials, host processes, and unrestricted network.

Use --git-ssh to delegate loaded SSH-agent identities for the session, or
--no-git-ssh to override a policy default that enables delegation. AgentJail
launch flags must appear before --; everything after -- is passed unchanged to
the child command. --require-tunnel makes tunnel setup fail closed instead of
falling back to another network mode. --no-sandbox disables OS isolation and
provides only the weaker hook-based policy layer.`,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		// --help before "--" prints help; after "--" it is forwarded to the
		// child command (e.g. `agentjail run -- some-tool --help`).
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runRunCmd(args))
	},
}

var claudeCmd = &cobra.Command{
	Use:    "claude [args...]",
	Short:  "Run Claude Code inside the agentjail shield",
	Hidden: true,
	Long: `Launch Claude Code inside the agentjail OS-native sandbox.

This is equivalent to: agentjail run -- claude [args...]

The session is protected by Landlock (Linux) or Seatbelt (macOS) by default:
credential paths, host processes, and unrestricted network access are blocked
at the kernel level. Use --git-ssh to delegate loaded SSH-agent identities.`,
	Deprecated:         "use `agentjail run -- claude` so every coding agent has the same launch pattern",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runClaudeCmd(args))
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(claudeCmd)
}

func runClaudeCmd(args []string) int {
	// Run-level flags may lead the claude alias: `agentjail claude --no-sandbox`.
	// Lift them ahead of the "claude" command name so runRunCmd's leading-flag
	// loop sees them the same way it does for `agentjail run --no-sandbox -- ...`.
	var lead []string
	for len(args) > 0 && isRunLaunchFlag(args[0]) {
		lead = append(lead, args[0])
		args = args[1:]
	}
	full := append(lead, append([]string{"claude"}, args...)...)
	return runRunCmd(full)
}

func runRunCmd(args []string) int {
	// Launch flags are recognized only before the child command.
	options, args := parseRunOptions(args)
	if options.requireTunnel {
		options.tunnelMode = true
	}
	if options.noSandbox && options.tunnelMode {
		fmt.Fprintln(os.Stderr, "agentjail run: --no-sandbox cannot be combined with --tunnel (the tunnel needs the sandbox)")
		return 2
	}
	if options.gitSSH && options.noGitSSH {
		fmt.Fprintln(os.Stderr, "agentjail run: --git-ssh and --no-git-ssh cannot be combined")
		return 2
	}
	if options.noSandbox && (options.gitSSH || options.noGitSSH) {
		fmt.Fprintln(os.Stderr, "agentjail run: Git-over-SSH launch controls require the OS sandbox; remove --no-sandbox")
		return 2
	}
	if options.noSandbox && options.verbose {
		fmt.Fprintln(os.Stderr, "agentjail run: --verbose controls shield logs and cannot be combined with --no-sandbox")
		return 2
	}
	if options.noSandbox && len(options.credentials) > 0 {
		fmt.Fprintln(os.Stderr, "agentjail run: credentialed tools require the OS sandbox; remove --no-sandbox")
		return 2
	}

	// Strip leading "--" if present (cobra passes it through with DisableFlagParsing).
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "agentjail run: no command given")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  usage: agentjail run -- <command> [args...]")
		return 2
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail run: cannot determine home directory: %v\n", err)
		return 1
	}

	// 1. Locate the shield binary (skipped under --no-sandbox).
	var shieldBin string
	if !options.noSandbox {
		shieldBin, err = findShieldBinary(home)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "  Run: agentjail install")
			fmt.Fprintln(os.Stderr, "  to install the shield binary, or pass --no-sandbox to run hook-only.")
			return 1
		}
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

	// 4. Resolve the REAL agent binary, skipping the agentjail shim directory.
	// The shim dir (~/.agentjail/bin) must be FIRST on PATH for transparent
	// `claude` interception, which would make a naive exec.LookPath resolve to
	// the shim and loop. Scanning PATH while skipping the shim dir (and anything
	// that resolves to the shim) works regardless of PATH order.
	agentPath, err := resolveRealAgent(agentName, home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 127
	}

	// 5a. --no-sandbox: exec the agent directly. Policy is still enforced by the
	// installed hook; there is no OS sandbox. This is the honest fallback for
	// hosts that cannot sandbox and an explicit opt-out.
	if options.noSandbox {
		fmt.Fprintf(os.Stderr, "agentjail: starting UNSANDBOXED session for %s — hook-only policy, no OS sandbox\n", agentName)
		execArgs := append([]string{agentPath}, args[1:]...)
		if err := syscall.Exec(agentPath, execArgs, os.Environ()); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed to exec %s: %v\n", agentName, err)
			return 1
		}
		return 0 // unreachable after exec
	}

	// 5b. Exec through shield (default). This replaces the current process.
	shieldArgs := []string{shieldBin}
	if options.tunnelMode {
		shieldArgs = append(shieldArgs, "--tunnel")
	}
	if options.requireTunnel {
		shieldArgs = append(shieldArgs, "--require-tunnel")
	}
	if options.gitSSH {
		shieldArgs = append(shieldArgs, "--git-ssh")
	}
	if options.noGitSSH {
		shieldArgs = append(shieldArgs, "--no-git-ssh")
	}
	if options.verbose {
		shieldArgs = append(shieldArgs, "--verbose")
	}
	for _, credential := range options.credentials {
		shieldArgs = append(shieldArgs, "--credential="+credential)
	}
	shieldArgs = append(shieldArgs, "--", agentPath)
	shieldArgs = append(shieldArgs, args[1:]...)

	if handled, code := maybeBootstrapSSH(options, home, shieldArgs); handled {
		return code
	}

	if err := syscall.Exec(shieldBin, shieldArgs, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to exec shield: %v\n", err)
		return 1
	}

	return 0 // unreachable after exec
}

type runOptions struct {
	tunnelMode    bool
	requireTunnel bool
	noSandbox     bool
	gitSSH        bool
	noGitSSH      bool
	verbose       bool
	credentials   []string
}

func isRunLaunchFlag(arg string) bool {
	if strings.HasPrefix(arg, "--credential=") {
		return true
	}
	switch arg {
	case "--tunnel", "--require-tunnel", "--no-sandbox", "--git-ssh", "--no-git-ssh", "--verbose":
		return true
	default:
		return false
	}
}

// parseRunOptions consumes only AgentJail's leading launch flags; everything
// after the command belongs to the child agent unchanged.
func parseRunOptions(args []string) (runOptions, []string) {
	var options runOptions
	for len(args) > 0 {
		if strings.HasPrefix(args[0], "--credential=") {
			value := strings.TrimPrefix(args[0], "--credential=")
			if value == "" {
				return options, args
			}
			options.credentials = append(options.credentials, value)
			args = args[1:]
			continue
		}
		switch args[0] {
		case "--tunnel":
			options.tunnelMode = true
		case "--require-tunnel":
			options.requireTunnel = true
		case "--no-sandbox":
			options.noSandbox = true
		case "--git-ssh":
			options.gitSSH = true
		case "--no-git-ssh":
			options.noGitSSH = true
		case "--verbose":
			options.verbose = true
		default:
			return options, args
		}
		args = args[1:]
	}
	return options, args
}

// resolveRealAgent finds the real agent binary on PATH, skipping the agentjail
// shim directory (~/.agentjail/bin) and anything that resolves to the shim
// itself. This lets `agentjail run` / `agentjail claude` work even when the shim
// dir is first on PATH (the ordering transparent interception needs) without
// resolving back to the shim and looping. Mirrors the shim script's own
// find_real_claude logic (install_wrapper.go).
func resolveRealAgent(agentName, home string) (string, error) {
	shimDir := filepath.Clean(filepath.Join(home, ".agentjail", "bin"))
	shimResolved, _ := filepath.EvalSymlinks(filepath.Join(shimDir, agentName))

	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if filepath.Clean(dir) == shimDir {
			continue // never resolve into our own shim dir
		}
		cand := filepath.Join(dir, agentName)
		info, err := os.Stat(cand)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		// Defensive: skip a symlink that points back at the shim.
		if shimResolved != "" {
			if r, err := filepath.EvalSymlinks(cand); err == nil && r == shimResolved {
				continue
			}
		}
		return cand, nil
	}
	return "", fmt.Errorf("%q not found on PATH (excluding the agentjail shim dir %s)", agentName, shimDir)
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
