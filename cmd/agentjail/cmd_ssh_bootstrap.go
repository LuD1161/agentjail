package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/sshagent"
	"github.com/spf13/cobra"
)

const sshBootstrapProbeTimeout = 500 * time.Millisecond
const sshBootstrapIdentityTimeout = 2 * time.Second

var sshBootstrapCmd = &cobra.Command{
	Use:                "__ssh-bootstrap -- <command> [args...]",
	Hidden:             true,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runSSHBootstrap(args))
	},
}

func init() {
	rootCmd.AddCommand(sshBootstrapCmd)
}

func gitSSHEnabledForLaunch(options runOptions, home string) (bool, error) {
	if options.noGitSSH {
		return false, nil
	}
	if options.gitSSH {
		return true, nil
	}
	cfg, err := config.LoadPolicyForEnforcement(filepath.Join(home, ".agentjail", "policy.yaml"))
	if err != nil {
		return false, err
	}
	return cfg.GitSSHEnabled(), nil
}

func shouldOfferSSHBootstrap(options runOptions, enabled bool, status sshagent.Status) bool {
	if !enabled || status.Readiness == sshagent.ReadinessReady {
		return false
	}
	if options.gitSSH {
		return true
	}
	// Avoid prompting HTTPS-only users who have no local SSH identity to load.
	return status.KeyState == sshagent.KeyStatePresent || len(status.PinnedIdentityPaths) > 0
}

func maybeBootstrapSSH(options runOptions, home string, shieldArgs []string) (bool, int) {
	enabled, err := gitSSHEnabledForLaunch(options, home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail run: cannot load Git-over-SSH policy: %v\n", err)
		return true, 1
	}
	if !enabled {
		return false, 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), sshBootstrapProbeTimeout)
	status := sshagent.DefaultProber().Probe(ctx)
	cancel()
	if !shouldOfferSSHBootstrap(options, enabled, status) {
		return false, 0
	}

	if _, err := exec.LookPath("ssh-agent"); err != nil {
		fmt.Fprintln(os.Stderr, "agentjail: OpenSSH ssh-agent is not installed")
		if options.gitSSH {
			return true, 1
		}
		return false, 0
	}
	if _, err := exec.LookPath("ssh-add"); err != nil {
		fmt.Fprintln(os.Stderr, "agentjail: OpenSSH ssh-add is not installed")
		if options.gitSSH {
			return true, 1
		}
		return false, 0
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if options.gitSSH {
			fmt.Fprintln(os.Stderr, "agentjail: --git-ssh requires a usable SSH agent or an interactive terminal for OpenSSH setup")
			return true, 1
		}
		return false, 0
	}
	defer tty.Close()
	identities := uniquePaths(append(status.KeyPaths, status.PinnedIdentityPaths...))
	selectionCtx, selectionCancel := context.WithTimeout(context.Background(), sshBootstrapIdentityTimeout)
	cwd, _ := os.Getwd()
	selection := sshagent.DefaultBootstrapIdentityResolver().Resolve(selectionCtx, cwd, home, identities)
	selectionCancel()
	selected, accepted := promptSSHBootstrap(tty, selection, home)
	if !accepted {
		fmt.Fprintln(tty, "Continuing without SSH-agent setup.")
		if options.gitSSH {
			return true, 1
		}
		return false, 0
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail: cannot start the session SSH agent: %v\n", err)
		return true, 1
	}
	agentPath, err := exec.LookPath("ssh-agent")
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail: cannot start OpenSSH ssh-agent: %v\n", err)
		return true, 1
	}
	agentArgs := []string{"ssh-agent", self, "__ssh-bootstrap"}
	for _, identity := range selected {
		agentArgs = append(agentArgs, "--identity", identity)
	}
	agentArgs = append(agentArgs, "--")
	agentArgs = append(agentArgs, shieldArgs...)
	if err := syscall.Exec(agentPath, agentArgs, sessionSSHAgentEnv(os.Environ())); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail: cannot start OpenSSH ssh-agent: %v\n", err)
		return true, 1
	}
	return true, 0
}

// OpenSSH appends its socket suffix literally, so canonicalize the session-agent
// temp root before handoff. See ADR 0139-canonical-ssh-temp.
func sessionSSHAgentEnv(environ []string) []string {
	env := append([]string(nil), environ...)
	for i, entry := range env {
		value, ok := strings.CutPrefix(entry, "TMPDIR=")
		if !ok || value == "" {
			continue
		}
		cleaned := filepath.Clean(value)
		if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
			cleaned = resolved
		}
		env[i] = "TMPDIR=" + cleaned
	}
	return env
}

func promptSSHBootstrap(tty io.ReadWriter, selection sshagent.IdentitySelection, home string) ([]string, bool) {
	reader := bufio.NewReader(tty)
	if len(selection.Paths) > 1 {
		fmt.Fprintln(tty, "Git SSH: choose a key for session-only OpenSSH; AgentJail never reads keys/passphrases.")
		if selection.Source == sshagent.IdentitySelectionSSHConfig {
			fmt.Fprintf(tty, "  Multiple SSH identities match %s:\n", selection.Host)
		} else if selection.Host != "" {
			fmt.Fprintf(tty, "  Multiple local identities were found; SSH config has no match for %s:\n", selection.Host)
		} else {
			fmt.Fprintln(tty, "  Multiple local SSH identities were found:")
		}
		fmt.Fprintln(tty, "  Start a session-only agent with one identity:")
		for i, identity := range selection.Paths {
			fmt.Fprintf(tty, "    %d. %s\n", i+1, displaySSHIdentity(identity, home))
		}
		fmt.Fprintln(tty, "    a. Load all identities (delegates every listed key)")
		fmt.Fprintln(tty, "    n. Continue without Git over SSH")
		for {
			fmt.Fprint(tty, "  Select an identity [1]: ")
			line, err := reader.ReadString('\n')
			if err != nil && len(line) == 0 {
				return nil, false
			}
			answer := strings.ToLower(strings.TrimSpace(line))
			switch answer {
			case "", "1":
				return []string{selection.Paths[0]}, true
			case "a", "all":
				return selection.Paths, true
			case "n", "no":
				return nil, false
			}
			choice, convErr := strconv.Atoi(answer)
			if convErr == nil && choice >= 1 && choice <= len(selection.Paths) {
				return []string{selection.Paths[choice-1]}, true
			}
			fmt.Fprintf(tty, "  Choose 1-%d, a, or n.\n", len(selection.Paths))
		}
	}

	prompt := "Git SSH: let session-only OpenSSH try default identities? AgentJail never reads keys/passphrases. [Y/n] "
	if len(selection.Paths) == 1 {
		identity := displaySSHIdentity(selection.Paths[0], home)
		prompt = fmt.Sprintf("Git SSH: load %s into session-only OpenSSH? AgentJail never reads keys/passphrases. [Y/n] ", identity)
	}
	fmt.Fprint(tty, prompt)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return nil, false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	accepted := answer == "" || answer == "y" || answer == "yes"
	return selection.Paths, accepted
}

func runSSHBootstrap(args []string) int {
	identities, command, err := parseSSHBootstrapArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail: internal SSH bootstrap: %v\n", err)
		return 2
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentjail: SSH setup requires an interactive terminal")
		return 1
	}
	defer tty.Close()

	return completeSSHBootstrap(command, tty, func(tty io.ReadWriter) error {
		return runNativeSSHAdd(tty, identities)
	}, syscall.Exec)
}

func parseSSHBootstrapArgs(args []string) (identities []string, command []string, err error) {
	for len(args) > 0 {
		switch args[0] {
		case "--":
			if len(args) == 1 {
				return nil, nil, fmt.Errorf("no command to launch")
			}
			return uniquePaths(identities), args[1:], nil
		case "--identity":
			if len(args) < 2 || !filepath.IsAbs(args[1]) || filepath.Clean(args[1]) != args[1] || strings.ContainsAny(args[1], "\x00\r\n") {
				return nil, nil, fmt.Errorf("invalid identity path")
			}
			identities = append(identities, args[1])
			args = args[2:]
		default:
			return nil, nil, fmt.Errorf("unexpected argument %q", args[0])
		}
	}
	return nil, nil, fmt.Errorf("no command to launch")
}

func completeSSHBootstrap(args []string, tty io.ReadWriter, runAdd func(io.ReadWriter) error, execProcess func(string, []string, []string) error) int {
	if err := runAdd(tty); err != nil {
		fmt.Fprintf(tty, "OpenSSH could not load a key: %v\n", err)
		return 1
	}
	if err := execProcess(args[0], args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail: cannot launch shield after SSH setup: %v\n", err)
		return 1
	}
	return 0
}

func runNativeSSHAdd(tty io.ReadWriter, identities []string) error {
	add := exec.Command("ssh-add", identities...)
	add.Stdin = tty
	add.Stdout = tty
	add.Stderr = tty
	return add.Run()
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	return result
}

func displaySSHIdentity(path, home string) string {
	sshDir := filepath.Join(home, ".ssh")
	if rel, err := filepath.Rel(sshDir, path); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.Join("~", ".ssh", rel)
	}
	return path
}
