package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/sshagent"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check agentjail installation health",
	Long:  "Diagnose the agentjail installation: platform capabilities, daemon status,\nhook configuration, shield availability, and IDE wrapper setup.",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runDoctor())
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

type doctorCheck struct {
	label  string
	status string // "ok", "warn", "fail", "skip"
	detail string
}

func runDoctor() int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail doctor: cannot determine home directory: %v\n", err)
		return 1
	}

	var checks []doctorCheck
	hasFailure := false

	// ── Platform ────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stdout, "Platform")
	checks = append(checks, checkPlatform()...)
	for _, c := range checks {
		printCheck(c)
	}
	fmt.Fprintln(os.Stdout)

	// ── Shield ──────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stdout, "Shield")
	shieldChecks := checkShield(home)
	for _, c := range shieldChecks {
		printCheck(c)
		if c.status == "fail" {
			hasFailure = true
		}
	}
	fmt.Fprintln(os.Stdout)

	// ── Daemon ──────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stdout, "Daemon")
	daemonChecks := checkDaemon(home)
	for _, c := range daemonChecks {
		printCheck(c)
		if c.status == "fail" {
			hasFailure = true
		}
	}
	fmt.Fprintln(os.Stdout)

	// ── Hooks ───────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stdout, "Hooks")
	hookChecks := checkHooks(home)
	for _, c := range hookChecks {
		printCheck(c)
		if c.status == "fail" {
			hasFailure = true
		}
	}
	fmt.Fprintln(os.Stdout)

	// ── Launch Integration ──────────────────────────────────────────────
	fmt.Fprintln(os.Stdout, "Launch Integration")
	launchChecks := checkLaunchIntegration(home)
	for _, c := range launchChecks {
		printCheck(c)
	}
	fmt.Fprintln(os.Stdout)

	// ── SSH ─────────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stdout, "SSH")
	sshChecks := checkSSHAgent(home)
	for _, c := range sshChecks {
		printCheck(c)
		if c.status == "fail" {
			hasFailure = true
		}
	}
	fmt.Fprintln(os.Stdout)

	// ── Summary ─────────────────────────────────────────────────────────
	if hasFailure {
		fmt.Fprintln(os.Stdout, "Run `agentjail install --all` to fix issues.")
		return 1
	}

	fmt.Fprintln(os.Stdout, "All checks passed.")
	return 0
}

func printCheck(c doctorCheck) {
	var marker string
	switch c.status {
	case "ok":
		marker = "  [ok]  "
	case "warn":
		marker = "  [!]   "
	case "fail":
		marker = "  [ERR] "
	case "skip":
		marker = "  [-]   "
	}
	if c.detail != "" {
		fmt.Fprintf(os.Stdout, "%s%-30s %s\n", marker, c.label, c.detail)
	} else {
		fmt.Fprintf(os.Stdout, "%s%s\n", marker, c.label)
	}
}

func checkPlatform() []doctorCheck {
	var checks []doctorCheck

	checks = append(checks, doctorCheck{
		label:  "OS",
		status: "ok",
		detail: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	})

	switch runtime.GOOS {
	case "linux":
		abi := detectLandlockABI()
		if abi == 0 {
			checks = append(checks, doctorCheck{
				label:  "Landlock",
				status: "fail",
				detail: "not available (kernel < 5.13)",
			})
		} else {
			detail := fmt.Sprintf("ABI v%d", abi)
			if abi < 4 {
				detail += " (filesystem only, no network — kernel < 6.7)"
			} else {
				detail += " (filesystem + network)"
			}
			checks = append(checks, doctorCheck{
				label:  "Landlock",
				status: "ok",
				detail: detail,
			})
		}
	case "darwin":
		checks = append(checks, doctorCheck{
			label:  "Seatbelt",
			status: "ok",
			detail: "available",
		})
	default:
		checks = append(checks, doctorCheck{
			label:  "Sandbox",
			status: "warn",
			detail: "no OS-native sandbox on this platform",
		})
	}

	return checks
}

func checkShield(home string) []doctorCheck {
	var checks []doctorCheck

	shieldBin, err := findShieldBinary(home)
	if err != nil {
		checks = append(checks, doctorCheck{
			label:  "agentjail-shield",
			status: "fail",
			detail: "not found — run `agentjail install`",
		})
	} else {
		checks = append(checks, doctorCheck{
			label:  "agentjail-shield",
			status: "ok",
			detail: shieldBin,
		})
	}

	return checks
}

func checkDaemon(home string) []doctorCheck {
	var checks []doctorCheck

	sockPath := filepath.Join(home, ".agentjail", "daemon.sock")
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		checks = append(checks, doctorCheck{
			label:  "Socket",
			status: "fail",
			detail: fmt.Sprintf("not found at %s", sockPath),
		})
		return checks
	}

	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		checks = append(checks, doctorCheck{
			label:  "Socket",
			status: "fail",
			detail: fmt.Sprintf("cannot connect: %v", err),
		})
	} else {
		conn.Close()
		checks = append(checks, doctorCheck{
			label:  "Socket",
			status: "ok",
			detail: "connected",
		})
	}

	return checks
}

func checkHooks(home string) []doctorCheck {
	var checks []doctorCheck

	hookBin := filepath.Join(home, ".agentjail", "bin", "agentjail-hook")
	if _, err := os.Stat(hookBin); os.IsNotExist(err) {
		checks = append(checks, doctorCheck{
			label:  "Hook binary",
			status: "fail",
			detail: "not found — run `agentjail install`",
		})
		return checks
	}

	checks = append(checks, doctorCheck{
		label:  "Hook binary",
		status: "ok",
		detail: hookBin,
	})

	// Check Claude Code hooks.
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if b, err := os.ReadFile(settingsPath); err == nil {
		if strings.Contains(string(b), "agentjail-hook") {
			checks = append(checks, doctorCheck{
				label:  "Claude Code",
				status: "ok",
				detail: "hook installed",
			})
		} else {
			checks = append(checks, doctorCheck{
				label:  "Claude Code",
				status: "warn",
				detail: "settings.json exists but agentjail hook not found",
			})
		}
	} else if os.IsNotExist(err) {
		checks = append(checks, doctorCheck{
			label:  "Claude Code",
			status: "skip",
			detail: "~/.claude/settings.json not found",
		})
	}

	return checks
}

func checkLaunchIntegration(home string) []doctorCheck {
	var checks []doctorCheck

	// PATH shim.
	shimPath := filepath.Join(home, ".agentjail", "bin", "claude")
	switch _, err := os.Stat(shimPath); {
	case err == nil:
		checks = append(checks, doctorCheck{
			label:  "PATH shim",
			status: "ok",
			detail: shimPath,
		})
	case shimConsentRecorded(home):
		// Dangling: the shell profile still prepends ~/.agentjail/bin to PATH,
		// but no shim sits there, so `claude` silently resolves to the real
		// unshielded binary. Reported as a failure, not a neutral "opt-in"
		// note — the user opted in and is not getting it (ADR 0062).
		checks = append(checks, doctorCheck{
			label:  "PATH shim",
			status: "fail",
			detail: "MISSING but your shell profile opts into it — `claude` is running UNSHIELDED. Repair: agentjail install --with-path-shim",
		})
	default:
		checks = append(checks, doctorCheck{
			label:  "PATH shim",
			status: "skip",
			detail: "not installed (opt-in: agentjail install --with-path-shim)",
		})
	}

	// VS Code wrapper.
	vscodeStatus := checkVSCodeWrapper(home, "Code")
	checks = append(checks, vscodeStatus)

	// Cursor wrapper.
	cursorStatus := checkVSCodeWrapper(home, "Cursor")
	checks = append(checks, cursorStatus)

	return checks
}

// checkSSHAgent probes ssh-agent readiness and reports whether an on-disk
// SSH key is actually usable. The shield blocks direct key-file reads (ADR
// 0001), so ssh access must go through ssh-agent forwarding — this check
// surfaces a clear diagnosis instead of a cryptic "Permission denied
// (publickey)" failure.
func checkSSHAgent(home string) []doctorCheck {
	_ = home // unused; sshagent.Probe locates ~/.ssh via os.UserHomeDir itself.

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	st := sshagent.Probe(ctx)
	return []doctorCheck{sshAgentCheck(st)}
}

// sshAgentCheck maps a probed sshagent.Status to a doctorCheck. It is a pure
// function of Status so it can be tested with hand-built values without a
// real ssh-agent.
//
// Ordering matters (Codex-required): PinnedBlindSpot is independent of
// KeysOnDisk (a pinned deploy key that ListKeyFiles never globs still hits
// the trap), so it must be evaluated BEFORE the !KeysOnDisk skip - otherwise
// a deploy-key-only user with no id_* files would be wrongly skipped instead
// of warned.
func sshAgentCheck(st sshagent.Status) doctorCheck {
	if st.Readiness == sshagent.ReadinessReady && st.PinnedBlindSpot() {
		return doctorCheck{
			label:  "ssh-agent",
			status: "warn",
			detail: "ssh key is loaded but your ssh config pins an IdentityFile the shield blocks, so ssh reads it first and fails. Fix: " + st.PinnedRemediation(runtime.GOOS) + " (git is auto-handled by the shield unless AGENTJAIL_NO_SSH_OVERRIDE is set)",
		}
	}

	if !st.KeysOnDisk && !st.PinnedIdentity() {
		return doctorCheck{
			label:  "ssh-agent",
			status: "skip",
			detail: "no ssh keys in ~/.ssh — skipping",
		}
	}

	if st.Readiness == sshagent.ReadinessReady {
		return doctorCheck{
			label:  "ssh-agent",
			status: "ok",
			detail: "key(s) loaded in agent",
		}
	}

	// NeedsRemediation() is true here: keys are on disk but not loaded.
	// This is user environment state, not an agentjail install defect, so
	// it must never trip hasFailure — status stays "warn".
	return doctorCheck{
		label:  "ssh-agent",
		status: "warn",
		detail: "ssh keys on disk but not loaded in ssh-agent; the shield blocks key-file reads, so ssh needs the agent. Fix: " + st.Remediation(runtime.GOOS),
	}
}

func checkVSCodeWrapper(home, app string) doctorCheck {
	settingsPath := vscodeSettingsPath(home, app)
	if settingsPath == "" {
		return doctorCheck{
			label:  app + " wrapper",
			status: "skip",
			detail: app + " not detected",
		}
	}

	b, err := os.ReadFile(settingsPath)
	if err != nil {
		return doctorCheck{
			label:  app + " wrapper",
			status: "skip",
			detail: "settings file not readable",
		}
	}

	content := string(b)
	if strings.Contains(content, "claudeCode.claudeProcessWrapper") {
		if strings.Contains(content, "agentjail") {
			return doctorCheck{
				label:  app + " wrapper",
				status: "ok",
				detail: "agentjail wrapper configured",
			}
		}
		return doctorCheck{
			label:  app + " wrapper",
			status: "warn",
			detail: "claudeProcessWrapper set to non-agentjail value",
		}
	}

	return doctorCheck{
		label:  app + " wrapper",
		status: "skip",
		detail: "claudeProcessWrapper not set",
	}
}

// vscodeSettingsPath returns the user settings.json path for VS Code or Cursor.
// Returns empty string if the app directory doesn't exist.
func vscodeSettingsPath(home, app string) string {
	var dir string
	switch runtime.GOOS {
	case "linux":
		switch app {
		case "Code":
			dir = filepath.Join(home, ".config", "Code", "User")
		case "Cursor":
			dir = filepath.Join(home, ".config", "Cursor", "User")
		}
	case "darwin":
		switch app {
		case "Code":
			dir = filepath.Join(home, "Library", "Application Support", "Code", "User")
		case "Cursor":
			dir = filepath.Join(home, "Library", "Application Support", "Cursor", "User")
		}
	}
	if dir == "" {
		return ""
	}
	settingsPath := filepath.Join(dir, "settings.json")
	if _, err := os.Stat(filepath.Dir(settingsPath)); os.IsNotExist(err) {
		return ""
	}
	return settingsPath
}

// detectLandlockABI probes the kernel for the highest supported Landlock ABI.
// Returns 0 if Landlock is not available.
func detectLandlockABI() int {
	// Try to detect via /sys or by probing the syscall.
	// For now, use a simple heuristic based on kernel version.
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return 0
	}

	version := string(data)
	// Very rough heuristic — the shield_linux.go has proper ABI probing.
	// This is just for doctor output.
	if strings.Contains(version, "Linux version 5.") {
		major := 5
		_ = major
		return 1 // ABI v1 at best
	}
	if strings.Contains(version, "Linux version 6.") {
		// Check minor for network support (ABI v4 = 6.7+)
		for _, prefix := range []string{"6.7", "6.8", "6.9", "6.10", "6.11", "6.12"} {
			if strings.Contains(version, "Linux version "+prefix) {
				return 4
			}
		}
		return 2 // 6.0-6.6
	}
	return 0
}

// findShieldBinary is defined in cmd_run.go but used by doctor too.
// If cmd_run.go is not compiled (shouldn't happen), this would fail at link time
// which is the correct behavior — both commands should always be present.

// findAgentBinary checks if an agent binary exists on PATH.
func findAgentBinary(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}
