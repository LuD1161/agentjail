package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/keyring"
	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/sshagent"
	"github.com/LuD1161/agentjail/internal/ui"
	"github.com/LuD1161/agentjail/internal/wire"
	"github.com/spf13/cobra"
)

var doctorFix bool

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run comprehensive protection diagnostics",
	Long:  "Diagnose platform capabilities, daemon status, hook configuration, shield\navailability, network enforcement, SSH delegation, and IDE wrappers. Use\n'agentjail status' for a quick installed-component snapshot.\n\nWith --fix, repair the failures agentjail can safely repair itself, then\nre-check and report the real post-repair state.",
	Run: func(cmd *cobra.Command, args []string) {
		mode := diagnoseOnly
		if doctorFix {
			mode = repairFailures
		}
		os.Exit(runDoctor(mode))
	},
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "repair the failures doctor can safely repair (default: diagnose only)")
	rootCmd.AddCommand(doctorCmd)
}

// checkStatus is a check's verdict. Named so a check cannot be given a status
// that printCheck and the exit-code logic disagree about.
type checkStatus string

const (
	statusOK   checkStatus = "ok"
	statusWarn checkStatus = "warn"
	statusFail checkStatus = "fail"
	statusSkip checkStatus = "skip"
)

type doctorCheck struct {
	label  string
	status checkStatus
	detail string
	// repair names the fix for this finding, empty for advice-only findings.
	// A repair runs only when the check carrying its id failed
	// (ADR 0086-doctor-repairs-diagnosed).
	repair repairID
}

// repairMode gates every mutation doctor can make. Diagnose-only is the
// default: doctor exists to attest, and a repair that runs unasked can turn an
// honest "you are unprotected" into a false "all good"
// (ADR 0086-doctor-repairs-diagnosed).
type repairMode int

const (
	diagnoseOnly repairMode = iota
	repairFailures
)

// doctorSection is one printed group of checks. gatesExit preserves the
// per-section exit semantics ADR 0082-doctor-attests-enforcement settled.
type doctorSection struct {
	name      string
	run       func(home string) []doctorCheck
	gatesExit bool
}

func doctorSections() []doctorSection {
	return []doctorSection{
		{name: "Platform", run: func(string) []doctorCheck { return checkPlatform() }},
		{name: "Shield", run: checkShield, gatesExit: true},
		// Does not gate exit: an absent tunnel is a posture, not a fault.
		{name: "Network Interception", run: func(string) []doctorCheck {
			checks := append(checkNetworkInterception(), checkTLSInterceptionPosture(), checkBodyEncryption())
			return append(checks, checkNetworkKnobSources()...)
		}},
		{name: "Daemon", run: checkDaemon, gatesExit: true},
		// Everything above reports what is configured RIGHT NOW; this reports
		// whether enforcement actually ran (ADR 0082-doctor-attests-enforcement).
		{name: "Protection", run: checkProtection, gatesExit: true},
		{name: "Hooks", run: checkHooks, gatesExit: true},
		{name: "Launch Integration", run: checkLaunchIntegration},
		{name: "SSH", run: checkSSHAgent, gatesExit: true},
	}
}

func runDoctor(mode repairMode) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail doctor: cannot determine home directory: %v\n", err)
		return 1
	}

	var repairable []doctorCheck
	otherFailures, gatingRepairs, warnings := 0, 0, 0
	u := ui.New(os.Stdout)

	fmt.Fprintln(os.Stdout, u.Header("AgentJail Doctor", "system health & protection", runtime.GOOS+"/"+runtime.GOARCH))
	fmt.Fprintln(os.Stdout)

	for _, s := range doctorSections() {
		fmt.Fprintln(os.Stdout, u.Section(doctorSectionTitle(u, s.name)))
		for _, c := range s.run(home) {
			printCheck(u, c)
			if c.status == statusWarn {
				warnings++
			}
			if c.status != statusFail {
				continue
			}
			if c.repair != "" {
				repairable = append(repairable, c)
			}
			if !s.gatesExit {
				continue
			}
			if c.repair == "" {
				otherFailures++
			} else {
				gatingRepairs++
			}
		}
		fmt.Fprintln(os.Stdout)
	}

	if mode == repairFailures {
		return runRepairPass(home, repairRegistry, repairable, otherFailures)
	}

	if len(repairable) > 0 {
		fmt.Fprintf(os.Stdout, "%d failure(s) above can be repaired: agentjail doctor --fix\n", len(repairable))
	}
	if otherFailures+gatingRepairs > 0 {
		fmt.Fprintln(os.Stdout, "Run `agentjail install --all` to fix issues.")
		return 1
	}

	if warnings > 0 {
		fmt.Fprintf(os.Stdout, "%d warning(s) above need attention.\n", warnings)
		return 0
	}
	fmt.Fprintln(os.Stdout, u.Badge("ok", "All checks passed."))
	return 0
}

// runRepairPass applies each failed check's repair and then re-checks it
// independently. The reported state is the observed post-repair state, never
// the repair's own return value (ADR 0086-doctor-repairs-diagnosed).
func runRepairPass(home string, reg map[repairID]repairAction, repairable []doctorCheck, otherFailures int) int {
	u := ui.New(os.Stdout)
	if len(repairable) == 0 {
		if otherFailures > 0 {
			fmt.Fprintln(os.Stdout, "Nothing here is safely repairable — run `agentjail install --all` to fix issues.")
			return 1
		}
		fmt.Fprintln(os.Stdout, "All checks passed. Nothing to repair.")
		return 0
	}

	fmt.Fprintln(os.Stdout, u.Section(u.Emoji("🪛  ")+"Repair"))
	allRepaired := true
	for _, c := range repairable {
		act, ok := reg[c.repair]
		if !ok {
			printCheck(u, doctorCheck{label: c.label, status: statusFail, detail: fmt.Sprintf("no repair registered for %q", c.repair)})
			allRepaired = false
			continue
		}
		fmt.Fprintf(os.Stdout, "  ->    %s\n", act.label)
		if err := act.apply(home); err != nil {
			printCheck(u, doctorCheck{label: c.label, status: statusFail, detail: fmt.Sprintf("repair FAILED: %v", err)})
			allRepaired = false
			continue
		}
		post := act.recheck(home)
		printCheck(u, post)
		if post.status != statusOK {
			allRepaired = false
		}
	}
	fmt.Fprintln(os.Stdout)

	switch {
	case !allRepaired:
		fmt.Fprintln(os.Stdout, "Repair did NOT restore every check — you are still not protected. Run `agentjail install --all`.")
		return 1
	case otherFailures > 0:
		fmt.Fprintln(os.Stdout, "Repaired what doctor can; other checks still fail. Run `agentjail install --all` to fix issues.")
		return 1
	}
	fmt.Fprintln(os.Stdout, "Repaired and verified.")
	return 0
}

func printCheck(u *ui.UI, c doctorCheck) {
	kind := string(c.status)
	if c.status == statusSkip {
		kind = "skip"
	}
	fmt.Fprintln(os.Stdout, "  "+u.StatusRow(kind, c.label, c.detail, 30))
}

func doctorSectionTitle(u *ui.UI, name string) string {
	emoji := map[string]string{
		"Platform":             "🖥  ",
		"Shield":               "🛡  ",
		"Network Interception": "🌐  ",
		"Daemon":               "⚙  ",
		"Protection":           "🔒  ",
		"Hooks":                "🪝  ",
		"Launch Integration":   "🚀  ",
		"SSH":                  "🔑  ",
	}
	return u.Emoji(emoji[name]) + name
}

func checkPlatform() []doctorCheck {
	var checks []doctorCheck

	checks = append(checks, doctorCheck{
		label:  "OS",
		status: statusOK,
		detail: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	})

	switch runtime.GOOS {
	case "linux":
		abi := detectLandlockABI()
		if abi == 0 {
			checks = append(checks, doctorCheck{
				label:  "Landlock",
				status: statusFail,
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
				status: statusOK,
				detail: detail,
			})
		}
	case "darwin":
		checks = append(checks, doctorCheck{
			label:  "Seatbelt",
			status: statusOK,
			detail: "available",
		})
	default:
		checks = append(checks, doctorCheck{
			label:  "Sandbox",
			status: statusWarn,
			detail: "no OS-native sandbox on this platform",
		})
	}

	return checks
}

// checkShield stays advice-only: replacing a missing binary is an install
// action (fetch, verify, place), not a repair (ADR 0086-doctor-repairs-diagnosed).
func checkShield(home string) []doctorCheck {
	var checks []doctorCheck

	shieldBin, err := findShieldBinary(home)
	if err != nil {
		checks = append(checks, doctorCheck{
			label:  "agentjail-shield",
			status: statusFail,
			detail: "not found — run `agentjail install`",
		})
	} else {
		checks = append(checks, doctorCheck{
			label:  "agentjail-shield",
			status: statusOK,
			detail: shieldBin,
		})
	}

	return checks
}

// daemonLiveness is what actually holds daemon.sock.
type daemonLiveness int

const (
	daemonSocketAbsent daemonLiveness = iota
	daemonNoListener                  // socket file present, dial failed
	daemonUnresponsive                // dialed, no valid ping reply
	daemonHealthy                     // answered ControlOpPing
)

const doctorPingTimeout = 500 * time.Millisecond

// Must require a ping reply: a wedged daemon still holds the socket, so a
// dial-and-close reads as healthy. Callers pass their own budget.
// See ADR 0086-doctor-repairs-diagnosed.
func probeDaemon(sockPath string, timeout time.Duration) (daemonLiveness, error) {
	liveness, _, err := probeDaemonDetails(sockPath, timeout)
	return liveness, err
}

func probeDaemonDetails(sockPath string, timeout time.Duration) (daemonLiveness, string, error) {
	if _, err := os.Stat(sockPath); err != nil {
		return daemonSocketAbsent, "", err
	}
	conn, err := net.DialTimeout("unix", sockPath, timeout)
	if err != nil {
		return daemonNoListener, "", err
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(wire.ControlRequest{Type: wire.ControlType, Op: wire.ControlOpPing}); err != nil {
		return daemonUnresponsive, "", err
	}
	var resp wire.ControlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return daemonUnresponsive, "", err
	}
	if !resp.OK {
		return daemonUnresponsive, "", fmt.Errorf("daemon replied not ok: %s", resp.Error)
	}
	return daemonHealthy, resp.Version, nil
}

// daemonLivenessCheck maps a probe result to a check. Pure, so the repair gate
// is tested without a daemon.
func daemonLivenessCheck(l daemonLiveness, sockPath string, probeErr error) doctorCheck {
	switch l {
	case daemonHealthy:
		return doctorCheck{label: "Socket", status: statusOK, detail: "daemon answered ping"}
	case daemonNoListener:
		return doctorCheck{
			label: "Socket", status: statusFail, repair: repairDaemon,
			detail: fmt.Sprintf("nothing listening on %s: %v — policy is NOT being enforced", sockPath, probeErr),
		}
	case daemonUnresponsive:
		return doctorCheck{
			label: "Socket", status: statusFail, repair: repairDaemon,
			detail: fmt.Sprintf("%s accepts connections but did not answer a ping: %v — policy is NOT being enforced", sockPath, probeErr),
		}
	default:
		return doctorCheck{
			label: "Socket", status: statusFail, repair: repairDaemon,
			detail: fmt.Sprintf("not found at %s — the daemon is not running, so policy is NOT being enforced", sockPath),
		}
	}
}

func daemonSocketPath(home string) string {
	return filepath.Join(home, ".agentjail", "daemon.sock")
}

func daemonSocketCheck(home string) doctorCheck {
	sockPath := daemonSocketPath(home)
	l, err := probeDaemon(sockPath, doctorPingTimeout)
	return daemonLivenessCheck(l, sockPath, err)
}

func daemonVersionCheck(l daemonLiveness, runningVersion, installedVersion string) doctorCheck {
	if l != daemonHealthy {
		return doctorCheck{label: "Version", status: statusSkip, detail: "unavailable until the daemon answers ping"}
	}
	if runningVersion == "" {
		return doctorCheck{
			label: "Version", status: statusFail, repair: repairDaemon,
			detail: "running daemon predates version reporting — restart required",
		}
	}
	if runningVersion != installedVersion {
		return doctorCheck{
			label: "Version", status: statusFail, repair: repairDaemon,
			detail: fmt.Sprintf("running %s, installed %s — restart required", runningVersion, installedVersion),
		}
	}
	return doctorCheck{label: "Version", status: statusOK, detail: runningVersion}
}

func checkDaemon(home string) []doctorCheck {
	sockPath := daemonSocketPath(home)
	liveness, runningVersion, err := probeDaemonDetails(sockPath, doctorPingTimeout)
	return []doctorCheck{
		daemonLivenessCheck(liveness, sockPath, err),
		daemonVersionCheck(liveness, runningVersion, buildinfo.Version),
		serviceRestartPolicyCheck(home),
	}
}

// serviceRestartPolicyCheck reads the DEPLOYED definition, never the template:
// only the bytes on disk decide whether the daemon returns after the updater's
// exit(0), and an install predating the template fix still has the old ones.
// See ADR 0088-deployed-supervisor-verified.
func serviceRestartPolicyCheck(home string) doctorCheck {
	const label = "Restart policy"
	spec := daemonServiceSpec(home)

	b, err := os.ReadFile(spec.path)
	switch {
	case os.IsNotExist(err):
		// Absent means no supervisor at all — an install action, not a repair
		// (ADR 0086-doctor-repairs-diagnosed).
		return doctorCheck{
			label:  label,
			status: statusFail,
			detail: fmt.Sprintf("no %s at %s — the daemon has no supervisor. Repair: agentjail install", spec.label, spec.path),
		}
	case err != nil:
		return doctorCheck{
			label:  label,
			status: statusFail,
			detail: fmt.Sprintf("cannot read %s at %s: %v", spec.label, spec.path, err),
		}
	case !restartsOnCleanExit(currentGOOS, string(b)):
		return doctorCheck{
			label:  label,
			status: statusFail,
			repair: repairServiceDef,
			detail: fmt.Sprintf("deployed %s will NOT restart the daemon after a clean exit — the next auto-update strands it, leaving you UNPROTECTED (ADR 0070). Repair: agentjail doctor --fix", spec.label),
		}
	}
	return doctorCheck{label: label, status: statusOK, detail: fmt.Sprintf("%s restarts the daemon after a clean exit", spec.label)}
}

func checkHooks(home string) []doctorCheck {
	var checks []doctorCheck

	hookBin := filepath.Join(home, ".agentjail", "bin", "agentjail-hook")
	if _, err := os.Stat(hookBin); os.IsNotExist(err) {
		checks = append(checks, doctorCheck{
			label:  "Hook binary",
			status: statusFail,
			detail: "not found — run `agentjail install`",
		})
		return checks
	}

	checks = append(checks, doctorCheck{
		label:  "Hook binary",
		status: statusOK,
		detail: hookBin,
	})

	// Check Claude Code hooks.
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if b, err := os.ReadFile(settingsPath); err == nil {
		if strings.Contains(string(b), "agentjail-hook") {
			checks = append(checks, doctorCheck{
				label:  "Claude Code",
				status: statusOK,
				detail: "hook installed",
			})
		} else {
			checks = append(checks, doctorCheck{
				label:  "Claude Code",
				status: statusWarn,
				detail: "settings.json exists but agentjail hook not found",
			})
		}
	} else if os.IsNotExist(err) {
		checks = append(checks, doctorCheck{
			label:  "Claude Code",
			status: statusSkip,
			detail: "~/.claude/settings.json not found",
		})
	}

	return checks
}

// pathShimCheck reports the shim's state. Only the dangling case is repairable:
// the "never opted in" case carries no repair, because installing a shim the
// user never consented to is not a repair (ADR 0086-doctor-repairs-diagnosed).
func pathShimCheck(home string) doctorCheck {
	shimDir := filepath.Join(home, ".agentjail", "bin")
	switch {
	case pathShimsInstalled(home):
		return doctorCheck{
			label:  "PATH shim",
			status: statusOK,
			detail: filepath.Join(shimDir, "{claude,codex,agent}"),
		}
	case shimConsentRecorded(home):
		var missing []string
		for _, target := range pathShimTargets {
			if _, err := os.Stat(filepath.Join(shimDir, target.Command)); err != nil {
				missing = append(missing, target.Command)
			}
		}
		return doctorCheck{
			label:  "PATH shim",
			status: statusFail,
			repair: repairPathShim,
			detail: fmt.Sprintf("MISSING %s but your shell profile opts in — those agents run UNSHIELDED. Repair: agentjail doctor --fix (or agentjail install --with-path-shim)", strings.Join(missing, ", ")),
		}
	default:
		return doctorCheck{
			label:  "PATH shim",
			status: statusSkip,
			detail: "not installed (opt-in: agentjail install --with-path-shim)",
		}
	}
}

func checkLaunchIntegration(home string) []doctorCheck {
	checks := []doctorCheck{pathShimCheck(home)}

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
// A shielded session cannot fall back to private-key files. Its socket must be
// usable even when ~/.ssh cannot be inspected. See ADR 0056-ssh-agent-pinned-identityfile-blindspot.
func sshAgentCheck(st sshagent.Status) doctorCheck {
	if st.PinnedBlindSpot() {
		return doctorCheck{
			label:  "ssh-agent",
			status: statusWarn,
			detail: "ssh key is loaded but your ssh config pins an IdentityFile the shield blocks, so ssh reads it first and fails. Fix: " + st.PinnedRemediation(runtime.GOOS) + " (git is auto-handled by the shield unless AGENTJAIL_NO_SSH_OVERRIDE is set)",
		}
	}

	if st.Execution == sshagent.ExecutionShielded {
		switch st.Readiness {
		case sshagent.ReadinessReady:
			return doctorCheck{
				label:  "ssh-agent",
				status: statusWarn,
				detail: "SSH-agent delegation is active with key(s) loaded. It exposes signing operations for every loaded identity and is not host- or repository-scoped",
			}
		case sshagent.ReadinessNoKeys:
			return doctorCheck{
				label:  "ssh-agent",
				status: statusWarn,
				detail: "SSH-agent delegation is active but the delegated agent has no loaded identities; private-key files stay blocked, so SSH Git cannot authenticate",
			}
		case sshagent.ReadinessNoAgent:
			if st.SockPath == "" {
				if st.Delegation == sshagent.DelegationRequested {
					return doctorCheck{
						label:  "ssh-agent",
						status: statusWarn,
						detail: "SSH-agent delegation was requested but is unavailable: SSH_AUTH_SOCK is unset. Private-key files stay blocked, so SSH Git cannot authenticate",
					}
				}
				return doctorCheck{
					label:  "ssh-agent",
					status: statusWarn,
					detail: "Git-over-SSH capability is not active in this shielded session; private-key files stay blocked, so SSH Git is unavailable",
				}
			}
			if st.Delegation == sshagent.DelegationRequested {
				return doctorCheck{
					label:  "ssh-agent",
					status: statusWarn,
					detail: "SSH-agent delegation was requested but the delegated SSH_AUTH_SOCK is unusable; private-key files stay blocked, so SSH Git cannot authenticate",
				}
			}
			return doctorCheck{
				label:  "ssh-agent",
				status: statusWarn,
				detail: "shielded session has an undelegated SSH_AUTH_SOCK that is unusable; private-key files stay blocked, so SSH Git cannot authenticate",
			}
		}
	}

	if st.Readiness == sshagent.ReadinessReady {
		return doctorCheck{
			label:  "ssh-agent",
			status: statusOK,
			detail: "key(s) loaded in agent",
		}
	}

	if st.KeyState == sshagent.KeyStateUnknown {
		return doctorCheck{
			label:  "ssh-agent",
			status: statusWarn,
			detail: "could not inspect ~/.ssh, so ssh key availability is unknown",
		}
	}

	if st.KeyState == sshagent.KeyStateAbsent {
		return doctorCheck{
			label:  "ssh-agent",
			status: statusSkip,
			detail: "no ssh keys in ~/.ssh — skipping",
		}
	}

	// A missing loaded key is a user-environment warning, not an install failure.
	return doctorCheck{
		label:  "ssh-agent",
		status: statusWarn,
		detail: "ssh keys on disk but not loaded in ssh-agent; the shield blocks key-file reads, so ssh needs the agent. Fix: " + st.Remediation(runtime.GOOS),
	}
}

func checkVSCodeWrapper(home, app string) doctorCheck {
	settingsPath := vscodeSettingsPath(home, app)
	if settingsPath == "" {
		return doctorCheck{
			label:  app + " wrapper",
			status: statusSkip,
			detail: app + " not detected",
		}
	}

	b, err := os.ReadFile(settingsPath)
	if err != nil {
		return doctorCheck{
			label:  app + " wrapper",
			status: statusSkip,
			detail: "settings file not readable",
		}
	}

	content := string(b)
	if strings.Contains(content, "claudeCode.claudeProcessWrapper") {
		if strings.Contains(content, "agentjail") {
			return doctorCheck{
				label:  app + " wrapper",
				status: statusOK,
				detail: "agentjail wrapper configured",
			}
		}
		return doctorCheck{
			label:  app + " wrapper",
			status: statusWarn,
			detail: "claudeProcessWrapper set to non-agentjail value",
		}
	}

	return doctorCheck{
		label:  app + " wrapper",
		status: statusSkip,
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

// checkTLSInterceptionPosture reports whether agentjail would decrypt a
// shielded agent's HTTPS. Cross-platform by contract, so it lives here rather
// than in the per-OS checkNetworkInterception. ADR 0077 (D4).
func checkTLSInterceptionPosture() doctorCheck {
	const label = "TLS interception"

	path, err := policyConfigPath()
	if err != nil {
		return doctorCheck{label: label, status: "skip", detail: "cannot locate policy.yaml: " + err.Error()}
	}
	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		return doctorCheck{label: label, status: "skip", detail: "cannot read policy.yaml: " + err.Error()}
	}

	if cfg.Network.TunnelMITM != nil && !*cfg.Network.TunnelMITM {
		return doctorCheck{
			label:  label,
			status: "warn",
			detail: "OFF — network.tunnel_mitm: false in policy.yaml. --tunnel relays TLS opaquely, so HTTP(S) policy templates cannot match (host/SNI visibility only). Remove it, or pass --mitm, to restore L7 policy",
		}
	}
	return doctorCheck{
		label:  label,
		status: "ok",
		detail: "on — under --tunnel, agentjail decrypts the agent's HTTPS via a per-session CA scoped to that agent's namespace (never the host), so policy templates apply. Pass --no-mitm, or set network.tunnel_mitm: false, to relay TLS opaquely instead",
	}
}

// tunnelIPv6EnvVar mirrors internal/shieldapp's transitional override name
// (AGE-262). Doctor reads it directly rather than importing shieldapp, since
// shieldapp is a leaf binary package, not a library other commands import.
const tunnelIPv6EnvVar = "AGENTJAIL_TUNNEL_IPV6"

// checkNetworkKnobSources reports, for each of the three network knobs
// (tunnel_mitm, capture_gateway, tunnel_ipv6), the value doctor sees from
// policy.yaml/env RIGHT NOW and which layer decided it -- config, env, or
// default. It cannot see a per-launch CLI flag (doctor does not launch
// anything), so "cli" never appears here; it is documented as the highest
// layer so users know a flag on their next `agentjail-shield` invocation can
// still override what is shown. Precedence for all three, highest first:
// cli > env > config > default. See ADR 0110-network-flag-consolidation.
func checkNetworkKnobSources() []doctorCheck {
	path, err := policyConfigPath()
	if err != nil {
		return []doctorCheck{{label: "Network knobs", status: "skip", detail: "cannot locate policy.yaml: " + err.Error()}}
	}
	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		return []doctorCheck{{label: "Network knobs", status: "skip", detail: "cannot read policy.yaml: " + err.Error()}}
	}

	describe := func(label string, val *bool, defaultVal bool, envVar string) doctorCheck {
		effective := defaultVal
		source := "default"
		switch {
		case envVar != "" && os.Getenv(envVar) == "1":
			effective = true
			source = "env (" + envVar + ", transitional)"
		case val != nil:
			effective = *val
			source = "config"
		}
		return doctorCheck{
			label:  label,
			status: "ok",
			detail: fmt.Sprintf("%t (source: %s; a CLI flag on the next launch takes precedence over all of this — cli > env > config > default)", effective, source),
		}
	}

	return []doctorCheck{
		describe("tunnel_mitm (effective)", cfg.Network.TunnelMITM, true, ""),
		describe("capture_gateway (effective)", cfg.Network.CaptureGateway, true, ""),
		describe("tunnel_ipv6 (effective)", cfg.Network.TunnelIPv6, false, tunnelIPv6EnvVar),
	}
}

// bodyKEKPosture is what doctor learned about the live KEK: which tier holds
// it and which backend implements that tier.
type bodyKEKPosture struct {
	tier    keyring.Tier
	backend string
}

// openBodyKEK is the seam: it reports the live KEK posture, or why there is
// none. keyring.Open is itself deadline-bounded (~3s), so doctor adds no
// timeout of its own. See ADR 0092-persist-request-bodies.
var openBodyKEK = func() (bodyKEKPosture, error) {
	k, err := keyring.Open()
	if err != nil {
		return bodyKEKPosture{}, err
	}
	return bodyKEKPosture{tier: k.Tier(), backend: k.Backend()}, nil
}

// checkBodyEncryption reports a property of the machine, so it runs whether or
// not a tunnel ever captured a body. ADR 0092 (D1/D3).
func checkBodyEncryption() doctorCheck {
	return bodyEncryptionCheck(openBodyKEK())
}

// bodyEncryptionCheck maps a KEK probe to a check. ErrKeychainLocked WRAPS
// ErrNoKeychain, so it must be tested first or locked reports the absent advice
// (AGE-254 is exactly this distinction).
func bodyEncryptionCheck(p bodyKEKPosture, err error) doctorCheck {
	const label = "Body encryption"
	// Degraded, never a failure: recording keeps working in the clear and says
	// so (ADR 0092-persist-request-bodies).
	switch {
	case err == nil:
		return bodyEncryptionTierCheck(label, p)
	case errors.Is(err, keyring.ErrKeychainLocked):
		return doctorCheck{
			label:  label,
			status: statusWarn,
			detail: fmt.Sprintf("OFF — a keychain is present but LOCKED, so no KEK is available and captured bodies are written IN THE CLEAR. Fix: unlock the login keyring, or enable PAM auto-unlock at login so it opens without an interactive prompt (%v)", err),
		}
	case errors.Is(err, keyring.ErrNoKeychain):
		return doctorCheck{
			label:  label,
			status: statusWarn,
			detail: fmt.Sprintf("OFF — no OS keychain on this host, so there is nothing to unlock and captured bodies are written IN THE CLEAR. Fix: run agentjail where a keychain exists, or accept plaintext bodies and rely on the sandbox deny (ADR 0092 D3) (%v)", err),
		}
	default:
		return doctorCheck{
			label:  label,
			status: statusWarn,
			detail: fmt.Sprintf("OFF — cannot reach a KEK, so captured bodies are written IN THE CLEAR: %v", err),
		}
	}
}

// bodyEncryptionTierCheck names the live tier and what it buys. A flat
// "encrypted" would be a lie for TierFileKEK, whose key sits under $HOME beside
// nothing but still falls to a whole-$HOME backup. See ADR 0097-linux-kek-fallback.
func bodyEncryptionTierCheck(label string, p bodyKEKPosture) doctorCheck {
	switch p.tier {
	case keyring.TierKeychain:
		return doctorCheck{
			label:  label,
			status: statusOK,
			detail: fmt.Sprintf("on (os-keychain) — captured bodies are encrypted under a KEK held by %s, which never writes the key to agentjail's disk. Survives a COPY of ~/.agentjail AND a whole-$HOME backup. It does not contain a sandboxed agent, which ADR 0092 D3 mediates by denying it the store", p.backend),
		}
	case keyring.TierFileKEK:
		return doctorCheck{
			label:  label,
			status: statusOK,
			detail: fmt.Sprintf("on, REDUCED (file-kek) — no keychain was reachable, so %s holds the KEK as a 0600 file at ~/.config/agentjail/kek. This survives a COPY of ~/.agentjail (support bundle, issue attachment, a synced agentjail dir), but it does NOT survive a whole-$HOME backup — that takes the key and the bodies together, so it is weaker than the os-keychain tier. Fix, if you want that: unlock a login keyring so the keychain tier is selected. It does not contain a sandboxed agent, which ADR 0092 D3 mediates by denying it the store", p.backend),
		}
	case keyring.TierMemory:
		return doctorCheck{
			label:  label,
			status: statusWarn,
			detail: fmt.Sprintf("on, PROCESS-ONLY (memory) — %s holds the KEK in memory for this process only, so every body written under it becomes unreadable when the daemon exits. This tier is for tests; seeing it on a real host is a bug", p.backend),
		}
	default:
		return doctorCheck{
			label:  label,
			status: statusWarn,
			detail: fmt.Sprintf("a KEK is available from %s but it reports an unknown tier %q, so its posture cannot be stated honestly. Treat captured bodies as unprotected until this is identified", p.backend, p.tier),
		}
	}
}

// repairID names a repairable finding, and is the only link between a check
// and a mutation: doctor never repairs something it did not diagnose
// (ADR 0086-doctor-repairs-diagnosed).
type repairID string

const (
	repairDaemon         repairID = "daemon"
	repairPathShim       repairID = "path-shim"
	repairServiceDef     repairID = "service-definition"
	repairApparmorUserns repairID = "apparmor-userns"
)

// repairAction is one finding's fix plus its independent re-check. recheck must
// observe real state and never echo apply's return value — doctor attests, so
// an unverified repair is not a repair (ADR 0086-doctor-repairs-diagnosed).
type repairAction struct {
	label   string
	apply   func(home string) error
	recheck func(home string) doctorCheck
}

// repairRegistry selects the repair by id rather than a switch at the call
// site. Membership here is the definition of "safely repairable" — a finding
// absent from this map stays advice-only (ADR 0086-doctor-repairs-diagnosed).
var repairRegistry = map[repairID]repairAction{
	repairDaemon: {
		label:   "asking the supervisor to restart the policy daemon",
		apply:   restartDaemonViaSupervisor,
		recheck: recheckDaemonAfterRestart,
	},
	repairPathShim: {
		label:   "restoring the PATH shim your shell profile opts into",
		apply:   restorePathShim,
		recheck: pathShimCheck,
	},
	repairServiceDef: {
		label:   "rewriting the daemon's supervisor definition so it restarts after a clean exit",
		apply:   repairDaemonServiceDefinition,
		recheck: serviceRestartPolicyCheck,
	},
	// The scoped AppArmor profile is the ONLY mechanism to enable the tunnel on
	// a userns-restricted host — no global sysctl flip. Consent-gated; needs
	// root once. See ADR 0104-shield-apparmor-userns.
	repairApparmorUserns: {
		label:   "installing the scoped AppArmor profile that enables the tunnel for agentjail's binary only",
		apply:   repairApparmorUsernsApply,
		recheck: repairApparmorUsernsRecheck,
	},
}

// repairDaemonServiceDefinition rewrites the deployed definition and makes the
// supervisor re-read it. Gated on serviceRestartPolicyCheck failing, so it only
// ever overwrites a definition that is already broken
// (ADR 0088-deployed-supervisor-verified).
func repairDaemonServiceDefinition(home string) error {
	if _, err := ensureDaemonRestartPolicy(home); err != nil {
		return err
	}
	return reloadDaemonService(home)
}

// daemonRepairWait bounds how long the post-restart re-check waits for the
// daemon to bind its socket.
const daemonRepairWait = 5 * time.Second

// daemonServiceTarget is the supervisor's handle for the daemon: a launchd
// plist path on macOS, a systemd unit name on Linux (ADR 0034).
func daemonServiceTarget(home string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "LaunchAgents", plistFilename)
	}
	return systemdUnitFilename
}

// restartDaemonViaSupervisor goes through launchd/systemd rather than spawning
// a daemon itself: the supervisor owns the process, and an unsupervised daemon
// would not survive the next restart (ADR 0070, ADR 0086-doctor-repairs-diagnosed).
func restartDaemonViaSupervisor(home string) error {
	return selfupdate.RestartDaemon(daemonServiceTarget(home))
}

func recheckDaemonAfterRestart(home string) doctorCheck {
	sockPath := daemonSocketPath(home)
	deadline := time.Now().Add(daemonRepairWait)
	for {
		l, version, err := probeDaemonDetails(sockPath, doctorPingTimeout)
		if l == daemonHealthy || !time.Now().Before(deadline) {
			if l != daemonHealthy {
				return daemonLivenessCheck(l, sockPath, err)
			}
			return daemonVersionCheck(l, version, buildinfo.Version)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// restorePathShim re-asserts a choice already on record. The rc block is that
// record, so a missing block means there is nothing to restore (ADR 0062).
func restorePathShim(home string) error {
	if !shimConsentRecorded(home) {
		return fmt.Errorf("no recorded opt-in for the PATH shim — run `agentjail install --with-path-shim`")
	}
	return installPathShim(home)
}

// findAgentBinary checks if an agent binary exists on PATH.
func findAgentBinary(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}
