// install.go — agentjail install/uninstall/status subcommands.
//
// What `agentjail install` does on macOS and Linux:
//  1. Copies agentjail-hook binary to ~/.agentjail/bin/agentjail-hook (0755).
//  2. Copies the agentjail (multicall) binary to ~/.agentjail/bin/agentjail
//     (0755), then ensures agentjail-daemon, agentjail-shield,
//     agentjail-netproxy, and agentjail-secrets are relative symlinks to it
//     (see selfupdate.EnsureRoleSymlinks in internal/selfupdate/rolesymlinks.go) — these four names are
//     never real files on disk.
//  3. Copies core .rego rules to ~/.agentjail/rules/ (idempotent).
//  4. Writes ~/.agentjail/policy.yaml from agentpolicy/default_policy.yaml
//     if the file does not already exist (never overwrites user customisations).
//  5. Installs the daemon service definition:
//     - macOS: the launchd plist at ~/Library/LaunchAgents/com.agentjail.daemon.plist
//     with ProgramArguments patched to ~/.agentjail/bin/agentjail-daemon.
//     - Linux: the systemd --user unit at
//     ~/.config/systemd/user/agentjail-daemon.service with ExecStart patched
//     to ~/.agentjail/bin/agentjail-daemon and Restart=on-failure.
//  6. (Re)starts the daemon: launchctl unload/load on macOS, `systemctl --user
//     enable --now` + `restart` on Linux. When no systemd user session is
//     reachable (e.g. a bare container with no login session), the unit is
//     still written and manual start instructions are printed instead of
//     failing the install.
//  7. Detects which agents are present on the machine (claude-code, codex, cursor)
//     and which of them already have the agentjail hook wired.
//  8. If every detected agent is already protected, the run is just a binary +
//     daemon refresh (steps 1-6 above): it skips the picker and reports, so
//     re-running `curl … | sh` on an installed machine behaves like an update.
//  9. Otherwise presents an interactive multi-select picker (already-protected
//     agents are marked) or falls back to non-interactive selection.
//
// 10. Dispatches agent.Install(env) for each selected agent.
// 11. Prints a summary and exits non-zero if any selected install failed.
//
// Use `agentjail install --for <agent>` for single-agent back-compat.
// Use `agentjail install --all` / `--yes` for non-interactive "install all".
// `agentjail install --allow-unsupported` is a deprecated no-op kept for
// back-compat: Linux is a fully supported install target (ADR 0051).
//
// What `agentjail uninstall` does (no --for):
//  1. Calls agent.Uninstall(env) for every agent in the registry. Failures are
//     collected but do not abort other agents (Uninstall is idempotent).
//  2. On macOS: unloads the launchd daemon and removes the plist. On Linux:
//     stops/disables the systemd --user unit and removes the unit file.
//  3. Removes the four role symlinks (agentjail-daemon, agentjail-shield,
//     agentjail-netproxy, agentjail-secrets) — tolerant of them already
//     being gone.
//  4. Removes ~/.agentjail and /tmp/agentjail-daemon.log.
//
// Use `agentjail uninstall --for <agent>` to remove only that agent's hook
// without touching the daemon or ~/.agentjail.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/agents"
	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/picker"
	"github.com/LuD1161/agentjail/internal/sandbox"
	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/telemetry"
	"github.com/LuD1161/agentjail/internal/ui"
)

// plistLabel is the launchd service identifier.
const plistLabel = "com.agentjail.daemon"

// plistFilename is the filename placed under ~/Library/LaunchAgents/.
const plistFilename = "com.agentjail.daemon.plist"

// systemdUnitName is the systemd --user service name (with and without the
// .service suffix, since some systemctl subcommands take either form).
const systemdUnitName = "agentjail-daemon"
const systemdUnitFilename = systemdUnitName + ".service"

// hookBinaryName, daemonBinaryName, and cliBinaryName are the binary
// filenames we install.
const hookBinaryName = "agentjail-hook"
const daemonBinaryName = "agentjail-daemon"
const cliBinaryName = "agentjail"

// Secrets broker (ADR 0058): a loaded-but-not-running service definition that
// clients start on demand. The label/unit are sourced from the shared sandbox
// package so the installer's plist Label and the client's `launchctl kickstart`
// target can never drift.
const secretsBinaryName = "agentjail-secrets"

var secretsPlistLabel = sandbox.SecretsBrokerLaunchdLabel         // com.agentjail.secrets
var secretsPlistFilename = secretsPlistLabel + ".plist"           // com.agentjail.secrets.plist
var secretsSystemdUnitFilename = sandbox.SecretsBrokerSystemdUnit // agentjail-secrets.service

// secretsBrokerIdleTimeout is the --idle-timeout the broker self-exits after
// (with zero active grants). Passed into the service definition so the broker
// reclaims the decrypted master key when idle (ADR 0058).
const secretsBrokerIdleTimeout = "15m"

// currentGOOS is the runtime OS. It is a variable (not a constant) so that
// tests can override it to simulate non-darwin platforms without recompiling.
var currentGOOS = runtime.GOOS

// systemdUserAvailableFn reports whether a systemd --user session is reachable
// on this machine. It is a variable so tests can stub it out — the real
// implementation shells out to systemctl and must never run against the
// developer's real session during `go test`.
var systemdUserAvailableFn = defaultSystemdUserAvailable

// systemctlUserEnableStartFn (re)starts the systemd --user unit. It is a
// variable so tests can stub it out and assert it was (or was not) called,
// without ever touching a real systemd session.
var systemctlUserEnableStartFn = defaultSystemctlUserEnableStart

// installResult holds the per-agent outcome of a single agent install attempt.
type installResult struct {
	name    string
	id      string
	err     error
	status  agents.Status
	skipped bool // not selected or not detected
}

// runInstallCmd handles `agentjail install [flags]`.
//
// Flags:
//
//	--for <agent>        install only a single named agent (back-compat)
//	--all / --yes        non-interactive; select all detected agents
//	--allow-unsupported  deprecated no-op; Linux is fully supported now
func runInstallCmd(args []string) {
	forAgent, all, yes, allowUnsupported := parseInstallFlags(args)

	u := ui.New(os.Stdout)
	_ = u // used below on macOS path

	// ── IDE wrapper and PATH shim targets work on all platforms ──────────
	// These don't need the daemon, so they run before the daemon preamble.
	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		if forAgent == "vscode" || forAgent == "cursor-ide" {
			chain := hasFlag(args, "--chain")
			replace := hasFlag(args, "--replace")
			app := "Code"
			if forAgent == "cursor-ide" {
				app = "Cursor"
			}
			if err := installVSCodeWrapper(home, app, chain, replace); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: %v", err)))
				os.Exit(1)
			}
			return
		}

		if hasFlag(args, "--with-path-shim") && forAgent == "" && !all && !yes {
			if err := installPathShim(home); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: %v", err)))
				os.Exit(1)
			}
			return
		}
	}

	// ── --allow-unsupported is deprecated ────────────────────────────────
	// Linux is a fully supported install target as of this release (the
	// daemon runs under a systemd --user service instead of launchd). The
	// flag is kept — and still parsed above — purely for back-compat with
	// existing scripts/docs that pass it; it is now a no-op other than this
	// notice.
	if allowUnsupported {
		fmt.Fprintln(os.Stdout, u.Badge("dim", "agentjail: --allow-unsupported is deprecated; Linux is fully supported, continuing normally"))
	}

	// ── macOS / Linux install path ───────────────────────────────────────

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: cannot determine home dir: %v", err)))
		os.Exit(1)
	}

	// Detect fresh vs. reinstall before any telemetry state is created.
	// A fresh install is one where telemetry.json did not exist yet; a
	// reinstall (binary/daemon refresh) already has the file.
	isFreshInstall := false
	if tp, tpErr := telemetry.DefaultPaths(); tpErr == nil {
		if _, statErr := os.Stat(tp.Consent()); os.IsNotExist(statErr) {
			isFreshInstall = true
		}
	}

	// Print the header banner.
	v := buildinfo.Version
	if v == "" {
		v = "dev"
	}
	fmt.Fprintln(os.Stdout, u.Header("agentjail", v, currentGOOS))

	// R10: Run MCP discovery BEFORE the daemon preamble writes policy.yaml so
	// the seed list is passed into the write path and policy.yaml is written
	// once with mcp.allowed pre-populated (never write-then-rewrite).
	mcpSeed := discoverMCPSeedList(home, os.Stdout)

	// Single-agent back-compat: --for <agent>.
	if forAgent != "" {
		env := buildAgentsEnv(home)
		ag := agentByID(forAgent)
		if ag == nil {
			fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: unknown agent %q (supported: claude-code, codex, cursor, vscode, cursor-ide)", forAgent)))
			os.Exit(2)
		}
		if err := installDaemonPreamble(home, os.Stdout, mcpSeed); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: daemon preamble: %v", err)))
			os.Exit(1)
		}
		if err := ag.Install(env); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: %s: %v", ag.DisplayName(), err)))
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, u.Badge("ok", fmt.Sprintf("agentjail: install complete for %s. Restart the agent to activate the hook.", ag.DisplayName())))
		if tp, err := telemetry.DefaultPaths(); err == nil {
			telemetry.MaybePrintNotice(tp, os.Getenv, os.Stdout)
			// Fire install telemetry synchronously (bounded 5s) so the install is
			// captured even if the user uninstalls moments later; a fire-and-forget
			// goroutine would be killed when this short-lived CLI exits. Never fails
			// the install (errors, including ErrNoBackend, are ignored).
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = telemetry.SendInstall(ctx, tp, os.Getenv, buildinfo.Version, runtime.GOOS, runtime.GOARCH,
					os.Getenv("AGENTJAIL_INSTALL_METHOD"), []string{ag.ID()}, 1, isFreshInstall)
			}()
		}
		return
	}

	// Discovery flow.
	if err := installDaemonPreamble(home, os.Stdout, mcpSeed); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: daemon preamble: %v", err)))
		os.Exit(1)
	}

	env := buildAgentsEnv(home)
	detected := detectAll(env)

	// Snapshot which detected agents are already protected. The daemon preamble
	// above has already (re)installed the binaries and restarted the daemon, so
	// if every detected agent is already wired this run is effectively just a
	// binary/daemon refresh — there is nothing new to wire. Skip the picker and
	// report, so re-running `curl … | sh` (or `agentjail install`) on an
	// already-protected machine behaves like an update instead of re-prompting.
	state := computeInstallState(detected, func(a agents.Agent) agents.Status { return a.Status(env) })
	if state.allProtected() {
		v := buildinfo.Version
		if v == "" {
			v = "dev"
		}
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, u.Badge("ok", fmt.Sprintf("agentjail: already protecting all %d detected agent(s); refreshed binaries and daemon to %s.", state.present, v)))
		fmt.Fprintln(os.Stdout, u.Badge("dim", "nothing to wire — run 'agentjail status' to verify, or 'agentjail install --for <agent>' to add another."))
		return
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, u.Section(u.Emoji("🔍  ")+"Discovering coding agents"))

	// Build picker items (all detected start checked). Mark which agents are
	// already protected so a re-run shows current state at a glance.
	var items []picker.Item
	for _, r := range detected {
		if r.d.Present {
			items = append(items, picker.Item{
				ID:      r.ag.ID(),
				Label:   r.ag.DisplayName(),
				Detail:  protectedDetail(r.d.Evidence, state.byID[r.ag.ID()]),
				Checked: true,
			})
		}
	}

	if len(items) == 0 {
		fmt.Fprintln(os.Stdout, u.Badge("warn", "agentjail: no supported agents detected on this machine."))
		return
	}

	// Select agents to install.
	var selectedIDs []string

	if all || yes {
		// Non-interactive: select all detected.
		for _, it := range items {
			selectedIDs = append(selectedIDs, it.ID)
		}
		fmt.Fprintln(os.Stdout, u.Badge("info", fmt.Sprintf("agentjail: --all/--yes specified; selecting all %d detected agent(s)", len(selectedIDs))))
	} else {
		ids, pickerErr := picker.RunPicker(items)
		var selErr error
		selectedIDs, selErr = resolveSelection(ids, pickerErr, items)
		if selErr != nil {
			// Fatal error from the picker (ErrAborted or unexpected).
			fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: picker error: %v", selErr)))
			os.Exit(1)
		}
		if selectedIDs == nil {
			// ErrCancelled — install nothing.
			fmt.Fprintln(os.Stdout, u.Badge("dim", "agentjail: install cancelled."))
			return
		}
	}

	if len(selectedIDs) == 0 {
		fmt.Fprintln(os.Stdout, u.Badge("dim", "agentjail: no agents selected; nothing installed."))
		return
	}

	// Dispatch install for each selected agent, collecting results.
	var results []installResult
	selectedSet := make(map[string]bool, len(selectedIDs))
	for _, id := range selectedIDs {
		selectedSet[id] = true
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, u.Section(u.Emoji("🔌  ")+"Wiring hooks"))
	const emojiSectionBodyIndent = "      "

	for _, r := range detected {
		id := r.ag.ID()
		if !selectedSet[id] {
			continue
		}
		fmt.Fprintln(os.Stdout, emojiSectionBodyIndent+u.Badge("info", u.Emoji("🔌  ")+"wiring "+r.ag.DisplayName()+"…"))
		installErr := r.ag.Install(env)
		status := r.ag.Status(env)
		results = append(results, installResult{
			name:   r.ag.DisplayName(),
			id:     id,
			err:    installErr,
			status: status,
		})
	}

	// Also report not-detected agents.
	for _, r := range detected {
		if !r.d.Present {
			results = append(results, installResult{
				name:    r.ag.DisplayName(),
				id:      r.ag.ID(),
				skipped: true,
			})
		}
	}

	// ── IDE wrappers (--all installs wrappers for detected IDEs) ────────
	if all || yes {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, u.Section(u.Emoji("🔧  ")+"Configuring IDE wrappers"))

		for _, app := range []string{"Code", "Cursor"} {
			settingsPath := vscodeSettingsPath(home, app)
			if settingsPath == "" {
				fmt.Fprintln(os.Stdout, "      "+u.Badge("dim", app+": not detected — skipping"))
				continue
			}
			if err := installVSCodeWrapper(home, app, false, false); err != nil {
				fmt.Fprintln(os.Stdout, "      "+u.Badge("warn", fmt.Sprintf("%s: %v", app, err)))
			}
		}

		// PATH shim only with --with-path-shim (even in --all mode).
		if hasFlag(args, "--with-path-shim") {
			fmt.Fprintln(os.Stdout)
			if err := installPathShim(home); err != nil {
				fmt.Fprintln(os.Stdout, "      "+u.Badge("warn", fmt.Sprintf("PATH shim: %v", err)))
			}
		}
	}

	// Print styled summary.
	anyFailed := printInstallSummary(os.Stdout, results)

	if tp, err := telemetry.DefaultPaths(); err == nil {
		telemetry.MaybePrintNotice(tp, os.Getenv, os.Stdout)
		// Fire install telemetry synchronously (bounded 5s) so the install is
		// captured even if the user uninstalls moments later; a fire-and-forget
		// goroutine would be killed when this short-lived CLI exits. Never fails
		// the install (errors, including ErrNoBackend, are ignored).
		// Collect successfully installed agent IDs for the event.
		var wiredAgents []string
		for _, res := range results {
			if !res.skipped && res.err == nil {
				wiredAgents = append(wiredAgents, res.id)
			}
		}
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = telemetry.SendInstall(ctx, tp, os.Getenv, buildinfo.Version, runtime.GOOS, runtime.GOARCH,
				os.Getenv("AGENTJAIL_INSTALL_METHOD"), wiredAgents, len(detected), isFreshInstall)
		}()
	}

	if anyFailed {
		os.Exit(1)
	}
}

// resolveSelection maps picker errors to the correct selection outcome.
// It is a pure helper — no I/O, no os.Exit — and is directly unit-testable.
//
// Return semantics:
//   - (ids, nil)    → pickerErr was nil (explicit confirm); use the returned ids.
//   - (allIDs, nil) → pickerErr was ErrNoTTY; non-interactive fallback; use all detected.
//   - (nil, nil)    → pickerErr was ErrCancelled; install nothing.
//   - (nil, err)    → pickerErr was ErrAborted or unknown; caller should stderr + exit 1.
//
// Side-effect: prints the "non-interactive install (piped stdin); wiring all N detected agent(s)" line
// to stdout when ErrNoTTY fires.
func resolveSelection(ids []string, pickerErr error, detected []picker.Item) (selectedIDs []string, fatal error) {
	switch {
	case pickerErr == nil:
		// Explicit confirm from picker.
		return ids, nil

	case errors.Is(pickerErr, picker.ErrNoTTY):
		// No TTY — non-interactive fallback: select all detected agents.
		all := make([]string, 0, len(detected))
		for _, it := range detected {
			all = append(all, it.ID)
		}
		fmt.Fprintln(os.Stdout, ui.New(os.Stdout).Badge("info", fmt.Sprintf("agentjail: non-interactive install (piped stdin); wiring all %d detected agent(s)", len(all))))
		return all, nil

	case errors.Is(pickerErr, picker.ErrCancelled):
		// User cancelled — install nothing. Caller prints the cancel message.
		return nil, nil

	default:
		// ErrAborted or any other unexpected error — hard failure, fail closed.
		// MUST NOT fall through to install-all.
		return nil, pickerErr
	}
}

// printInstallSummary writes the styled install-summary box to w.
// It returns true when any agent install failed.
func printInstallSummary(w io.Writer, results []installResult) bool {
	u := ui.New(w)
	anyFailed := false

	var lines []string
	for _, res := range results {
		if res.skipped {
			lines = append(lines, u.Badge("dim", res.name+" not detected (skipped)"))
			continue
		}
		if res.err != nil {
			lines = append(lines, u.Badge("fail", res.name+" FAILED: "+res.err.Error()))
			anyFailed = true
			continue
		}
		state := "installed"
		badgeKind := "ok"
		if !res.status.Installed {
			state = "installed (partial)"
			badgeKind = "warn"
		}
		lines = append(lines, u.Badge(badgeKind, res.name+" "+state))
		for _, note := range res.status.Notes {
			lines = append(lines, "  "+u.Badge("dim", "note: "+note))
		}
	}
	lines = append(lines, "")
	lines = append(lines, u.Badge("info", "daemon ready — see 'agentjail status' for daemon and plist state"))
	lines = append(lines, u.Badge("dim", "harden further: 'agentjail policy list' to enable optional rules"))

	body := strings.Join(lines, "\n")
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Box(u.Emoji("✅  ")+"install summary", body))
	fmt.Fprintln(w)

	return anyFailed
}

// runUninstallCmd handles `agentjail uninstall [--for <target>]`.
//
// Without --for: performs a full teardown — unhooks all agents, stops and
// removes the launchd daemon (macOS only), removes ~/.agentjail and the
// daemon log.
//
// With --for <agent>: single-agent back-compat — removes only that agent's
// hook; does NOT touch the daemon or ~/.agentjail.
func runUninstallCmd(args []string) {
	target := parseOptionalForFlag(args)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail uninstall: cannot determine home dir: %v", err)))
		os.Exit(1)
	}

	// ── Single-agent path ─────────────────────────────────────────────────
	if target != "" {
		env := buildAgentsEnv(home)
		ag := agentByID(target)
		if ag == nil {
			fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail uninstall: unknown agent %q", target)))
			os.Exit(2)
		}
		if err := ag.Uninstall(env); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail uninstall: %v", err)))
			os.Exit(1)
		}
		// Fire uninstall telemetry synchronously (bounded 5s) so a single-agent
		// unhook is captured as churn, mirroring the single-agent install path; the
		// agents list distinguishes it from a full teardown. ~/.agentjail is left
		// intact here, so telemetry.json is still readable. Never fails the
		// uninstall (errors, including ErrNoBackend, are ignored).
		if tp, err := telemetry.DefaultPaths(); err == nil {
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = telemetry.SendUninstall(ctx, tp, os.Getenv, buildinfo.Version, runtime.GOOS, runtime.GOARCH, []string{ag.ID()})
			}()
		}
		uout := ui.New(os.Stdout)
		fmt.Fprintln(os.Stdout, uout.Badge("ok", fmt.Sprintf("agentjail: uninstall complete for %s.", ag.DisplayName())))
		return
	}

	// ── Full teardown path ────────────────────────────────────────────────
	result := performFullUninstall(home, currentGOOS, hasFlag(args, "--keep-secrets"))
	printUninstallResult(result)
	if result.HardFailed {
		os.Exit(1)
	}
}

// UninstallAgentResult holds the outcome of uninstalling a single agent hook.
type UninstallAgentResult struct {
	Name string
	Err  error
}

// UninstallResult holds the aggregated outcome of a full teardown.
type UninstallResult struct {
	// Agents contains one result per registry agent.
	Agents []UninstallAgentResult

	// DaemonSkipped is true when we are on a non-darwin platform and
	// daemon teardown was intentionally skipped.
	DaemonSkipped bool

	// DaemonErr is non-nil when daemon teardown was attempted but failed.
	DaemonErr error

	// InstallDirErr is non-nil when ~/.agentjail removal failed.
	InstallDirErr error

	// LogFileErr is non-nil when /tmp/agentjail-daemon.log removal failed and
	// the file existed (ENOENT is swallowed and does not set this field).
	LogFileErr error

	// RCCleaned lists the shell rc files from which the agentjail PATH block was
	// removed (empty when none contained it).
	RCCleaned []string

	// BrewUninstalled is true when the running binary was brew-managed and
	// brew uninstall was attempted.
	BrewUninstalled bool

	// BrewErr is non-nil when brew uninstall was attempted but failed.
	BrewErr error

	// SecretsExisted is true when the encrypted secrets store or master key was
	// present at uninstall time (so the summary can speak to their fate).
	SecretsExisted bool

	// SecretsKept is true when --keep-secrets preserved the store + master key
	// across the ~/.agentjail wipe.
	SecretsKept bool

	// HardFailed is true when any step that should succeed actually failed.
	HardFailed bool
}

// performFullUninstall runs the full teardown without calling os.Exit or
// printing anything. It is the unit-testable core of runUninstallCmd.
//
//   - home is the user's home directory (e.g. os.UserHomeDir()).
//   - goos is the runtime OS string (pass currentGOOS, or "linux" in tests
//     to skip the real launchctl calls).
//   - keepSecrets, when true, preserves the encrypted secrets store and master
//     key (~/.agentjail/secrets + secrets.key) across the ~/.agentjail wipe.
func performFullUninstall(home, goos string, keepSecrets bool) UninstallResult {
	var r UninstallResult
	env := buildAgentsEnv(home)

	// Step 0: send uninstall telemetry BEFORE removing ~/.agentjail so that
	// telemetry.json (and its anonymous ID) is still readable. Synchronous with
	// a bounded 5s timeout — it must complete before teardown deletes the state;
	// never fails the uninstall (errors, including ErrNoBackend, are ignored).
	if tp, err := telemetry.DefaultPaths(); err == nil {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = telemetry.SendUninstall(ctx, tp, os.Getenv, buildinfo.Version, goos, runtime.GOARCH, nil)
		}()
	}

	// Step 1: unhook every agent; collect results, never abort early.
	for _, ag := range agents.Registry() {
		err := ag.Uninstall(env)
		r.Agents = append(r.Agents, UninstallAgentResult{Name: ag.DisplayName(), Err: err})
		if err != nil {
			r.HardFailed = true
		}
	}

	// Step 2: daemon teardown (macOS: launchd, Linux: systemd --user).
	if goos == "darwin" || goos == "linux" {
		r.DaemonErr = uninstallDaemon(home, goos)
		if r.DaemonErr != nil {
			r.HardFailed = true
		}
		// Secrets broker teardown (ADR 0058). Best-effort: a leftover
		// loaded-but-not-running definition is harmless, so a failure here does
		// not fail the uninstall.
		if err := uninstallSecretsBroker(home, goos); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail: warning: secrets broker teardown: %v\n", err)
		}
	} else {
		r.DaemonSkipped = true
	}

	// Step 2.5: remove IDE wrappers (best-effort).
	for _, app := range []string{"Code", "Cursor"} {
		_ = uninstallVSCodeWrapper(home, app)
	}
	uninstallPathShim(home)

	// Step 2.6: remove the four role symlinks (agentjail-daemon, agentjail-shield,
	// agentjail-netproxy, agentjail-secrets). Best-effort and idempotent —
	// removeInstallDir below removes the whole ~/.agentjail/bin tree anyway
	// (unless --keep-secrets, which never preserves bin/), but this makes the
	// symlink teardown explicit and independently correct even if that ever
	// changes, and tolerates a bin dir that's already partially torn down.
	selfupdate.RemoveRoleSymlinks(filepath.Join(home, ".agentjail", "bin"))

	// Step 3: remove ~/.agentjail (optionally preserving the secrets store/key).
	installDir := filepath.Join(home, ".agentjail")
	r.SecretsExisted = fileExists(filepath.Join(installDir, "secrets.key")) ||
		fileExists(filepath.Join(installDir, "secrets"))
	if err := removeInstallDir(installDir, keepSecrets); err != nil {
		r.InstallDirErr = err
		r.HardFailed = true
	}
	r.SecretsKept = keepSecrets && r.SecretsExisted

	// Step 4: remove daemon log (best-effort; ENOENT is fine).
	const daemonLog = "/tmp/agentjail-daemon.log"
	if err := os.Remove(daemonLog); err != nil && !os.IsNotExist(err) {
		r.LogFileErr = err
		// Not a hard failure — the log is ephemeral.
	}

	// Step 5: scrub the PATH block install.sh appended to the shell rc(s). We
	// check every candidate rc (zsh/bash/bash_profile/profile/fish) so cleanup
	// works regardless of which shell the user runs. Best-effort — a failure
	// here never fails the uninstall (the env file under ~/.agentjail is already
	// gone with the dir; this only tidies the rc reference).
	r.RCCleaned = cleanupShellRCPath(home)

	// Step 6: if the running binary is brew-managed, also run brew uninstall
	// so the Homebrew copy is removed and `which agentjail` returns nothing.
	if _, brew := selfupdate.ResolveExecutablePath(); brew {
		r.BrewUninstalled = true
		cmd := exec.Command("brew", "uninstall", "agentjail")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			r.BrewErr = err
			r.HardFailed = true
		}
	}

	return r
}

// pathRCMarker is the comment line install.sh writes immediately above the PATH
// export it appends to a shell rc. uninstall scrubs this marker and the PATH
// line that follows it.
const pathRCMarker = "# added by agentjail installer"

// stripAgentjailPathBlock removes every agentjail-installer PATH block from shell
// rc content: the marker line, the line right after it (only when it references
// ~/.agentjail/bin, so unrelated user lines are never touched), and a single
// blank line directly preceding the marker (install.sh prepends one). It returns
// the rewritten content and whether anything changed.
func stripAgentjailPathBlock(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	changed := false
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == pathRCMarker {
			changed = true
			// Drop a single blank line we may have emitted before the marker.
			if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
				out = out[:len(out)-1]
			}
			// Skip the following line only when it's our PATH line, so a marker
			// left dangling above unrelated content can't eat a user line.
			if i+1 < len(lines) && strings.Contains(lines[i+1], ".agentjail/bin") {
				i++
			}
			continue
		}
		out = append(out, lines[i])
	}
	return strings.Join(out, "\n"), changed
}

// cleanupShellRCPath removes the agentjail PATH block from every candidate shell
// rc file under home (and $ZDOTDIR/.zshrc when set). Best-effort: files that are
// absent, unreadable, or unwritable are skipped. Returns the rc files actually
// modified. Each modified file is rewritten atomically (temp + rename) preserving
// its original permissions.
func cleanupShellRCPath(home string) []string {
	candidates := []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".config", "fish", "config.fish"),
	}
	if zd := os.Getenv("ZDOTDIR"); zd != "" {
		candidates = append(candidates, filepath.Join(zd, ".zshrc"))
	}

	var cleaned []string
	seen := map[string]bool{}
	for _, rc := range candidates {
		if seen[rc] {
			continue
		}
		seen[rc] = true

		b, err := os.ReadFile(rc)
		if err != nil {
			continue // absent or unreadable — nothing to do
		}
		newContent, changed := stripAgentjailPathBlock(string(b))
		if !changed {
			continue
		}

		mode := os.FileMode(0o644)
		if info, statErr := os.Stat(rc); statErr == nil {
			mode = info.Mode().Perm()
		}
		tmp, err := os.CreateTemp(filepath.Dir(rc), ".agentjail-rc-*.tmp")
		if err != nil {
			continue
		}
		tmpName := tmp.Name()
		if _, err := tmp.WriteString(newContent); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			continue
		}
		_ = tmp.Chmod(mode)
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmpName)
			continue
		}
		if err := os.Rename(tmpName, rc); err != nil {
			_ = os.Remove(tmpName)
			continue
		}
		cleaned = append(cleaned, rc)
	}
	return cleaned
}

// uninstallDaemon tears down the platform daemon service for goos: the
// launchd plist on macOS, the systemd --user unit on Linux. It tolerates
// "already unloaded/stopped" and "file not found" gracefully.
func uninstallDaemon(home, goos string) error {
	if goos == "darwin" {
		return uninstallLaunchdDaemon(home)
	}
	return uninstallSystemdDaemon(home)
}

// uninstallLaunchdDaemon unloads the launchd service and removes the plist file.
// It tolerates "already unloaded" and "file not found" gracefully.
func uninstallLaunchdDaemon(home string) error {
	plistDst := filepath.Join(home, "Library", "LaunchAgents", plistFilename)

	// Unload — tolerate "not loaded" / non-zero exit gracefully.
	if fileExists(plistDst) {
		out, err := exec.Command("launchctl", "unload", plistDst).CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			// launchctl exits non-zero when the service was never loaded; that is
			// fine — we just want it stopped. Only surface genuinely unexpected errors.
			if msg != "" && !strings.Contains(msg, "Could not find specified service") &&
				!strings.Contains(msg, "No such process") {
				return fmt.Errorf("launchctl unload: %w: %s", err, msg)
			}
		}
	}

	// Remove the plist file.
	if err := os.Remove(plistDst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	return nil
}

// uninstallSystemdDaemon stops and disables the systemd --user unit and
// removes the unit file. It tolerates "already stopped" / "unit not found"
// gracefully (systemctlUserDisableStopFn already tolerates those), and skips
// the disable/stop call entirely when no systemd --user session is reachable
// (nothing to stop) or the unit file was never installed.
func uninstallSystemdDaemon(home string) error {
	unitDst := filepath.Join(systemdUserUnitDir(home), systemdUnitFilename)

	if fileExists(unitDst) && systemdUserAvailableFn() {
		if err := systemctlUserDisableStopFn(systemdUnitFilename); err != nil {
			return fmt.Errorf("systemctl --user disable/stop: %w", err)
		}
	}

	if err := os.Remove(unitDst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove systemd unit: %w", err)
	}

	return nil
}

// removeInstallDir removes ~/.agentjail. When keepSecrets is true it preserves
// the encrypted secrets store and master key (secrets/ and secrets.key) by
// removing every OTHER top-level entry instead of the whole tree. The two
// preserved names mirror the shield's AgentjailSecretsProtectedNames() contract
// (ADR 0048) — keep them in lockstep if that set ever changes.
func removeInstallDir(installDir string, keepSecrets bool) error {
	if !keepSecrets {
		return os.RemoveAll(installDir)
	}
	preserved := map[string]bool{"secrets": true, "secrets.key": true}
	entries, err := os.ReadDir(installDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var firstErr error
	for _, e := range entries {
		if preserved[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(installDir, e.Name())); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// secretsBrokerDefInstalled reports whether the secrets broker service
// definition is present (launchd plist on macOS, systemd --user unit on Linux).
// Pure file-presence check — does not start or connect to the broker.
func secretsBrokerDefInstalled(home string) bool {
	if currentGOOS == "darwin" {
		return fileExists(filepath.Join(home, "Library", "LaunchAgents", secretsPlistFilename))
	}
	return fileExists(filepath.Join(systemdUserUnitDir(home), secretsSystemdUnitFilename))
}

// uninstallSecretsBroker tears down the secrets broker service definition
// (ADR 0058): unload+remove the launchd plist on macOS, disable+remove the
// systemd --user unit on Linux. Tolerates "not loaded"/"not found" gracefully.
// The encrypted store and master key under ~/.agentjail are NOT removed here —
// that happens with the whole ~/.agentjail tree in the caller's Step 3.
func uninstallSecretsBroker(home, goos string) error {
	if goos == "darwin" {
		plistDst := filepath.Join(home, "Library", "LaunchAgents", secretsPlistFilename)
		if fileExists(plistDst) {
			out, err := exec.Command("launchctl", "unload", plistDst).CombinedOutput()
			if err != nil {
				msg := strings.TrimSpace(string(out))
				if msg != "" && !strings.Contains(msg, "Could not find specified service") &&
					!strings.Contains(msg, "No such process") {
					return fmt.Errorf("launchctl unload (secrets): %w: %s", err, msg)
				}
			}
		}
		if err := os.Remove(plistDst); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove secrets plist: %w", err)
		}
		return nil
	}

	unitDst := filepath.Join(systemdUserUnitDir(home), secretsSystemdUnitFilename)
	if fileExists(unitDst) && systemdUserAvailableFn() {
		// Stop first (it may be running from an on-demand start), then disable.
		_ = exec.Command("systemctl", "--user", "stop", secretsSystemdUnitFilename).Run()
		if out, err := exec.Command("systemctl", "--user", "disable", secretsSystemdUnitFilename).CombinedOutput(); err != nil {
			msg := strings.TrimSpace(string(out))
			if msg != "" && !strings.Contains(msg, "does not exist") && !strings.Contains(msg, "not loaded") {
				return fmt.Errorf("systemctl --user disable (secrets): %w: %s", err, msg)
			}
		}
	}
	if err := os.Remove(unitDst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove secrets systemd unit: %w", err)
	}
	return nil
}

// printUninstallResult writes a human-readable summary of a full uninstall.
// It is a thin wrapper around printUninstallSummary writing to os.Stdout.
func printUninstallResult(r UninstallResult) {
	printUninstallSummary(os.Stdout, r)
}

// printUninstallSummary writes the styled uninstall-summary box to w.
// It mirrors printInstallSummary and is the testable core of printUninstallResult.
func printUninstallSummary(w io.Writer, r UninstallResult) {
	u := ui.New(w)

	var lines []string
	for _, ar := range r.Agents {
		if ar.Err != nil {
			lines = append(lines, u.KeyValue(ar.Name, "", u.Badge("fail", "FAILED to unhook: "+ar.Err.Error())))
		} else {
			lines = append(lines, u.KeyValue(ar.Name, "", u.Badge("ok", "unhooked")))
		}
	}

	if r.DaemonSkipped {
		lines = append(lines, u.KeyValue("daemon", "", u.Badge("dim", "skipped (unsupported OS)")))
	} else if r.DaemonErr != nil {
		lines = append(lines, u.KeyValue("daemon", "", u.Badge("fail", "FAILED: "+r.DaemonErr.Error())))
	} else if currentGOOS == "darwin" {
		lines = append(lines, u.KeyValue("daemon", "", u.Badge("ok", "stopped and plist removed")))
	} else {
		lines = append(lines, u.KeyValue("daemon", "", u.Badge("ok", "stopped and systemd unit removed")))
	}

	if r.InstallDirErr != nil {
		lines = append(lines, u.KeyValue("~/.agentjail", "", u.Badge("fail", "FAILED to remove: "+r.InstallDirErr.Error())))
	} else if r.SecretsKept {
		lines = append(lines, u.KeyValue("~/.agentjail", "", u.Badge("ok", "removed (secrets store + key preserved: --keep-secrets)")))
	} else {
		lines = append(lines, u.KeyValue("~/.agentjail", "", u.Badge("ok", "removed")))
	}

	// Speak to the stored secrets' fate whenever any existed, so a destructive
	// delete is never silent (ADR 0058 OQ4).
	if r.SecretsExisted {
		if r.SecretsKept {
			lines = append(lines, u.KeyValue("secrets", "", u.Badge("ok", "kept — encrypted store + master key left in place")))
		} else {
			lines = append(lines, u.KeyValue("secrets", "", u.Badge("dim", "deleted — encrypted store + master key removed (re-run with --keep-secrets to preserve)")))
		}
	}

	if r.BrewUninstalled {
		if r.BrewErr != nil {
			lines = append(lines, u.KeyValue("homebrew", "", u.Badge("fail", "brew uninstall failed: "+r.BrewErr.Error())))
		} else {
			lines = append(lines, u.KeyValue("homebrew", "", u.Badge("ok", "brew formula removed")))
		}
	}

	lines = append(lines, "")
	if r.HardFailed {
		lines = append(lines, u.Badge("fail", "some steps failed — see above"))
	} else {
		lines = append(lines, u.Badge("ok", "agentjail fully removed"))
		if len(r.RCCleaned) > 0 {
			homeDir, _ := os.UserHomeDir()
			display := make([]string, 0, len(r.RCCleaned))
			for _, p := range r.RCCleaned {
				if homeDir != "" && strings.HasPrefix(p, homeDir+"/") {
					p = "~" + strings.TrimPrefix(p, homeDir)
				}
				display = append(display, p)
			}
			lines = append(lines, u.Badge("ok", "PATH: removed the installer line from "+strings.Join(display, ", ")))
			lines = append(lines, u.Badge("dim", "open a new shell (or unset PATH manually) for it to drop from the current session"))
		} else {
			lines = append(lines, u.Badge("dim", "PATH: no installer line found in your shell rc (nothing to clean)"))
		}
	}

	body := strings.Join(lines, "\n")
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Box(u.Emoji("🧹  ")+"uninstall summary", body))
	fmt.Fprintln(w)
}

// runStatusCmd handles `agentjail status`.
// It prints daemon infrastructure status plus per-agent detection and hook state.
func runStatusCmd() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail status: cannot determine home dir: %v", err)))
		os.Exit(1)
	}
	printStatusOutput(os.Stdout, home)
}

// printStatusOutput writes the full styled status output to w.
// Separated from runStatusCmd so tests can pass a bytes.Buffer.
func printStatusOutput(w io.Writer, home string) {
	u := ui.New(w)
	const emojiSectionBodyIndent = "      "

	v := buildinfo.Version
	if v == "" {
		v = "dev"
	}
	fmt.Fprintln(w, u.Header("agentjail", v, currentGOOS))
	fmt.Fprintln(w)

	binDir := filepath.Join(home, ".agentjail", "bin")
	hookBin := filepath.Join(binDir, hookBinaryName)
	daemonBin := filepath.Join(binDir, daemonBinaryName)
	policyFile := filepath.Join(home, ".agentjail", "policy.yaml")

	// Service definition path + label differ by platform: launchd plist on
	// macOS, systemd --user unit on Linux.
	serviceLabel := "launchd plist"
	serviceDst := filepath.Join(home, "Library", "LaunchAgents", plistFilename)
	if currentGOOS != "darwin" {
		serviceLabel = "systemd unit"
		serviceDst = filepath.Join(systemdUserUnitDir(home), systemdUnitFilename)
	}

	// Infrastructure section.
	fmt.Fprintln(w, u.Section(u.Emoji("🧱  ")+"Infrastructure"))

	// Rows show label + badge only (no paths) so the badge column stays aligned
	// via the fixed-width label; the path vars below are still used for the
	// fileExists checks that decide each badge.
	hookBadge := u.Badge("ok", "ok")
	if !fileExists(hookBin) {
		hookBadge = u.Badge("fail", "missing")
	}
	fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue("hook binary", "", hookBadge))

	daemonBadge := u.Badge("ok", "ok")
	if !fileExists(daemonBin) {
		daemonBadge = u.Badge("fail", "missing")
	}
	fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue("daemon binary", "", daemonBadge))

	policyBadge := u.Badge("ok", "ok")
	if !fileExists(policyFile) {
		policyBadge = u.Badge("fail", "missing")
	}
	fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue("policy.yaml", "", policyBadge))

	serviceBadge := u.Badge("ok", "ok")
	if !fileExists(serviceDst) {
		serviceBadge = u.Badge("fail", "missing")
	}
	fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue(serviceLabel, "", serviceBadge))

	daemonRunning := isDaemonRunning()
	daemonBadge2 := u.Badge("ok", "running")
	if !daemonRunning {
		daemonBadge2 = u.Badge("fail", "not running")
	}
	fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue("daemon", "", daemonBadge2))

	// Secrets broker (ADR 0058): report definition presence + up/dormant state
	// WITHOUT starting it. Non-activating by design — stat the socket file
	// (present while listening, removed on exit), never kickstart or connect.
	var secretsBadge string
	switch {
	case !secretsBrokerDefInstalled(home):
		secretsBadge = u.Badge("fail", "not installed")
	case fileExists(sandbox.SecretsSocketPath()):
		secretsBadge = u.Badge("ok", "listening")
	default:
		secretsBadge = u.Badge("dim", "on-demand (dormant)")
	}
	fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue("secrets broker", "", secretsBadge))

	fmt.Fprintln(w)

	// Agent hooks section.
	fmt.Fprintln(w, u.Section(u.Emoji("🔌  ")+"Agent hooks"))
	env := buildAgentsEnv(home)
	for _, ag := range agents.Registry() {
		d := ag.Detect(env)
		s := ag.Status(env)

		detectedBadge := u.Badge("fail", "not detected")
		if d.Present {
			detectedBadge = u.Badge("ok", "detected ("+d.Evidence+")")
		}

		installedBadge := u.Badge("fail", "not installed")
		if s.Installed {
			installedBadge = u.Badge("ok", "installed")
		}

		fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue(ag.DisplayName(), "", detectedBadge+"  "+installedBadge))
		for _, note := range s.Notes {
			fmt.Fprintln(w, emojiSectionBodyIndent+"  "+u.Badge("dim", "note: "+note))
		}
	}
	fmt.Fprintln(w)
}

// runVersionCmd handles `agentjail version`.
func runVersionCmd() {
	printVersionOutput(os.Stdout)
}

// printVersionOutput writes the styled version output to w.
// Separated so tests can pass a bytes.Buffer. The version string itself
// always appears verbatim so scripts/tests grepping it still work.
func printVersionOutput(w io.Writer) {
	v := buildinfo.Version
	if v == "" {
		v = "dev"
	}
	u := ui.New(w)
	fmt.Fprintln(w, u.Header("agentjail", v, currentGOOS))
	fmt.Fprintln(w)
}

// ---- daemon preamble -----------------------------------------------------------

// installDaemonPreamble performs the infrastructure steps 1–6 that are shared
// across all per-agent installs, on both macOS and Linux:
//  1. Copy agentjail-hook to ~/.agentjail/bin/
//  2. Copy agentjail-daemon to ~/.agentjail/bin/
//  3. Install core .rego rules to ~/.agentjail/rules/
//  4. Write ~/.agentjail/policy.yaml (if absent) with mcpSeed pre-populated
//  5. Install the daemon service definition (launchd plist on macOS,
//     systemd --user unit on Linux)
//  6. Start the daemon (launchctl on macOS; `systemctl --user enable --now` +
//     restart on Linux — or, if no systemd user session is reachable, print
//     manual-start instructions instead of failing)
//
// mcpSeed is a pre-filtered list of MCP server names to seed into mcp.allowed
// on first install (R10: discovery runs before this function is called so the
// file is written once with the seed — never write-then-rewrite).
//
// It is idempotent and safe to call multiple times.
// Output is written to w (use os.Stdout in production, a bytes.Buffer in tests).
func installDaemonPreamble(home string, w io.Writer, mcpSeed []string) error {
	u := ui.New(w)
	binDir := filepath.Join(home, ".agentjail", "bin")

	// One section header, then a single completion line per step — half the
	// vertical noise of printing a "doing…" line followed by a "done" line.
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section(u.Emoji("🔧  ")+"Setting up the daemon"))

	// Step 1: copy agentjail-hook.
	hookSrc, err := findBinary(hookBinaryName)
	if err != nil {
		return fmt.Errorf("locate agentjail-hook: %w", err)
	}
	hookDst := filepath.Join(binDir, hookBinaryName)
	if err := copyBinary(hookSrc, hookDst); err != nil {
		return fmt.Errorf("copy agentjail-hook: %w", err)
	}
	fmt.Fprintln(w, u.Step(1, 6, "agentjail-hook installed", true))

	// Step 2: copy the agentjail (multicall) binary itself, then ensure the
	// four role names (agentjail-daemon, agentjail-shield, agentjail-netproxy,
	// agentjail-secrets) are relative symlinks to it. THE WATCHPOINT: this
	// order matters — selfupdate.EnsureRoleSymlinks must run AFTER the real agentjail
	// binary lands in binDir, never before, or the symlinks would dangle.
	cliSrc, err := findBinary(cliBinaryName)
	if err != nil {
		return fmt.Errorf("locate agentjail: %w", err)
	}
	cliDst := filepath.Join(binDir, cliBinaryName)
	if err := copyBinary(cliSrc, cliDst); err != nil {
		return fmt.Errorf("copy agentjail: %w", err)
	}
	if err := selfupdate.EnsureRoleSymlinks(binDir); err != nil {
		return fmt.Errorf("ensure role symlinks: %w", err)
	}
	daemonDst := filepath.Join(binDir, daemonBinaryName)
	fmt.Fprintln(w, u.Step(2, 6, "agentjail-daemon, agentjail-shield, agentjail-netproxy, agentjail-secrets symlinked to agentjail", true))

	// Step 3: copy core .rego rules.
	rulesD := filepath.Join(home, ".agentjail", "rules")
	if err := installCoreRules(rulesD); err != nil {
		return fmt.Errorf("install core rules: %w", err)
	}
	fmt.Fprintln(w, u.Step(3, 6, "core policy rules installed", true))

	// Step 4: write default policy.yaml if missing (with MCP seed list).
	if err := writeDefaultPolicy(home, mcpSeed); err != nil {
		return fmt.Errorf("write policy.yaml: %w", err)
	}
	fmt.Fprintln(w, u.Step(4, 6, "policy.yaml ready", true))

	// Steps 5-6: install + (re)start the daemon service. The daemon log lives
	// under ~/.agentjail so it is co-located with the install (and removed on
	// uninstall) and matches the path `agentjail logs` reads by default.
	daemonLogPath := filepath.Join(home, ".agentjail", "daemon.log")
	crashLogPath := filepath.Join(home, ".agentjail", "crash.log")
	if err := installAndStartDaemonService(home, daemonDst, rulesD, daemonLogPath, crashLogPath, w); err != nil {
		return err
	}

	// Install the secrets broker as a loaded-but-not-running service (ADR 0058).
	// Fail-soft: a broker install failure must never block the daemon install,
	// so errors are logged and swallowed here.
	if err := installSecretsBrokerService(home, w); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail: warning: secrets broker setup skipped: %v\n", err)
	}

	// Note: shield and netproxy no longer need a separate refresh step. They
	// are role symlinks (agentjail-shield, agentjail-netproxy) to the agentjail
	// binary copied in Step 2 above, via selfupdate.EnsureRoleSymlinks — so a reinstall's
	// fresh agentjail binary is picked up automatically without re-copying
	// anything. (Historically `agentjail install` refreshed only hook+daemon,
	// leaving a STALE shield wrapping the session until hand-copied — that
	// papercut is now impossible by construction.)

	// Refresh the PATH shim if one was previously installed. This ensures
	// brew upgrade / curl|sh reinstall picks up the current template and
	// does not retain stale flags from a dev build.
	refreshPathShimIfExists(home)

	return nil
}

// secretsPlistTemplate is the launchd plist for the on-demand secrets broker.
// Unlike the daemon (RunAtLoad + KeepAlive), this job is loaded-but-not-running:
// RunAtLoad=false, no KeepAlive, no Sockets key. It is registered so a client
// can `launchctl kickstart` it on demand (ADR 0058); the broker self-exits on
// idle. Placeholders: __SECRETS_PATH__, __STORE_DIR__, __KEY_PATH__, __IDLE__,
// __CRASH_LOG_PATH__.
const secretsPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.agentjail.secrets</string>
    <key>ProgramArguments</key>
    <array>
        <string>__SECRETS_PATH__</string>
        <string>serve</string>
        <string>--store=__STORE_DIR__</string>
        <string>--key=__KEY_PATH__</string>
        <string>--log=__LOG_PATH__</string>
        <string>--idle-timeout=__IDLE__</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardErrorPath</key>
    <string>__CRASH_LOG_PATH__</string>
    <key>StandardOutPath</key>
    <string>__CRASH_LOG_PATH__</string>
</dict>
</plist>
`

// installSecretsPlist writes the secrets broker launchd plist to dst.
func installSecretsPlist(secretsBin, storeDir, keyPath, logPath, idle, crashLogPath, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	content := strings.ReplaceAll(secretsPlistTemplate, "__SECRETS_PATH__", secretsBin)
	content = strings.ReplaceAll(content, "__STORE_DIR__", storeDir)
	content = strings.ReplaceAll(content, "__KEY_PATH__", keyPath)
	content = strings.ReplaceAll(content, "__LOG_PATH__", logPath)
	content = strings.ReplaceAll(content, "__IDLE__", idle)
	content = strings.ReplaceAll(content, "__CRASH_LOG_PATH__", crashLogPath)
	return os.WriteFile(dst, []byte(content), 0o644)
}

// secretsSystemdServiceTemplate is the systemd --user unit for the on-demand
// secrets broker. Plain Type=simple with NO Restart= — the broker self-exits on
// idle by design (ADR 0058) and must not be restarted into an always-on loop.
// Installed + enabled but not started at boot; a client runs `systemctl --user
// start` on demand. Placeholders match secretsPlistTemplate.
const secretsSystemdServiceTemplate = `[Unit]
Description=agentjail secrets broker — on-demand credential vault (ADR 0058)
After=default.target

[Service]
Type=simple
ExecStart=__SECRETS_PATH__ serve --store=__STORE_DIR__ --key=__KEY_PATH__ --log=__LOG_PATH__ --idle-timeout=__IDLE__
StandardOutput=append:__CRASH_LOG_PATH__
StandardError=append:__CRASH_LOG_PATH__

[Install]
WantedBy=default.target
`

// installSecretsSystemdUnit writes the secrets broker systemd --user unit to dst.
func installSecretsSystemdUnit(secretsBin, storeDir, keyPath, logPath, idle, crashLogPath, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	content := strings.ReplaceAll(secretsSystemdServiceTemplate, "__SECRETS_PATH__", secretsBin)
	content = strings.ReplaceAll(content, "__STORE_DIR__", storeDir)
	content = strings.ReplaceAll(content, "__KEY_PATH__", keyPath)
	content = strings.ReplaceAll(content, "__LOG_PATH__", logPath)
	content = strings.ReplaceAll(content, "__IDLE__", idle)
	content = strings.ReplaceAll(content, "__CRASH_LOG_PATH__", crashLogPath)
	return os.WriteFile(dst, []byte(content), 0o644)
}

// installSecretsBrokerService installs the loaded-but-not-running service
// definition for the secrets broker (ADR 0058), pointing it at the
// agentjail-secrets role symlink (created earlier in installDaemonPreamble's
// Step 2, via selfupdate.EnsureRoleSymlinks — agentjail-secrets is never a real file, see
// rolesymlinks.go). It does NOT start the broker — clients bring it up on
// demand via sandbox.EnsureSecretsBroker. Independent and fail-soft: it never
// blocks the daemon install.
func installSecretsBrokerService(home string, w io.Writer) error {
	u := ui.New(w)
	binDir := filepath.Join(home, ".agentjail", "bin")
	secretsDst := filepath.Join(binDir, secretsBinaryName)

	storeDir := filepath.Join(home, ".agentjail", "secrets")
	keyPath := filepath.Join(home, ".agentjail", "secrets.key")
	logPath := filepath.Join(home, ".agentjail", "secrets.log")
	crashLogPath := filepath.Join(home, ".agentjail", "secrets-crash.log")

	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section(u.Emoji("🔐  ")+"Setting up the secrets broker"))
	fmt.Fprintln(w, u.Step(1, 2, "agentjail-secrets symlinked to agentjail", true))

	// Migration note (ADR 0058 OQ5): if a broker is already listening — e.g. a
	// hand-started `agentjail-secrets serve` or a personal launchd/cron entry —
	// it will keep owning the socket, so the new on-demand definition can't take
	// over until that one exits. Warn rather than kill someone else's process.
	if fileExists(sandbox.SecretsSocketPath()) {
		fmt.Fprintln(w, "      "+u.Badge("dim", "a secrets broker is already running; stop any manual `agentjail-secrets serve` so the managed on-demand job can own the socket"))
	}

	if currentGOOS == "darwin" {
		plistDst := filepath.Join(home, "Library", "LaunchAgents", secretsPlistFilename)
		if err := installSecretsPlist(secretsDst, storeDir, keyPath, logPath, secretsBrokerIdleTimeout, crashLogPath, plistDst); err != nil {
			return fmt.Errorf("install secrets launchd plist: %w", err)
		}
		// Load registers the job in the domain (RunAtLoad=false → not started),
		// so a later `launchctl kickstart` can start it on demand.
		if err := launchctlLoad(plistDst); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail: warning: launchctl load (secrets) failed: %v\n", err)
		}
		fmt.Fprintln(w, u.Step(2, 2, "secrets broker registered (on-demand)", true))
		return nil
	}

	// Linux (and other non-darwin unix): systemd --user unit, enabled-not-started.
	unitDst := filepath.Join(systemdUserUnitDir(home), secretsSystemdUnitFilename)
	if err := installSecretsSystemdUnit(secretsDst, storeDir, keyPath, logPath, secretsBrokerIdleTimeout, crashLogPath, unitDst); err != nil {
		return fmt.Errorf("install secrets systemd user unit: %w", err)
	}
	if systemdUserAvailableFn() {
		// daemon-reload so `systemctl --user start` can find the new unit;
		// enable (not --now) so it's known but not started at boot.
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		if out, err := exec.Command("systemctl", "--user", "enable", secretsSystemdUnitFilename).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail: warning: systemctl --user enable (secrets) failed: %v: %s\n", err, strings.TrimSpace(string(out)))
		}
		fmt.Fprintln(w, u.Step(2, 2, "secrets broker registered (on-demand, systemd --user)", true))
	} else {
		fmt.Fprintln(w, u.Step(2, 2, "secrets broker unit installed (no systemd --user session)", true))
	}
	return nil
}

// installAndStartDaemonService performs steps 5-6 of installDaemonPreamble:
// install the platform service definition and (re)start it. Split out as its
// own function — independent of findBinary/copyBinary — so it is directly
// unit-testable with a fake daemon binary path, no real binaries required.
//
//   - macOS: writes the launchd plist and runs launchctlLoad.
//   - Linux: writes the systemd --user unit and, if a systemd --user session
//     is reachable (systemdUserAvailableFn), enables + starts it via
//     systemctlUserEnableStartFn. If no session is reachable (e.g. a bare
//     container with no login session), the unit is still written and manual
//     start instructions are printed instead of failing the install.
//
// currentGOOS selects the branch, so tests can override it to exercise the
// Linux path on any host; systemdUserAvailableFn / systemctlUserEnableStartFn
// are themselves variables so tests can stub them and never touch a real
// systemd session.
func installAndStartDaemonService(home, daemonDst, rulesD, daemonLogPath, crashLogPath string, w io.Writer) error {
	u := ui.New(w)

	if currentGOOS == "darwin" {
		plistDst := filepath.Join(home, "Library", "LaunchAgents", plistFilename)
		if err := installPlist(daemonDst, rulesD, daemonLogPath, crashLogPath, plistDst); err != nil {
			return fmt.Errorf("install launchd plist: %w", err)
		}
		fmt.Fprintln(w, u.Step(5, 6, "launchd plist installed", true))

		if err := launchctlLoad(plistDst); err != nil {
			// Non-fatal: log but continue.
			fmt.Fprintf(os.Stderr, "agentjail: warning: launchctl load failed (daemon may not be running): %v\n", err)
		}
		fmt.Fprintln(w, u.Step(6, 6, "daemon started", true))
		return nil
	}

	// Linux (and any other non-darwin unix): systemd --user unit.
	unitDst := filepath.Join(systemdUserUnitDir(home), systemdUnitFilename)
	if err := installSystemdUnit(daemonDst, rulesD, daemonLogPath, crashLogPath, unitDst); err != nil {
		return fmt.Errorf("install systemd user unit: %w", err)
	}
	fmt.Fprintln(w, u.Step(5, 6, "systemd --user unit installed", true))

	if systemdUserAvailableFn() {
		if err := systemctlUserEnableStartFn(systemdUnitFilename); err != nil {
			// Non-fatal: log but continue, same as the launchd path.
			fmt.Fprintf(os.Stderr, "agentjail: warning: systemctl --user enable/start failed (daemon may not be running): %v\n", err)
		}
		fmt.Fprintln(w, u.Step(6, 6, "daemon started (systemd --user)", true))
	} else {
		fmt.Fprintln(w, u.Step(6, 6, "daemon NOT started — no systemd --user session detected", true))
		fmt.Fprintln(w, "      "+u.Badge("dim", fmt.Sprintf("unit installed at %s", unitDst)))
		fmt.Fprintln(w, "      "+u.Badge("dim", fmt.Sprintf("start it manually once a session exists: systemctl --user enable --now %s", systemdUnitFilename)))
	}
	return nil
}

// ---- agents env + registry helpers --------------------------------------------

// buildAgentsEnv constructs the agents.Env for the given home directory.
func buildAgentsEnv(home string) agents.Env {
	binDir := filepath.Join(home, ".agentjail", "bin")
	return agents.Env{
		Home:     home,
		BinDir:   binDir,
		HookBin:  filepath.Join(binDir, hookBinaryName),
		CLIBin:   filepath.Join(binDir, cliBinaryName),
		LookPath: exec.LookPath,
	}
}

// agentByID returns the Agent from the registry matching the given ID, or nil.
func agentByID(id string) agents.Agent {
	for _, ag := range agents.Registry() {
		if ag.ID() == id {
			return ag
		}
	}
	return nil
}

// detectedAgent is the result of running Detect on a single agent.
type detectedAgent struct {
	ag agents.Agent
	d  agents.Detection
}

// detectAll runs Detect on every agent in the registry and returns the results.
func detectAll(env agents.Env) []detectedAgent {
	all := agents.Registry()
	out := make([]detectedAgent, 0, len(all))
	for _, ag := range all {
		out = append(out, detectedAgent{ag: ag, d: ag.Detect(env)})
	}
	return out
}

// agentInstallState summarizes, across all detected agents, how many are present
// and how many already have the agentjail hook wired. byID maps an agent ID to
// true when that agent is already protected.
type agentInstallState struct {
	present   int
	installed int
	byID      map[string]bool
}

// allProtected reports whether every present agent is already wired — i.e. there
// is nothing new for the discovery flow to do, so a re-run is just a refresh.
func (s agentInstallState) allProtected() bool {
	return s.present > 0 && s.installed == s.present
}

// computeInstallState builds an agentInstallState from detection results, using
// statusOf to read each agent's current hook status (injectable for tests).
// Only present (detected) agents are counted.
func computeInstallState(detected []detectedAgent, statusOf func(agents.Agent) agents.Status) agentInstallState {
	st := agentInstallState{byID: make(map[string]bool, len(detected))}
	for _, r := range detected {
		if !r.d.Present {
			continue
		}
		st.present++
		if statusOf(r.ag).Installed {
			st.byID[r.ag.ID()] = true
			st.installed++
		}
	}
	return st
}

// protectedDetail annotates a picker item's detail line with whether the agent
// is already protected, so a re-run shows current state at a glance.
func protectedDetail(evidence string, installed bool) string {
	if installed {
		return evidence + "  ·  already protected"
	}
	return evidence + "  ·  not protected yet"
}

// countPresent counts how many detected agents are present.
func countPresent(detected []detectedAgent) int {
	n := 0
	for _, r := range detected {
		if r.d.Present {
			n++
		}
	}
	return n
}

// ---- filesystem / launchctl helpers ----------------------------------------

// findBinary searches for the named binary:
//  1. Next to the current executable.
//  2. In PATH.
func findBinary(name string) (string, error) {
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	p, err := exec.LookPath(name)
	if err == nil {
		return p, nil
	}
	return "", fmt.Errorf("%s not found next to the agentjail binary or in PATH", name)
}

// copyBinary copies src to dst, creating parent directories, and sets 0755.
func copyBinary(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".agentjail-install-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	buf := make([]byte, 32*1024)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				_ = tmp.Close()
				return fmt.Errorf("write temp: %w", werr)
			}
		}
		if rerr != nil {
			break
		}
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return os.Rename(tmpName, dst)
}

// writeDefaultPolicy writes the default policy YAML to ~/.agentjail/policy.yaml
// if the file does not already exist. On re-install (file exists), it merges
// any newly discovered MCP servers into mcp.allowed without clobbering user
// customisations — servers already present or matching a blocked pattern are
// skipped.
func writeDefaultPolicy(home string, mcpSeed []string) error {
	dst := filepath.Join(home, ".agentjail", "policy.yaml")
	if _, err := os.Stat(dst); err == nil {
		return mergeNewMCPServers(dst, mcpSeed)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	cfg := config.Default()
	if len(mcpSeed) > 0 {
		cfg.MCP.Allowed = mcpSeed
	}

	return config.Save(cfg, dst)
}

// mergeNewMCPServers adds newly discovered MCP server names to an existing
// policy.yaml's mcp.allowed list. It is additive only — existing entries and
// user-blocked servers are never touched. A load failure is non-fatal (the
// install continues with the existing policy).
func mergeNewMCPServers(path string, mcpSeed []string) error {
	if len(mcpSeed) == 0 {
		fmt.Println("  policy.yaml already exists — no new MCP servers to add.")
		return nil
	}

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Println("  policy.yaml already exists — skipping (could not load for merge).")
		return nil
	}

	existing := make(map[string]struct{}, len(cfg.MCP.Allowed))
	for _, name := range cfg.MCP.Allowed {
		existing[name] = struct{}{}
	}

	var added []string
	for _, name := range mcpSeed {
		if _, ok := existing[name]; ok {
			continue
		}
		if matchesAnyGlob(name, cfg.MCP.Blocked) {
			continue
		}
		added = append(added, name)
	}

	if len(added) == 0 {
		fmt.Println("  policy.yaml already exists — no new MCP servers to add.")
		return nil
	}

	cfg.MCP.Allowed = append(cfg.MCP.Allowed, added...)
	sort.Strings(cfg.MCP.Allowed)

	if err := config.Save(cfg, path); err != nil {
		return fmt.Errorf("merge MCP servers: %w", err)
	}
	fmt.Printf("  policy.yaml: merged %d new MCP server(s): %s\n", len(added), strings.Join(added, ", "))
	return nil
}

// To disable daemon update checks, users may add an EnvironmentVariables
// section to the plist:
//
//	<key>EnvironmentVariables</key>
//	<dict>
//	    <key>AGENTJAIL_NO_UPDATE_CHECK</key>
//	    <string>1</string>
//	</dict>
//
// plistTemplate is the launchd plist with placeholders for the daemon path,
// rules directory, log path, and crash log path. Placeholders are patched at
// install time:
//   - __DAEMON_PATH__   — absolute path to the agentjail-daemon binary
//   - __RULES_DIR__     — absolute path to the rules directory
//   - __LOG_PATH__      — daemon.log, managed by the daemon's internal rotating
//     writer (passed via --log flag); `agentjail logs` reads this file
//   - __CRASH_LOG_PATH__ — crash.log, written by launchd via StandardErrorPath /
//     StandardOutPath; captures panics and runtime output on restart
//
// The split keeps structured slog JSON in daemon.log (rotated by the daemon)
// separate from raw crash/panic output in crash.log (captured by launchd).
// launchd opens StandardErrorPath/StandardOutPath with O_TRUNC on each restart,
// which is acceptable for crash.log but would wipe structured logs if pointed at
// daemon.log.
const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.agentjail.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>__DAEMON_PATH__</string>
        <string>--rules=__RULES_DIR__</string>
        <string>--log=__LOG_PATH__</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>__CRASH_LOG_PATH__</string>
    <key>StandardOutPath</key>
    <string>__CRASH_LOG_PATH__</string>
</dict>
</plist>
`

// installPlist writes the launchd plist to dst with the daemon binary path,
// rules directory, log path, and crash log path patched in.
func installPlist(daemonBin, rulesDir, logPath, crashLogPath, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	content := strings.ReplaceAll(plistTemplate, "__DAEMON_PATH__", daemonBin)
	content = strings.ReplaceAll(content, "__RULES_DIR__", rulesDir)
	content = strings.ReplaceAll(content, "__LOG_PATH__", logPath)
	content = strings.ReplaceAll(content, "__CRASH_LOG_PATH__", crashLogPath)
	return os.WriteFile(dst, []byte(content), 0o644)
}

// launchctlLoad unloads (if loaded) then loads the given plist.
// Thin wrapper around selfupdate.LaunchctlLoad for backward compatibility
// within this package.
func launchctlLoad(plistPath string) error {
	return selfupdate.LaunchctlLoad(plistPath)
}

// launchctlUnload unloads the given plist.
// Thin wrapper around selfupdate.LaunchctlUnload for backward compatibility
// within this package.
func launchctlUnload(plistPath string) error {
	return selfupdate.LaunchctlUnload(plistPath)
}

// isDaemonRunning asks the platform service manager whether the daemon
// service is active: launchctl on macOS, systemctl --user on Linux.
func isDaemonRunning() bool {
	if currentGOOS == "darwin" {
		out, err := exec.Command("launchctl", "list", plistLabel).Output()
		if err != nil {
			return false
		}
		return len(out) > 0
	}
	return exec.Command("systemctl", "--user", "is-active", "--quiet", systemdUnitFilename).Run() == nil
}

// ---- systemd --user (Linux) helpers ----------------------------------------

// systemdUserUnitDir returns the directory systemd searches for --user unit
// files under a given home: ~/.config/systemd/user.
func systemdUserUnitDir(home string) string {
	return filepath.Join(home, ".config", "systemd", "user")
}

// systemdUnitTemplate is the systemd --user unit with placeholders for the
// daemon path, rules directory, log path, and crash log path. Placeholders
// are patched at install time (same names as plistTemplate):
//   - __DAEMON_PATH__    — absolute path to the agentjail-daemon binary
//   - __RULES_DIR__      — absolute path to the rules directory
//   - __LOG_PATH__       — daemon.log, managed by the daemon's internal
//     rotating writer (passed via --log flag); `agentjail logs` reads this
//   - __CRASH_LOG_PATH__ — crash.log; captures stdout/stderr (panics, runtime
//     output) across restarts, appended rather than truncated so a crash loop
//     doesn't erase prior history
//
// Restart=on-failure + RestartSec gives the daemon the same self-recovery
// launchd's KeepAlive provides on macOS. WantedBy=default.target (not
// graphical-session.target) so the unit starts in headless/SSH user sessions
// too, not only desktop logins.
const systemdUnitTemplate = `[Unit]
Description=agentjail daemon — policy enforcement for coding agents
After=default.target

[Service]
ExecStart=__DAEMON_PATH__ --rules=__RULES_DIR__ --log=__LOG_PATH__
Restart=on-failure
RestartSec=2
StandardOutput=append:__CRASH_LOG_PATH__
StandardError=append:__CRASH_LOG_PATH__

[Install]
WantedBy=default.target
`

// installSystemdUnit writes the systemd --user unit to dst with the daemon
// binary path, rules directory, log path, and crash log path patched in.
func installSystemdUnit(daemonBin, rulesDir, logPath, crashLogPath, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	content := strings.ReplaceAll(systemdUnitTemplate, "__DAEMON_PATH__", daemonBin)
	content = strings.ReplaceAll(content, "__RULES_DIR__", rulesDir)
	content = strings.ReplaceAll(content, "__LOG_PATH__", logPath)
	content = strings.ReplaceAll(content, "__CRASH_LOG_PATH__", crashLogPath)
	return os.WriteFile(dst, []byte(content), 0o644)
}

// defaultSystemdUserAvailable reports whether a systemd --user session is
// reachable on this machine. `systemctl --user show-environment` is a
// read-only query that only succeeds when a user session/bus exists (it
// fails fast in bare containers or SSH sessions with no logind session), so
// it is safe to use as a capability probe.
func defaultSystemdUserAvailable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "--user", "show-environment").Run() == nil
}

// defaultSystemctlUserEnableStart enables (persists across logins) and starts
// the given systemd --user unit, then restarts it so a reinstall picks up a
// refreshed binary or unit file. Mirrors launchctlLoad's "unload then load"
// idempotency.
func defaultSystemctlUserEnableStart(unit string) error {
	if out, err := exec.Command("systemctl", "--user", "enable", "--now", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user enable --now %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "--user", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user restart %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// defaultSystemctlUserDisableStop stops and disables the given systemd --user
// unit. Tolerates "not loaded"/"not found" gracefully, mirroring
// uninstallDaemon's launchctl-unload tolerance on macOS.
func defaultSystemctlUserDisableStop(unit string) error {
	out, err := exec.Command("systemctl", "--user", "disable", "--now", unit).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" && !strings.Contains(msg, "not loaded") && !strings.Contains(msg, "does not exist") &&
			!strings.Contains(msg, "No such file or directory") {
			return fmt.Errorf("systemctl --user disable --now %s: %w: %s", unit, err, msg)
		}
	}
	return nil
}

// systemctlUserDisableStopFn is a variable so tests can stub it out and never
// touch a real systemd session.
var systemctlUserDisableStopFn = defaultSystemctlUserDisableStop

// fileExists reports whether path exists (any file type).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ---- flag parsing -------------------------------------------------------

// parseInstallFlags extracts install subcommand flags from args.
// Returns (forAgent, all, yes, allowUnsupported).
func parseInstallFlags(args []string) (forAgent string, all, yes, allowUnsupported bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--for" && i+1 < len(args):
			forAgent = validateTarget(args[i+1], "install", installTargets)
			i++
		case strings.HasPrefix(a, "--for="):
			forAgent = validateTarget(strings.TrimPrefix(a, "--for="), "install", installTargets)
		case a == "--all":
			all = true
		case a == "--yes", a == "-y":
			yes = true
		case a == "--allow-unsupported":
			allowUnsupported = true
		case a == "--with-path-shim":
			// Handled in runInstallCmd via hasFlag.
		case a == "--chain":
			// Handled in runInstallCmd via hasFlag.
		case a == "--replace":
			// Handled in runInstallCmd via hasFlag.
		}
	}
	return
}

// installTargets lists all valid --for targets.
var installTargets = []string{"claude-code", "codex", "cursor", "vscode", "cursor-ide"}

// hasFlag checks if a flag is present in the args slice.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// parseForFlag extracts the --for flag from args for uninstall.
// Exits with a usage message if the flag is missing or the value is not supported.
func parseForFlag(args []string, subcmd string) string {
	supported := []string{"claude-code", "codex", "cursor"}
	for i, a := range args {
		if a == "--for" && i+1 < len(args) {
			return validateTarget(args[i+1], subcmd, supported)
		}
		if strings.HasPrefix(a, "--for=") {
			return validateTarget(strings.TrimPrefix(a, "--for="), subcmd, supported)
		}
	}
	fmt.Fprintf(os.Stderr, "usage: agentjail %s --for <claude-code|codex|cursor>\n", subcmd)
	os.Exit(2)
	return ""
}

// parseOptionalForFlag extracts the --for flag from args for uninstall.
// Unlike parseForFlag, it does NOT exit when --for is absent — it returns ""
// to signal the caller should perform a full teardown.
func parseOptionalForFlag(args []string) string {
	supported := []string{"claude-code", "codex", "cursor"}
	for i, a := range args {
		if a == "--for" && i+1 < len(args) {
			return validateTarget(args[i+1], "uninstall", supported)
		}
		if strings.HasPrefix(a, "--for=") {
			return validateTarget(strings.TrimPrefix(a, "--for="), "uninstall", supported)
		}
	}
	return ""
}

func validateTarget(target, subcmd string, supported []string) string {
	for _, s := range supported {
		if target == s {
			return target
		}
	}
	fmt.Fprintf(os.Stderr, "agentjail %s: unknown target %q (supported: %s)\n",
		subcmd, target, strings.Join(supported, ", "))
	os.Exit(2)
	return ""
}
