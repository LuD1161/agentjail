// install.go — agentjail install/uninstall/status subcommands.
//
// What `agentjail install` does on macOS:
//  1. Copies agentjail-hook binary to ~/.agentjail/bin/agentjail-hook (0755).
//  2. Copies agentjail-daemon binary to ~/.agentjail/bin/agentjail-daemon (0755).
//  3. Copies core .rego rules to ~/.agentjail/rules/ (idempotent).
//  4. Writes ~/.agentjail/policy.yaml from agentpolicy/default_policy.yaml
//     if the file does not already exist (never overwrites user customisations).
//  5. Installs the launchd plist at ~/Library/LaunchAgents/com.agentjail.daemon.plist
//     with ProgramArguments patched to ~/.agentjail/bin/agentjail-daemon.
//  6. Runs launchctl unload/load to (re)start the daemon.
//  7. Detects which agents are present on the machine (claude-code, codex, cursor)
//     and which of them already have the agentjail hook wired.
//  8. If every detected agent is already protected, the run is just a binary +
//     daemon refresh (steps 1-6 above): it skips the picker and reports, so
//     re-running `curl … | sh` on an installed machine behaves like an update.
//  9. Otherwise presents an interactive multi-select picker (already-protected
//     agents are marked) or falls back to non-interactive selection.
// 10. Dispatches agent.Install(env) for each selected agent.
// 11. Prints a summary and exits non-zero if any selected install failed.
//
// Use `agentjail install --for <agent>` for single-agent back-compat.
// Use `agentjail install --all` / `--yes` for non-interactive "install all".
// Use `agentjail install --allow-unsupported` on Linux to detect without error.
//
// What `agentjail uninstall` does (no --for):
//  1. Calls agent.Uninstall(env) for every agent in the registry. Failures are
//     collected but do not abort other agents (Uninstall is idempotent).
//  2. On macOS: unloads the launchd daemon and removes the plist.
//  3. Removes ~/.agentjail and /tmp/agentjail-daemon.log.
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
	"strings"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/agents"
	"github.com/LuD1161/agentjail/internal/picker"
	"github.com/LuD1161/agentjail/internal/telemetry"
	"github.com/LuD1161/agentjail/internal/ui"
)

// plistLabel is the launchd service identifier.
const plistLabel = "com.agentjail.daemon"

// plistFilename is the filename placed under ~/Library/LaunchAgents/.
const plistFilename = "com.agentjail.daemon.plist"

// hookBinaryName and daemonBinaryName are the binary filenames we install.
const hookBinaryName = "agentjail-hook"
const daemonBinaryName = "agentjail-daemon"

// currentGOOS is the runtime OS. It is a variable (not a constant) so that
// tests can override it to simulate non-darwin platforms without recompiling.
var currentGOOS = runtime.GOOS

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
//	--allow-unsupported  on Linux, print the detection report and exit 0
//	                     (default on Linux: exit non-zero after detection)
func runInstallCmd(args []string) {
	forAgent, all, yes, allowUnsupported := parseInstallFlags(args)

	u := ui.New(os.Stdout)

	// ── Linux gate ──────────────────────────────────────────────────────────
	if currentGOOS != "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: cannot determine home dir: %v", err)))
			os.Exit(1)
		}
		env := buildAgentsEnv(home)
		detected := detectAll(env)
		n := countPresent(detected)
		printLinuxGate(os.Stdout, n, currentGOOS, detected)
		if allowUnsupported {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// ── macOS path ──────────────────────────────────────────────────────────

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: cannot determine home dir: %v", err)))
		os.Exit(1)
	}

	// Print the header banner.
	v := version
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
			fmt.Fprintf(os.Stderr, "%s\n", ui.New(os.Stderr).Badge("fail", fmt.Sprintf("agentjail install: unknown agent %q (supported: claude-code, codex, cursor)", forAgent)))
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
				_ = telemetry.SendInstall(ctx, tp, os.Getenv, version, runtime.GOOS, runtime.GOARCH,
					os.Getenv("AGENTJAIL_INSTALL_METHOD"), []string{ag.ID()}, 1)
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
		v := version
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
			_ = telemetry.SendInstall(ctx, tp, os.Getenv, version, runtime.GOOS, runtime.GOARCH,
				os.Getenv("AGENTJAIL_INSTALL_METHOD"), wiredAgents, len(detected))
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
				_ = telemetry.SendUninstall(ctx, tp, os.Getenv, version, runtime.GOOS, runtime.GOARCH, []string{ag.ID()})
			}()
		}
		uout := ui.New(os.Stdout)
		fmt.Fprintln(os.Stdout, uout.Badge("ok", fmt.Sprintf("agentjail: uninstall complete for %s.", ag.DisplayName())))
		return
	}

	// ── Full teardown path ────────────────────────────────────────────────
	result := performFullUninstall(home, currentGOOS)
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

	// HardFailed is true when any step that should succeed actually failed.
	HardFailed bool
}

// performFullUninstall runs the full teardown without calling os.Exit or
// printing anything. It is the unit-testable core of runUninstallCmd.
//
//   - home is the user's home directory (e.g. os.UserHomeDir()).
//   - goos is the runtime OS string (pass currentGOOS, or "linux" in tests
//     to skip the real launchctl calls).
func performFullUninstall(home, goos string) UninstallResult {
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
			_ = telemetry.SendUninstall(ctx, tp, os.Getenv, version, goos, runtime.GOARCH, nil)
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

	// Step 2: daemon teardown (macOS only).
	if goos == "darwin" {
		r.DaemonErr = uninstallDaemon(home)
		if r.DaemonErr != nil {
			r.HardFailed = true
		}
	} else {
		r.DaemonSkipped = true
	}

	// Step 3: remove ~/.agentjail.
	installDir := filepath.Join(home, ".agentjail")
	if err := os.RemoveAll(installDir); err != nil {
		r.InstallDirErr = err
		r.HardFailed = true
	}

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

// uninstallDaemon unloads the launchd service and removes the plist file.
// It tolerates "already unloaded" and "file not found" gracefully.
func uninstallDaemon(home string) error {
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
		lines = append(lines, u.KeyValue("daemon", "", u.Badge("dim", "skipped (non-darwin)")))
	} else if r.DaemonErr != nil {
		lines = append(lines, u.KeyValue("daemon", "", u.Badge("fail", "FAILED: "+r.DaemonErr.Error())))
	} else {
		lines = append(lines, u.KeyValue("daemon", "", u.Badge("ok", "stopped and plist removed")))
	}

	if r.InstallDirErr != nil {
		lines = append(lines, u.KeyValue("~/.agentjail", "", u.Badge("fail", "FAILED to remove: "+r.InstallDirErr.Error())))
	} else {
		lines = append(lines, u.KeyValue("~/.agentjail", "", u.Badge("ok", "removed")))
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

// printLinuxGate writes the styled Linux gate detection report to w.
// It is the testable core of the Linux gate block in runInstallCmd.
func printLinuxGate(w io.Writer, n int, goos string, detected []detectedAgent) {
	u := ui.New(w)
	fmt.Fprintln(w, u.Section(fmt.Sprintf("%d agent(s) detected; hook wiring skipped (daemon not yet supported on %s)", n, goos)))
	for _, r := range detected {
		if r.d.Present {
			fmt.Fprintln(w, "  "+u.KeyValue(r.ag.DisplayName(), r.d.Evidence, u.Badge("warn", "detected — hooks not wired")))
		}
	}
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

	v := version
	if v == "" {
		v = "dev"
	}
	fmt.Fprintln(w, u.Header("agentjail", v, currentGOOS))
	fmt.Fprintln(w)

	binDir := filepath.Join(home, ".agentjail", "bin")
	hookBin := filepath.Join(binDir, hookBinaryName)
	daemonBin := filepath.Join(binDir, daemonBinaryName)
	policyFile := filepath.Join(home, ".agentjail", "policy.yaml")
	plistDst := filepath.Join(home, "Library", "LaunchAgents", plistFilename)

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

	plistBadge := u.Badge("ok", "ok")
	if !fileExists(plistDst) {
		plistBadge = u.Badge("fail", "missing")
	}
	fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue("launchd plist", "", plistBadge))

	daemonRunning := isDaemonRunning()
	daemonBadge2 := u.Badge("ok", "running")
	if !daemonRunning {
		daemonBadge2 = u.Badge("fail", "not running")
	}
	fmt.Fprintln(w, emojiSectionBodyIndent+u.KeyValue("daemon", "", daemonBadge2))

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
	v := version
	if v == "" {
		v = "dev"
	}
	u := ui.New(w)
	fmt.Fprintln(w, u.Header("agentjail", v, currentGOOS))
	fmt.Fprintln(w)
}

// version is set via -ldflags at build time.
var version = ""

// ---- daemon preamble -----------------------------------------------------------

// installDaemonPreamble performs the macOS-only infrastructure steps 1–6 that
// are shared across all per-agent installs:
//  1. Copy agentjail-hook to ~/.agentjail/bin/
//  2. Copy agentjail-daemon to ~/.agentjail/bin/
//  3. Install core .rego rules to ~/.agentjail/rules/
//  4. Write ~/.agentjail/policy.yaml (if absent) with mcpSeed pre-populated
//  5. Install the launchd plist
//  6. Load the daemon via launchctl
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

	// Step 2: copy agentjail-daemon.
	daemonSrc, err := findBinary(daemonBinaryName)
	if err != nil {
		return fmt.Errorf("locate agentjail-daemon: %w", err)
	}
	daemonDst := filepath.Join(binDir, daemonBinaryName)
	if err := copyBinary(daemonSrc, daemonDst); err != nil {
		return fmt.Errorf("copy agentjail-daemon: %w", err)
	}
	fmt.Fprintln(w, u.Step(2, 6, "agentjail-daemon installed", true))

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

	// Step 5: install launchd plist. The daemon log lives under ~/.agentjail so
	// it is co-located with the install (and removed on uninstall) and matches
	// the path `agentjail logs` reads by default.
	plistDst := filepath.Join(home, "Library", "LaunchAgents", plistFilename)
	daemonLogPath := filepath.Join(home, ".agentjail", "daemon.log")
	crashLogPath := filepath.Join(home, ".agentjail", "crash.log")
	if err := installPlist(daemonDst, rulesD, daemonLogPath, crashLogPath, plistDst); err != nil {
		return fmt.Errorf("install launchd plist: %w", err)
	}
	fmt.Fprintln(w, u.Step(5, 6, "launchd plist installed", true))

	// Step 6: load daemon.
	if err := launchctlLoad(plistDst); err != nil {
		// Non-fatal: log but continue.
		fmt.Fprintf(os.Stderr, "agentjail: warning: launchctl load failed (daemon may not be running): %v\n", err)
	}
	fmt.Fprintln(w, u.Step(6, 6, "daemon started", true))

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
// only if the destination does not already exist (write-once idempotency — AC2.3).
//
// When mcpSeed is non-empty, the discovered MCP server names are pre-populated
// into mcp.allowed on the first write (R10). The policy is written via
// config.Save so the result is always a valid, well-structured PolicyConfig —
// the YAML template files are NOT changed.
//
// Re-install: if policy.yaml already exists, this function is a no-op, so user
// customisations are never clobbered.
func writeDefaultPolicy(home string, mcpSeed []string) error {
	dst := filepath.Join(home, ".agentjail", "policy.yaml")
	if _, err := os.Stat(dst); err == nil {
		fmt.Println("  policy.yaml already exists — skipping.")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Build the initial config from defaults and inject the seed list.
	cfg := config.Default()
	if len(mcpSeed) > 0 {
		cfg.MCP.Allowed = mcpSeed
	}

	return config.Save(cfg, dst)
}

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
func launchctlLoad(plistPath string) error {
	_ = exec.Command("launchctl", "unload", plistPath).Run()
	out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// launchctlUnload unloads the given plist.
func launchctlUnload(plistPath string) error {
	if !fileExists(plistPath) {
		return nil
	}
	out, err := exec.Command("launchctl", "unload", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl unload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isDaemonRunning asks launchctl whether the daemon service is loaded.
func isDaemonRunning() bool {
	out, err := exec.Command("launchctl", "list", plistLabel).Output()
	if err != nil {
		return false
	}
	return len(out) > 0
}

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
			forAgent = validateTarget(args[i+1], "install", []string{"claude-code", "codex", "cursor"})
			i++
		case strings.HasPrefix(a, "--for="):
			forAgent = validateTarget(strings.TrimPrefix(a, "--for="), "install", []string{"claude-code", "codex", "cursor"})
		case a == "--all":
			all = true
		case a == "--yes", a == "-y":
			yes = true
		case a == "--allow-unsupported":
			allowUnsupported = true
		}
	}
	return
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
