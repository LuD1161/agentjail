// update.go — `agentjail update` self-update subcommand.
//
// Downloads the latest release tarball from GitHub, verifies its SHA256
// checksum against the upstream SHA256SUMS manifest (mirroring install.sh
// exactly), atomically replaces the installed binaries, and restarts the
// daemon. The entire operation is gated behind an interactive-TTY check —
// if stdin is not a real terminal, the command refuses with an explicit
// message, preventing any agent-driven self-modification.
//
// Platform notes:
//   - macOS: daemon is managed via launchd (launchctlUnload / launchctlLoad).
//   - Linux: daemon is restarted through its systemd user service after the
//     binary swap.
//
// Binary list: agentjail, agentjail-hook (mirrors install.sh and
// selfupdate.UpdateBinaries). agentjail-daemon, agentjail-shield,
// agentjail-netproxy, and agentjail-secrets are never downloaded or swapped
// directly — they are symlinks to agentjail, reconciled by
// selfupdate.EnsureRoleSymlinks after the swap.
//
// Atomic swap: each binary is downloaded to a temp file in the SAME directory
// as the target (guarantees os.Rename is on the same filesystem), chmod 0755,
// then renamed over the live binary. A crash between renames leaves at most
// one stale temp file, never a half-written binary.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/agentguidance"
	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/pathshim"
	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/telemetry"
)

// updateURLBaseFn is the package-level hook used by performUpdate to build the
// primary download URL.  Tests override it to point at a mock HTTP server.
var updateURLBaseFn = selfupdate.UpdateURLBase

var updateHomeDirFn = os.UserHomeDir
var updateRestartDaemonFn = selfupdate.RestartDaemon
var updateLaunchctlLoadFn = selfupdate.LaunchctlLoad
var updateLaunchctlUnloadFn = selfupdate.LaunchctlUnload
var updateEnsureRoleSymlinksFn = selfupdate.EnsureRoleSymlinks
var updateAttestDaemonFn = attestDaemonVersion
var updateDaemonSocketPathFn = daemonSocketPath
var updateAuditFn = emitUpdateAudit
var updateReconcileGuidanceFn = agentguidance.RunReconciler

const (
	updateActivationTimeout      = 5 * time.Second
	updateActivationProbeTimeout = 250 * time.Millisecond
	updateAuditTimeout           = 3 * time.Second
)

type updatePathBackup struct {
	name       string
	existed    bool
	mode       os.FileMode
	linkTarget string
}

// defaultUpdateInstallDir returns the binary installation directory, honouring
// AGENTJAIL_HOME (default: ~/.agentjail/bin).
func defaultUpdateInstallDir() (string, error) {
	home := os.Getenv("AGENTJAIL_HOME")
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home dir: %w", err)
		}
		home = filepath.Join(home, ".agentjail")
	}
	return filepath.Join(home, "bin"), nil
}

// runUpdate is the entry point for `agentjail update`.
// Returns an exit code (0 = success, 1 = error).
//
// Flags:
//
//	--force   Reinstall the current version (e.g. for repair). Downgrade is
//	          still refused even with --force.
func runUpdate(args []string) int {
	// Parse --force flag.
	force := false
	for _, a := range args {
		if a == "--force" {
			force = true
		}
	}

	// ── SECURITY GATE: interactive human confirmation required ───────────────
	// This operation replaces agentjail's own binaries and restarts its daemon.
	// An agent MUST NOT be able to trigger it. We not only open /dev/tty but also
	// READ a typed 'y' from it (the same full pattern as confirmDisableInteractive
	// in policy.go). Merely opening /dev/tty is insufficient — an agent running
	// under a terminal-backed session inherits a controlling terminal, so the
	// openability check alone would pass. Requiring a typed confirmation that the
	// agent cannot produce is the robust guard.
	if !confirmUpdateInteractive() {
		return 1
	}

	installDir, err := defaultUpdateInstallDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: %v\n", err)
		return 1
	}

	// Detect path mismatch: if the running binary is not in installDir,
	// delegate to the appropriate package manager instead of silently
	// updating the wrong location.
	if exePath, brew := selfupdate.ResolveExecutablePath(); exePath != "" {
		exeDir := filepath.Dir(exePath)
		if exeDir != installDir {
			if brew {
				current := buildinfo.Version
				if current == "" {
					current = "dev"
				}
				fmt.Println("agentjail update: installed via Homebrew — running `brew upgrade agentjail`…")
				cmd := exec.Command("brew", "upgrade", "agentjail")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "agentjail update: brew upgrade failed: %v\n", err)
					return 1
				}
				guidanceCLI, _ := selfupdate.ResolveExecutablePath()
				if guidanceCLI == "" {
					guidanceCLI = exePath
				}
				if err := updateReconcileGuidanceFn(guidanceCLI); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: could not refresh agent guidance: %v\n", err)
				}
				// Emit telemetry for brew upgrade path (best-effort).
				if tp, err := telemetry.DefaultPaths(); err == nil {
					tCtx, tCancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer tCancel()
					_ = telemetry.SendUpdate(tCtx, tp, os.Getenv, current, "brew-upgrade", currentGOOS, runtime.GOARCH)
				}
				return 0
			}
			fmt.Fprintf(os.Stderr, "agentjail update: the running binary is at %s\n", exePath)
			fmt.Fprintf(os.Stderr, "  but updates install to %s.\n", installDir)
			fmt.Fprintln(os.Stderr, "  The update would not take effect. Update via your package manager instead.")
			return 1
		}
	}

	return performUpdate(installDir, currentGOOS, runtime.GOARCH, force)
}

// confirmUpdateInteractive opens /dev/tty, prints a warning, and waits for
// the user to press Enter (or type 'y') to proceed. It refuses (returns false)
// when no terminal is attached or when the user types something other than
// empty/y. The /dev/tty gate prevents agents from triggering self-updates —
// they cannot open the controlling terminal to supply input. The update command
// is intentionally lenient (Enter = proceed) because the user explicitly ran
// `agentjail update`, signalling clear intent; policy-disable and mcp-allow
// use the stricter requireInteractiveConfirm that demands an explicit 'y'.
func confirmUpdateInteractive() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprint(os.Stderr,
			"agentjail update: REFUSED — no interactive terminal detected.\n"+
				"  Self-update replaces agentjail's own binaries and restarts the daemon.\n"+
				"  It must be run in a terminal by a human.\n"+
				"  This restriction prevents agents from self-modifying the security tool.\n")
		return false
	}
	defer tty.Close()

	fmt.Fprint(tty,
		"\n"+
			"  ⚠  You are about to self-update agentjail.\n"+
			"\n"+
			"  Effect:   downloads the latest release, replaces agentjail's binaries\n"+
			"            in place, and restarts the daemon.\n"+
			"  Source:   https://github.com/LuD1161/agentjail/releases (official only).\n"+
			"  Verify:   the release tarball is SHA256-checked before anything is swapped.\n"+
			"\n"+
			"  Press Enter to continue, or type 'n' to cancel: ")

	line, _ := bufio.NewReader(tty).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Fprintln(tty, "Cancelled.")
		return false
	}
	return true
}

// performUpdate is the testable core of runUpdate. It accepts an explicit
// installDir (tests pass a t.TempDir()), goos/goarch for platform detection,
// and force to allow reinstalling the same version.
// Returns 0 on success, non-zero on error.
func performUpdate(installDir, goos, goarch string, force bool) int {
	current := buildinfo.Version
	if current == "" {
		current = "dev"
	}

	// Step 1: fetch the latest version from GitHub.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	releaseInfo, _ := defaultChecker.FetchLatestRelease(ctx, current)
	latest := releaseInfo.Version
	if latest == "" {
		fmt.Fprintln(os.Stderr, "agentjail update: could not fetch latest version (check your network).")
		return 1
	}

	// Step 2: gate on version comparison.
	// Downgrade is always refused (even with --force).
	// Same version: proceed only with --force (reinstall/repair).
	// Newer version: always proceed.
	if selfupdate.IsValid(current) && selfupdate.IsValid(latest) {
		if selfupdate.IsNewerVersion(latest, current) {
			// latest < current — downgrade
			fmt.Fprintf(os.Stderr, "agentjail update: downgrade not supported (%s → %s); refusing.\n", current, latest)
			return 0
		}
		if current == latest || (!selfupdate.IsNewerVersion(current, latest) && !selfupdate.IsNewerVersion(latest, current)) {
			// same version
			if !force {
				fmt.Printf("agentjail update: already up to date (%s).\n", current)
				return 0
			}
			fmt.Printf("\n⬆  reinstalling %s (--force)\n\n", current)
		} else {
			// latest > current — normal upgrade
			fmt.Printf("\n⬆  %s → %s\n\n", current, latest)
		}
	} else if !selfupdate.IsNewerVersion(current, latest) {
		// Non-semver current (dev builds) — skip.
		if !selfupdate.IsValid(current) {
			fmt.Printf("agentjail update: current build is a development version (%s); skipping update.\n", current)
		} else {
			fmt.Printf("agentjail update: already up to date (%s).\n", current)
		}
		return 0
	} else {
		fmt.Printf("agentjail update: %s → %s\n", current, latest)
	}

	// Step 3: download tarball + SHA256SUMS into a temp directory.
	tmpDir, err := os.MkdirTemp("", "agentjail-update-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: create temp dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	tarball := selfupdate.TarballName(latest, goos, goarch)
	urlBase := updateURLBaseFn(latest)

	fmt.Printf("📥  downloading %s …\n", tarball)
	tarballPath := filepath.Join(tmpDir, tarball)

	// Try primary (Worker) URL; fall back to GitHub direct on failure.
	dlErr := selfupdate.DownloadFile(ctx, urlBase+"/"+tarball, tarballPath, selfupdate.MaxDownloadBytes)
	if dlErr != nil {
		fallbackBase := selfupdate.UpdateURLBaseFallback(latest)
		fmt.Fprintf(os.Stderr, "  warning: primary download failed (%v); retrying via GitHub…\n", dlErr)
		if err2 := selfupdate.DownloadFile(ctx, fallbackBase+"/"+tarball, tarballPath, selfupdate.MaxDownloadBytes); err2 != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: download tarball: %v\n", err2)
			return 1
		}
		urlBase = fallbackBase
	}

	sumsPath := filepath.Join(tmpDir, "SHA256SUMS")
	if err := selfupdate.DownloadFile(ctx, urlBase+"/SHA256SUMS", sumsPath, selfupdate.MaxDownloadBytes); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: download SHA256SUMS: %v\n", err)
		return 1
	}

	// Step 3b: verify minisign signature on SHA256SUMS (when key is configured).
	if selfupdate.SigningPubKey != "" {
		sigPath := filepath.Join(tmpDir, "SHA256SUMS.minisig")
		if err := selfupdate.DownloadFile(ctx, urlBase+"/SHA256SUMS.minisig", sigPath, selfupdate.MaxDownloadBytes); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: download SHA256SUMS.minisig: %v\n", err)
			return 1
		}
		if err := selfupdate.VerifyManifest(sumsPath, sigPath); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: signature verification failed: %v\n", err)
			return 1
		}
		fmt.Println("🔏  signature verified")
	}

	// Step 4: verify SHA256 — mirrors install.sh exactly.
	if err := selfupdate.VerifyTarball(tarballPath, tarball, sumsPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: %v\n", err)
		return 1
	}
	fmt.Println("🔐  checksum verified")

	// Step 5: extract tarball.
	if err := selfupdate.ExtractTarball(tarballPath, tmpDir); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: extract: %v\n", err)
		return 1
	}

	// The service definition and control socket both live under the invoking
	// user's home. Refuse to mutate binaries when their supervised activation
	// target cannot be determined.
	home, err := updateHomeDirFn()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: determine daemon home: %v\n", err)
		return 1
	}

	// Step 6: stop the daemon before swapping its binary (macOS/launchd only).
	plistPath := ""
	if goos == "darwin" {
		plistPath = filepath.Join(home, "Library", "LaunchAgents", plistFilename)
		if err := updateLaunchctlUnloadFn(plistPath); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: stop daemon before update: %v\n", err)
			return 1
		}
	}

	// Step 7: create a backup of existing binaries for rollback on failure.
	backupDir, err := os.MkdirTemp("", "agentjail-update-backup-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: create backup dir: %v\n", err)
		if goos == "darwin" {
			if reloadErr := updateLaunchctlLoadFn(plistPath); reloadErr != nil {
				fmt.Fprintf(os.Stderr, "  warning: could not restore daemon after backup failure: %v\n", reloadErr)
			}
		}
		return 1
	}
	defer os.RemoveAll(backupDir)

	backupNames := append(append([]string{}, selfupdate.UpdateBinaries...), selfupdate.RoleNames...)
	backups, err := backupUpdatePaths(installDir, backupDir, backupNames)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: back up installed files: %v\n", err)
		if goos == "darwin" {
			if reloadErr := updateLaunchctlLoadFn(plistPath); reloadErr != nil {
				fmt.Fprintf(os.Stderr, "  warning: could not restore daemon after backup failure: %v\n", reloadErr)
			}
		}
		return 1
	}

	// Step 8: atomically replace each binary in the install directory.
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: mkdir %s: %v\n", installDir, err)
		if goos == "darwin" {
			if reloadErr := updateLaunchctlLoadFn(plistPath); reloadErr != nil {
				fmt.Fprintf(os.Stderr, "  warning: could not restore daemon after directory failure: %v\n", reloadErr)
			}
		}
		return 1
	}

	installed := 0
	swapped := []string{}
	var swapErr error
	for _, binName := range selfupdate.UpdateBinaries {
		src := filepath.Join(tmpDir, binName)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			// This binary was not shipped in the tarball — skip gracefully.
			continue
		}
		dst := filepath.Join(installDir, binName)
		if err := selfupdate.AtomicReplaceBinary(src, dst); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: replace %s: %v\n", binName, err)
			swapErr = err
			break
		}
		swapped = append(swapped, binName)
		installed++
	}

	if swapErr != nil {
		fmt.Fprintln(os.Stderr, "  rolling back installed binaries…")
		return rollbackFailedUpdate(installDir, backupDir, backups, latest, goos, swapErr, daemonRollback(home, current, goos, plistPath))
	}

	// Step 8b: reconcile the four role symlinks (agentjail-daemon,
	// agentjail-shield, agentjail-netproxy, agentjail-secrets) against the
	// just-swapped agentjail binary. The role paths are part of the installed
	// generation, so failure restores every path captured before the swap.
	if err := updateEnsureRoleSymlinksFn(installDir); err != nil {
		return rollbackFailedUpdate(installDir, backupDir, backups, latest, goos, fmt.Errorf("reconcile role symlinks: %w", err), daemonRollback(home, current, goos, plistPath))
	}
	reassertUpdatedPathShim(installDir)

	// Step 8c: keep the deployed definition ready for daemon-side updates, which
	// use the exit-0 handoff. See ADR 0088-deployed-supervisor-verified.
	repaired, err := ensureDaemonRestartPolicy(home)
	switch {
	case err != nil:
		return rollbackFailedUpdate(installDir, backupDir, backups, latest, goos, fmt.Errorf("refresh daemon supervisor definition: %w", err), daemonRollback(home, current, goos, plistPath))
	case repaired:
		fmt.Println("🔧  supervisor definition repaired — it would not have restarted the daemon after a clean exit")
		// On darwin the plist was unloaded at step 6; step 9's load reads the
		// rewrite. Only systemd needs an explicit reload here.
		if goos != "darwin" {
			if err := reloadDaemonService(home); err != nil {
				return rollbackFailedUpdate(installDir, backupDir, backups, latest, goos, fmt.Errorf("reload daemon supervisor definition: %w", err), daemonRollback(home, current, goos, plistPath))
			}
		}
	}

	// Step 9: restart the daemon. Activation is part of the update transaction:
	// a release is not installed successfully until its daemon is running.
	if goos == "darwin" {
		if err := activateDaemon(home, latest, func() error { return updateLaunchctlLoadFn(plistPath) }); err != nil {
			return rollbackFailedUpdate(installDir, backupDir, backups, latest, goos, err, daemonRollback(home, current, goos, plistPath))
		}
		fmt.Println("🔄  daemon restarted and attested")
	} else if goos == "linux" {
		target := systemdUnitFilename
		if err := activateDaemon(home, latest, func() error { return updateRestartDaemonFn(target) }); err != nil {
			return rollbackFailedUpdate(installDir, backupDir, backups, latest, goos, err, daemonRollback(home, current, goos, plistPath))
		}
		fmt.Println("🔄  daemon restarted and attested")
	}
	if err := updateReconcileGuidanceFn(filepath.Join(installDir, cliBinaryName)); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not refresh agent guidance: %v\n", err)
	}

	fmt.Printf("✅  updated %d binaries  %s → %s\n", installed, current, latest)
	reportUpdateAudit(grantctl.UpdateAuditCompleted, latest, goos)

	if cl := releaseInfo.Changelog; cl != "" {
		fmt.Println()
		fmt.Println("  📋  What's new:")
		for _, line := range formatChangelogBullets(cl, 8) {
			fmt.Println(line)
		}
		fmt.Printf("  → Full changelog: https://github.com/LuD1161/agentjail/releases/tag/%s\n", latest)
	}

	// Step 10: emit update telemetry (best-effort; respects opt-out).
	if tp, err := telemetry.DefaultPaths(); err == nil {
		tCtx, tCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer tCancel()
		_ = telemetry.SendUpdate(tCtx, tp, os.Getenv, current, latest, goos, goarch)
	}

	return 0
}

func backupUpdatePaths(installDir, backupDir string, names []string) ([]updatePathBackup, error) {
	backups := make([]updatePathBackup, 0, len(names))
	for _, name := range names {
		src := filepath.Join(installDir, name)
		info, err := os.Lstat(src)
		if os.IsNotExist(err) {
			backups = append(backups, updatePathBackup{name: name})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", name, err)
		}

		backup := updatePathBackup{name: name, existed: true, mode: info.Mode()}
		if info.Mode()&os.ModeSymlink != 0 {
			backup.linkTarget, err = os.Readlink(src)
			if err != nil {
				return nil, fmt.Errorf("read link %s: %w", name, err)
			}
		} else if info.Mode().IsRegular() {
			if err := selfupdate.CopyFile(src, filepath.Join(backupDir, name)); err != nil {
				return nil, fmt.Errorf("copy %s: %w", name, err)
			}
		} else {
			return nil, fmt.Errorf("%s has unsupported mode %s", name, info.Mode())
		}
		backups = append(backups, backup)
	}
	return backups, nil
}

func restoreUpdatePaths(installDir, backupDir string, backups []updatePathBackup) error {
	var restoreErrs []error
	for _, backup := range backups {
		dst := filepath.Join(installDir, backup.name)
		if !backup.existed {
			if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
				restoreErrs = append(restoreErrs, fmt.Errorf("remove %s: %w", backup.name, err))
			}
			continue
		}
		if backup.mode&os.ModeSymlink != 0 {
			if err := atomicReplaceSymlink(dst, backup.linkTarget); err != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("restore link %s: %w", backup.name, err))
			}
			continue
		}
		if err := selfupdate.AtomicReplaceBinary(filepath.Join(backupDir, backup.name), dst); err != nil {
			restoreErrs = append(restoreErrs, fmt.Errorf("restore %s: %w", backup.name, err))
			continue
		}
		if err := os.Chmod(dst, backup.mode.Perm()); err != nil {
			restoreErrs = append(restoreErrs, fmt.Errorf("restore mode for %s: %w", backup.name, err))
		}
	}
	return errors.Join(restoreErrs...)
}

func atomicReplaceSymlink(dst, target string) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".agentjail-link-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := os.Symlink(target, tmpPath); err != nil {
		return err
	}
	return os.Rename(tmpPath, dst)
}

func activateDaemon(home, wantVersion string, restart func() error) error {
	if err := restart(); err != nil {
		return fmt.Errorf("restart daemon: %w", err)
	}
	if err := updateAttestDaemonFn(home, wantVersion); err != nil {
		return fmt.Errorf("attest restarted daemon: %w", err)
	}
	return nil
}

func daemonRollback(home, oldVersion, goos, plistPath string) func() error {
	if goos == "darwin" {
		return func() error {
			return activateDaemon(home, oldVersion, func() error { return updateLaunchctlLoadFn(plistPath) })
		}
	}
	if goos == "linux" {
		return func() error {
			return activateDaemon(home, oldVersion, func() error { return updateRestartDaemonFn(systemdUnitFilename) })
		}
	}
	return nil
}

func rollbackFailedUpdate(installDir, backupDir string, backups []updatePathBackup, version, goos string, cause error, restartOld func() error) int {
	fmt.Fprintf(os.Stderr, "  warning: could not activate updated release: %v; rolling back…\n", cause)
	rollbackSucceeded := true
	if err := restoreUpdatePaths(installDir, backupDir, backups); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: rollback failed: %v\n", err)
		rollbackSucceeded = false
	}
	if restartOld != nil {
		if err := restartOld(); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not restart previous daemon after rollback: %v\n", err)
			rollbackSucceeded = false
		}
	}
	if rollbackSucceeded {
		reportUpdateAudit(grantctl.UpdateAuditRolledBack, version, goos)
	} else {
		reportUpdateAudit(grantctl.UpdateAuditRollbackFailed, version, goos)
	}
	return 1
}

func emitUpdateAudit(status grantctl.UpdateAuditStatus, version, goos string) error {
	token, err := ctlauth.Load()
	if err != nil {
		return err
	}
	return grantctl.UpdateAudit(grantctl.ControlSocketPath(), token, status, version, goos, updateAuditTimeout)
}

func reportUpdateAudit(status grantctl.UpdateAuditStatus, version, goos string) {
	if err := updateAuditFn(status, version, goos); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not write update audit event: %v\n", err)
	}
}

func attestDaemonVersion(home, wantVersion string) error {
	deadline := time.Now().Add(updateActivationTimeout)
	var lastErr error
	for {
		liveness, runningVersion, err := probeDaemonDetails(updateDaemonSocketPathFn(home), updateActivationProbeTimeout)
		if err == nil && liveness == daemonHealthy && runningVersion == wantVersion {
			return nil
		}
		if err != nil {
			lastErr = err
		} else if liveness != daemonHealthy {
			lastErr = fmt.Errorf("daemon liveness state %v", liveness)
		} else {
			lastErr = fmt.Errorf("daemon version %q, want %q", runningVersion, wantVersion)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("versioned daemon ping did not attest %s within %s: %w", wantVersion, updateActivationTimeout, lastErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func reassertUpdatedPathShim(installDir string) {
	home, err := updateHomeDirFn()
	if err != nil || filepath.Clean(installDir) != filepath.Join(home, ".agentjail", "bin") {
		return
	}
	result, err := pathshim.Reassert(home, filepath.Join(installDir, "agentjail-shield"), os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not reassert PATH shim: %v\n", err)
		return
	}
	if result.Restored {
		fmt.Println("🔧  PATH shim restored from your existing shell-profile opt-in")
	}
}

// formatChangelogBullets extracts markdown bullet lines from a changelog body,
// strips markdown formatting (bold, backticks), and returns them as
// unicode-formatted lines with the given indent. Returns at most 8 lines.
func formatChangelogBullets(body string, indent int) []string {
	prefix := strings.Repeat(" ", indent)
	var out []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- ") && !strings.HasPrefix(trimmed, "* ") {
			continue
		}
		// Strip leading bullet marker
		trimmed = strings.TrimLeft(trimmed[2:], " ")
		// Strip **bold** markers
		for strings.Contains(trimmed, "**") {
			start := strings.Index(trimmed, "**")
			end := strings.Index(trimmed[start+2:], "**")
			if end < 0 {
				break
			}
			trimmed = trimmed[:start] + trimmed[start+2:start+2+end] + trimmed[start+2+end+2:]
		}
		// Strip `backtick` markers
		trimmed = strings.ReplaceAll(trimmed, "`", "")
		out = append(out, prefix+"• "+trimmed)
		if len(out) >= 8 {
			break
		}
	}
	return out
}
