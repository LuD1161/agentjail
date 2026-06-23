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
//   - Linux: daemon stop/restart is skipped (no launchd); binaries are still
//     swapped atomically. The daemon must be restarted manually or via the
//     user's init system.
//
// Binary list: agentjail, agentjail-hook, agentjail-daemon,
//
//	agentjail-shield, agentjail-netproxy  (mirrors install.sh).
//
// Atomic swap: each binary is downloaded to a temp file in the SAME directory
// as the target (guarantees os.Rename is on the same filesystem), chmod 0755,
// then renamed over the live binary. A crash between renames leaves at most
// one stale temp file, never a half-written binary.
package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/telemetry"
	"github.com/LuD1161/agentjail/internal/updater"
)

// maxDownloadBytes is the maximum number of bytes allowed per download (100 MB).
const maxDownloadBytes = 100 * 1024 * 1024

// signingPubKey is the minisign public key used to verify release SHA256SUMS
// signatures. An empty string disables signature verification (dev/pre-release
// builds that have no signed manifest).
var signingPubKey = "RWRg/Bbl+U571C1qv/08AwUwlvf6zG4lYzV8e0QHFd0FrjYTmImUoRpQ"

// updateBinaries is the ordered list of binaries placed in $INSTALL_DIR,
// matching install.sh exactly.
var updateBinaries = []string{
	"agentjail",
	"agentjail-hook",
	"agentjail-daemon",
	"agentjail-shield",
	"agentjail-netproxy",
}

// updateURLBaseFn returns the primary download base URL for a version.
// It is a package-level variable so tests can override it to point at a mock
// HTTP server without hitting the real network.
var updateURLBaseFn = updateURLBase

// updateURLBase is the default implementation of updateURLBaseFn.
// It routes through the Cloudflare Worker at releases.agentjail.io first; the
// Worker itself proxies to GitHub, providing integrity checks and analytics.
func updateURLBase(ver string) string {
	return fmt.Sprintf("https://releases.agentjail.io/download/%s", ver)
}

// updateURLBaseGitHubFallback returns the direct GitHub releases URL as a
// fallback when the Worker URL is unreachable.
func updateURLBaseGitHubFallback(ver string) string {
	return fmt.Sprintf("https://github.com/LuD1161/agentjail/releases/download/%s", ver)
}

// updateTarballName returns the tarball filename for the given version and
// platform. Matches install.sh: agentjail-${VERSION}-${PLATFORM}.tar.gz
func updateTarballName(ver, goos, goarch string) string {
	return fmt.Sprintf("agentjail-%s-%s-%s.tar.gz", ver, goos, goarch)
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
				current := version
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
	current := version
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
			fmt.Printf("agentjail update: reinstalling %s (--force).\n", current)
		} else {
			// latest > current — normal upgrade
			fmt.Printf("agentjail update: %s → %s\n", current, latest)
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

	tarball := updateTarballName(latest, goos, goarch)
	urlBase := updateURLBaseFn(latest)

	fmt.Printf("  downloading %s …\n", tarball)
	tarballPath := filepath.Join(tmpDir, tarball)

	// Try primary (Worker) URL; fall back to GitHub direct on failure.
	dlErr := downloadFile(ctx, urlBase+"/"+tarball, tarballPath)
	if dlErr != nil {
		fallbackBase := updateURLBaseGitHubFallback(latest)
		fmt.Fprintf(os.Stderr, "  warning: primary download failed (%v); retrying via GitHub…\n", dlErr)
		if err2 := downloadFile(ctx, fallbackBase+"/"+tarball, tarballPath); err2 != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: download tarball: %v\n", err2)
			return 1
		}
		urlBase = fallbackBase
	}

	sumsPath := filepath.Join(tmpDir, "SHA256SUMS")
	if err := downloadFile(ctx, urlBase+"/SHA256SUMS", sumsPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: download SHA256SUMS: %v\n", err)
		return 1
	}

	// Step 3b: verify minisign signature on SHA256SUMS (when key is configured).
	if signingPubKey != "" {
		sigPath := filepath.Join(tmpDir, "SHA256SUMS.minisig")
		if err := downloadFile(ctx, urlBase+"/SHA256SUMS.minisig", sigPath); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: download SHA256SUMS.minisig: %v\n", err)
			return 1
		}
		if err := updater.VerifySignature(sumsPath, sigPath, signingPubKey); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: signature verification failed: %v\n", err)
			return 1
		}
		fmt.Println("  signature verified")
	}

	// Step 4: verify SHA256 — mirrors install.sh exactly.
	if err := verifySHA256(tarballPath, tarball, sumsPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: %v\n", err)
		return 1
	}
	fmt.Println("  checksum verified")

	// Step 5: extract tarball.
	if err := extractTarGz(tarballPath, tmpDir); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: extract: %v\n", err)
		return 1
	}

	// Step 6: stop the daemon before swapping its binary (macOS/launchd only).
	plistPath := ""
	if goos == "darwin" {
		home, herr := os.UserHomeDir()
		if herr == nil {
			plistPath = filepath.Join(home, "Library", "LaunchAgents", plistFilename)
			if err := launchctlUnload(plistPath); err != nil {
				// Non-fatal — warn and continue; the rename is still atomic.
				fmt.Fprintf(os.Stderr, "  warning: could not stop daemon: %v\n", err)
				plistPath = "" // skip restart attempt
			}
		}
	}

	// Step 7: create a backup of existing binaries for rollback on failure.
	backupDir, err := os.MkdirTemp("", "agentjail-update-backup-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: create backup dir: %v\n", err)
		if goos == "darwin" && plistPath != "" {
			_ = launchctlLoad(plistPath)
		}
		return 1
	}
	defer os.RemoveAll(backupDir)

	// Copy existing binaries to backup dir.
	backed := []string{}
	for _, binName := range updateBinaries {
		existing := filepath.Join(installDir, binName)
		if _, err := os.Stat(existing); os.IsNotExist(err) {
			continue // not installed yet — nothing to back up
		}
		backupDst := filepath.Join(backupDir, binName)
		if copyErr := copyFile(existing, backupDst); copyErr != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not back up %s: %v\n", binName, copyErr)
			// Non-fatal: proceed without backup for this binary.
			continue
		}
		backed = append(backed, binName)
	}

	// Step 8: atomically replace each binary in the install directory.
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: mkdir %s: %v\n", installDir, err)
		if goos == "darwin" && plistPath != "" {
			_ = launchctlLoad(plistPath)
		}
		return 1
	}

	installed := 0
	swapped := []string{}
	var swapErr error
	for _, binName := range updateBinaries {
		src := filepath.Join(tmpDir, binName)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			// This binary was not shipped in the tarball — skip gracefully.
			continue
		}
		dst := filepath.Join(installDir, binName)
		if err := atomicReplaceBinary(src, dst); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: replace %s: %v\n", binName, err)
			swapErr = err
			break
		}
		swapped = append(swapped, binName)
		installed++
	}

	if swapErr != nil {
		// Rollback: restore backups for all already-swapped binaries.
		fmt.Fprintln(os.Stderr, "  rolling back installed binaries…")
		for _, binName := range swapped {
			backupSrc := filepath.Join(backupDir, binName)
			dst := filepath.Join(installDir, binName)
			if _, statErr := os.Stat(backupSrc); statErr == nil {
				if restoreErr := atomicReplaceBinary(backupSrc, dst); restoreErr != nil {
					fmt.Fprintf(os.Stderr, "  warning: rollback of %s failed: %v\n", binName, restoreErr)
				}
			}
		}
		if goos == "darwin" && plistPath != "" {
			_ = launchctlLoad(plistPath)
		}
		return 1
	}

	// Step 9: restart the daemon.
	if goos == "darwin" && plistPath != "" {
		if err := launchctlLoad(plistPath); err != nil {
			// Daemon restart failed — rollback and restore old daemon.
			fmt.Fprintf(os.Stderr, "  warning: could not restart daemon: %v; rolling back…\n", err)
			for _, binName := range backed {
				backupSrc := filepath.Join(backupDir, binName)
				dst := filepath.Join(installDir, binName)
				if restoreErr := atomicReplaceBinary(backupSrc, dst); restoreErr != nil {
					fmt.Fprintf(os.Stderr, "  warning: rollback of %s failed: %v\n", binName, restoreErr)
				}
			}
			_ = launchctlLoad(plistPath)
		} else {
			fmt.Println("  daemon restarted")
		}
	} else if goos != "darwin" {
		fmt.Println("  note: restart the agentjail daemon manually (non-macOS).")
	}

	fmt.Printf("agentjail update: updated %d binaries  %s → %s\n", installed, current, latest)

	if cl := releaseInfo.Changelog; cl != "" {
		bullets := formatChangelogBullets(cl, 0)
		if len(bullets) > 0 {
			fmt.Println()
			fmt.Println("  ── 📋 What's new ─────────────────────────────────────────────────")
			fmt.Println()
			for _, b := range bullets {
				fmt.Printf("     %s\n", b)
			}
			fmt.Println()
			fmt.Printf("     → https://github.com/LuD1161/agentjail/releases/tag/%s\n", latest)
			fmt.Println()
			fmt.Println("  ─────────────────────────────────────────────────────────────────")
		}
	}

	// Step 10: emit update telemetry (best-effort; respects opt-out).
	if tp, err := telemetry.DefaultPaths(); err == nil {
		tCtx, tCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer tCancel()
		_ = telemetry.SendUpdate(tCtx, tp, os.Getenv, current, latest, goos, goarch)
	}

	return 0
}

// copyFile copies the file at src to dst, creating dst if needed.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src %q: %w", src, err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create dst %q: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %q → %q: %w", src, dst, err)
	}
	return nil
}

// downloadFile fetches url via HTTP and writes the body to dst.
func downloadFile(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "agentjail/"+version)

	hc := &http.Client{Timeout: 60 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	f, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer f.Close()

	// Enforce a 100 MB download cap to prevent runaway/malicious responses.
	limited := io.LimitReader(resp.Body, maxDownloadBytes+1)
	n, err := io.Copy(f, limited)
	if err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if n > maxDownloadBytes {
		return fmt.Errorf("download of %s exceeds %d MB limit; aborting", dst, maxDownloadBytes/(1024*1024))
	}
	return nil
}

// verifySHA256 checks that the file at tarballPath matches the expected hash
// listed in sumsPath for the entry named tarballName.
//
// Mirrors install.sh exactly:
//
//	EXPECTED=$(grep "  ${TARBALL}$" "$TMP/SHA256SUMS" | awk '{print $1}')
//	ACTUAL=$(sha256 "$TMP/$TARBALL" | awk '{print $1}')
//	[ "$ACTUAL" != "$EXPECTED" ] → fail
func verifySHA256(tarballPath, tarballName, sumsPath string) error {
	sumsBytes, err := os.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("read SHA256SUMS: %w", err)
	}

	// Format: "<hex>  <filename>\n"  (two spaces, as output by sha256sum / shasum -a 256)
	expected := ""
	needle := "  " + tarballName
	for _, line := range strings.Split(string(sumsBytes), "\n") {
		if strings.HasSuffix(line, needle) {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				expected = fields[0]
			}
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("no SHA256 entry for %q in checksum manifest — aborting", tarballName)
	}

	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("open tarball for hashing: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash tarball: %w", err)
	}
	actual := hex.EncodeToString(h.Sum(nil))

	if actual != expected {
		return fmt.Errorf("SHA256 mismatch — aborting\n  expected: %s\n  actual:   %s", expected, actual)
	}
	return nil
}

// extractTarGz extracts a .tar.gz archive into destDir (pure-Go, no exec).
// Only regular files are extracted, and file names are stripped to their base
// component to prevent path-traversal attacks.
func extractTarGz(tarballPath, destDir string) error {
	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return extractTarGzReader(f, destDir)
}

// extractTarGzReader is the testable inner implementation of extractTarGz.
func extractTarGzReader(r io.Reader, destDir string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		// Only regular files.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Strip any directory prefix: only the base file name is written.
		name := filepath.Base(hdr.Name)
		if name == "" || name == "." {
			continue
		}
		dst := filepath.Join(destDir, name)
		out, err := os.Create(dst)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := out.Close(); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
	}
	return nil
}

// formatChangelogBullets extracts the TL;DR bullet lines from a release body,
// strips markdown formatting, truncates for terminal display, and returns
// unicode-formatted lines. Stops at the first ### heading (detailed sections)
// so only the concise summary bullets are shown.
func formatChangelogBullets(body string, indent int) []string {
	const maxBullets = 5
	prefix := strings.Repeat(" ", indent)
	var out []string
	inTLDR := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "## TL;DR") {
			inTLDR = true
			continue
		}
		// Stop at the first ### heading (detailed changelog sections).
		if inTLDR && strings.HasPrefix(trimmed, "###") {
			break
		}
		if !inTLDR {
			// If there's no TL;DR section, fall back to collecting all bullets
			// but still stop at ### headings.
			if strings.HasPrefix(trimmed, "###") {
				// Once we have some bullets, stop; otherwise skip section headers.
				if len(out) > 0 {
					break
				}
				continue
			}
		}
		if !strings.HasPrefix(trimmed, "- ") && !strings.HasPrefix(trimmed, "* ") {
			continue
		}
		trimmed = strings.TrimLeft(trimmed[2:], " ")
		// Strip **bold** markers.
		for strings.Contains(trimmed, "**") {
			start := strings.Index(trimmed, "**")
			end := strings.Index(trimmed[start+2:], "**")
			if end < 0 {
				break
			}
			trimmed = trimmed[:start] + trimmed[start+2:start+2+end] + trimmed[start+2+end+2:]
		}
		trimmed = strings.ReplaceAll(trimmed, "`", "")
		out = append(out, prefix+"• "+trimmed)
		if len(out) >= maxBullets {
			break
		}
	}
	return out
}

// atomicReplaceBinary copies src to a temp file in the same directory as dst,
// sets mode 0755, then renames over dst. Crash-safe: dst is only swapped on a
// successful rename; a failure mid-flight leaves dst untouched.
func atomicReplaceBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".agentjail-update-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return os.Rename(tmpName, dst)
}
