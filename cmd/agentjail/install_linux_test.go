package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise the Linux (systemd --user) install/uninstall logic.
// They run on any host GOOS by overriding currentGOOS, and they NEVER shell
// out to a real systemctl: systemdUserAvailableFn / systemctlUserEnableStartFn
// / systemctlUserDisableStopFn are package-level variables stubbed here for
// the duration of each test, so these tests are safe to run on a machine with
// a real ~/.agentjail install and a real systemd --user session.

// withCurrentGOOS overrides currentGOOS for the duration of the test.
func withCurrentGOOS(t *testing.T, goos string) {
	t.Helper()
	orig := currentGOOS
	currentGOOS = goos
	t.Cleanup(func() { currentGOOS = orig })
}

// stubSystemdAvailable overrides systemdUserAvailableFn for the duration of
// the test, restoring the original afterwards.
func stubSystemdAvailable(t *testing.T, available bool) {
	t.Helper()
	orig := systemdUserAvailableFn
	systemdUserAvailableFn = func() bool { return available }
	t.Cleanup(func() { systemdUserAvailableFn = orig })
}

// stubSystemctlEnableStart overrides systemctlUserEnableStartFn, recording
// every unit it was called with, and restores the original afterwards.
func stubSystemctlEnableStart(t *testing.T, err error) *[]string {
	t.Helper()
	calls := &[]string{}
	orig := systemctlUserEnableStartFn
	systemctlUserEnableStartFn = func(unit string) error {
		*calls = append(*calls, unit)
		return err
	}
	t.Cleanup(func() { systemctlUserEnableStartFn = orig })
	return calls
}

// stubSystemctlDisableStop overrides systemctlUserDisableStopFn, recording
// every unit it was called with, and restores the original afterwards.
func stubSystemctlDisableStop(t *testing.T, err error) *[]string {
	t.Helper()
	calls := &[]string{}
	orig := systemctlUserDisableStopFn
	systemctlUserDisableStopFn = func(unit string) error {
		*calls = append(*calls, unit)
		return err
	}
	t.Cleanup(func() { systemctlUserDisableStopFn = orig })
	return calls
}

// ---- unit-file generation --------------------------------------------------

// TestInstallSystemdUnitContent verifies the generated unit has the required
// sections, a working ExecStart pointing at the daemon binary with --rules
// and --log flags, and a restart policy so the daemon self-recovers.
func TestInstallSystemdUnitContent(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, systemdUnitFilename)

	const daemonBin = "/home/test/.agentjail/bin/agentjail-daemon"
	const rulesDir = "/home/test/.agentjail/rules"
	const logPath = "/home/test/.agentjail/daemon.log"
	const crashLogPath = "/home/test/.agentjail/crash.log"

	if err := installSystemdUnit(daemonBin, rulesDir, logPath, crashLogPath, dst); err != nil {
		t.Fatalf("installSystemdUnit: %v", err)
	}

	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(b)

	for _, section := range []string{"[Unit]", "[Service]", "[Install]"} {
		if !strings.Contains(content, section) {
			t.Errorf("unit missing section %q\ngot:\n%s", section, content)
		}
	}
	// Must be "always", not "on-failure" — the auto-updater exits 0 and relies
	// on the supervisor to restart it (ADR 0070).
	if !strings.Contains(content, "Restart=always") {
		t.Errorf("unit missing Restart=always (self-recovery incl. clean exit-0)\ngot:\n%s", content)
	}
	if strings.Contains(content, "Restart=on-failure") {
		t.Errorf("unit must not use Restart=on-failure — it strands the daemon after exit(0)\ngot:\n%s", content)
	}
	if !strings.Contains(content, "ExecStart="+daemonBin) {
		t.Errorf("unit ExecStart does not reference daemon binary %q\ngot:\n%s", daemonBin, content)
	}
	if !strings.Contains(content, "--rules="+rulesDir) {
		t.Errorf("unit does not contain --rules=%q\ngot:\n%s", rulesDir, content)
	}
	if !strings.Contains(content, "--log="+logPath) {
		t.Errorf("unit does not contain --log=%q\ngot:\n%s", logPath, content)
	}
	if !strings.Contains(content, crashLogPath) {
		t.Errorf("unit does not reference crash log path %q\ngot:\n%s", crashLogPath, content)
	}
	if strings.Contains(content, "__DAEMON_PATH__") || strings.Contains(content, "__RULES_DIR__") ||
		strings.Contains(content, "__LOG_PATH__") || strings.Contains(content, "__CRASH_LOG_PATH__") {
		t.Errorf("unit still contains unpatched placeholder(s)\ngot:\n%s", content)
	}
	if !strings.Contains(content, "WantedBy=default.target") {
		t.Errorf("unit missing WantedBy=default.target (needed for headless/SSH sessions)\ngot:\n%s", content)
	}
}

// TestInstallSystemdUnitIdempotent verifies calling installSystemdUnit twice
// is safe (the second call overwrites the first without error).
func TestInstallSystemdUnitIdempotent(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, systemdUnitFilename)

	if err := installSystemdUnit("/bin/agentjail-daemon", "/rules", "/log/daemon.log", "/log/crash.log", dst); err != nil {
		t.Fatalf("first installSystemdUnit: %v", err)
	}
	if err := installSystemdUnit("/bin/agentjail-daemon", "/rules", "/log/daemon.log", "/log/crash.log", dst); err != nil {
		t.Fatalf("second installSystemdUnit: %v", err)
	}
}

// TestSystemdUserUnitDir verifies the unit directory follows the systemd
// --user search path convention: ~/.config/systemd/user.
func TestSystemdUserUnitDir(t *testing.T) {
	got := systemdUserUnitDir("/home/test")
	want := filepath.Join("/home/test", ".config", "systemd", "user")
	if got != want {
		t.Errorf("systemdUserUnitDir = %q, want %q", got, want)
	}
}

// ---- installAndStartDaemonService (Linux branch) ---------------------------

// TestInstallAndStartDaemonServiceLinuxAvailable verifies that when a systemd
// --user session is reachable, the unit is written and
// systemctlUserEnableStartFn is called with the expected unit name — using a
// stub, so no real systemctl is ever invoked.
func TestInstallAndStartDaemonServiceLinuxAvailable(t *testing.T) {
	withCurrentGOOS(t, "linux")
	stubSystemdAvailable(t, true)
	calls := stubSystemctlEnableStart(t, nil)

	home := t.TempDir()
	var buf bytes.Buffer
	daemonDst := filepath.Join(home, ".agentjail", "bin", "agentjail-daemon")
	rulesD := filepath.Join(home, ".agentjail", "rules")
	logPath := filepath.Join(home, ".agentjail", "daemon.log")
	crashLogPath := filepath.Join(home, ".agentjail", "crash.log")

	if err := installAndStartDaemonService(home, daemonDst, rulesD, logPath, crashLogPath, &buf); err != nil {
		t.Fatalf("installAndStartDaemonService: %v", err)
	}

	unitDst := filepath.Join(systemdUserUnitDir(home), systemdUnitFilename)
	if _, err := os.Stat(unitDst); err != nil {
		t.Errorf("expected unit file at %s: %v", unitDst, err)
	}

	if len(*calls) != 1 || (*calls)[0] != systemdUnitFilename {
		t.Errorf("systemctlUserEnableStartFn calls = %v, want [%s]", *calls, systemdUnitFilename)
	}

	out := buf.String()
	if !strings.Contains(out, "systemd --user unit installed") {
		t.Errorf("output missing unit-installed step\ngot:\n%s", out)
	}
	if !strings.Contains(out, "daemon started (systemd --user)") {
		t.Errorf("output missing daemon-started step\ngot:\n%s", out)
	}
}

// TestInstallAndStartDaemonServiceLinuxUnavailable verifies the graceful
// fallback when no systemd --user session is reachable (e.g. a bare
// container): the unit is still written, systemctlUserEnableStartFn is NOT
// called, and manual-start instructions are printed instead of failing.
func TestInstallAndStartDaemonServiceLinuxUnavailable(t *testing.T) {
	withCurrentGOOS(t, "linux")
	stubSystemdAvailable(t, false)
	calls := stubSystemctlEnableStart(t, nil)

	home := t.TempDir()
	var buf bytes.Buffer
	daemonDst := filepath.Join(home, ".agentjail", "bin", "agentjail-daemon")
	rulesD := filepath.Join(home, ".agentjail", "rules")
	logPath := filepath.Join(home, ".agentjail", "daemon.log")
	crashLogPath := filepath.Join(home, ".agentjail", "crash.log")

	if err := installAndStartDaemonService(home, daemonDst, rulesD, logPath, crashLogPath, &buf); err != nil {
		t.Fatalf("installAndStartDaemonService: %v", err)
	}

	unitDst := filepath.Join(systemdUserUnitDir(home), systemdUnitFilename)
	if _, err := os.Stat(unitDst); err != nil {
		t.Errorf("expected unit file to still be written at %s: %v", unitDst, err)
	}

	if len(*calls) != 0 {
		t.Errorf("systemctlUserEnableStartFn must not be called when no session is reachable, got calls=%v", *calls)
	}

	out := buf.String()
	if !strings.Contains(out, "no systemd --user session detected") {
		t.Errorf("output missing fallback notice\ngot:\n%s", out)
	}
	if !strings.Contains(out, "systemctl --user enable --now "+systemdUnitFilename) {
		t.Errorf("output missing manual-start instructions\ngot:\n%s", out)
	}
}

// TestInstallAndStartDaemonServiceLinuxEnableStartFailureNonFatal verifies
// that a failure from systemctlUserEnableStartFn does not fail the install
// (mirrors the launchd behavior on macOS, where a launchctl load failure is
// logged but non-fatal).
func TestInstallAndStartDaemonServiceLinuxEnableStartFailureNonFatal(t *testing.T) {
	withCurrentGOOS(t, "linux")
	stubSystemdAvailable(t, true)
	stubSystemctlEnableStart(t, errors.New("simulated systemctl failure"))

	home := t.TempDir()
	var buf bytes.Buffer
	daemonDst := filepath.Join(home, ".agentjail", "bin", "agentjail-daemon")
	rulesD := filepath.Join(home, ".agentjail", "rules")
	logPath := filepath.Join(home, ".agentjail", "daemon.log")
	crashLogPath := filepath.Join(home, ".agentjail", "crash.log")

	if err := installAndStartDaemonService(home, daemonDst, rulesD, logPath, crashLogPath, &buf); err != nil {
		t.Fatalf("installAndStartDaemonService should not fail when enable/start fails: %v", err)
	}
}

// ---- uninstallSystemdDaemon --------------------------------------------------

// TestUninstallSystemdDaemonNoUnitFileIsNoop verifies that with no unit file
// present (the common case in a test's isolated tmp home), uninstall never
// calls systemctlUserDisableStopFn — it short-circuits on the fileExists
// check — so it is always safe to call in tests without stubbing.
func TestUninstallSystemdDaemonNoUnitFileIsNoop(t *testing.T) {
	withCurrentGOOS(t, "linux")
	calls := stubSystemctlDisableStop(t, nil)
	// Deliberately do NOT stub systemdUserAvailableFn — if the short-circuit
	// on fileExists ever regresses, this test would attempt a real systemctl
	// call and we want that to be visible rather than silently masked.

	home := t.TempDir()
	if err := uninstallSystemdDaemon(home); err != nil {
		t.Fatalf("uninstallSystemdDaemon: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("systemctlUserDisableStopFn must not be called with no unit file, got calls=%v", *calls)
	}
}

// TestUninstallSystemdDaemonRemovesUnitFile verifies that when a unit file
// exists and a systemd session is available, uninstall calls
// systemctlUserDisableStopFn and removes the unit file.
func TestUninstallSystemdDaemonRemovesUnitFile(t *testing.T) {
	withCurrentGOOS(t, "linux")
	stubSystemdAvailable(t, true)
	calls := stubSystemctlDisableStop(t, nil)

	home := t.TempDir()
	unitDst := filepath.Join(systemdUserUnitDir(home), systemdUnitFilename)
	if err := installSystemdUnit("/bin/agentjail-daemon", "/rules", "/log/daemon.log", "/log/crash.log", unitDst); err != nil {
		t.Fatalf("installSystemdUnit: %v", err)
	}

	if err := uninstallSystemdDaemon(home); err != nil {
		t.Fatalf("uninstallSystemdDaemon: %v", err)
	}

	if len(*calls) != 1 || (*calls)[0] != systemdUnitFilename {
		t.Errorf("systemctlUserDisableStopFn calls = %v, want [%s]", *calls, systemdUnitFilename)
	}
	if _, err := os.Stat(unitDst); !os.IsNotExist(err) {
		t.Errorf("expected unit file to be removed, stat err = %v", err)
	}
}

// TestUninstallSystemdDaemonSkipsDisableStopWhenSessionUnavailable verifies
// that when a unit file exists but no systemd session is reachable, the
// disable/stop call is skipped (nothing to stop) but the unit file is still
// removed.
func TestUninstallSystemdDaemonSkipsDisableStopWhenSessionUnavailable(t *testing.T) {
	withCurrentGOOS(t, "linux")
	stubSystemdAvailable(t, false)
	calls := stubSystemctlDisableStop(t, nil)

	home := t.TempDir()
	unitDst := filepath.Join(systemdUserUnitDir(home), systemdUnitFilename)
	if err := installSystemdUnit("/bin/agentjail-daemon", "/rules", "/log/daemon.log", "/log/crash.log", unitDst); err != nil {
		t.Fatalf("installSystemdUnit: %v", err)
	}

	if err := uninstallSystemdDaemon(home); err != nil {
		t.Fatalf("uninstallSystemdDaemon: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("systemctlUserDisableStopFn must not be called when no session is reachable, got calls=%v", *calls)
	}
	if _, err := os.Stat(unitDst); !os.IsNotExist(err) {
		t.Errorf("expected unit file to be removed even without a session, stat err = %v", err)
	}
}

// ---- install gate removal ----------------------------------------------------

// TestAllowUnsupportedFlagStillParses verifies the deprecated
// --allow-unsupported flag still parses without error (back-compat for
// existing scripts/docs), even though it is now a no-op.
func TestAllowUnsupportedFlagStillParses(t *testing.T) {
	_, _, _, allowUnsupported := parseInstallFlags([]string{"--allow-unsupported"})
	if !allowUnsupported {
		t.Error("expected allowUnsupported=true for --allow-unsupported flag")
	}
}
