package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withGOOS overrides the OS axis for the duration of a test. Named distinctly
// from install_linux_test.go's withCurrentGOOS so this file stays free of a
// _linux suffix and runs on macOS too.
func withGOOS(t *testing.T, goos string) {
	t.Helper()
	orig := currentGOOS
	currentGOOS = goos
	t.Cleanup(func() { currentGOOS = orig })
}

// staleSystemdUnit is the unit installs before 6a41303 have ON DISK, verbatim.
// Restart=on-failure does not restart a clean exit(0), so the auto-updater's
// handoff (ADR 0070) strands the daemon permanently.
const staleSystemdUnit = `[Unit]
Description=agentjail daemon — policy enforcement for coding agents
After=default.target

[Service]
ExecStart=/home/test/.agentjail/bin/agentjail-daemon --rules=/home/test/.agentjail/rules --log=/home/test/.agentjail/daemon.log
Restart=on-failure
RestartSec=2
StandardOutput=append:/home/test/.agentjail/crash.log
StandardError=append:/home/test/.agentjail/crash.log

[Install]
WantedBy=default.target
`

// stalePlist is the launchd equivalent: KeepAlive as a dict with
// SuccessfulExit=false suppresses exactly the exit(0) restart the updater needs.
const stalePlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.agentjail.daemon</string>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
</dict>
</plist>
`

// deploy writes content to the spec path for home, creating the directory the
// supervisor reads from.
func deploy(t *testing.T, home, content string) string {
	t.Helper()
	spec := daemonServiceSpec(home)
	if err := os.MkdirAll(filepath.Dir(spec.path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(spec.path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", spec.path, err)
	}
	return spec.path
}

// ── the invariant, over deployed bytes (ADR 0088-deployed-supervisor-verified) ──

func TestRestartsOnCleanExit(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		content string
		want    bool
	}{
		{"systemd always", "linux", "[Service]\nRestart=always\n", true},
		{"systemd on-failure strands exit-0", "linux", staleSystemdUnit, false},
		{"systemd on-success misses crashes", "linux", "[Service]\nRestart=on-success\n", false},
		{"systemd no directive", "linux", "[Service]\nExecStart=/bin/x\n", false},
		{"systemd last directive wins", "linux", "[Service]\nRestart=always\nRestart=on-failure\n", false},
		{"systemd commented-out is not a directive", "linux", "[Service]\n#Restart=always\n", false},
		{"launchd KeepAlive true", "darwin", plistTemplate, true},
		{"launchd KeepAlive dict is conditional", "darwin", stalePlist, false},
		{"launchd no KeepAlive", "darwin", "<dict><key>Label</key><string>x</string></dict>", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := restartsOnCleanExit(tc.goos, tc.content); got != tc.want {
				t.Errorf("restartsOnCleanExit = %v, want %v", got, tc.want)
			}
		})
	}
}

// The template agentjail ships must satisfy the invariant it checks for, on
// both platforms — otherwise the repair writes a file that fails its recheck.
func TestShippedTemplatesSatisfyTheInvariant(t *testing.T) {
	if !restartsOnCleanExit("linux", systemdUnitTemplate) {
		t.Error("systemdUnitTemplate does not restart after a clean exit")
	}
	if !restartsOnCleanExit("darwin", plistTemplate) {
		t.Error("plistTemplate does not restart after a clean exit")
	}
}

// ── the doctor check, over the DEPLOYED file ────────────────────────────

// The bug AGE-233 shipped: the template was fixed, the file on disk was not.
// Asserting the template would have passed here — this reads the disk.
func TestStaleDeployedUnitIsDetected(t *testing.T) {
	withGOOS(t, "linux")
	home := t.TempDir()
	deploy(t, home, staleSystemdUnit)

	got := serviceRestartPolicyCheck(home)
	if got.status != statusFail {
		t.Errorf("status = %q, want %q (deployed unit says Restart=on-failure)", got.status, statusFail)
	}
	if got.repair != repairServiceDef {
		t.Errorf("repair = %q, want %q", got.repair, repairServiceDef)
	}
}

func TestStaleDeployedPlistIsDetected(t *testing.T) {
	withGOOS(t, "darwin")
	home := t.TempDir()
	deploy(t, home, stalePlist)

	got := serviceRestartPolicyCheck(home)
	if got.status != statusFail {
		t.Errorf("status = %q, want %q (KeepAlive dict suppresses the exit-0 restart)", got.status, statusFail)
	}
	if got.repair != repairServiceDef {
		t.Errorf("repair = %q, want %q", got.repair, repairServiceDef)
	}
}

func TestCurrentDeployedDefinitionIsNotFlagged(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			withGOOS(t, goos)
			home := t.TempDir()
			deploy(t, home, daemonServiceSpec(home).content)

			if got := serviceRestartPolicyCheck(home); got.status != statusOK {
				t.Errorf("status = %q, want %q: %s", got.status, statusOK, got.detail)
			}
		})
	}
}

// A definition doctor never wrote is install's job, not a repair
// (ADR 0086-doctor-repairs-diagnosed).
func TestMissingDefinitionFailsWithoutRepair(t *testing.T) {
	withGOOS(t, "linux")
	got := serviceRestartPolicyCheck(t.TempDir())
	if got.status != statusFail {
		t.Errorf("status = %q, want %q", got.status, statusFail)
	}
	if got.repair != "" {
		t.Errorf("repair = %q, want none — a missing unit is `agentjail install`", got.repair)
	}
}

// ── the repair ──────────────────────────────────────────────────────────

func TestRepairProducesDefinitionMatchingTemplate(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			withGOOS(t, goos)
			home := t.TempDir()
			stale := map[string]string{"linux": staleSystemdUnit, "darwin": stalePlist}[goos]
			path := deploy(t, home, stale)

			repaired, err := ensureDaemonRestartPolicy(home)
			if err != nil {
				t.Fatalf("ensureDaemonRestartPolicy: %v", err)
			}
			if !repaired {
				t.Fatal("repaired = false, want true — the deployed definition was stale")
			}

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if want := daemonServiceSpec(home).content; string(got) != want {
				t.Errorf("repaired file does not match the template\ngot:\n%s\nwant:\n%s", got, want)
			}
			if post := serviceRestartPolicyCheck(home); post.status != statusOK {
				t.Errorf("post-repair check = %q, want %q: %s", post.status, statusOK, post.detail)
			}
			if strings.Contains(string(got), "__DAEMON_PATH__") {
				t.Error("repaired file still has unpatched placeholders")
			}
		})
	}
}

// The repair is gated on the invariant, not on byte equality, so a hand-edit
// that keeps the invariant is not clobbered — the plist comment documents
// adding EnvironmentVariables (ADR 0088-deployed-supervisor-verified).
func TestCustomizedButValidDefinitionIsNotRewritten(t *testing.T) {
	withGOOS(t, "darwin")
	home := t.TempDir()
	customized := strings.Replace(daemonServiceSpec(home).content,
		"<key>KeepAlive</key>",
		"<key>EnvironmentVariables</key>\n    <dict>\n        <key>AGENTJAIL_NO_UPDATE_CHECK</key>\n        <string>1</string>\n    </dict>\n    <key>KeepAlive</key>", 1)
	path := deploy(t, home, customized)

	repaired, err := ensureDaemonRestartPolicy(home)
	if err != nil {
		t.Fatalf("ensureDaemonRestartPolicy: %v", err)
	}
	if repaired {
		t.Error("repaired = true; a customization that keeps the invariant must be left alone")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != customized {
		t.Errorf("customized definition was rewritten\ngot:\n%s", got)
	}
}

// Absent means no supervisor; writing a unit for an install that may not exist
// is `agentjail install`, so ensure must not conjure one.
func TestEnsureDoesNotCreateMissingDefinition(t *testing.T) {
	withGOOS(t, "linux")
	home := t.TempDir()

	repaired, err := ensureDaemonRestartPolicy(home)
	if err != nil {
		t.Fatalf("ensureDaemonRestartPolicy: %v", err)
	}
	if repaired {
		t.Error("repaired = true, want false — nothing was deployed to repair")
	}
	if _, err := os.Stat(daemonServiceSpec(home).path); !os.IsNotExist(err) {
		t.Error("ensureDaemonRestartPolicy created a definition where none existed")
	}
}

func TestEnsureDaemonRestartPolicyIsIdempotent(t *testing.T) {
	withGOOS(t, "linux")
	home := t.TempDir()
	deploy(t, home, staleSystemdUnit)

	if repaired, err := ensureDaemonRestartPolicy(home); err != nil || !repaired {
		t.Fatalf("first call: repaired=%v err=%v", repaired, err)
	}
	repaired, err := ensureDaemonRestartPolicy(home)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if repaired {
		t.Error("second call rewrote an already-correct definition")
	}
}

// ── the contract the installer and the checker share (ADR 0034) ─────────

// daemonServiceSpec must reconstruct exactly what installAndStartDaemonService
// writes; if the two derivations drift, doctor flags every healthy install.
func TestSpecMatchesWhatTheInstallerWrites(t *testing.T) {
	withGOOS(t, "linux")
	home := t.TempDir()
	spec := daemonServiceSpec(home)

	daemonDst := filepath.Join(home, ".agentjail", "bin", daemonBinaryName)
	rulesD := filepath.Join(home, ".agentjail", "rules")
	logPath := filepath.Join(home, ".agentjail", "daemon.log")
	crashLogPath := filepath.Join(home, ".agentjail", "crash.log")
	if err := installSystemdUnit(daemonDst, rulesD, logPath, crashLogPath, spec.path); err != nil {
		t.Fatalf("installSystemdUnit: %v", err)
	}

	got, err := os.ReadFile(spec.path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != spec.content {
		t.Errorf("spec content differs from what the installer wrote\ngot:\n%s\nwant:\n%s", got, spec.content)
	}
	if got := serviceRestartPolicyCheck(home); got.status != statusOK {
		t.Errorf("a freshly installed unit reads as %q: %s", got.status, got.detail)
	}
}
