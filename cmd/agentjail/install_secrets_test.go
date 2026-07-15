package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallSecretsPlistContent verifies the launchd plist is loaded-but-not-
// running (RunAtLoad false, no KeepAlive, no Sockets) and passes the broker its
// store/key/log/idle args (ADR 0058).
func TestInstallSecretsPlistContent(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "com.agentjail.secrets.plist")
	if err := installSecretsPlist("/opt/aj/agentjail-secrets", "/h/.agentjail/secrets",
		"/h/.agentjail/secrets.key", "/h/.agentjail/secrets.log", "15m",
		"/h/.agentjail/secrets-crash.log", dst); err != nil {
		t.Fatalf("installSecretsPlist: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read plist: %v", err)
	}
	got := string(b)

	mustContain := []string{
		"<string>com.agentjail.secrets</string>",
		"<key>RunAtLoad</key>",
		"<false/>",
		"<string>serve</string>",
		"<string>--store=/h/.agentjail/secrets</string>",
		"<string>--key=/h/.agentjail/secrets.key</string>",
		"<string>--log=/h/.agentjail/secrets.log</string>",
		"<string>--idle-timeout=15m</string>",
		"<string>/h/.agentjail/secrets-crash.log</string>",
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Errorf("plist missing %q\n---\n%s", s, got)
		}
	}
	mustNotContain := []string{"KeepAlive", "Sockets", "__"} // on-demand, no leftover placeholders
	for _, s := range mustNotContain {
		if strings.Contains(got, s) {
			t.Errorf("plist should not contain %q\n---\n%s", s, got)
		}
	}
}

// TestInstallSecretsSystemdUnitContent verifies the systemd --user unit is a
// plain Type=simple service with NO Restart= (the broker self-exits on idle and
// must not be restarted into an always-on loop) and the broker args (ADR 0058).
func TestInstallSecretsSystemdUnitContent(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "agentjail-secrets.service")
	if err := installSecretsSystemdUnit("/opt/aj/agentjail-secrets", "/h/.agentjail/secrets",
		"/h/.agentjail/secrets.key", "/h/.agentjail/secrets.log", "15m",
		"/h/.agentjail/secrets-crash.log", dst); err != nil {
		t.Fatalf("installSecretsSystemdUnit: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	got := string(b)

	mustContain := []string{
		"Type=simple",
		"ExecStart=/opt/aj/agentjail-secrets serve --store=/h/.agentjail/secrets --key=/h/.agentjail/secrets.key --log=/h/.agentjail/secrets.log --idle-timeout=15m",
		"WantedBy=default.target",
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Errorf("unit missing %q\n---\n%s", s, got)
		}
	}
	if strings.Contains(got, "Restart=") {
		t.Errorf("unit must NOT set Restart= (broker self-exits on idle)\n---\n%s", got)
	}
	if strings.Contains(got, "__") {
		t.Errorf("unit has unreplaced placeholder\n---\n%s", got)
	}
}

// TestSecretsBrokerDefInstalled checks presence detection on both platforms.
func TestSecretsBrokerDefInstalled(t *testing.T) {
	home := t.TempDir()

	origGOOS := currentGOOS
	t.Cleanup(func() { currentGOOS = origGOOS })

	currentGOOS = "darwin"
	if secretsBrokerDefInstalled(home) {
		t.Error("darwin: reported installed with no plist present")
	}
	plist := filepath.Join(home, "Library", "LaunchAgents", secretsPlistFilename)
	if err := os.MkdirAll(filepath.Dir(plist), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !secretsBrokerDefInstalled(home) {
		t.Error("darwin: reported not installed with plist present")
	}

	currentGOOS = "linux"
	if secretsBrokerDefInstalled(home) {
		t.Error("linux: reported installed with no unit present")
	}
	unit := filepath.Join(systemdUserUnitDir(home), secretsSystemdUnitFilename)
	if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !secretsBrokerDefInstalled(home) {
		t.Error("linux: reported not installed with unit present")
	}
}

// TestUninstallSecretsBrokerRemovesUnit_Linux verifies the systemd unit file is
// removed on teardown, without shelling out to a real systemctl (stubbed
// unavailable so the disable/stop path is skipped).
func TestUninstallSecretsBrokerRemovesUnit_Linux(t *testing.T) {
	home := t.TempDir()
	origFn := systemdUserAvailableFn
	t.Cleanup(func() { systemdUserAvailableFn = origFn })
	systemdUserAvailableFn = func() bool { return false } // skip real systemctl

	unit := filepath.Join(systemdUserUnitDir(home), secretsSystemdUnitFilename)
	if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := uninstallSecretsBroker(home, "linux"); err != nil {
		t.Fatalf("uninstallSecretsBroker: %v", err)
	}
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Error("systemd unit still present after uninstallSecretsBroker")
	}
	// Idempotent: a second call on the now-absent unit must not error.
	if err := uninstallSecretsBroker(home, "linux"); err != nil {
		t.Errorf("second uninstallSecretsBroker should be a no-op, got: %v", err)
	}
}

// TestRemoveInstallDir_KeepSecrets is the ADR 0058 OQ4 guard: --keep-secrets
// preserves the encrypted store + master key while removing everything else.
func TestRemoveInstallDir_KeepSecrets(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "secrets.key"), "KEY")
	mustWrite(t, filepath.Join(dir, "secrets", "aws", "prod"), "CIPHERTEXT")
	mustWrite(t, filepath.Join(dir, "policy.yaml"), "policy")
	mustWrite(t, filepath.Join(dir, "bin", "agentjail"), "binary")

	if err := removeInstallDir(dir, true); err != nil {
		t.Fatalf("removeInstallDir keep: %v", err)
	}
	// Assert via directory listing rather than os.Stat: when this test runs
	// inside the agentjail shield, stat on a *.key path is EPERM'd by the shield's
	// sensitive-file deny (ADR 0039), so a direct fileExists("secrets.key") would
	// false-negative. A ReadDir of the parent is a plain directory read.
	top := dirEntrySet(t, dir)
	if !top["secrets.key"] {
		t.Error("secrets.key was deleted despite keepSecrets")
	}
	if !top["secrets"] {
		t.Error("secrets store was deleted despite keepSecrets")
	}
	if top["policy.yaml"] {
		t.Error("policy.yaml survived (only secrets should be kept)")
	}
	if top["bin"] {
		t.Error("bin/ survived (only secrets should be kept)")
	}
	// The store subtree is preserved intact.
	if !dirEntrySet(t, filepath.Join(dir, "secrets", "aws"))["prod"] {
		t.Error("secrets store contents were not preserved")
	}
}

// dirEntrySet returns the immediate child names of dir as a set. Used instead of
// os.Stat so assertions survive the shield's *.key stat deny (see caller).
func dirEntrySet(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		set[e.Name()] = true
	}
	return set
}

// TestRemoveInstallDir_NoKeep removes the whole tree.
func TestRemoveInstallDir_NoKeep(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "secrets.key"), "KEY")
	mustWrite(t, filepath.Join(dir, "policy.yaml"), "policy")

	if err := removeInstallDir(dir, false); err != nil {
		t.Fatalf("removeInstallDir: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("install dir still present after removeInstallDir(false)")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
