//go:build darwin

package shieldapp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

func TestGenerateTunnelProfile_DarwinTempDirCarveOutMatchesOrdinaryProfile(t *testing.T) {
	canonical, symlink := withSyntheticDarwinTempDir(t)
	home := "/Users/testuser"
	cfg := config.Default()
	ordinary := generateSBProfileWithIPs(cfg, home, nil, false)
	tunnel := generateSBProfileTunnel(cfg, home)
	var filesystem strings.Builder
	filesystem.WriteString("(version 1)\n(allow default)\n\n")
	appendDarwinFilesystemProfile(&filesystem, cfg, home, darwinProfileCapabilities{})

	for _, profile := range []struct {
		name string
		text string
	}{
		{name: "ordinary", text: ordinary},
		{name: "tunnel", text: tunnel},
	} {
		if !strings.HasPrefix(profile.text, filesystem.String()) {
			t.Errorf("%s profile does not begin with the shared Darwin filesystem contract", profile.name)
		}
	}

	for _, dir := range []string{canonical, symlink} {
		allow := fmt.Sprintf("(allow file-write*\n    (subpath %q))", dir)
		if !strings.Contains(ordinary, allow) {
			t.Fatalf("ordinary profile missing validated TMPDIR write carve-out for %q", dir)
		}
		if !strings.Contains(tunnel, allow) {
			t.Errorf("tunnel profile missing validated TMPDIR write carve-out for %q", dir)
		}
	}

	for _, profile := range []struct {
		name string
		text string
	}{
		{name: "ordinary", text: ordinary},
		{name: "tunnel", text: tunnel},
	} {
		t.Run(profile.name+"_negative_controls", func(t *testing.T) {
			if strings.Contains(profile.text, "(allow file-write*\n    (subpath \"/var\"))") {
				t.Fatal("profile must not allow the whole /var tree")
			}
			if strings.Contains(profile.text, "(allow file-write*\n    (subpath \"/private/var\"))") {
				t.Fatal("profile must not allow the whole /private/var tree")
			}
			if strings.Contains(profile.text, "(allow file-write*\n    (subpath \"/tmp\"))") {
				t.Fatal("profile must not widen the carve-out to shared /tmp")
			}
		})
	}
}

// Compatibility source: Codex CLI 0.147.0; verified 2026-08-16 against
// https://github.com/openai/codex/blob/rust-v0.147.0/codex-rs/tui/src/clipboard_paste.rs#L109-L140.
func TestSandboxExec_DarwinImagePasteTempPNGLifecycle(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only sandbox-exec integration test")
	}
	skipIfNoSandboxExec(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}

	tmpdir := os.TempDir()
	if validateDarwinTempDir(tmpdir) == nil {
		t.Skipf("os.TempDir() = %q is not a validated per-user T directory", tmpdir)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	deniedDir, err := os.MkdirTemp("/tmp", "agentjail-shield-paste-deny-")
	if err != nil {
		t.Fatalf("MkdirTemp denied directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(deniedDir) })
	deniedDir, err = filepath.EvalSymlinks(deniedDir)
	if err != nil {
		t.Fatalf("EvalSymlinks denied directory: %v", err)
	}
	cfg := config.Default()
	cfg.File.ExtraDeny = []string{deniedDir}
	profiles := []struct {
		name string
		text string
	}{
		{name: "ordinary", text: generateSBProfile(cfg, home)},
		{name: "tunnel", text: generateSBProfileTunnel(cfg, home)},
	}

	const script = `
import os
import tempfile

png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0dIDAT\x08\xd7c\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff\x89\x99=\x1d\x00\x00\x00\x00IEND\xaeB\x60\x82"

fd, image_path = tempfile.mkstemp(prefix="codex-clipboard-", suffix=".png")
try:
    if os.path.dirname(image_path) != os.path.normpath(os.environ["TMPDIR"]):
        raise RuntimeError("paste image was not created in TMPDIR: " + image_path)
    with os.fdopen(fd, "wb") as image:
        image.write(png)
    with open(image_path, "rb") as image:
        if image.read() != png:
            raise RuntimeError("paste image content changed")
    os.unlink(image_path)
    if os.path.exists(image_path):
        raise RuntimeError("paste image remained after cleanup")
    print("png_lifecycle=ok")
except Exception:
    try:
        os.unlink(image_path)
    except OSError:
        pass
    raise

negative_path = os.path.join(os.environ["AGENTJAIL_TEST_DENIED_DIR"], "must-remain-denied.png")
try:
    with open(negative_path, "wb") as denied:
        denied.write(png)
except OSError:
    print("extra_deny=denied")
else:
    os.unlink(negative_path)
    raise RuntimeError("ExtraDeny write unexpectedly succeeded")
`

	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			profilePath := filepath.Join(t.TempDir(), "image-paste.sb")
			if err := os.WriteFile(profilePath, []byte(profile.text), 0o600); err != nil {
				t.Fatalf("write profile: %v", err)
			}

			cmd := exec.Command(sandboxExecPath, "-f", profilePath, python, "-c", script)
			cmd.Env = append(os.Environ(), "AGENTJAIL_TEST_DENIED_DIR="+deniedDir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("sandbox-exec %s profile: %v\n%s", profile.name, err, out)
			}
			output := string(out)
			for _, want := range []string{"png_lifecycle=ok", "extra_deny=denied"} {
				if !strings.Contains(output, want) {
					t.Errorf("sandbox-exec %s profile output missing %q:\n%s", profile.name, want, output)
				}
			}
		})
	}
}
