package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/pathshim"
)

func TestCLIShellProfiles(t *testing.T) {
	for _, test := range []struct{ shell, goos, zdotdir, want string }{
		{"/bin/zsh", "darwin", "", "/home/agent/.zshrc"},
		{"", "darwin", "", "/home/agent/.zshrc"},
		{"/bin/zsh", "darwin", "/home/agent/dotfiles", "/home/agent/dotfiles/.zshrc"},
		{"/bin/bash", "darwin", "", "/home/agent/.bash_profile"},
		{"/bin/bash", "linux", "", "/home/agent/.bashrc"},
		{"/bin/fish", "darwin", "", "/home/agent/.config/fish/config.fish"},
		{"/bin/sh", "darwin", "", "/home/agent/.profile"},
	} {
		t.Run(test.shell+test.goos+test.zdotdir, func(t *testing.T) {
			got, _ := cliShellProfile("/home/agent", test.shell, test.zdotdir, test.goos)
			if got != test.want {
				t.Fatalf("profile = %q, want %q", got, test.want)
			}
		})
	}
}

func TestInstallCLIPathPreservesProfileAndDoesNotOptIntoShims(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("ZDOTDIR", "")
	t.Setenv("AGENTJAIL_NO_MODIFY_PATH", "")
	rc := filepath.Join(home, ".zshrc")
	before := "export EDITOR=vim\n# personal settings\n"
	if err := os.WriteFile(rc, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installCLIPath(home); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(rc)
	if err := installCLIPath(home); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(rc)
	if string(first) != string(second) || strings.Count(string(second), pathRCMarker) != 1 {
		t.Fatalf("CLI profile reconciliation is not idempotent: %s", second)
	}
	if !strings.HasPrefix(string(second), before) {
		t.Fatalf("user profile changed: %s", second)
	}
	info, _ := os.Stat(rc)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("profile mode = %v", info.Mode())
	}
	if pathshim.ConsentRecorded(home, "") || pathshim.AnyInstalled(home) {
		t.Fatal("CLI PATH setup opted into agent launch shims")
	}
	cleaned, _ := stripAgentjailPathBlock(string(second))
	if strings.TrimSpace(cleaned) != strings.TrimSpace(before) {
		t.Fatalf("uninstall did not restore profile content: %s", cleaned)
	}
}

func TestInstallCLIPathPreservesSymlinkAndShimConsent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("ZDOTDIR", "")
	t.Setenv("AGENTJAIL_NO_MODIFY_PATH", "")
	target := filepath.Join(home, "dotfile")
	shim := shimRCMarkerStart + "\nexport PATH=\"$HOME/.agentjail/bin:$PATH\"\n" + shimRCMarkerEnd + "\n"
	if err := os.WriteFile(target, []byte(shim), 0o600); err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(home, ".zshrc")
	if err := os.Symlink(target, rc); err != nil {
		t.Fatal(err)
	}
	if err := installCLIPath(home); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(rc); err != nil || got != target {
		t.Fatalf("profile symlink changed: %q, %v", got, err)
	}
	contents, _ := os.ReadFile(target)
	if !strings.Contains(string(contents), shim) || !pathshim.ConsentRecorded(home, "") {
		t.Fatal("existing shim consent was lost")
	}
}

func TestCLIEnvironmentUsesLiteralPathAndTakesPrecedence(t *testing.T) {
	home := filepath.Join(t.TempDir(), "agent's $(literal) home")
	t.Setenv("AGENTJAIL_NO_MODIFY_PATH", "1")
	if err := installCLIPath(home); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, ".agentjail", "bin")
	command := exec.Command("/bin/sh", "-c", `. "$1"; . "$1"; printf '%s' "$PATH"`, "sh", filepath.Join(home, ".agentjail", "env"))
	command.Env = []string{"PATH=/old/bin:" + bin + ":/usr/bin:/bin"}
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != bin+":/old/bin:"+bin+":/usr/bin:/bin" {
		t.Fatalf("environment did not preserve literal path and precedence: %q", output)
	}
	if _, err := os.Stat(filepath.Join(home, ".profile")); !os.IsNotExist(err) {
		t.Fatal("PATH opt-out modified a shell profile")
	}
}

func TestCLIPathReconciliationKeepsUnownedLines(t *testing.T) {
	before := pathRCMarker + "\nexport EDITOR=nvim\n" + pathRCMarker + "\nexport PATH=\"/old/.agentjail/bin:$PATH\"\n"
	got := reconcileCLIPathBlock(before, `export PATH="$HOME/.agentjail/bin:$PATH"`)
	if !strings.Contains(got, "export EDITOR=nvim") || strings.Contains(got, "/old/") || strings.Count(got, pathRCMarker) != 1 {
		t.Fatalf("unexpected reconciled profile: %s", got)
	}
}
