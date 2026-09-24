package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetirementReceiptFailureKeepsCLIForRetry(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".agentjail")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(bin, cliBinaryName)
	if err := os.WriteFile(cli, []byte("real CLI"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := retireInstallDirWithWriter(root, false, func(path string, data []byte, mode os.FileMode) error {
		if filepath.Base(path) == uninstallReceiptName {
			return errors.New("receipt write failed")
		}
		return writeRetirementFile(path, data, mode)
	})
	if err == nil {
		t.Fatal("receipt failure swallowed")
	}
	data, err := os.ReadFile(cli)
	if err != nil || string(data) != "real CLI" {
		t.Fatalf("retry CLI removed: %q %v", data, err)
	}
	if explicitlyUninstalled(home) {
		t.Fatal("failed uninstall marked complete")
	}
}

func TestRetiredHookServesCachedCommands(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(map[bool]string{false: "remove credentials", true: "keep credentials"}[keep], func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".agentjail")
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			hook := filepath.Join(bin, hookBinaryName)
			for _, path := range []string{hook, filepath.Join(bin, cliBinaryName), filepath.Join(root, "policy.yaml"), filepath.Join(root, "secrets.key"), filepath.Join(root, "agentjail.db")} {
				if err := os.WriteFile(path, []byte("old payload"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := retireInstallDir(root, keep); err != nil {
				t.Fatal(err)
			}
			if !explicitlyUninstalled(home) {
				t.Fatal("missing explicit retirement state")
			}
			for _, adapter := range []string{"", "--agent=codex", "--agent=cursor"} {
				args := []string{}
				if adapter != "" {
					args = append(args, adapter)
				}
				cmd := exec.Command(hook, args...)
				cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read"}`)
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("cached %q: %v", adapter, err)
				}
				var response map[string]string
				if err := json.Unmarshal(out, &response); err != nil {
					t.Fatal(err)
				}
				if adapter == "--agent=cursor" {
					if len(response) != 1 || response["permission"] != "allow" {
						t.Fatalf("Cursor response = %s", out)
					}
				} else if len(response) != 0 {
					t.Fatalf("native permissions were overridden: %s", out)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "agentjail.db")); !os.IsNotExist(err) {
				t.Fatal("history retained")
			}
			if _, err := os.Stat(filepath.Join(root, "secrets.key")); os.IsNotExist(err) == keep {
				t.Fatalf("credential retention mismatch: %v", err)
			}
			if err := retireInstallDir(root, keep); err != nil {
				t.Fatalf("repeat uninstall: %v", err)
			}
		})
	}
}

func TestRetiredCLIOnlyAcceptsCachedStatusLine(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".agentjail")
	if err := retireInstallDir(root, false); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(root, "bin", cliBinaryName)
	cmd := exec.Command(cli, "statusline", "--integration", "cursor")
	cmd.Stdin = strings.NewReader(`{}`)
	if out, err := cmd.CombinedOutput(); err != nil || len(out) != 0 {
		t.Fatalf("statusline: %s %v", out, err)
	}
	for _, command := range []string{"approval-exec", "credential", "run"} {
		if err := exec.Command(cli, command).Run(); err == nil {
			t.Fatalf("retired CLI accepted %s", command)
		}
	}
}

func TestUninstallReceiptCannotRetireOperationalState(t *testing.T) {
	for _, name := range []string{"policy.yaml", "daemon.sock", "rules", "bin/agentjail", "bin/agentjail-hook"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".agentjail")
			if err := retireInstallDir(root, false); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte("operational state"), 0o600); err != nil {
				t.Fatal(err)
			}
			if explicitlyUninstalled(home) {
				t.Fatal("receipt overrode installed state")
			}
		})
	}
}

func TestRetirementRejectsSymlinkedInstallDirectories(t *testing.T) {
	for _, symlinkBin := range []bool{false, true} {
		home := t.TempDir()
		root := filepath.Join(home, ".agentjail")
		outside := t.TempDir()
		path := root
		if symlinkBin {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			path = filepath.Join(root, "bin")
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
		if err := retireInstallDir(root, false); err == nil {
			t.Fatal("accepted symlinked install directory")
		}
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatalf("modified unrelated directory: %v", err)
		}
	}
}
