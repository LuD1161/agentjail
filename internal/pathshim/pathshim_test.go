package pathshim

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReassertRequiresPriorConsent(t *testing.T) {
	home := t.TempDir()
	shield := installTestShield(t, home)

	result, err := Reassert(home, shield, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied || AnyInstalled(home) {
		t.Fatal("reassert installed shims without prior consent")
	}
}

func TestReassertRestoresCompleteTargetSet(t *testing.T) {
	home := t.TempDir()
	shield := installTestShield(t, home)
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(MarkerStart+"\n"+MarkerEnd+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Reassert(home, shield, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || !result.Restored || !Complete(home) {
		t.Fatalf("result = %+v, complete = %v", result, Complete(home))
	}
}

func TestRenderedTargetsAreValidShell(t *testing.T) {
	for _, target := range Targets() {
		t.Run(target.Command, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, target.Command)
			content := Render(target, filepath.Join(dir, "agentjail-shield"), dir, path)
			if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("/bin/sh", "-n", path).CombinedOutput(); err != nil {
				t.Fatalf("invalid shell: %v\n%s", err, out)
			}
			for _, want := range []string{"command -v " + target.Command, "Running " + target.Command + " UNSHIELDED"} {
				if !strings.Contains(content, want) {
					t.Errorf("shim missing %q", want)
				}
			}
		})
	}
}

func installTestShield(t *testing.T, home string) string {
	t.Helper()
	binDir := filepath.Join(home, ".agentjail", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	shield := filepath.Join(binDir, "agentjail-shield")
	if err := os.WriteFile(shield, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return shield
}
