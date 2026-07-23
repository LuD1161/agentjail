package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStripAgentjailPathBlock_ShimFence: uninstall must scrub the fenced shim
// block, not just install.sh's bare marker (ADR 0062).
func TestStripAgentjailPathBlock_ShimFence(t *testing.T) {
	content := strings.Join([]string{
		"export EDITOR=vim",
		"",
		shimRCMarkerStart,
		`export PATH="/home/u/.agentjail/bin:$PATH"`,
		shimRCMarkerEnd,
		"export LANG=en_US.UTF-8",
	}, "\n")

	got, changed := stripAgentjailPathBlock(content)
	if !changed {
		t.Fatal("expected the fenced shim block to be stripped")
	}
	for _, leftover := range []string{shimRCMarkerStart, shimRCMarkerEnd, ".agentjail/bin"} {
		if strings.Contains(got, leftover) {
			t.Errorf("leftover %q after strip:\n%s", leftover, got)
		}
	}
	for _, keep := range []string{"export EDITOR=vim", "export LANG=en_US.UTF-8"} {
		if !strings.Contains(got, keep) {
			t.Errorf("stripped unrelated line %q:\n%s", keep, got)
		}
	}
}

// TestStripAgentjailPathBlock_BothMarkers: a profile carrying both writers'
// blocks (install.sh + shim installer) must come out clean in one pass.
func TestStripAgentjailPathBlock_BothMarkers(t *testing.T) {
	content := strings.Join([]string{
		"export EDITOR=vim",
		"",
		shimRCMarkerStart,
		`export PATH="/home/u/.agentjail/bin:$PATH"`,
		shimRCMarkerEnd,
		"",
		pathRCMarker,
		`export PATH="$HOME/.agentjail/bin:$PATH"`,
		"export LANG=en_US.UTF-8",
	}, "\n")

	got, changed := stripAgentjailPathBlock(content)
	if !changed {
		t.Fatal("expected both blocks to be stripped")
	}
	if strings.Contains(got, ".agentjail/bin") {
		t.Errorf("an agentjail PATH line survived:\n%s", got)
	}
	if !strings.Contains(got, "export EDITOR=vim") || !strings.Contains(got, "export LANG=en_US.UTF-8") {
		t.Errorf("stripped unrelated lines:\n%s", got)
	}
}

// TestStripShimRCBlock_PreservesInstallMarker: `uninstall --path-shim-only`
// removes ONLY the fenced shim block; the bare install.sh PATH marker (and its
// export) must survive, since the rest of the install stays.
func TestStripShimRCBlock_PreservesInstallMarker(t *testing.T) {
	content := strings.Join([]string{
		"export EDITOR=vim",
		"",
		shimRCMarkerStart,
		`export PATH="/home/u/.agentjail/bin:$PATH"`,
		shimRCMarkerEnd,
		"",
		pathRCMarker,
		`export PATH="$HOME/.agentjail/bin:$PATH"`,
		"export LANG=en_US.UTF-8",
	}, "\n")

	got, changed := stripShimRCBlock(content)
	if !changed {
		t.Fatal("expected the fenced shim block to be stripped")
	}
	if strings.Contains(got, shimRCMarkerStart) || strings.Contains(got, shimRCMarkerEnd) {
		t.Errorf("shim fence survived:\n%s", got)
	}
	// The install.sh block must be untouched.
	if !strings.Contains(got, pathRCMarker) || !strings.Contains(got, `export PATH="$HOME/.agentjail/bin:$PATH"`) {
		t.Errorf("shim-only strip removed the install.sh PATH block:\n%s", got)
	}
	for _, keep := range []string{"export EDITOR=vim", "export LANG=en_US.UTF-8"} {
		if !strings.Contains(got, keep) {
			t.Errorf("stripped unrelated line %q:\n%s", keep, got)
		}
	}
}

// TestStripShimRCBlock_NoShim: content with no shim fence is returned unchanged.
func TestStripShimRCBlock_NoShim(t *testing.T) {
	content := "export EDITOR=vim\n" + pathRCMarker + "\nexport PATH=\"$HOME/.agentjail/bin:$PATH\"\n"
	got, changed := stripShimRCBlock(content)
	if changed {
		t.Errorf("expected no change when there is no shim fence:\n%s", got)
	}
}

// TestStripAgentjailPathBlock_UnterminatedFence: a hand-edited rc whose closing
// fence was deleted must not swallow the rest of the file.
func TestStripAgentjailPathBlock_UnterminatedFence(t *testing.T) {
	content := strings.Join([]string{
		shimRCMarkerStart,
		`export PATH="/home/u/.agentjail/bin:$PATH"`,
		"export LANG=en_US.UTF-8",
	}, "\n")

	got, _ := stripAgentjailPathBlock(content)
	if !strings.Contains(got, "export LANG=en_US.UTF-8") {
		t.Errorf("unterminated fence ate the rest of the file:\n%s", got)
	}
	if strings.Contains(got, ".agentjail/bin") {
		t.Errorf("our PATH export should still be scrubbed:\n%s", got)
	}
}

// TestShimConsentRecorded covers the probe that distinguishes "never opted in"
// from "opted in, then wiped" — the distinction reassertPathShim keys off.
func TestShimConsentRecorded(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export EDITOR=vim\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ZDOTDIR", "")
		if shimConsentRecorded(home) {
			t.Error("expected no consent for an rc with no agentjail block")
		}
	})

	t.Run("present", func(t *testing.T) {
		home := t.TempDir()
		rc := shimRCMarkerStart + "\nexport PATH=\"" + home + "/.agentjail/bin:$PATH\"\n" + shimRCMarkerEnd + "\n"
		if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(rc), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ZDOTDIR", "")
		if !shimConsentRecorded(home) {
			t.Error("expected consent to be detected from the fenced rc block")
		}
	})

	t.Run("no rc files at all", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("ZDOTDIR", "")
		if shimConsentRecorded(home) {
			t.Error("expected no consent when no rc file exists")
		}
	})
}
