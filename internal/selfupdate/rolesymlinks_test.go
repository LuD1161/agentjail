package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFakeAgentjail writes a real (non-symlink) file at binDir/agentjail so
// tests exercise EnsureRoleSymlinks against a realistic bin directory.
func writeFakeAgentjail(t *testing.T, binDir string) {
	t.Helper()
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatalf("mkdir binDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "agentjail"), []byte("fake-multicall-binary"), 0o755); err != nil {
		t.Fatalf("write fake agentjail: %v", err)
	}
}

// assertRoleSymlinks verifies every role name in binDir is a symlink
// pointing at "agentjail".
func assertRoleSymlinks(t *testing.T, binDir string) {
	t.Helper()
	for _, role := range RoleNames {
		link := filepath.Join(binDir, role)
		fi, err := os.Lstat(link)
		if err != nil {
			t.Fatalf("lstat %s: %v", link, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s is not a symlink (mode=%v)", link, fi.Mode())
		}
		got, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("readlink %s: %v", link, err)
		}
		if got != "agentjail" {
			t.Errorf("%s -> %q, want %q", link, got, "agentjail")
		}
		// Resolve to make sure it actually points at the real binary content.
		resolved, err := filepath.EvalSymlinks(link)
		if err != nil {
			t.Fatalf("EvalSymlinks %s: %v", link, err)
		}
		content, err := os.ReadFile(resolved)
		if err != nil {
			t.Fatalf("read resolved target: %v", err)
		}
		if string(content) != "fake-multicall-binary" {
			t.Errorf("%s resolves to content %q, want %q", link, content, "fake-multicall-binary")
		}
	}
}

// TestEnsureRoleSymlinks_FreshDir verifies that against a temp dir containing
// only a real `agentjail` binary, all four role paths become symlinks to it.
func TestEnsureRoleSymlinks_FreshDir(t *testing.T) {
	binDir := t.TempDir()
	writeFakeAgentjail(t, binDir)

	if err := EnsureRoleSymlinks(binDir); err != nil {
		t.Fatalf("EnsureRoleSymlinks: %v", err)
	}

	assertRoleSymlinks(t, binDir)
}

// TestEnsureRoleSymlinks_ReplacesStaleRealFile is THE WATCHPOINT test: when a
// role path is a pre-existing REAL file (e.g. left over from a pre-refactor
// install, or a bug that dropped a real copy), EnsureRoleSymlinks must remove
// it and replace it with a symlink — never leave the real file in place.
func TestEnsureRoleSymlinks_ReplacesStaleRealFile(t *testing.T) {
	binDir := t.TempDir()
	writeFakeAgentjail(t, binDir)

	// Simulate a stale real binary at a role path (the pre-refactor shape).
	stale := filepath.Join(binDir, "agentjail-daemon")
	if err := os.WriteFile(stale, []byte("stale-real-daemon-binary"), 0o755); err != nil {
		t.Fatalf("write stale real file: %v", err)
	}
	fi, err := os.Lstat(stale)
	if err != nil {
		t.Fatalf("lstat stale: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("test setup bug: stale path is already a symlink")
	}

	if err := EnsureRoleSymlinks(binDir); err != nil {
		t.Fatalf("EnsureRoleSymlinks: %v", err)
	}

	assertRoleSymlinks(t, binDir)
}

// TestEnsureRoleSymlinks_Idempotent verifies re-running EnsureRoleSymlinks
// against an already-correct bin directory is a safe no-op.
func TestEnsureRoleSymlinks_Idempotent(t *testing.T) {
	binDir := t.TempDir()
	writeFakeAgentjail(t, binDir)

	if err := EnsureRoleSymlinks(binDir); err != nil {
		t.Fatalf("first EnsureRoleSymlinks: %v", err)
	}
	if err := EnsureRoleSymlinks(binDir); err != nil {
		t.Fatalf("second EnsureRoleSymlinks: %v", err)
	}

	assertRoleSymlinks(t, binDir)
}

// TestEnsureRoleSymlinks_CreatesBinDir verifies EnsureRoleSymlinks creates
// binDir (0700) if it does not already exist. The symlinks will dangle since
// there is no real "agentjail" binary — that's expected; this test only
// checks directory creation and symlink presence, mirroring a defensive call
// order bug (calling EnsureRoleSymlinks before the real binary is written).
func TestEnsureRoleSymlinks_CreatesBinDir(t *testing.T) {
	parent := t.TempDir()
	binDir := filepath.Join(parent, "bin")

	if err := EnsureRoleSymlinks(binDir); err != nil {
		t.Fatalf("EnsureRoleSymlinks: %v", err)
	}

	fi, err := os.Stat(binDir)
	if err != nil {
		t.Fatalf("stat binDir: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("binDir is not a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("binDir mode = %04o, want 0700", fi.Mode().Perm())
	}
}

// TestRemoveRoleSymlinks_RemovesAll verifies RemoveRoleSymlinks removes all
// four role symlinks.
func TestRemoveRoleSymlinks_RemovesAll(t *testing.T) {
	binDir := t.TempDir()
	writeFakeAgentjail(t, binDir)
	if err := EnsureRoleSymlinks(binDir); err != nil {
		t.Fatalf("EnsureRoleSymlinks: %v", err)
	}

	RemoveRoleSymlinks(binDir)

	for _, role := range RoleNames {
		if _, err := os.Lstat(filepath.Join(binDir, role)); !os.IsNotExist(err) {
			t.Errorf("role %s still present after RemoveRoleSymlinks (err=%v)", role, err)
		}
	}
}

// TestRemoveRoleSymlinks_ToleratesAlreadyGone verifies RemoveRoleSymlinks does
// not panic or otherwise misbehave when the role paths (or binDir itself)
// don't exist — uninstall must tolerate a partially/already torn-down install.
func TestRemoveRoleSymlinks_ToleratesAlreadyGone(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "does-not-exist")
	RemoveRoleSymlinks(binDir) // must not panic
}
