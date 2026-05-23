package agents

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileAtomicBasic verifies that writeFileAtomic creates a new file
// with the supplied content and mode when the target does not yet exist.
func TestWriteFileAtomicBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.json")
	data := []byte(`{"key":"value"}`)

	if err := writeFileAtomic(path, data, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}

	// Verify mode.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// TestWriteFileAtomicPreservesMode verifies that when an existing file is
// rewritten via writeFileAtomic the original file mode is preserved, even
// when a different mode is passed as the default.
func TestWriteFileAtomicPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	// Create the initial file with mode 0600.
	original := []byte(`{"version":1}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("setup WriteFile: %v", err)
	}

	// Rewrite with different content, passing 0o644 as default mode.
	updated := []byte(`{"version":2}`)
	if err := writeFileAtomic(path, updated, 0o644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	// Content must be updated.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(updated) {
		t.Errorf("content = %q, want %q", got, updated)
	}

	// Mode must be preserved at 0600, not widened to 0644.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o, want 0600 (original mode should be preserved)", fi.Mode().Perm())
	}
}

// TestWriteFileAtomicBakCreatedOnFirstMutation verifies that the first call
// to writeFileAtomic on an existing file creates a <path>.bak with the
// original content, and that a second call does NOT overwrite that .bak.
func TestWriteFileAtomicBakCreatedOnFirstMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	bakPath := path + ".bak"

	original := []byte(`{"original":true}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("setup WriteFile: %v", err)
	}

	// First mutation — .bak should be created with the original content.
	first := []byte(`{"mutation":1}`)
	if err := writeFileAtomic(path, first, 0o600); err != nil {
		t.Fatalf("first writeFileAtomic: %v", err)
	}

	bak, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("ReadFile .bak after first mutation: %v", err)
	}
	if string(bak) != string(original) {
		t.Errorf(".bak content = %q, want original %q", bak, original)
	}

	// Second mutation — .bak must NOT be overwritten with the already-mutated
	// content; it must still contain the original bytes.
	second := []byte(`{"mutation":2}`)
	if err := writeFileAtomic(path, second, 0o600); err != nil {
		t.Fatalf("second writeFileAtomic: %v", err)
	}

	bak2, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("ReadFile .bak after second mutation: %v", err)
	}
	if string(bak2) != string(original) {
		t.Errorf(".bak overwritten on second mutation: got %q, want original %q", bak2, original)
	}
}

// TestWriteFileAtomicNoBakForNewFile verifies that no .bak file is created
// when writeFileAtomic is called on a path that does not yet exist.
func TestWriteFileAtomicNoBakForNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.json")
	bakPath := path + ".bak"

	if err := writeFileAtomic(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Errorf(".bak file should not exist for a new file, but Stat returned: %v", err)
	}
}

// TestWriteFileAtomicNoTmpDebris verifies that no *.tmp / agentjail-atomic-*
// files are left in the directory after a successful writeFileAtomic call.
func TestWriteFileAtomicNoTmpDebris(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")

	if err := writeFileAtomic(path, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	for _, e := range entries {
		name := e.Name()
		// The only expected files are the target and the .bak (not created for
		// new files, but guard both). Any .agentjail-atomic-* file is debris.
		if name != filepath.Base(path) && name != filepath.Base(path)+".bak" {
			t.Errorf("unexpected file left in dir after writeFileAtomic: %q", name)
		}
	}
}

// TestWriteFileAtomicReplacesContent is a focused atomic-replace check:
// the file must contain the new content after the call, not the old.
func TestWriteFileAtomicReplacesContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replace.json")

	if err := os.WriteFile(path, []byte(`old`), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	newData := []byte(`new`)
	if err := writeFileAtomic(path, newData, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("after writeFileAtomic content = %q, want %q", got, newData)
	}
}
