package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

// ── AtomicReplaceBinary tests ────────────────────────────────────────────────

// TestAtomicReplaceBinary_WritesContent verifies that the binary is replaced
// with the correct content.
func TestAtomicReplaceBinary_WritesContent(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	src := filepath.Join(srcDir, "bin")
	want := []byte("updated binary content")
	if err := os.WriteFile(src, want, 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	dst := filepath.Join(dstDir, "bin")
	if err := AtomicReplaceBinary(src, dst); err != nil {
		t.Fatalf("AtomicReplaceBinary: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}
}

// TestAtomicReplaceBinary_Mode0755 verifies that the output binary has mode 0755.
func TestAtomicReplaceBinary_Mode0755(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	src := filepath.Join(srcDir, "bin")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	dst := filepath.Join(dstDir, "bin")
	if err := AtomicReplaceBinary(src, dst); err != nil {
		t.Fatalf("AtomicReplaceBinary: %v", err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %04o, want 0755", fi.Mode().Perm())
	}
}

// TestAtomicReplaceBinary_OverwritesExisting verifies that an existing binary is
// correctly replaced (not appended to).
func TestAtomicReplaceBinary_OverwritesExisting(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	src := filepath.Join(srcDir, "bin")
	want := []byte("new content")
	if err := os.WriteFile(src, want, 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	dst := filepath.Join(dstDir, "bin")
	// Write initial content to dst.
	if err := os.WriteFile(dst, []byte("old content that is longer than new"), 0o755); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := AtomicReplaceBinary(src, dst); err != nil {
		t.Fatalf("AtomicReplaceBinary: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content after replace = %q, want %q", got, want)
	}
}

// TestAtomicReplaceBinary_CreatesParentDirs verifies that missing parent
// directories are created.
func TestAtomicReplaceBinary_CreatesParentDirs(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	src := filepath.Join(srcDir, "bin")
	if err := os.WriteFile(src, []byte("x"), 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}
	dst := filepath.Join(dstDir, "deep", "nested", "bin")
	if err := AtomicReplaceBinary(src, dst); err != nil {
		t.Fatalf("AtomicReplaceBinary with nested dst: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("dst not created: %v", err)
	}
}
