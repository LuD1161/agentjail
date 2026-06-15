package logrotate

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestRotateAtThreshold writes exactly maxSize bytes, then one more byte.
// After the second write the original content should be in .1.
func TestRotateAtThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	const maxSize = 16

	w, err := New(path, maxSize, 3)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// Fill exactly maxSize bytes.
	payload := make([]byte, maxSize)
	for i := range payload {
		payload[i] = 'A'
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write fill: %v", err)
	}

	// One more byte — should trigger rotation before writing.
	if _, err := w.Write([]byte("B")); err != nil {
		t.Fatalf("Write trigger: %v", err)
	}

	// .1 must exist and contain the original content.
	backup := path + ".1"
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup %q: %v", backup, err)
	}
	if len(data) != maxSize {
		t.Errorf("backup size = %d, want %d", len(data), maxSize)
	}

	// Current file must contain only the one byte written after rotation.
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(cur) != "B" {
		t.Errorf("current file content = %q, want %q", cur, "B")
	}
}

// TestOversizedWrite verifies that a single write larger than maxSize still
// succeeds (written to the fresh file after rotation).
func TestOversizedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")
	const maxSize = 4

	w, err := New(path, maxSize, 2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// Seed the file so the oversized write would definitely exceed maxSize.
	if _, err := w.Write([]byte("seed")); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	big := make([]byte, maxSize*3)
	for i := range big {
		big[i] = 'X'
	}
	n, err := w.Write(big)
	if err != nil {
		t.Fatalf("oversized Write: %v", err)
	}
	if n != len(big) {
		t.Errorf("wrote %d bytes, want %d", n, len(big))
	}

	// The seed content should be in .1.
	data, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("read .1: %v", err)
	}
	if string(data) != "seed" {
		t.Errorf(".1 content = %q, want %q", data, "seed")
	}
}

// TestMaxFilesCleanup triggers maxFiles+1 rotations and verifies that the
// file numbered maxFiles+1 does not exist (i.e. the oldest was deleted).
func TestMaxFilesCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rot.log")
	const maxSize = 4
	const maxFiles = 3

	w, err := New(path, maxSize, maxFiles)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// Write enough 1-byte payloads to trigger maxFiles+1 rotations.
	// Each rotation happens when the file is full (maxSize bytes) and a new
	// byte arrives.  We need (maxFiles+1) rotations, so:
	//   (maxFiles+1) * (maxSize+1) bytes total, roughly.
	for i := 0; i < (maxFiles+1)*(maxSize+1); i++ {
		if _, err := w.Write([]byte("Z")); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}

	// .{maxFiles} may or may not exist depending on exact boundary, but
	// .{maxFiles+1} must never exist.
	ghost := fmt.Sprintf("%s.%d", path, maxFiles+1)
	if _, err := os.Stat(ghost); err == nil {
		t.Errorf("file %q should not exist (oldest backup not cleaned up)", ghost)
	}
}

// TestPreserveSizeOnReopen checks that New() picks up the existing file size
// so that rotation triggers correctly after a restart.
func TestPreserveSizeOnReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reopen.log")
	const maxSize = 10

	// First writer: fill exactly maxSize bytes.
	w1, err := New(path, maxSize, 2)
	if err != nil {
		t.Fatalf("New w1: %v", err)
	}
	payload := make([]byte, maxSize)
	for i := range payload {
		payload[i] = 'A'
	}
	if _, err := w1.Write(payload); err != nil {
		t.Fatalf("w1 Write: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("w1 Close: %v", err)
	}

	// Second writer: opens the existing file; size should be maxSize.
	w2, err := New(path, maxSize, 2)
	if err != nil {
		t.Fatalf("New w2: %v", err)
	}
	defer w2.Close()

	if w2.size != maxSize {
		t.Errorf("size after reopen = %d, want %d", w2.size, maxSize)
	}

	// One more byte should trigger rotation.
	if _, err := w2.Write([]byte("B")); err != nil {
		t.Fatalf("w2 Write: %v", err)
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected .1 backup after reopen-triggered rotation: %v", err)
	}
}

// TestFilePermissions verifies that the log file is created with mode 0600.
func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.log")

	w, err := New(path, 1024, 2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	got := info.Mode().Perm()
	if got != 0600 {
		t.Errorf("file mode = %o, want %o", got, 0600)
	}
}

// TestInvalidArgs verifies that New() returns an error for invalid arguments.
func TestInvalidArgs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inv.log")

	if _, err := New(path, 0, 2); err == nil {
		t.Error("New with maxSize=0 should return error")
	}
	if _, err := New(path, -1, 2); err == nil {
		t.Error("New with maxSize=-1 should return error")
	}
}

// TestConcurrentWrites runs 10 goroutines writing simultaneously and checks
// that no panics occur and the writer can be closed cleanly.
func TestConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.log")

	w, err := New(path, 64, 5)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const goroutines = 10
	const writesEach = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < writesEach; j++ {
				if _, err := w.Write([]byte("hello\n")); err != nil {
					// Log but don't t.Fatal from goroutine — use t.Error.
					t.Errorf("concurrent Write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
