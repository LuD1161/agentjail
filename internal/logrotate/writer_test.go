package logrotate

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestBasicWriteAndClose verifies that New() creates the log file and writes
// succeed, and Close does not return an error.
func TestBasicWriteAndClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := New(path, 1024, 3)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := w.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello\n" {
		t.Errorf("content = %q, want %q", data, "hello\n")
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

	w, err := New(path, 1024*1024, 5)
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

// TestMaxSizeConversion verifies the bytes-to-megabytes conversion rounds up.
func TestMaxSizeConversion(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name     string
		maxSize  int64
		wantMB   int
	}{
		{"exact 1MB", 1024 * 1024, 1},
		{"1 byte", 1, 1},
		{"1MB + 1", 1024*1024 + 1, 2},
		{"500KB", 500 * 1024, 1},
		{"10MB", 10 * 1024 * 1024, 10},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".log")
			w, err := New(path, tc.maxSize, 2)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if w.lj.MaxSize != tc.wantMB {
				t.Errorf("MaxSize = %d MB, want %d MB", w.lj.MaxSize, tc.wantMB)
			}
			w.Close()
		})
	}
}

// TestParentDirCreated verifies that New() creates parent directories.
func TestParentDirCreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "deep", "test.log")

	w, err := New(path, 1024, 2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("data")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("log file should exist: %v", err)
	}
}
