package logrotate

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Writer is a thread-safe io.WriteCloser that rotates the underlying file
// when it exceeds maxSize bytes. Rotation renames the chain:
//
//	current → .1, .1 → .2, ..., .{maxFiles} is deleted.
//
// After rotation, a fresh file is opened with the same path.
type Writer struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	size     int64 // in-memory byte count (initialized from Stat, incremented on Write)
	maxSize  int64
	maxFiles int
}

// New opens (or creates) the log file at path. maxSize is the maximum number
// of bytes before rotation; maxFiles is the number of rotated backups to keep
// (0 means no backups — the old file is simply removed).
func New(path string, maxSize int64, maxFiles int) (*Writer, error) {
	if maxSize <= 0 {
		return nil, fmt.Errorf("logrotate: maxSize must be > 0, got %d", maxSize)
	}
	if maxFiles < 0 {
		return nil, fmt.Errorf("logrotate: maxFiles must be >= 0, got %d", maxFiles)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("logrotate: create parent dir %q: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("logrotate: open %q: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("logrotate: stat %q: %w", path, err)
	}

	return &Writer{
		f:        f,
		path:     path,
		size:     info.Size(),
		maxSize:  maxSize,
		maxFiles: maxFiles,
	}, nil
}

// Write implements io.Writer. It rotates the file if the write would exceed
// maxSize, then writes p to the (possibly fresh) file.
func (w *Writer) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxSize {
		if rerr := w.rotate(); rerr != nil {
			return 0, rerr
		}
	}

	n, err = w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate renames the backup chain and opens a fresh log file.
// Must be called with w.mu held.
func (w *Writer) rotate() error {
	if err := w.f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "logrotate: close %q: %v\n", w.path, err)
	}

	// Delete the oldest backup if maxFiles > 0.
	if w.maxFiles > 0 {
		oldest := fmt.Sprintf("%s.%d", w.path, w.maxFiles)
		if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "logrotate: remove %q: %v\n", oldest, err)
		}

		// Shift backups: path.{i} → path.{i+1}, from maxFiles-1 down to 1.
		for i := w.maxFiles - 1; i >= 1; i-- {
			src := fmt.Sprintf("%s.%d", w.path, i)
			dst := fmt.Sprintf("%s.%d", w.path, i+1)
			if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "logrotate: rename %q → %q: %v\n", src, dst, err)
			}
		}

		// Rename current → .1.
		if err := os.Rename(w.path, fmt.Sprintf("%s.1", w.path)); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "logrotate: rename %q → %q: %v\n", w.path, w.path+".1", err)
		}
	} else {
		// maxFiles == 0: just remove the current file.
		if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "logrotate: remove %q: %v\n", w.path, err)
		}
	}

	// Open a fresh file.
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("logrotate: open fresh file %q: %w", w.path, err)
	}
	w.f = f
	w.size = 0
	return nil
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
