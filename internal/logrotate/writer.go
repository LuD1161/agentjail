package logrotate

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Writer is a thread-safe io.WriteCloser that rotates the underlying file
// when it exceeds maxSize bytes. It delegates to lumberjack.Logger for the
// actual rotation mechanics.
type Writer struct {
	lj *lumberjack.Logger
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

	// Convert bytes → megabytes, rounding up so we never rotate earlier
	// than the caller expects.
	const mb = 1024 * 1024
	maxSizeMB := int(maxSize / mb)
	if maxSize%mb != 0 || maxSizeMB == 0 {
		maxSizeMB++
	}

	lj := &lumberjack.Logger{
		Filename:   path,
		MaxSize:    maxSizeMB, // megabytes
		MaxBackups: maxFiles,
		LocalTime:  true,
		Compress:   false,
	}

	return &Writer{lj: lj}, nil
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (n int, err error) {
	return w.lj.Write(p)
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	return w.lj.Close()
}
