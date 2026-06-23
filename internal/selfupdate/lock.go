package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// AcquireUpdateLock acquires an exclusive, non-blocking file lock on
// <basePath>/update.lock. Returns the locked file handle (caller must
// pass to ReleaseUpdateLock when done). Returns error if another process
// holds the lock.
func AcquireUpdateLock(basePath string) (*os.File, error) {
	lockPath := filepath.Join(basePath, "update.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("acquire lock (another update in progress?): %w", err)
	}
	return f, nil
}

// ReleaseUpdateLock releases the file lock and closes the file.
func ReleaseUpdateLock(f *os.File) error {
	if f == nil {
		return nil
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return f.Close()
}
