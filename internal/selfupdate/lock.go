package selfupdate

import (
	"fmt"
	"path/filepath"

	"github.com/gofrs/flock"
)

// AcquireUpdateLock acquires an exclusive, non-blocking file lock on
// <basePath>/update.lock. Returns the locked flock handle (caller must
// pass to ReleaseUpdateLock when done). Returns error if another process
// holds the lock.
func AcquireUpdateLock(basePath string) (*flock.Flock, error) {
	lockPath := filepath.Join(basePath, "update.lock")
	fl := flock.New(lockPath)
	locked, err := fl.TryLock()
	if err != nil {
		return nil, fmt.Errorf("acquire lock: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("acquire lock (another update in progress?): lock held by another process")
	}
	return fl, nil
}

// ReleaseUpdateLock releases the file lock and closes the underlying file.
func ReleaseUpdateLock(fl *flock.Flock) error {
	if fl == nil {
		return nil
	}
	if err := fl.Unlock(); err != nil {
		return err
	}
	return fl.Close()
}
