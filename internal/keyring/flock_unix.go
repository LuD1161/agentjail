//go:build unix

package keyring

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock, blocking until it is ours: two
// daemons starting together must converge on one KEK.
// See ADR 0097-linux-kek-fallback.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
