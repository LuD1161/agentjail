//go:build !unix

package keyring

import (
	"fmt"
	"os"
)

// No advisory lock here means no way to guarantee one KEK across processes, so
// the file backend refuses rather than minting two.
// See ADR 0097-linux-kek-fallback.
func lockFile(*os.File) error {
	return fmt.Errorf("%w: no file locking on this OS", ErrNoKeychain)
}

func unlockFile(*os.File) error { return nil }
