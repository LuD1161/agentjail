//go:build !darwin && !linux

package keyring

import (
	"fmt"
	"runtime"
)

// No keychain primitive is claimed for other platforms; the caller gets the
// same typed error a headless Linux host gets (plan 014 §9.2).
func openOSStore() (Store, error) {
	return nil, fmt.Errorf("%w: no keychain backend for %s", ErrNoKeychain, runtime.GOOS)
}
