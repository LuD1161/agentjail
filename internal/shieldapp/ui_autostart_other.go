//go:build !linux && !darwin

package shieldapp

import "errors"

func startDetachedLocalUI() error {
	return errors.New("detached local UI is unsupported on this platform")
}
