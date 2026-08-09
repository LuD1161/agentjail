//go:build darwin || linux

package shieldapp

import (
	"errors"
	"syscall"
)

func credentialProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
