//go:build !darwin && !linux

package selfupdate

import "fmt"

// LaunchctlLoad is not supported on non-Darwin platforms.
func LaunchctlLoad(_ string) error {
	return fmt.Errorf("launchctl: not supported on this platform")
}

// LaunchctlUnload is not supported on non-Darwin platforms.
func LaunchctlUnload(_ string) error {
	return fmt.Errorf("launchctl: not supported on this platform")
}

// RestartDaemon is not supported on this platform.
func RestartDaemon(_ string) error {
	return fmt.Errorf("daemon restart: not supported on this platform")
}
