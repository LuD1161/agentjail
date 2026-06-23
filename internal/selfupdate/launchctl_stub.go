//go:build !darwin

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
