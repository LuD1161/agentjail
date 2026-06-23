//go:build linux

package selfupdate

import (
	"fmt"
	"os/exec"
)

// SystemdRestart restarts the agentjail daemon via systemd user service.
func SystemdRestart(unit string) error {
	out, err := exec.Command("systemctl", "--user", "restart", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl --user restart %s: %s: %w", unit, out, err)
	}
	return nil
}

// RestartDaemon restarts the daemon via systemd user service on Linux.
func RestartDaemon(unit string) error {
	return SystemdRestart(unit)
}

// LaunchctlLoad is a no-op stub on Linux (launchd is macOS-only).
func LaunchctlLoad(_ string) error {
	return fmt.Errorf("launchctl: not available on Linux, use systemctl")
}

// LaunchctlUnload is a no-op stub on Linux (launchd is macOS-only).
func LaunchctlUnload(_ string) error {
	return fmt.Errorf("launchctl: not available on Linux, use systemctl")
}
