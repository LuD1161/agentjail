//go:build darwin

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// daemonLabel is the launchd service label for the agentjail daemon.
const daemonLabel = "com.agentjail.daemon"

// launchctlTarget returns the launchd "gui/<uid>/<label>" target for the
// current user's session.
func launchctlTarget() string {
	return fmt.Sprintf("gui/%d/%s", os.Getuid(), daemonLabel)
}

// LaunchctlLoad (re)starts the daemon via launchd. It first tries
// `launchctl kickstart -kp`, which kills any running instance and restarts
// it using the on-disk plist even if the service isn't bootstrapped yet.
// If that fails (e.g. on older launchd or if the service isn't bootstrapped
// at all), it falls back to the deprecated unload+load sequence.
func LaunchctlLoad(plistPath string) error {
	out, err := exec.Command("launchctl", "kickstart", "-kp", launchctlTarget()).CombinedOutput()
	if err == nil {
		return nil
	}
	kickstartErr := fmt.Errorf("launchctl kickstart: %w: %s", err, strings.TrimSpace(string(out)))

	_ = exec.Command("launchctl", "unload", plistPath).Run()
	out, err = exec.Command("launchctl", "load", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v; launchctl load fallback: %w: %s", kickstartErr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LaunchctlUnload stops and removes the daemon from launchd. It first tries
// `launchctl bootout`, falling back to the deprecated unload if that fails.
func LaunchctlUnload(plistPath string) error {
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		return nil
	}

	out, err := exec.Command("launchctl", "bootout", launchctlTarget()).CombinedOutput()
	if err == nil {
		return nil
	}
	bootoutErr := fmt.Errorf("launchctl bootout: %w: %s", err, strings.TrimSpace(string(out)))

	out, err = exec.Command("launchctl", "unload", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v; launchctl unload fallback: %w: %s", bootoutErr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RestartDaemon reloads the daemon via launchd on macOS.
func RestartDaemon(servicePath string) error {
	return LaunchctlLoad(servicePath)
}
