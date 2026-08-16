//go:build darwin

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// daemonLabel is the launchd service label for the agentjail daemon.
const daemonLabel = "com.agentjail.daemon"

var launchctlRun = func(args ...string) ([]byte, error) {
	return exec.Command("launchctl", args...).CombinedOutput()
}

// launchctlTarget returns the launchd "gui/<uid>/<label>" target for the
// current user's session.
func launchctlTarget() string {
	return fmt.Sprintf("gui/%d/%s", os.Getuid(), daemonLabel)
}

func launchctlTargetForPlist(plistPath string) string {
	label := strings.TrimSuffix(filepath.Base(plistPath), filepath.Ext(plistPath))
	return fmt.Sprintf("gui/%d/%s", os.Getuid(), label)
}

// LaunchctlLoad re-registers the job so launchd refreshes its code requirement
// after an executable replacement. See ADR 0088-deployed-supervisor-verified.
func LaunchctlLoad(plistPath string) error {
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	target := launchctlTargetForPlist(plistPath)
	bootoutOut, bootoutErr := launchctlRun("bootout", target)
	out, err := launchctlRun("bootstrap", domain, plistPath)
	if err == nil {
		return nil
	}
	bootstrapErr := fmt.Errorf("launchctl bootstrap after bootout (%v: %s): %w: %s",
		bootoutErr, strings.TrimSpace(string(bootoutOut)), err, strings.TrimSpace(string(out)))

	_, _ = launchctlRun("unload", plistPath)
	out, err = launchctlRun("load", plistPath)
	if err != nil {
		return fmt.Errorf("%v; launchctl load fallback: %w: %s", bootstrapErr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LaunchctlUnload stops and removes the daemon from launchd. It first tries
// `launchctl bootout`, falling back to the deprecated unload if that fails.
func LaunchctlUnload(plistPath string) error {
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		return nil
	}

	out, err := launchctlRun("bootout", launchctlTargetForPlist(plistPath))
	if err == nil {
		return nil
	}
	bootoutErr := fmt.Errorf("launchctl bootout: %w: %s", err, strings.TrimSpace(string(out)))

	out, err = launchctlRun("unload", plistPath)
	if err != nil {
		return fmt.Errorf("%v; launchctl unload fallback: %w: %s", bootoutErr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RestartDaemon reloads the daemon via launchd on macOS.
func RestartDaemon(servicePath string) error {
	return LaunchctlLoad(servicePath)
}
