//go:build darwin

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// LaunchctlLoad unloads (if loaded) then loads the given plist.
func LaunchctlLoad(plistPath string) error {
	_ = exec.Command("launchctl", "unload", plistPath).Run()
	out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LaunchctlUnload unloads the given plist.
func LaunchctlUnload(plistPath string) error {
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		return nil
	}
	out, err := exec.Command("launchctl", "unload", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl unload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
