//go:build linux

package apparmor

import (
	"fmt"
	"os"
	"os/exec"
)

// linuxManager loads the scoped userns profile via apparmor_parser. Render is
// inherited from the shared renderer (one source of truth for the profile text).
type linuxManager struct {
	renderer
}

// New returns the Linux Manager.
func New() Manager { return linuxManager{} }

// Available shells out to apparmor_parser --version and inspects the kernel's
// exposed policy features. A missing parser or old version is a reported
// (Supported=false) result, not an error; errors are for unexpected failures.
func (linuxManager) Available() (Availability, error) {
	var a Availability

	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		return a, nil // ParserFound stays false
	}
	a.ParserFound = true

	out, err := exec.Command(parser, "--version").CombinedOutput()
	if err != nil {
		return a, fmt.Errorf("agentjail apparmor: apparmor_parser --version failed: %w", err)
	}
	if v, ok := parseParserVersion(string(out)); ok {
		a.ParserVersion = v
	}

	if _, err := os.Stat(usernsFeaturePath); err == nil {
		a.UsernsFeature = true
	}

	a.Supported = a.ParserFound && a.ParserVersion.AtLeast(minParserVersion)
	return a, nil
}

// Install writes the profile and loads it with apparmor_parser -r -W. Requires
// root (writing /etc/apparmor.d and loading into the kernel).
func (m linuxManager) Install(installDir string) error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}

	avail, err := m.Available()
	if err != nil {
		return err
	}
	if !avail.ParserFound {
		return ErrParserMissing
	}
	if !avail.ParserVersion.AtLeast(minParserVersion) {
		return fmt.Errorf("%w: found %s", ErrParserTooOld, avail.ParserVersion)
	}

	profile := m.Render(installDir)
	if err := os.WriteFile(profileInstallPath, []byte(profile), 0o644); err != nil {
		return fmt.Errorf("agentjail apparmor: write %s: %w", profileInstallPath, err)
	}

	// -r replace (idempotent), -W wait for the kernel to finish loading.
	cmd := exec.Command("apparmor_parser", "-r", "-W", profileInstallPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("agentjail apparmor: load %s: %w: %s", profileInstallPath, err, out)
	}
	return nil
}
