//go:build linux

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const systemctlPath = "/usr/bin/systemctl"

// SystemdRestart restarts the agentjail daemon via systemd user service.
func SystemdRestart(unit string) error {
	return systemdUserCommand("restart", unit)
}

// SystemdDaemonReload makes the user manager re-read service definitions.
func SystemdDaemonReload() error {
	return systemdUserCommand("daemon-reload")
}

func systemdUserCommand(args ...string) error {
	uid := os.Getuid()
	env, err := systemdUserEnvironment(os.Environ(), uid, filepath.Join("/run/user", strconv.Itoa(uid)))
	if err != nil {
		return fmt.Errorf("systemctl --user environment: %w", err)
	}
	cmd := exec.Command(systemctlPath, append([]string{"--user"}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl --user %s: %s: %w", strings.Join(args, " "), out, err)
	}
	return nil
}

func systemdUserEnvironment(environ []string, uid int, expectedRuntimeDir string) ([]string, error) {
	if err := validateUserRuntimeDir(expectedRuntimeDir, uid); err != nil {
		return nil, err
	}

	busPath := filepath.Join(expectedRuntimeDir, "bus")
	if err := validateUserBusSocket(busPath, uid); err != nil {
		return nil, err
	}

	completed := make([]string, 0, len(environ)+2)
	for _, entry := range environ {
		if strings.HasPrefix(entry, "XDG_RUNTIME_DIR=") || strings.HasPrefix(entry, "DBUS_SESSION_BUS_ADDRESS=") {
			continue
		}
		completed = append(completed, entry)
	}
	completed = append(completed,
		"XDG_RUNTIME_DIR="+expectedRuntimeDir,
		"DBUS_SESSION_BUS_ADDRESS=unix:path="+busPath,
	)
	return completed, nil
}

func environmentValue(environ []string, name string) (string, bool) {
	prefix := name + "="
	for _, entry := range environ {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix), true
		}
	}
	return "", false
}

func validateUserRuntimeDir(path string, uid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect runtime directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("runtime path %s is not a directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("runtime directory %s permits group or other access", path)
	}
	return validatePathOwner(path, info, uid)
}

func validateUserBusSocket(path string, uid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect user bus %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("user bus path %s is not a socket", path)
	}
	return validatePathOwner(path, info, uid)
}

func validatePathOwner(path string, info os.FileInfo, uid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect owner of %s: unsupported stat result", path)
	}
	if stat.Uid != uint32(uid) {
		return fmt.Errorf("path %s is owned by uid %d, want %d", path, stat.Uid, uid)
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
