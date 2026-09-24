package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const uninstallReceiptName = "uninstalled.json"

type uninstallReceipt struct {
	Version uint32 `json:"version"`
}

// Retired commands serve cached registrations only. See ADR 0151-install-lifecycle.
const retiredHook = `#!/bin/sh
# AgentJail uninstalled: compatibility for registrations awaiting client reload.
/bin/cat >/dev/null
for arg do
    case "$arg" in
        --agent=cursor) printf '%s\n' '{"permission":"allow"}'; exit 0 ;;
    esac
done
printf '%s\n' '{}'
`

const retiredCLI = `#!/bin/sh
# AgentJail uninstalled: compatibility for cached status-line commands only.
if [ "${1-}" = "statusline" ]; then
    /bin/cat >/dev/null
    exit 0
fi
printf '%s\n' 'AgentJail is uninstalled. Install it again to use this command.' >&2
exit 127
`

// A receipt alone never retires an operational installation.
// See ADR 0151-install-lifecycle.
func explicitlyUninstalled(home string) bool {
	root := filepath.Join(home, ".agentjail")
	data, err := os.ReadFile(filepath.Join(root, uninstallReceiptName))
	if err != nil {
		return false
	}
	var receipt uninstallReceipt
	if json.Unmarshal(data, &receipt) != nil || receipt.Version != 1 {
		return false
	}
	for _, name := range []string{"policy.yaml", "daemon.sock", "rules"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			return false
		}
	}
	for name, content := range map[string]string{cliBinaryName: retiredCLI, hookBinaryName: retiredHook} {
		path := filepath.Join(root, "bin", name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(content)) {
			return false
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, []byte(content)) {
			return false
		}
	}
	return true
}

func clearUninstallReceipt(home string) error {
	err := os.Remove(filepath.Join(home, ".agentjail", uninstallReceiptName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Only call after services stop and every owned registration is detached.
// See ADR 0151-install-lifecycle.
func retireInstallDir(root string, keepSecrets bool) error {
	return retireInstallDirWithWriter(root, keepSecrets, writeRetirementFile)
}

func retireInstallDirWithWriter(root string, keepSecrets bool, write func(string, []byte, os.FileMode) error) error {
	for _, dir := range []string{root, filepath.Join(root, "bin")} {
		if info, err := os.Lstat(dir); err == nil && !info.IsDir() {
			return fmt.Errorf("retire installation: %s is not a directory", dir)
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	bin := filepath.Join(root, "bin")
	if err := write(filepath.Join(bin, hookBinaryName), []byte(retiredHook), 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var cleanupErrors []error
	for _, entry := range entries {
		name := entry.Name()
		if name == "bin" || (keepSecrets && (name == "secrets" || name == "secrets.key")) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	entries, err = os.ReadDir(bin)
	if err != nil {
		return errors.Join(append(cleanupErrors, err)...)
	}
	for _, entry := range entries {
		if entry.Name() == hookBinaryName || entry.Name() == cliBinaryName {
			continue
		}
		if err := os.RemoveAll(filepath.Join(bin, entry.Name())); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if err := errors.Join(cleanupErrors...); err != nil {
		return err
	}
	data, err := json.Marshal(uninstallReceipt{Version: 1})
	if err != nil {
		return err
	}
	if err := write(filepath.Join(root, uninstallReceiptName), append(data, '\n'), 0o600); err != nil {
		return err
	}
	// The receipt is ignored until the last operational executable is retired.
	return write(filepath.Join(bin, cliBinaryName), []byte(retiredCLI), 0o755)
}

func writeRetirementFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".retire-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
