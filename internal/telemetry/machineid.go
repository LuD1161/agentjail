package telemetry

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func stableMachineID() string {
	raw := rawMachineID()
	if raw == "" {
		return ""
	}
	h := sha256.Sum256([]byte(raw + "agentjail"))
	return fmt.Sprintf("%x", h)
}

func rawMachineID() string {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					return strings.Trim(strings.TrimSpace(parts[1]), "\"")
				}
			}
		}
		return ""
	case "linux":
		for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			b, err := os.ReadFile(path)
			if err == nil {
				id := strings.TrimSpace(string(b))
				if id != "" {
					return id
				}
			}
		}
		return ""
	default:
		return ""
	}
}
