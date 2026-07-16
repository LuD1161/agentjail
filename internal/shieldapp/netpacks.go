package shieldapp

import (
	"os"
	"path/filepath"
)

// resolveNetpacksDir returns the L7 template dir (AGENTJAIL_NETPACKS_DIR, else
// ~/.agentjail/netpacks if present), or "" for observe-only. Tag-free: where the
// packs live is not an OS decision. See ADR 0034-platform-backend-shared-contract.
func resolveNetpacksDir() string {
	if d := os.Getenv("AGENTJAIL_NETPACKS_DIR"); d != "" {
		return d
	}
	if home, err := os.UserHomeDir(); err == nil {
		def := filepath.Join(home, ".agentjail", "netpacks")
		if fi, err := os.Stat(def); err == nil && fi.IsDir() {
			return def
		}
	}
	return ""
}
