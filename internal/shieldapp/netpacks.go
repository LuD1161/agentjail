package shieldapp

import (
	"os"
	"path/filepath"
)

// resolveNetpacksDir returns the directory of L7 policy templates to load into
// the tunnel matcher, or "" (observe/log-only) when none is configured. It
// prefers AGENTJAIL_NETPACKS_DIR, then ~/.agentjail/netpacks if that directory
// exists. Returning "" keeps the fail-open default: no templates => no denials,
// just logging.
//
// Tag-free on purpose: where the packs live is not an OS decision, and the
// launch path needs it before any per-OS tunnel code runs.
// ADR 0034-platform-backend-shared-contract.
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
