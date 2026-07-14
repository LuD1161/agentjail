// rolesymlinks.go — role binary symlink management (multicall-binary refactor).
//
// As of the multicall-binary refactor, agentjail ships exactly two real
// binaries: `agentjail` (the multicall CLI/daemon/shield/netproxy/secrets
// binary, dispatched by argv[0] — see cmd/agentjail/main.go) and
// `agentjail-hook` (a separate, lean binary). The four role names below are
// never real files on disk; they are relative symlinks to the `agentjail`
// binary in the same directory, so argv[0] dispatch sees the expected role
// name no matter how the binary was invoked.
//
// This lives in internal/selfupdate (rather than cmd/agentjail) because both
// the CLI install/update paths (cmd/agentjail) and the daemon's background
// auto-update (internal/daemonapp) need to reconcile role symlinks after
// swapping in a new agentjail binary, and cmd/agentjail is a `main` package
// that cannot be imported.
package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
)

// RoleNames lists the four role binary names that must be symlinks to the
// multicall `agentjail` binary. agentjail-hook is deliberately excluded: it
// ships as its own separate binary and is never dispatched via the argv[0]
// switch in cmd/agentjail/main.go.
var RoleNames = []string{
	"agentjail-daemon",
	"agentjail-shield",
	"agentjail-netproxy",
	"agentjail-secrets",
}

// EnsureRoleSymlinks makes each of the four role names in binDir a relative
// symlink to "agentjail" (the multicall binary, which MUST already exist in
// binDir before this is called). Whatever currently occupies a role path —
// a stale real file (the watchpoint this refactor guards against) or an
// existing symlink — is removed first via Lstat+Remove (never dereferenced),
// then replaced with a fresh symlink. Idempotent and safe to re-run.
//
// binDir is created with 0700 if it does not already exist.
//
// THE WATCHPOINT: any install/update code path that lays down a role binary
// by name must call this AFTER the real `agentjail` binary has been written
// to binDir, and must never os.Rename/copy a real multicall binary directly
// over a role path — doing so would silently replace the symlink with a
// real file, and the role binary would stop tracking future agentjail
// upgrades.
func EnsureRoleSymlinks(binDir string) error {
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", binDir, err)
	}

	const target = "agentjail" // relative — resolves inside binDir regardless of its absolute path

	for _, role := range RoleNames {
		link := filepath.Join(binDir, role)

		if _, err := os.Lstat(link); err == nil {
			if err := os.Remove(link); err != nil {
				return fmt.Errorf("remove stale %s: %w", link, err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("lstat %s: %w", link, err)
		}

		if err := os.Symlink(target, link); err != nil {
			return fmt.Errorf("symlink %s -> %s: %w", link, target, err)
		}
	}

	return nil
}

// RemoveRoleSymlinks removes the four role symlinks from binDir. Best-effort
// and idempotent — a role path that is already absent (or binDir itself
// absent) is not an error, since uninstall must tolerate a partially or
// already torn-down install.
func RemoveRoleSymlinks(binDir string) {
	for _, role := range RoleNames {
		_ = os.Remove(filepath.Join(binDir, role))
	}
}
