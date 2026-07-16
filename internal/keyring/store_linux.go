//go:build linux

package keyring

import "fmt"

// NAMED EXCEPTION (ADR 0034 rule 3): Linux has no keychain backend yet.
// Secret Service is the only primitive that satisfies plan 014 §5's 90-day
// retention (the kernel keyring's persistent keys expire by default, which is
// why §5 rejects option C), and it needs godbus/dbus/v5 promoted from an
// indirect dep to a direct one -- a dependency addition, so an ADR per
// AGENTS.md. Until that lands this reports the same typed ErrNoKeychain a
// headless host gets, which is the case plan 014 §9.2 says is the common one.
func openOSStore() (Store, error) {
	return nil, fmt.Errorf("%w: linux Secret Service backend is not implemented (needs godbus/dbus/v5 + an ADR)", ErrNoKeychain)
}
