//go:build linux

// Guards the multicall re-exec dispatch invariant: a tunnel re-exec MUST present
// argv[0]=agentjail-shield, else the installed symlink resolves to `agentjail`,
// routes to the CLI, and the tunnel silently falls back to netproxy.
// See ADR 0103-shield-reexec-argv0.
package netns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShieldReexecPathPrefersRoleInvocation(t *testing.T) {
	saved := os.Args[0]
	t.Cleanup(func() { os.Args[0] = saved })

	// Invoked through the installed symlink path: keep it verbatim so nsenter
	// dispatches back to the shield role rather than the resolved `agentjail`.
	os.Args[0] = "/home/u/.agentjail/bin/" + shieldRoleName
	if got := shieldReexecPath(); got != os.Args[0] {
		t.Fatalf("role invocation not preserved: got %q want %q", got, os.Args[0])
	}
	if filepath.Base(shieldReexecPath()) != shieldRoleName {
		t.Fatalf("re-exec path basename %q must be the shield role %q",
			filepath.Base(shieldReexecPath()), shieldRoleName)
	}
}

func TestShieldReexecPathFallsBackToExe(t *testing.T) {
	saved := os.Args[0]
	t.Cleanup(func() { os.Args[0] = saved })

	// argv[0] does not name the shield role (e.g. resolved multicall name): fall
	// back to the real executable rather than returning a bogus path.
	os.Args[0] = "agentjail"
	exe, _ := os.Executable()
	if got := shieldReexecPath(); got != exe {
		t.Fatalf("expected fallback to os.Executable() %q, got %q", exe, got)
	}
}

// shieldRoleName must match the case cmd/agentjail main.go dispatches on. A drift
// here re-opens the netproxy-fallback bug, so pin the literal.
func TestShieldRoleNameLiteral(t *testing.T) {
	if shieldRoleName != "agentjail-shield" {
		t.Fatalf("shieldRoleName=%q; multicall dispatch expects \"agentjail-shield\"", shieldRoleName)
	}
}
