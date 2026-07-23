package shieldapp

import (
	"os"
	"time"

	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/grantctl"
)

// attestShieldSession tells the daemon this process is a running shield, so its
// descendant agent gets sandbox-redundant filesystem deny rules downgraded.
// Best-effort: any failure leaves the session fully strict (fail-safe).
// See ADR 0111.
func attestShieldSession() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	token, err := ctlauth.Load()
	if err != nil || token == "" {
		return
	}
	_ = grantctl.ShieldAttest(grantctl.ControlSocketPathForHome(home), token, os.Getpid(), 500*time.Millisecond)
}
