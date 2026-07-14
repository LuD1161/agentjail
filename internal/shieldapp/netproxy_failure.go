package shieldapp

import (
	"context"
	"fmt"
	"os"

	"github.com/LuD1161/agentjail/internal/audit"
)

// abortOnNetproxyFailure is the shared (OS-agnostic) fail-closed decision
// point for a netproxy start failure (binary not found, or start error).
//
// Default posture: if netproxy was requested (the caller did not pass
// --no-netproxy) and it could not be started, the shield refuses to launch
// the agent rather than silently downgrading to port-only egress filtering
// (80/443, no per-host enforcement). A silent downgrade is exactly the kind
// of gap a malicious or misbehaving agent could rely on -- the sandbox
// profile still looks "active" but the network allowlist the user configured
// (network.allowed_hosts / mcp-derived hosts) is no longer enforced.
//
// Egress enforcement is opt-in (--netproxy); this function is only reached
// when the operator explicitly asked for netproxy and it could not start.
// Omitting --netproxy (the default) runs port-only and never reaches here.
//
// An audit.ShieldFailed event is emitted before exit so the downgrade
// attempt (and refusal) is visible in the audit log even though the shield
// never reaches the exec step.
func abortOnNetproxyFailure(ctx context.Context, emitter audit.Emitter, reason string) {
	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.ShieldFailed,
		Entity:    "netproxy",
		Detail:    map[string]string{"reason": reason},
		Actor:     "shield",
	})
	fmt.Fprintf(os.Stderr,
		"agentjail-shield ERROR: %s\n"+
			"  Refusing to launch: netproxy is required for per-host network enforcement\n"+
			"  and could not be started (fail-closed default -- see ADR 0041).\n"+
			"  Omit --netproxy to run port-only (the default: no per-host\n"+
			"  enforcement, TCP allowed on 80/443 only).\n",
		reason,
	)
	os.Exit(1)
}
