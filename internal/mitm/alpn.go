package mitm

import (
	"context"
	"strings"

	"github.com/LuD1161/agentjail/internal/audit"
)

// offersH2 reports whether a ClientHello's ALPN list asks for HTTP/2.
// "h2c" is cleartext h2 and never appears in a TLS handshake, so only "h2"
// matters here.
func offersH2(protos []string) bool {
	for _, p := range protos {
		if p == "h2" {
			return true
		}
	}
	return false
}

// noteH2Downgrade reports, once per session, that a client asked for HTTP/2 and
// got HTTP/1.1. Once per session and not per connection: an agent opens many
// connections and this is a property of the session's posture, not of any one
// request -- per-connection it would be noise, and noise is ignored.
//
// A client that can downgrade (curl, most HTTP libraries) is unaffected in
// practice; one that cannot (gRPC) fails. Either way the limitation is stated
// rather than inferred. AGE-222; AGE-223 removes it.
func (h *MITMHandler) noteH2Downgrade(host string, offered []string) {
	if h.h2Noted.Swap(true) {
		return // already said it this session
	}

	h.Logger.Warn("client offered HTTP/2; agentjail's TLS interception serves HTTP/1.1 only",
		"host", host,
		"offered", strings.Join(offered, ","),
		"effect", "clients that cannot fall back to HTTP/1.1 (gRPC) will fail",
		"workaround", "--no-mitm relays TLS opaquely and preserves h2, forfeiting HTTP(S) policy",
	)

	// Best-effort: a missed audit row must never break the agent's network.
	if h.Audit == nil {
		return
	}
	_ = h.Audit.Emit(context.Background(), audit.Event{
		EventType: audit.TunnelALPNDowngraded,
		Entity:    host,
		Detail: map[string]string{
			"offered":  strings.Join(offered, ","),
			"served":   "http/1.1",
			"scope":    "session",
			"fallback": "--no-mitm preserves h2 without HTTP(S) policy",
		},
	})
}
