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

// noteH2Downgrade reports, once per session, that a client asked for HTTP/2
// and did not get it. Before AGE-223 this fired whenever a client merely
// offered h2, because http/1.1 was the only thing on offer -- offering h2 and
// then not serving it made every h2-capable client a downgrade. Now h2 is
// genuinely served (NextProtos lists it first, mitm.go Handle branches on
// ConnectionState().NegotiatedProtocol), so an h2 offer that is honored is not
// a downgrade at all; this only fires when the TLS stack picks something else
// despite our server-preference offer of h2 -- a real anomaly, not the common
// case.
//
// Once per session and not per connection: an agent opens many connections
// and this is a property of the session's posture, not of any one request --
// per-connection it would be noise, and noise is ignored.
func (h *MITMHandler) noteH2Downgrade(host string, offered []string) {
	if h.h2Noted.Swap(true) {
		return // already said it this session
	}

	h.Logger.Warn("client offered HTTP/2 but the TLS stack did not negotiate it; agentjail served HTTP/1.1 instead",
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
