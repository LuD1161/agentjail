package tunnel

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/LuD1161/agentjail/internal/netpolicy"
)

const (
	// peekSize is how many bytes we read for protocol detection.
	// Must be large enough for TLS ClientHello SNI, Postgres startup,
	// Redis RESP, MongoDB OpMsg header, and SSH version string.
	peekSize = 1024

	// maxManagedInspections bounds how many client→upstream chunks we
	// re-inspect on a managed-port connection (S-D2). After this many chunks
	// the remainder of the stream is relayed without re-inspection. This caps
	// per-connection CPU so a long-lived managed connection cannot force
	// unbounded parser+matcher work; each inspection is itself bounded to the
	// first peekSize bytes of the chunk. 64 comfortably covers the handful of
	// distinct statements a normal DB session issues while denying an attacker
	// a cheap CPU-exhaustion primitive.
	maxManagedInspections = 64
)

// handleConn processes a single intercepted TCP connection:
//  1. Extract destination IP:port
//  2. Look up VIP in dnsvip.Registry to get the real hostname
//  3. Peek at the first bytes for protocol detection
//  4. Evaluate the operation against policy templates
//  5. Relay or deny
func (g *Gateway) handleConn(c net.Conn) {
	// Panic isolation (S-F2): handleConn runs on attacker-controlled bytes and
	// addresses (protocol recognition, type assertions, policy evaluation). A
	// panic must DENY this one connection — close it and return — never allow
	// traffic and never crash the gateway process. This defer is registered
	// first so it runs last, after c.Close below has already closed the conn;
	// it also closes c defensively in case the panic pre-empted that defer.
	defer func() {
		if r := recover(); r != nil {
			g.logger.Error("handleConn recovered from panic; denying connection", "panic", r)
			_ = c.Close()
		}
	}()
	defer c.Close()

	remote := c.RemoteAddr().(*net.TCPAddr)
	local := c.LocalAddr().(*net.TCPAddr)

	dstIP := local.IP
	dstPort := local.Port

	log := g.logger.With(
		"src", remote.String(),
		"dst_ip", dstIP.String(),
		"dst_port", dstPort,
	)

	// Step 1: Resolve VIP to hostname.
	hostname, ok := g.registry.Lookup(dstIP)
	if !ok {
		// No VIP mapping; use the raw IP as the hostname.
		hostname = dstIP.String()
		log.Warn("no VIP mapping for destination", "ip", dstIP.String())
	}
	log = log.With("hostname", hostname)

	// TLS interception (AGE-149): if MITM is enabled and this is the HTTPS
	// port, terminate TLS here — decrypt, run policy, log to network.db, and
	// re-originate upstream — instead of relaying opaque bytes. The handler
	// reads the ClientHello directly, so this must run BEFORE the peek below.
	// handleConn's recover() still guards this path (S-F2); a nil handler
	// (the default) falls through to the plain relay (fail-open).
	g.mu.Lock()
	mh := g.mitmHandler
	g.mu.Unlock()
	if mh != nil && dstPort == 443 {
		log.Debug("routing connection through MITM (TLS interception)")
		mh.Handle(c, hostname, strconv.Itoa(dstPort))
		return
	}

	// Step 2: Peek at the first bytes for protocol detection.
	// We use a peekConn to buffer the peeked bytes so they can be
	// replayed to the upstream connection.
	peek := make([]byte, peekSize)
	n, err := c.Read(peek)
	if err != nil && n == 0 {
		log.Debug("connection closed before data", "err", err)
		return
	}
	peek = peek[:n]

	// Step 3: Protocol detection via netpolicy.RecognizeTCP. recognized is true
	// only when a real protocol parser matched; false means we fell back to the
	// generic "connect" operation.
	op, recognized := g.recognizeTCP(hostname, dstPort, peek)

	log = log.With(
		"protocol", op.Protocol,
		"service", op.Service,
		"verb", op.Verb,
	)

	// Step 3.5: Fail-closed on managed database ports (S-D1). If this is a
	// managed DB port but we could NOT confidently recognize the protocol
	// (truncated/unparseable/insufficient bytes → generic fallback), treat it as
	// UNKNOWN and DENY without relaying. Anything that dodges recognition would
	// otherwise dodge the verb-keyed deny-list packs. Non-managed ports (80, 443,
	// …) are unaffected and remain allow-by-default to preserve availability.
	if !recognized && netpolicy.ManagedPort(dstPort) {
		log.Warn("unknown protocol on managed port; denying (fail-closed)")
		return
	}

	// Step 4: Policy evaluation.
	if g.matcher != nil {
		result := g.matcher.Evaluate(op)
		if result != nil && result.Action == "deny" {
			log.Warn("connection denied by policy",
				"template", result.Template.ID,
				"reason", result.Reason,
			)
			return
		}
		if result != nil {
			log = log.With("policy_action", result.Action, "template", result.Template.ID)
		}
	}

	// Step 4.5: VIP-pool loop guard (S-F3). The VIP→hostname mapping is
	// attacker-influenced (a crafted mapping, or a hostname that resolves into
	// the VIP CIDR). If the upstream we are about to dial is itself inside the
	// pool, dialing it re-enters our own forwarder → an infinite interception
	// loop / resource exhaustion. Resolve the target to concrete IPs and refuse
	// if ANY lands in the pool (CIDR membership) or is a currently-allocated VIP
	// (registry.Lookup). Deny by closing without relaying. A resolution failure
	// is not a loop — let the dial below fail naturally.
	if g.upstreamHitsVIPPool(hostname) {
		log.Warn("upstream resolves into the VIP pool; denying (loop guard)")
		return
	}

	log.Info("connection allowed, relaying")

	// Step 5: Dial the real upstream and relay bidirectionally.
	upstream, err := net.Dial("tcp", net.JoinHostPort(hostname, strconv.Itoa(dstPort)))
	if err != nil {
		log.Error("failed to dial upstream", "err", err)
		return
	}
	defer upstream.Close()

	// Replay the peeked bytes to the upstream first.
	if _, err := upstream.Write(peek); err != nil {
		log.Error("failed to write peeked bytes to upstream", "err", err)
		return
	}

	// Bidirectional relay. On a managed database port we re-inspect subsequent
	// client→upstream messages so a benign first message cannot smuggle a later
	// deny verb past policy (S-D2). Non-managed ports keep the plain relay to
	// preserve availability.
	if netpolicy.ManagedPort(dstPort) {
		g.relayManaged(c, upstream, hostname, dstPort, log)
	} else {
		relay(c, upstream, log)
	}
}

// upstreamHitsVIPPool resolves host to concrete IPs and reports whether any of
// them is a VIP — either by CIDR membership in a pool (authoritative, covers
// unallocated addresses) or by a live registry Lookup. Used by the S-F3 loop
// guard before dialing an upstream. A resolution error returns false: an
// unresolvable host is not a loop, and the subsequent dial will fail on its own.
func (g *Gateway) upstreamHitsVIPPool(host string) bool {
	ips, err := g.resolveIPs(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if g.registry != nil && g.registry.IsVIP(ip) {
			return true
		}
		if g.registry != nil {
			if _, ok := g.registry.Lookup(ip); ok {
				return true
			}
		}
	}
	return false
}

// resolveIPs resolves a host (hostname or IP literal) to IP addresses. It is a
// thin wrapper over net.LookupIP that tests can override via g.lookupIP; an IP
// literal is returned as-is by net.LookupIP without any network I/O.
func (g *Gateway) resolveIPs(host string) ([]net.IP, error) {
	if g.lookupIP != nil {
		return g.lookupIP(host)
	}
	return net.LookupIP(host)
}

// recognizeTCP wraps netpolicy.RecognizeTCP with a fallback for unrecognized
// protocols (e.g. HTTPS/TLS on port 443). The second return value reports
// whether a real protocol parser matched (true) or we synthesized the generic
// "connect" fallback (false); the caller branches on this to fail closed on
// managed database ports.
func (g *Gateway) recognizeTCP(hostname string, port int, data []byte) (*operation, bool) {
	op := g.recognizer(hostname, port, data)
	if op != nil {
		return op, true
	}

	// Fallback: create a generic TCP operation. This is NOT a confident
	// recognition — signal that to the caller via the false return.
	proto := "tcp"
	if port == 443 {
		proto = "tls"
	} else if port == 80 {
		proto = "http"
	}

	return &operation{
		Protocol: proto,
		Service:  hostname,
		Verb:     "connect",
		Host:     fmt.Sprintf("%s:%d", hostname, port),
	}, false
}

// operation is an alias to avoid a stutter import path.
type operation = netpolicy.Operation

// recognizer calls netpolicy.RecognizeTCP. Extracted for testing.
func (g *Gateway) recognizer(hostname string, port int, data []byte) *operation {
	return netpolicy.RecognizeTCP(hostname, port, data)
}

// halfCloser is implemented by both *net.TCPConn and gVisor's *gonet.TCPConn
// (the client conn on the transparent forward path). relay uses it to propagate
// a half-close (FIN) to the peer when one direction's copy ends, so e.g. an
// upstream that closes first delivers EOF to the in-ns agent instead of leaving
// it blocked on a read. Asserting only *net.TCPConn silently dropped the FIN on
// the forward path, where the client side is never a *net.TCPConn.
type halfCloser interface{ CloseWrite() error }

// relay copies data bidirectionally between two connections.
// It returns when either direction's copy completes or errors.
func relay(client, upstream net.Conn, log *slog.Logger) {
	var wg sync.WaitGroup
	wg.Add(2)

	// upstream → client
	go func() {
		defer wg.Done()
		n, err := io.Copy(client, upstream)
		if err != nil && log != nil {
			log.Debug("relay upstream→client ended", "bytes", n, "err", err)
		}
		// Signal the other direction to stop by closing the write half.
		if hc, ok := client.(halfCloser); ok {
			_ = hc.CloseWrite()
		}
	}()

	// client → upstream
	go func() {
		defer wg.Done()
		n, err := io.Copy(upstream, client)
		if err != nil && log != nil {
			log.Debug("relay client→upstream ended", "bytes", n, "err", err)
		}
		if hc, ok := upstream.(halfCloser); ok {
			_ = hc.CloseWrite()
		}
	}()

	wg.Wait()
}

// relayManaged is the S-D2 inspecting relay used for managed database ports. It
// preserves the plain relay's bidirectionality and half-close semantics but, on
// the client→upstream direction, re-inspects each read chunk before forwarding
// it so a benign first message cannot smuggle a later deny verb (e.g. a Postgres
// DROP after an opening SELECT) past policy.
//
// Re-inspection policy (deliberately asymmetric with the S-D1 first-message
// fail-closed):
//   - Each chunk is recognized with recognizeTCP over its first peekSize bytes.
//   - If recognition succeeds AND the matcher returns deny → tear the connection
//     down immediately (mid-stream deny).
//   - If recognition succeeds with allow/ask → forward the chunk.
//   - If recognition FAILS (recognizeTCP's generic fallback) → forward the chunk.
//     Mid-stream, an arbitrary TCP segment is not guaranteed to start on a
//     protocol message boundary, so an unrecognized continuation segment of an
//     already-recognized benign message must NOT be denied (that would break
//     legitimate multi-packet messages / availability). S-D1 still guards the
//     FIRST message at connection establishment, where a boundary is guaranteed.
//   - Inspection is bounded: after maxManagedInspections chunks the remainder is
//     relayed without re-inspection to cap per-connection CPU.
//
// The client→upstream goroutine runs protocol parsers and the matcher on
// attacker-controlled bytes, so it carries its own recover to keep S-F2 panic
// isolation intact (a panic denies this connection, never crashes the process).
func (g *Gateway) relayManaged(client, upstream net.Conn, hostname string, port int, log *slog.Logger) {
	var wg sync.WaitGroup
	wg.Add(2)

	// upstream → client (plain copy; upstream is trusted relative to the agent).
	go func() {
		defer wg.Done()
		n, err := io.Copy(client, upstream)
		if err != nil && log != nil {
			log.Debug("managed relay upstream→client ended", "bytes", n, "err", err)
		}
		// Propagate the half-close so the in-ns agent sees EOF. On the forward
		// path client is a *gonet.TCPConn, not *net.TCPConn, so assert the
		// shared halfCloser interface (see relay()).
		if hc, ok := client.(halfCloser); ok {
			_ = hc.CloseWrite()
		}
	}()

	// client → upstream (inspecting).
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				if log != nil {
					log.Error("managed relay recovered from panic; tearing down connection", "panic", r)
				}
				_ = upstream.Close()
				_ = client.Close()
			}
		}()

		buf := make([]byte, peekSize)
		inspections := 0
		for {
			n, err := client.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if inspections < maxManagedInspections {
					inspections++
					op, recognized := g.recognizeTCP(hostname, port, chunk)
					if recognized && g.matcher != nil {
						if res := g.matcher.Evaluate(op); res != nil && res.Action == "deny" {
							if log != nil {
								log.Warn("managed-port deny mid-stream; tearing down connection",
									"protocol", op.Protocol,
									"verb", op.Verb,
								)
							}
							_ = upstream.Close()
							_ = client.Close()
							return
						}
					}
				}
				if _, werr := upstream.Write(chunk); werr != nil {
					if log != nil {
						log.Debug("managed relay client→upstream write ended", "err", werr)
					}
					return
				}
			}
			if err != nil {
				if err != io.EOF && log != nil {
					log.Debug("managed relay client→upstream read ended", "err", err)
				}
				if hc, ok := upstream.(halfCloser); ok {
					_ = hc.CloseWrite()
				}
				return
			}
		}
	}()

	wg.Wait()
}
