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

	// Step 3: Protocol detection via netpolicy.RecognizeTCP.
	op := g.recognizeTCP(hostname, dstPort, peek)

	log = log.With(
		"protocol", op.Protocol,
		"service", op.Service,
		"verb", op.Verb,
	)

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

	// Bidirectional relay.
	relay(c, upstream, log)
}

// recognizeTCP wraps netpolicy.RecognizeTCP with a fallback for unrecognized
// protocols (e.g. HTTPS/TLS on port 443).
func (g *Gateway) recognizeTCP(hostname string, port int, data []byte) *operation {
	op := g.recognizer(hostname, port, data)
	if op != nil {
		return op
	}

	// Fallback: create a generic TCP operation.
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
	}
}

// operation is an alias to avoid a stutter import path.
type operation = netpolicy.Operation

// recognizer calls netpolicy.RecognizeTCP. Extracted for testing.
func (g *Gateway) recognizer(hostname string, port int, data []byte) *operation {
	return netpolicy.RecognizeTCP(hostname, port, data)
}

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
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// client → upstream
	go func() {
		defer wg.Done()
		n, err := io.Copy(upstream, client)
		if err != nil && log != nil {
			log.Debug("relay client→upstream ended", "bytes", n, "err", err)
		}
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}
