// Package tunnel routes an agent's network traffic into a single userspace
// gateway for DNS-VIP mapping, protocol recognition, and content-based policy.
//
// # Transparent TCP forwarder (AGE-148 gate 0)
//
// The gateway must accept a SYN to *any* destination the agent dials — the
// destination is a VIP the DNS-VIP layer handed out, never the gateway's own
// address. The security review (docs/reviews/2026-07-08-network-visibility-review.md,
// finding S-F1) showed the previous gateway could not do this: it built its
// stack via wireguard-go's netstack.CreateNetTUN, which sets HandleLocal:true,
// adds only the tunnel's own address, and never enables spoofing/promiscuous
// mode — so ListenTCP(Port:0) binds an ephemeral port on the gateway's own
// address and a SYN to any other destination IP is silently dropped. The
// interception premise was structurally unbuilt.
//
// forwardStack fixes that. It is the "transparent L3 forwarder" pattern: a
// custom gVisor stack (cribbed from internal/tunnel/cbridge/cbridge.go's
// newNetTUN) with HandleLocal:false, SetPromiscuousMode + SetSpoofing on NIC 1
// so the NIC accepts packets to arbitrary destination addresses, and a
// tcp.NewForwarder registered as the TCP protocol handler. The forwarder
// intercepts every inbound SYN regardless of destination, hands us an endpoint
// whose LocalAddr() is the ORIGINAL destination (the VIP), and we surface it as
// a net.Conn to the accept callback.
//
// This file is the standalone forwarder primitive only; wiring it into the
// gateway happens in a later slice. See ADR 0079 for the surrounding
// network-interception design.
package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// forwarderNIC is the single NIC ID the forwarder stack uses.
const forwarderNIC tcpip.NICID = 1

// forwarderQueueSize bounds the channel endpoint's outbound packet queue. It
// mirrors cbridge's sizing: large enough to absorb realistic bursts without
// dropping under whole-machine traffic.
const forwarderQueueSize = 16384

// forwarderMaxInFlight caps the number of half-open (SYN-received) connections
// the TCP forwarder tracks concurrently before it starts refusing new SYNs.
const forwarderMaxInFlight = 1024

// dnsUDPPort is the destination UDP port the forwarder answers from the VIP
// registry; every other UDP port is dropped.
const dnsUDPPort = 53

// dnsMaxQuerySize bounds a single intercepted DNS query datagram (EDNS0 allows
// up to 4096; anything larger is truncated by the read).
const dnsMaxQuerySize = 4096

// dnsReadTimeout bounds how long the UDP handler waits for the agent's query
// datagram after the endpoint is created, so a stalled endpoint cannot leak a
// goroutine indefinitely.
const dnsReadTimeout = 5 * time.Second

// forwardStack is a transparent L3 TCP forwarder built on a gVisor netstack. It
// owns the stack and its channel endpoint. Inbound IP packets are injected via
// InjectInbound; outbound packets (SYN-ACKs, data, RSTs the stack emits) are
// read back via ReadOutbound. Every inbound TCP SYN — to any destination
// address — is intercepted by the registered tcp.Forwarder, turned into a
// net.Conn whose LocalAddr() is the original destination, and delivered to the
// accept callback on its own goroutine.
type forwardStack struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	mtu    int
	accept func(net.Conn)

	// dnsResolve, when non-nil, answers an inbound UDP:53 query datagram (DNS
	// wire format) and returns the response datagram to write back. The agent
	// inside the namespace resolves names via UDP:53, so this is what lets DNS
	// reach the VIP registry and allocate VIPs (AGE-148, review finding W1).
	// When nil, all UDP — including :53 — is dropped.
	dnsResolve func([]byte) ([]byte, error)
}

// newForwardStack builds a transparent forwarder stack. accept is invoked (on a
// fresh goroutine, so it never blocks the forwarder's packet path) for every
// accepted connection; accept must not be nil. dnsResolve answers intercepted
// UDP:53 DNS queries from the VIP registry; when nil, all UDP is dropped.
func newForwardStack(mtu int, accept func(net.Conn), dnsResolve func([]byte) ([]byte, error)) (*forwardStack, error) {
	if accept == nil {
		return nil, fmt.Errorf("tunnel: forwarder accept callback is required")
	}

	fs := &forwardStack{
		ep: channel.New(forwarderQueueSize, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol, ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol, udp.NewProtocol,
				icmp.NewProtocol4, icmp.NewProtocol6,
			},
			// HandleLocal:false routes everything through the link
			// endpoint rather than short-circuiting loopback-style.
			HandleLocal: false,
		}),
		mtu:        mtu,
		accept:     accept,
		dnsResolve: dnsResolve,
	}

	if err := fs.stack.CreateNIC(forwarderNIC, fs.ep); err != nil {
		return nil, fmt.Errorf("tunnel: CreateNIC: %v", err)
	}

	// Promiscuous mode makes the NIC accept packets addressed to any
	// destination (not just its own assigned addresses); spoofing lets the
	// stack originate replies from those foreign addresses. Together they
	// are what let a SYN to an arbitrary VIP reach the forwarder — the S-F1
	// fix.
	if err := fs.stack.SetPromiscuousMode(forwarderNIC, true); err != nil {
		return nil, fmt.Errorf("tunnel: SetPromiscuousMode: %v", err)
	}
	if err := fs.stack.SetSpoofing(forwarderNIC, true); err != nil {
		return nil, fmt.Errorf("tunnel: SetSpoofing: %v", err)
	}

	// Default routes for both families so replies to arbitrary destinations
	// have an egress path back through the channel endpoint.
	fs.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: forwarderNIC})
	fs.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: forwarderNIC})

	// rcvWnd=0 asks the forwarder for the default receive window.
	fwd := tcp.NewForwarder(fs.stack, 0, forwarderMaxInFlight, fs.handleForward)
	fs.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	// UDP forwarder: intercepts every inbound UDP datagram to any destination.
	// Only :53 (DNS) is answered — from the VIP registry — so the agent's name
	// resolution reaches the registry and VIPs get allocated (AGE-148/W1). All
	// other UDP ports are dropped (no exfil/covert channel via raw UDP).
	udpFwd := udp.NewForwarder(fs.stack, fs.handleUDP)
	fs.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return fs, nil
}

// handleForward is the tcp.Forwarder handler. It fires once per inbound SYN.
// r.ID().LocalAddress/LocalPort is the ORIGINAL destination the agent dialed
// (the VIP); r.ID().RemoteAddress/RemotePort is the agent side.
func (fs *forwardStack) handleForward(r *tcp.ForwarderRequest) {
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		// Refuse the connection with a RST rather than leaving the agent
		// hanging on a half-open handshake.
		r.Complete(true)
		return
	}
	r.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	// Never block the forwarder's packet-processing path: hand the accepted
	// conn off to the callback on its own goroutine.
	go fs.accept(conn)
}

// handleUDP is the udp.Forwarder handler. It fires once per inbound UDP
// datagram to any destination. r.ID().LocalPort is the ORIGINAL destination
// port the agent addressed. Only :53 is answered (DNS, from the VIP registry);
// every other UDP port is dropped. The work happens on its own goroutine so it
// never blocks the forwarder's packet path, mirroring handleForward.
func (fs *forwardStack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()

	// Drop non-DNS UDP and DNS when no resolver is wired: no endpoint is
	// created, so the datagram is silently discarded (no response emitted).
	if id.LocalPort != dnsUDPPort || fs.dnsResolve == nil {
		slog.Debug("tunnel: dropping non-DNS UDP datagram",
			"dst_port", id.LocalPort, "src", id.RemoteAddress.String())
		return
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		slog.Debug("tunnel: UDP CreateEndpoint failed", "err", tcpErr)
		return
	}

	go func() {
		// Panic isolation: the resolver runs on attacker-controlled query
		// bytes. A panic must drop just this datagram, never crash the
		// gateway. Mirrors handleConn's S-F2 defer.
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("tunnel: handleUDP recovered from panic; dropping datagram", "panic", rec)
			}
		}()

		conn := gonet.NewUDPConn(&wq, ep)
		defer conn.Close()

		// A DNS query is at most 512 bytes over UDP without EDNS0, and 4096
		// with it; dnsMaxQuerySize bounds a single datagram read.
		buf := make([]byte, dnsMaxQuerySize)
		_ = conn.SetReadDeadline(time.Now().Add(dnsReadTimeout))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			slog.Debug("tunnel: reading UDP DNS query failed", "err", err, "n", n)
			return
		}

		resp, err := fs.dnsResolve(buf[:n])
		if err != nil {
			slog.Debug("tunnel: DNS resolve failed", "err", err)
			return
		}
		if _, err := conn.Write(resp); err != nil {
			slog.Debug("tunnel: writing UDP DNS response failed", "err", err)
		}
	}()
}

// InjectInbound feeds a raw inbound IP packet (as received from the agent side)
// into the stack. The IP version is read from the first nibble; malformed or
// non-IP input is dropped without panicking.
func (fs *forwardStack) InjectInbound(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	switch pkt[0] >> 4 {
	case 4:
		fs.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
	case 6:
		fs.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
	default:
		pkb.DecRef()
	}
}

// ReadOutbound blocks until the stack emits an outbound IP packet (or ctx is
// cancelled) and returns a copy of it. It returns nil when ctx is done.
func (fs *forwardStack) ReadOutbound(ctx context.Context) []byte {
	pkt := fs.ep.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	v := pkt.ToView()
	pkt.DecRef()
	b := v.AsSlice()
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Close tears down the NIC and the underlying stack.
func (fs *forwardStack) Close() error {
	fs.stack.RemoveNIC(forwarderNIC)
	fs.stack.Close()
	fs.ep.Close()
	return nil
}
