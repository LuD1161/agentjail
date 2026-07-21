// serverNetstack is a userspace, gVisor-backed network stack that implements
// wgtun.Device, so a wireguard-go device.Device can run directly on top of it
// instead of a kernel TUN or golang.zx2c4.com/wireguard/tun/netstack's
// CreateNetTUN. It is a Phase 0 prerequisite for the macOS NE transparent-
// proxy path (AGE-149): that path runs WireGuard over the NE's loopback, and
// needs a stack that intercepts flows to any destination, not just its own
// tunnel address. Wiring it into a Gateway constructor is a later slice; this
// file is the standalone primitive.
//
// Unlike CreateNetTUN (HandleLocal:true, only the gateway's own address
// added), this stack is built with HandleLocal:false and explicit
// SetPromiscuousMode/SetSpoofing calls, so it accepts and forwards packets
// addressed to ANY destination IP — every DNS-VIP address the registry hands
// out, not just the gateway's own. See forwarder.go's forwardStack for the
// same promiscuous-mode pattern applied to the Linux netns/TUN forward path;
// serverNetstack differs in that it is consumed as a wgtun.Device (WireGuard
// device), not via direct packet injection.
//
// No //go:build tag: gVisor and the wireguard tun.Device interface are both
// pure Go and build on every OS. Only the darwin NE wiring that will consume
// this type is platform-specific.
package tunnel

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	wgtun "golang.zx2c4.com/wireguard/tun"
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

// serverNetstackNIC is the only NIC the server netstack ever creates. A
// single NIC is sufficient because it has a single packet source/sink (the
// wgtun.Device Read/Write pair).
const serverNetstackNIC tcpip.NICID = 1

// serverNetstackQueueSize is the per-direction packet capacity of the gVisor
// channel.Endpoint and the inbound buffer: 16384 packets (~24MB at MTU 1500)
// absorbs realistic whole-machine bursts without dropping. Matches
// forwarderQueueSize in forwarder.go.
const serverNetstackQueueSize = 16384

// serverNetstackBatchSize lets a consumer pull up to N packets per Read call,
// amortizing per-packet overhead under burst traffic.
const serverNetstackBatchSize = 128

// serverNetstack is a wgtun.Device backed by a gVisor stack with promiscuous
// mode and spoofing enabled, so it can intercept traffic addressed to any
// destination IP (all DNS-VIP addresses, not just its own).
type serverNetstack struct {
	ep             *channel.Endpoint
	stk            *stack.Stack
	events         chan wgtun.Event
	incomingPacket chan []byte
	done           chan struct{}
	mtu            int
	closed         bool
}

// serverNSNotify pumps outbound packets from the gVisor channel.Endpoint into
// the serverNetstack's incomingPacket queue, where Read drains them for the
// consumer (e.g. a wireguard-go device.Device).
type serverNSNotify struct{ dev *serverNetstack }

func (n *serverNSNotify) WriteNotify() {
	for {
		pkt := n.dev.ep.Read()
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		pkt.DecRef()
		b := v.AsSlice()
		cp := make([]byte, len(b))
		copy(cp, b)
		// Block, do NOT drop, when the buffer is full: dropping silently loses
		// TCP segments the peer expects delivered. Guarded by done so Close
		// can unwedge a blocked send. See ADR 0108-servernetstack-tcp-tuning.
		select {
		case n.dev.incomingPacket <- cp:
		default:
			select {
			case n.dev.incomingPacket <- cp:
			case <-n.dev.done:
				return
			}
		}
	}
}

// tuneServerNetstackTCP enables TCP SACK on the stack, matching the upstream
// wireguard-go tun/netstack reference (which flips it too: gVisor disables SACK
// by default). SACK is a strict improvement for loss recovery. NOTE: SACK +
// buffer-size tuning was investigated as the AGE-259 streaming-hang fix and
// RULED OUT -- on-host loss/latency reproduction showed the hang is not a
// transport window/SACK problem (the transport streams multi-MB SSE cleanly at
// 200ms RTT). SACK stays only as parity with the reference. See ADR 0108.
func tuneServerNetstackTCP(stk *stack.Stack) error {
	sack := tcpip.TCPSACKEnabled(true)
	if e := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); e != nil {
		return fmt.Errorf("serverNetstack: enable TCP SACK: %v", e)
	}
	return nil
}

// newServerNetstack builds a gVisor netstack bound to gwAddr and enables
// promiscuous mode + spoofing on its NIC so the stack accepts and forwards
// packets destined for any IP, not just gwAddr. Without this, the stack
// silently drops all DNS-VIP and real-destination traffic — the interception
// gap this type fixes. See the package-level doc comment above.
func newServerNetstack(gwAddr netip.Addr, mtu int) (*serverNetstack, error) {
	t := &serverNetstack{
		ep: channel.New(serverNetstackQueueSize, uint32(mtu), ""),
		stk: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol, ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol, udp.NewProtocol,
				icmp.NewProtocol4, icmp.NewProtocol6,
			},
			HandleLocal: false,
		}),
		events:         make(chan wgtun.Event, 10),
		incomingPacket: make(chan []byte, serverNetstackQueueSize),
		done:           make(chan struct{}),
		mtu:            mtu,
	}
	if err := tuneServerNetstackTCP(t.stk); err != nil {
		return nil, err
	}
	t.ep.AddNotify(&serverNSNotify{dev: t})
	if e := t.stk.CreateNIC(serverNetstackNIC, t.ep); e != nil {
		return nil, fmt.Errorf("CreateNIC: %v", e)
	}

	if !gwAddr.Is4() {
		return nil, fmt.Errorf("newServerNetstack: gateway address %s is not IPv4", gwAddr)
	}
	pa4 := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(gwAddr.AsSlice()).WithPrefix(),
	}
	if e := t.stk.AddProtocolAddress(serverNetstackNIC, pa4, stack.AddressProperties{}); e != nil {
		return nil, fmt.Errorf("AddProtocolAddress v4: %v", e)
	}

	t.stk.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: serverNetstackNIC})
	t.stk.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: serverNetstackNIC})

	// Promiscuous mode + spoofing: accept and originate packets for any
	// destination/source IP, not just gwAddr. This is the fix — without it,
	// CreateNetTUN-style stacks (HandleLocal:true, no spoofing) drop every
	// packet whose destination the stack doesn't itself own.
	if e := t.stk.SetPromiscuousMode(serverNetstackNIC, true); e != nil {
		return nil, fmt.Errorf("set promiscuous: %v", e)
	}
	if e := t.stk.SetSpoofing(serverNetstackNIC, true); e != nil {
		return nil, fmt.Errorf("set spoofing: %v", e)
	}

	t.events <- wgtun.EventUp
	return t, nil
}

func (t *serverNetstack) File() *os.File             { return nil }
func (t *serverNetstack) Name() (string, error)      { return "agentjail-server-ns", nil }
func (t *serverNetstack) MTU() (int, error)          { return t.mtu, nil }
func (t *serverNetstack) Events() <-chan wgtun.Event { return t.events }
func (t *serverNetstack) BatchSize() int             { return serverNetstackBatchSize }

func (t *serverNetstack) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var pkt []byte
	select {
	case p, ok := <-t.incomingPacket:
		if !ok {
			return 0, os.ErrClosed
		}
		pkt = p
	case <-t.done:
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	count := 1
	for count < len(bufs) {
		select {
		case more, ok := <-t.incomingPacket:
			if !ok {
				return count, os.ErrClosed
			}
			sizes[count] = copy(bufs[count][offset:], more)
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

func (t *serverNetstack) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		switch pkt[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
		}
	}
	return len(bufs), nil
}

func (t *serverNetstack) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	// Signal done BEFORE tearing the stack down so a WriteNotify blocked on a
	// full incomingPacket unwedges via its done-guard. Do NOT close
	// incomingPacket: WriteNotify may still be mid-send, and a send on a closed
	// channel panics. Readers observe closure via the done channel instead.
	close(t.done)
	t.stk.RemoveNIC(serverNetstackNIC)
	t.stk.Close()
	close(t.events)
	return nil
}

// serveTCP installs a TCP forwarder that hands every accepted connection to
// handler, running each in its own goroutine. Because promiscuous mode and
// spoofing are enabled, this intercepts TCP SYNs to any destination IP:port —
// every DNS-VIP address the registry hands out, not just the stack's own
// address.
func (t *serverNetstack) serveTCP(handler func(net.Conn)) {
	fwd := tcp.NewForwarder(t.stk, 1<<20, 16384, func(req *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := req.CreateEndpoint(&wq)
		if err != nil {
			req.Complete(true)
			return
		}
		req.Complete(false)
		go handler(gonet.NewTCPConn(&wq, ep))
	})
	t.stk.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// dnsPacketConn returns a net.PacketConn bound to gwAddr:port INSIDE this
// netstack, for a dnsvip.Server to use instead of binding a host socket.
// Binding host-side to a VIP gateway address like 10.78.0.1:53 fails with
// "can't assign requested address" because the host kernel doesn't own that
// address — only the netstack does. Binding inside the stack (gwAddr is the
// stack's own protocol address, added in newServerNetstack) works because no
// spoofing is required to listen on an address the NIC actually holds.
func (t *serverNetstack) dnsPacketConn(gwAddr netip.Addr, port uint16) (net.PacketConn, error) {
	if !gwAddr.Is4() {
		return nil, fmt.Errorf("dnsPacketConn: gateway address %s is not IPv4", gwAddr)
	}
	laddr := tcpip.FullAddress{
		NIC:  serverNetstackNIC,
		Addr: tcpip.AddrFromSlice(gwAddr.AsSlice()),
		Port: port,
	}
	conn, err := gonet.DialUDP(t.stk, &laddr, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("dnsPacketConn: bind %s:%d: %w", gwAddr, port, err)
	}
	return conn, nil
}
