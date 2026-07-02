// Package main is the cgo c-archive bridge between the macOS
// NETransparentProxyProvider Swift extension and the agentjail WireGuard
// tunnel.
//
// This exposes a per-connection L4 API (tcp_connect, udp_connect,
// send, recv, close_conn) instead of a raw packet L3 API. The Swift
// extension operates at L4 — it receives individual TCP flows and UDP
// datagrams from NETransparentProxyProvider, NOT raw IP packets.
//
// Build with:
//
//	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
//	  go build -buildmode=c-archive \
//	  -o build/libagentjail_tunnel.a \
//	  ./internal/tunnel/cbridge/
//
// The package must be "main" for c-archive build mode.
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
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
)

// ---------------------------------------------------------------------------
// netTun: userspace WireGuard TUN backed by a gVisor netstack.
//
// wireguard-go reads outbound IP packets from Read (fed via
// incomingPacket) and writes inbound IP packets to Write (injected
// into the gVisor stack). HandleLocal=false so the stack routes all
// traffic through the WireGuard device.
// ---------------------------------------------------------------------------

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan wgtun.Event
	incomingPacket chan []byte
	mtu            int
	closed         bool
}

type epNotify struct{ dev *netTun }

func (n *epNotify) WriteNotify() {
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
		select {
		case n.dev.incomingPacket <- cp:
		default:
		}
	}
}

// netstackQueueSize: 16384 absorbs realistic bursts under whole-machine
// traffic without dropping.
const netstackQueueSize = 16384

func newNetTUN(addr netip.Addr, addr6 netip.Addr, mtu int) (*netTun, error) {
	t := &netTun{
		ep: channel.New(netstackQueueSize, uint32(mtu), ""),
		stack: stack.New(stack.Options{
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
		incomingPacket: make(chan []byte, netstackQueueSize),
		mtu:            mtu,
	}
	t.ep.AddNotify(&epNotify{dev: t})
	if e := t.stack.CreateNIC(1, t.ep); e != nil {
		return nil, fmt.Errorf("CreateNIC: %v", e)
	}
	pa4 := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
	}
	if e := t.stack.AddProtocolAddress(1, pa4, stack.AddressProperties{}); e != nil {
		return nil, fmt.Errorf("AddProtocolAddress v4: %v", e)
	}
	if addr6.IsValid() {
		pa6 := tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(addr6.AsSlice()).WithPrefix(),
		}
		if e := t.stack.AddProtocolAddress(1, pa6, stack.AddressProperties{}); e != nil {
			return nil, fmt.Errorf("AddProtocolAddress v6: %v", e)
		}
	}
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	t.events <- wgtun.EventUp
	return t, nil
}

func (t *netTun) File() *os.File            { return nil }
func (t *netTun) Name() (string, error)     { return "agentjail-wg", nil }
func (t *netTun) MTU() (int, error)         { return t.mtu, nil }
func (t *netTun) Events() <-chan wgtun.Event { return t.events }
func (t *netTun) BatchSize() int            { return tunBatchSize }

const tunBatchSize = 128

func (t *netTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-t.incomingPacket
	if !ok {
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

func (t *netTun) Write(bufs [][]byte, offset int) (int, error) {
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

func (t *netTun) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	t.stack.RemoveNIC(1)
	t.stack.Close()
	close(t.events)
	close(t.incomingPacket)
	return nil
}

// ---------------------------------------------------------------------------
// Global tunnel state. Only one WireGuard client tunnel per extension
// instance.
// ---------------------------------------------------------------------------

var (
	tun     *netTun
	dev     *device.Device
	mu      sync.Mutex
	started bool
)

// ---------------------------------------------------------------------------
// Connection-handle tracking. Each TCP/UDP flow gets an opaque int64
// ID. Swift drives send/recv/close on these IDs from background
// dispatch queues.
// ---------------------------------------------------------------------------

type connHandle struct {
	conn io.ReadWriteCloser
}

var (
	conns      sync.Map // int64 -> *connHandle
	nextConnID atomic.Int64
)

// ---------------------------------------------------------------------------
// wg-quick config parsing
// ---------------------------------------------------------------------------

// parseWG extracts (PrivateKey, Address, PeerPublicKey, Endpoint,
// PersistentKeepalive) from a wg-quick style config string.
func parseWG(conf string) (priv, addr, peerPub, ep string, ka int, err error) {
	section := ""
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		switch section + "/" + k {
		case "interface/PrivateKey":
			priv = v
		case "interface/Address":
			addr = v
		case "peer/PublicKey":
			peerPub = v
		case "peer/Endpoint":
			ep = v
		case "peer/PersistentKeepalive":
			ka, _ = strconv.Atoi(v)
		}
	}
	if priv == "" || addr == "" || peerPub == "" || ep == "" {
		err = errors.New("wg-conf missing required field (PrivateKey/Address/PublicKey/Endpoint)")
	}
	return
}

// b64ToHex converts a base64 WireGuard key to the hex format that
// wireguard-go's IpcSet expects.
func b64ToHex(b64 string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, len(dec)*2)
	for i, v := range dec {
		out[i*2] = hexd[v>>4]
		out[i*2+1] = hexd[v&0xf]
	}
	return string(out), nil
}

// ---------------------------------------------------------------------------
// Exported C API
// ---------------------------------------------------------------------------

// wg_netstack_init parses a wg-quick config, creates a gVisor netstack
// + wireguard-go device, and brings the tunnel up. Returns 0 on
// success, -1 on error (with errBuf populated).
//
//export wg_netstack_init
func wg_netstack_init(confC *C.char, errBuf *C.char, errLen C.int) C.int {
	mu.Lock()
	defer mu.Unlock()
	if started {
		return 0
	}
	// Raise the per-process file-descriptor limit. macOS extensions
	// default to RLIMIT_NOFILE=256; whole-machine traffic blows past
	// that almost immediately.
	raiseFDLimit()
	conf := C.GoString(confC)
	priv, addr, peerPub, ep, ka, perr := parseWG(conf)
	if perr != nil {
		setErr(errBuf, errLen, perr.Error())
		return -1
	}
	// Address may carry both v4 and v6 separated by ", ". Each part
	// is `addr/prefix`.
	var clientIP, clientIP6 netip.Addr
	for _, part := range strings.Split(addr, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		ip, perr := netip.ParseAddr(s)
		if perr != nil {
			continue
		}
		if ip.Is4() && !clientIP.IsValid() {
			clientIP = ip
		} else if ip.Is6() && !clientIP6.IsValid() {
			clientIP6 = ip
		}
	}
	if !clientIP.IsValid() {
		setErr(errBuf, errLen, "parse client IP: no IPv4 in Address")
		return -1
	}
	t, err := newNetTUN(clientIP, clientIP6, 1420)
	if err != nil {
		setErr(errBuf, errLen, "newNetTUN: "+err.Error())
		return -1
	}
	d := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg "))

	privHex, err := b64ToHex(priv)
	if err != nil {
		setErr(errBuf, errLen, "decode privkey: "+err.Error())
		return -1
	}
	pubHex, err := b64ToHex(peerPub)
	if err != nil {
		setErr(errBuf, errLen, "decode peer pub: "+err.Error())
		return -1
	}
	ipc := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		privHex, pubHex, ep,
	)
	// Force keepalive on so handshake happens at startup rather than
	// waiting for the first user flow's SYN.
	if ka <= 0 {
		ka = 10
	}
	ipc += fmt.Sprintf("persistent_keepalive_interval=%d\n", ka)
	if err := d.IpcSet(ipc); err != nil {
		setErr(errBuf, errLen, "IpcSet: "+err.Error())
		return -1
	}
	if err := d.Up(); err != nil {
		setErr(errBuf, errLen, "device.Up: "+err.Error())
		return -1
	}
	tun = t
	dev = d
	started = true
	return 0
}

// wg_netstack_wait_handshake blocks until the WireGuard peer completes
// a handshake or timeoutMs elapses. Returns 0 on success, -1 on
// timeout. Must be called AFTER wg_netstack_init and BEFORE driving
// any TCP/UDP flows.
//
//export wg_netstack_wait_handshake
func wg_netstack_wait_handshake(timeoutMs C.int) C.int {
	mu.Lock()
	d := dev
	mu.Unlock()
	if d == nil {
		return -1
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	for {
		if cfg, err := d.IpcGet(); err == nil {
			for _, line := range strings.Split(cfg, "\n") {
				if strings.HasPrefix(line, "last_handshake_time_sec=") {
					sec, _ := strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
					if sec > 0 {
						return 0
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return -1
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// wg_netstack_tcp_connect dials host:port through the WireGuard
// netstack and returns a positive connection ID on success, -1 on
// failure. Host must be an IP literal; DNS resolution happens via
// wg_netstack_resolve.
//
// timeoutMs is the dial deadline in milliseconds. <=0 means no timeout.
// Always pass a finite timeout: if the WireGuard peer is unreachable,
// DialContextTCP blocks indefinitely.
//
//export wg_netstack_tcp_connect
func wg_netstack_tcp_connect(hostC *C.char, port C.int, timeoutMs C.int, errBuf *C.char, errLen C.int) C.int64_t {
	if !started {
		setErr(errBuf, errLen, "wg_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		setErr(errBuf, errLen, "parse host: "+err.Error())
		return -1
	}
	proto := ipv4.ProtocolNumber
	if ip.Is6() {
		proto = ipv6.ProtocolNumber
	}
	addr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(port),
	}
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutMs > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
	}
	gconn, err := gonet.DialContextTCP(ctx, tun.stack, addr, proto)
	if err != nil {
		setErr(errBuf, errLen, "DialContextTCP: "+err.Error())
		return -1
	}
	id := nextConnID.Add(1)
	conns.Store(id, &connHandle{conn: gconn})
	return C.int64_t(id)
}

// wg_netstack_udp_connect dials a UDP "connection" through the
// WireGuard netstack (fixed remote, datagram semantics). Returns a
// positive connection ID on success, -1 on failure.
//
//export wg_netstack_udp_connect
func wg_netstack_udp_connect(hostC *C.char, port C.int, errBuf *C.char, errLen C.int) C.int64_t {
	if !started {
		setErr(errBuf, errLen, "wg_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		setErr(errBuf, errLen, "parse host: "+err.Error())
		return -1
	}
	proto := ipv4.ProtocolNumber
	if ip.Is6() {
		proto = ipv6.ProtocolNumber
	}
	addr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(port),
	}
	gconn, err := gonet.DialUDP(tun.stack, nil, &addr, proto)
	if err != nil {
		setErr(errBuf, errLen, "DialUDP: "+err.Error())
		return -1
	}
	id := nextConnID.Add(1)
	conns.Store(id, &connHandle{conn: gconn})
	return C.int64_t(id)
}

// wg_netstack_send writes up to dataLen bytes to the connection
// identified by connID. Blocks until the gVisor stack accepts the
// bytes (TCP back-pressure from slow receiver). Returns bytes written
// or -1 on error.
//
//export wg_netstack_send
func wg_netstack_send(connID C.int64_t, data *C.char, dataLen C.int) C.int {
	v, ok := conns.Load(int64(connID))
	if !ok {
		return -1
	}
	h := v.(*connHandle)
	if dataLen <= 0 {
		return 0
	}
	p := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(dataLen))
	written, err := h.conn.Write(p)
	if err != nil {
		return -1
	}
	return C.int(written)
}

// wg_netstack_recv reads up to bufLen bytes from the connection into
// buf. BLOCKING: waits until at least one byte is available or the
// connection closes. The Swift side must call this on a dedicated
// background pthread/dispatch queue.
//
// Returns:
//
//	> 0 : bytes received
//	  0 : EOF (connection closed cleanly by remote)
//	 -1 : error (connection reset, not found, etc.)
//
//export wg_netstack_recv
func wg_netstack_recv(connID C.int64_t, buf *C.char, bufLen C.int) C.int {
	v, ok := conns.Load(int64(connID))
	if !ok {
		return -1
	}
	h := v.(*connHandle)
	if bufLen <= 0 {
		return 0
	}
	p := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	read, err := h.conn.Read(p)
	if err != nil {
		if read == 0 {
			if err == io.EOF {
				return 0
			}
			return -1
		}
		// Short read with error: return what we got. Next call
		// will surface the error.
	}
	return C.int(read)
}

// wg_netstack_close_conn closes a specific connection and frees its
// slot. Idempotent.
//
//export wg_netstack_close_conn
func wg_netstack_close_conn(connID C.int64_t) {
	if v, ok := conns.LoadAndDelete(int64(connID)); ok {
		_ = v.(*connHandle).conn.Close()
	}
}

// wg_netstack_resolve resolves a hostname to an IPv4 address string
// through the tunnel's DNS (1.1.1.1:53 via the netstack). If the
// input is already an IP literal, it is returned as-is.
//
// Returns 0 on success (IP written to outBuf), -1 on error.
//
//export wg_netstack_resolve
func wg_netstack_resolve(hostC *C.char, outBuf *C.char, outLen C.int) C.int {
	if !started {
		setErr(outBuf, outLen, "wg_netstack not initialized")
		return -1
	}
	host := C.GoString(hostC)
	// Fast path: already an IP literal.
	if _, err := netip.ParseAddr(host); err == nil {
		setErr(outBuf, outLen, host)
		return 0
	}
	// Route DNS queries through the netstack to 1.1.1.1:53.
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr := tcpip.FullAddress{
				NIC:  1,
				Addr: tcpip.AddrFromSlice([]byte{1, 1, 1, 1}),
				Port: 53,
			}
			if strings.HasPrefix(network, "udp") {
				return gonet.DialUDP(tun.stack, nil, &addr, ipv4.ProtocolNumber)
			}
			return gonet.DialContextTCP(ctx, tun.stack, addr, ipv4.ProtocolNumber)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, host)
	if err != nil {
		setErr(outBuf, outLen, "lookup: "+err.Error())
		return -1
	}
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			setErr(outBuf, outLen, ip)
			return 0
		}
	}
	setErr(outBuf, outLen, "no IPv4 for "+host)
	return -1
}

// wg_netstack_close shuts down the entire WireGuard tunnel, closes
// the wireguard-go device and gVisor stack. All open connections
// become invalid after this call.
//
//export wg_netstack_close
func wg_netstack_close() {
	mu.Lock()
	defer mu.Unlock()
	if dev != nil {
		dev.Close()
		dev = nil
	}
	if tun != nil {
		tun.Close()
		tun = nil
	}
	started = false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setErr writes a NUL-terminated error message into a C buffer.
func setErr(buf *C.char, n C.int, msg string) {
	if buf == nil || n <= 0 {
		return
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	limit := len(dst) - 1
	if limit < 0 {
		return
	}
	if len(msg) > limit {
		msg = msg[:limit]
	}
	copy(dst, msg)
	dst[len(msg)] = 0
}

// raiseFDLimit lifts RLIMIT_NOFILE to the hard cap. Idempotent;
// failures (sandbox refuses) are silently ignored.
func raiseFDLimit() {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return
	}
	rlim.Cur = rlim.Max
	if rlim.Cur > 1<<20 {
		rlim.Cur = 1 << 20
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim)
}

func main() {} // required for c-archive build mode
