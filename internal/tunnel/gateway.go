package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// Gateway is the WireGuard tunnel gateway that intercepts and inspects
// all agent network traffic via gVisor netstack.
type Gateway struct {
	cfg      Config
	registry *dnsvip.Registry
	matcher  *netpolicy.Matcher

	// mitmHandler, when non-nil, enables TLS termination on the forward path:
	// handleConn routes :443 through it (decrypt, policy, log to network.db,
	// re-originate upstream) instead of a plain byte relay. See SetMITM.
	mitmHandler *mitm.MITMHandler

	tnet      *netstack.Net
	dev       *device.Device
	kernelTun tun.Device // non-nil only in utun mode (NewGatewayUTun)
	logger    *slog.Logger

	// serverNS, when non-nil, is the promiscuous gVisor stack backing the
	// WireGuard device (the macOS NE loopback path). Unlike CreateNetTUN's
	// stack it accepts SYNs to ANY destination IP (spoofing+promiscuous), so
	// the agent's real-IP connections are delivered to handleConn instead of
	// dropped. serveTCP is push-based like fwd; ListenAndServe installs it and
	// blocks. See ADR 0104-tunnel-promiscuous-gateway and servernetstack.go.
	serverNS *serverNetstack

	// fwd is non-nil only for a transparent forward gateway
	// (NewForwardGateway). When set, the serve path is push-based: accepted
	// conns arrive via the forwardStack's accept callback (g.handleConn), not
	// via tnet.ListenTCP. This is the S-F1 fix — the stack accepts SYNs to
	// arbitrary VIP destinations. See forwarder.go.
	fwd *forwardStack

	// pump, when set, is the fd<->forwarder packet pump started by AttachTUN
	// (Linux only). It is typed as io.Closer rather than *fdPump so this
	// cross-platform struct compiles on non-Linux targets, where fdPump does
	// not exist; the concrete *fdPump is only referenced in attach_linux.go.
	// Guarded by mu. Close/detachTUN stops it.
	pump io.Closer

	// dnsConn, when non-nil, is a UDP PacketConn bound to localAddr:53 inside
	// tnet. A dnsvip.Server serves DNS on it instead of a host socket, which
	// fails for a VIP-range address the host kernel doesn't own. See
	// DNSPacketConn. nil on a forward gateway (fwd != nil), which answers DNS
	// via forwardStack's own dnsResolve callback instead.
	dnsConn net.PacketConn

	mu       sync.Mutex
	closed   bool
	listener net.Listener

	// lookupIP, when non-nil, overrides net.LookupIP for the S-F3 loop guard.
	// Tests set it to drive resolution deterministically; production leaves it
	// nil (resolveIPs falls back to net.LookupIP).
	lookupIP func(host string) ([]net.IP, error)
}

// NewGateway creates a WireGuard tunnel gateway. It initializes the gVisor
// netstack TUN device, configures the WireGuard peer, and loads policy
// templates. No traffic flows until ListenAndServe is called.
func NewGateway(cfg Config, registry *dnsvip.Registry, logger *slog.Logger) (*Gateway, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if registry == nil {
		return nil, errors.New("tunnel: registry is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Parse the tunnel address.
	prefix, err := netip.ParsePrefix(cfg.TunnelAddr)
	if err != nil {
		return nil, fmt.Errorf("tunnel: parsing tunnel address: %w", err)
	}
	localAddr := prefix.Addr()

	// Create the promiscuous gVisor server netstack. Unlike CreateNetTUN
	// (which adds only localAddr and drops SYNs to any other destination), this
	// stack has SetPromiscuousMode/SetSpoofing enabled, so it accepts the
	// agent's connections to ANY destination IP — the real IPs the agent dials
	// when it did NOT resolve through the tunnel's DNS-VIP, as well as VIPs.
	// Without this the macOS NE loopback path completed the WireGuard handshake
	// but the gateway never answered the tunneled TCP SYN. See ADR
	// 0087-macos-tunnel-promiscuous-gateway.
	serverNS, err := newServerNetstack(localAddr, cfg.mtu())
	if err != nil {
		return nil, fmt.Errorf("tunnel: creating server netstack: %w", err)
	}
	var tunDev tun.Device = serverNS

	// Bridge wireguard-go logging to slog.
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...), "component", "wireguard")
		},
		Errorf: func(format string, args ...any) {
			logger.Error(fmt.Sprintf(format, args...), "component", "wireguard")
		},
	}

	// Create the WireGuard device.
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), wgLogger)

	// Configure the device via the UAPI IPC interface.
	ipcConf, err := buildIPC(cfg)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: building IPC config: %w", err)
	}
	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: IPC set: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: bringing device up: %w", err)
	}

	// Load policy templates (optional; nil matcher means allow-all).
	var matcher *netpolicy.Matcher
	if cfg.PacksDir != "" {
		matcher, err = netpolicy.NewMatcher(cfg.PacksDir)
		if err != nil {
			dev.Close()
			return nil, fmt.Errorf("tunnel: loading policy templates: %w", err)
		}
		logger.Info("loaded policy templates", "dir", cfg.PacksDir)
	}

	// Bind the DNS-VIP server's UDP socket INSIDE the netstack, on the
	// gateway's own tunnel address. A host socket can't bind a VIP-range
	// address the kernel doesn't own; binding inside the stack works because
	// localAddr is the stack's own protocol address (added in newServerNetstack).
	dnsConn, err := serverNS.dnsPacketConn(localAddr, 53)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: creating DNS packet conn: %w", err)
	}

	g := &Gateway{
		cfg:      cfg,
		registry: registry,
		matcher:  matcher,
		serverNS: serverNS,
		dev:      dev,
		dnsConn:  dnsConn,
		logger:   logger,
	}

	return g, nil
}

// bindStackDNSConn binds a UDP PacketConn to addr:53 inside tnet, for a
// dnsvip.Server to serve DNS on. See DNSPacketConn.
func bindStackDNSConn(tnet *netstack.Net, addr netip.Addr) (net.PacketConn, error) {
	conn, err := tnet.ListenUDP(&net.UDPAddr{IP: addr.AsSlice(), Port: 53})
	if err != nil {
		return nil, fmt.Errorf("bind %s:53: %w", addr, err)
	}
	return conn, nil
}

// NewForwardGateway creates a transparent forward gateway. Unlike NewGateway it
// does NOT stand up wireguard-go / netstack.CreateNetTUN: instead it builds a
// forwardStack (see forwarder.go) that accepts a SYN to *any* destination the
// agent dials — the destination VIP is never the gateway's own address — and
// delivers each accepted connection to g.handleConn via the accept callback
// (push), not via tnet.ListenTCP. This is the structural S-F1 fix.
//
// A later slice pumps a TUN fd into the stack through the gateway's
// InjectInbound / ReadOutbound methods. No traffic flows until ListenAndServe
// is called (which, for a forward gateway, simply blocks until ctx is done).
func NewForwardGateway(cfg Config, registry *dnsvip.Registry, logger *slog.Logger) (*Gateway, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if registry == nil {
		return nil, errors.New("tunnel: registry is required")
	}

	// Load policy templates (optional; nil matcher means allow-all). The
	// forward path does not need WireGuard keys, so we do not run the full
	// Config.Validate() — only the fields the forwarder consumes matter.
	var matcher *netpolicy.Matcher
	if cfg.PacksDir != "" {
		m, err := netpolicy.NewMatcher(cfg.PacksDir)
		if err != nil {
			return nil, fmt.Errorf("tunnel: loading policy templates: %w", err)
		}
		matcher = m
		logger.Info("loaded policy templates", "dir", cfg.PacksDir)
	}

	g := &Gateway{
		cfg:      cfg,
		registry: registry,
		matcher:  matcher,
		logger:   logger,
	}

	// Build the transparent forwarder, wiring the gateway's own handleConn as
	// the accept callback. handleConn is panic-isolated (S-F2), so a parser
	// panic on attacker bytes denies just that connection. The DNS resolver
	// closure answers intercepted UDP:53 queries straight from the shared VIP
	// registry (AGE-148/W1) — no import cycle since internal/dnsvip does not
	// import internal/tunnel and this file already depends on dnsvip.
	dnsResolve := func(query []byte) ([]byte, error) {
		return dnsvip.Resolve(g.registry, query)
	}
	fs, err := newForwardStack(cfg.mtu(), g.handleConn, dnsResolve)
	if err != nil {
		return nil, fmt.Errorf("tunnel: building forward stack: %w", err)
	}
	g.fwd = fs

	return g, nil
}

// Matcher returns the gateway's policy matcher (loaded from cfg.PacksDir), or
// nil if none was configured. Callers wire it into the MITM handler so decrypted
// HTTPS is evaluated against the same templates.
func (g *Gateway) Matcher() *netpolicy.Matcher { return g.matcher }

// ListenPort returns the actual UDP port the WireGuard device is bound to. If
// cfg.ListenPort was set explicitly (non-zero), it is returned directly. If it
// was 0 (OS-assigned ephemeral port), the actual bound port is read back from
// the device's UAPI IPC state. Returns 0 if it cannot be determined (e.g. no
// WireGuard device, as in utun mode, or the device isn't up).
func (g *Gateway) ListenPort() int {
	if g.cfg.ListenPort != 0 {
		return g.cfg.ListenPort
	}
	if g.dev == nil {
		return 0
	}
	ipc, err := g.dev.IpcGet()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(ipc, "\n") {
		portStr, ok := strings.CutPrefix(line, "listen_port=")
		if !ok {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return 0
		}
		return port
	}
	return 0
}

// DNSPacketConn returns the netstack-bound UDP packet conn a dnsvip.Server
// should serve DNS on, instead of binding a host socket (which fails for a VIP
// the host kernel doesn't own). Returns nil on a forward gateway (fwd != nil),
// which answers DNS via forwardStack's own dnsResolve callback instead.
func (g *Gateway) DNSPacketConn() net.PacketConn { return g.dnsConn }

// SetMITM enables TLS interception on the transparent forward path. When set,
// handleConn routes :443 connections through the MITM handler (TLS terminate +
// policy + logging to network.db) instead of a plain relay. Leaving it nil (the
// default) keeps the plain relay — fail-open. The same in-memory CA the handler
// signs leaf certs with must be injected into the agent's trust store.
func (g *Gateway) SetMITM(h *mitm.MITMHandler) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mitmHandler = h
}

// ListenAndServe starts accepting TCP connections on the tunnel interface.
// It blocks until ctx is cancelled or an unrecoverable error occurs.
func (g *Gateway) ListenAndServe(ctx context.Context) error {
	// Forward gateways are push-based: conns arrive via the forwardStack's
	// accept callback, so there is nothing to Accept() here. Just block until
	// the context is cancelled, then tear the stack down.
	if g.fwd != nil {
		return g.serveForward(ctx)
	}

	// The promiscuous serverNetstack path is also push-based: serveTCP installs
	// a tcp.NewForwarder that delivers every accepted connection (to any dest)
	// straight to handleConn. See ADR 0104-tunnel-promiscuous-gateway.
	if g.serverNS != nil {
		return g.serveServerNS(ctx)
	}

	// Listen on all addresses, port 0 means accept connections to any port.
	// gVisor netstack with spoofing enabled delivers all TCP SYNs to this
	// listener regardless of destination IP/port.
	ln, err := g.tnet.ListenTCP(&net.TCPAddr{Port: 0})
	if err != nil {
		return fmt.Errorf("tunnel: listen: %w", err)
	}

	g.mu.Lock()
	g.listener = ln
	g.mu.Unlock()

	g.logger.Info("tunnel gateway listening", "addr", g.cfg.TunnelAddr)

	// Close the listener when the context is done.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			// Check if we were shut down intentionally.
			g.mu.Lock()
			closed := g.closed
			g.mu.Unlock()
			if closed {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				g.logger.Error("accept error", "err", err)
				return fmt.Errorf("tunnel: accept: %w", err)
			}
		}
		go g.handleConn(c)
	}
}

// serveServerNS is the serve path for the promiscuous serverNetstack gateway
// (the macOS NE loopback path). serveTCP installs a TCP forwarder that pushes
// every accepted conn (to any destination) into g.handleConn on its own
// goroutine, so like serveForward this simply blocks until ctx is cancelled and
// then tears the stack down. See ADR 0104-tunnel-promiscuous-gateway.
func (g *Gateway) serveServerNS(ctx context.Context) error {
	g.serverNS.serveTCP(g.handleConn)
	g.logger.Info("tunnel gateway listening", "addr", g.cfg.TunnelAddr)
	<-ctx.Done()
	if err := g.Close(); err != nil {
		return err
	}
	return ctx.Err()
}

// serveForward is the serve path for a transparent forward gateway. The
// forwardStack pushes accepted conns into g.handleConn on its own goroutines,
// so this simply blocks until ctx is cancelled and then tears the stack down.
func (g *Gateway) serveForward(ctx context.Context) error {
	g.logger.Info("tunnel forward gateway serving", "mtu", g.cfg.mtu())
	<-ctx.Done()
	// Close() is idempotent and closes the forwardStack; safe to call even if
	// the caller also defers gw.Close().
	if err := g.Close(); err != nil {
		return err
	}
	return ctx.Err()
}

// InjectInbound feeds a raw inbound IP packet (as received from the agent side)
// into the forward gateway's stack. It is a no-op on a non-forward gateway. A
// later slice pumps a TUN fd into this method.
func (g *Gateway) InjectInbound(pkt []byte) {
	if g.fwd != nil {
		g.fwd.InjectInbound(pkt)
	}
}

// ReadOutbound blocks until the forward gateway's stack emits an outbound IP
// packet (or ctx is cancelled) and returns a copy of it. It returns nil when
// ctx is done or on a non-forward gateway.
func (g *Gateway) ReadOutbound(ctx context.Context) []byte {
	if g.fwd == nil {
		return nil
	}
	return g.fwd.ReadOutbound(ctx)
}

// Close shuts down the gateway, closing the WireGuard device and listener.
func (g *Gateway) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return nil
	}
	g.closed = true

	// Stop the fd<->forwarder pump (if AttachTUN started one) before tearing
	// down the stack it feeds. fdPump.Close never closes the caller's fd; it
	// only stops the pump goroutines. Nil it out so Close stays idempotent and
	// never double-closes.
	if g.pump != nil {
		g.pump.Close()
		g.pump = nil
	}
	if g.listener != nil {
		g.listener.Close()
	}
	if g.dnsConn != nil {
		g.dnsConn.Close()
	}
	if g.fwd != nil {
		g.fwd.Close()
	}
	if g.dev != nil {
		g.dev.Close()
	}
	if g.serverNS != nil {
		g.serverNS.Close()
	}
	if g.kernelTun != nil {
		g.kernelTun.Close()
	}

	g.logger.Info("tunnel gateway closed")
	return nil
}

// buildIPC constructs the WireGuard UAPI IPC configuration string.
func buildIPC(cfg Config) (string, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decoding private key: %w", err)
	}
	peerPubBytes, err := base64.StdEncoding.DecodeString(cfg.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("decoding peer public key: %w", err)
	}

	ipc := fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		hex.EncodeToString(privKeyBytes),
		cfg.ListenPort,
		hex.EncodeToString(peerPubBytes),
	)
	return ipc, nil
}
