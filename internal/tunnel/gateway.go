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
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// Gateway is the WireGuard tunnel gateway that intercepts and inspects
// all agent network traffic via gVisor netstack.
type Gateway struct {
	cfg      Config
	registry *dnsvip.Registry
	matcher  *netpolicy.Matcher

	tnet      *netstack.Net
	dev       *device.Device
	kernelTun tun.Device // non-nil only in utun mode (NewGatewayUTun)
	logger    *slog.Logger

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

	mu       sync.Mutex
	closed   bool
	listener net.Listener
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

	// Create the gVisor netstack TUN device. This runs entirely in
	// userspace; no /dev/net/tun or kernel module needed.
	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		nil, // no DNS servers (we handle DNS via the VIP registry)
		cfg.mtu(),
	)
	if err != nil {
		return nil, fmt.Errorf("tunnel: creating netstack TUN: %w", err)
	}

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

	g := &Gateway{
		cfg:      cfg,
		registry: registry,
		matcher:  matcher,
		tnet:     tnet,
		dev:      dev,
		logger:   logger,
	}

	return g, nil
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
	// panic on attacker bytes denies just that connection.
	fs, err := newForwardStack(cfg.mtu(), g.handleConn)
	if err != nil {
		return nil, fmt.Errorf("tunnel: building forward stack: %w", err)
	}
	g.fwd = fs

	return g, nil
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
	if g.fwd != nil {
		g.fwd.Close()
	}
	if g.dev != nil {
		g.dev.Close()
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
