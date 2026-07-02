//go:build darwin

package tunnel

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// NewGatewayUTun creates a Gateway backed by a kernel utun device on macOS.
//
// Architecture:
//
//	kernel utun ──(IP packets)──> bridge goroutine ──> gVisor netstack
//	kernel utun <─(IP packets)── bridge goroutine <── gVisor netstack
//	                                                        │
//	                                              tnet.ListenTCP (spoofing)
//	                                                        │
//	                                              handleConn: VIP → hostname
//	                                              → policy eval → upstream relay
//
// Unlike NewGateway (which uses gVisor netstack in-memory and WireGuard UDP
// tunnelling), NewGatewayUTun creates a real macOS utun kernel interface and
// bridges IP packets between it and gVisor netstack. The kernel routes all
// agent traffic through the utun interface via the routes set up by
// ConfigureUTunRoutes; the gateway intercepts every TCP connection via the
// gVisor listener regardless of destination VIP.
//
// cfg only requires TunnelAddr; WireGuard keys and ListenPort are not used.
// The caller must call ConfigureUTunRoutes on the returned utunName after this
// function returns, before starting ListenAndServe.
//
// Requires root privileges (must run as LaunchDaemon).
func NewGatewayUTun(cfg Config, registry *dnsvip.Registry, logger *slog.Logger) (*Gateway, string, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if registry == nil {
		return nil, "", errors.New("tunnel: registry is required")
	}
	if cfg.TunnelAddr == "" {
		return nil, "", errors.New("tunnel: tunnel address is required")
	}
	prefix, err := netip.ParsePrefix(cfg.TunnelAddr)
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: parsing tunnel address: %w", err)
	}
	localAddr := prefix.Addr()

	// Create the gVisor netstack for the gateway listener. gVisor runs in
	// spoofing mode (Port:0 in ListenAndServe catches all VIP connections)
	// so no configuration change is needed here — it's identical to NewGateway.
	stackTun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		nil, // DNS handled by the DNS-VIP server, not here
		cfg.mtu(),
	)
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: creating netstack TUN: %w", err)
	}

	// Create the kernel utun device. wireguard-go allocates the next available
	// utunN interface from the macOS kernel without requiring a Network Extension
	// or any app bundle.
	kernelTun, utunName, err := CreateUTun("utun")
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: creating utun: %w", err)
	}

	// Load policy templates (optional; nil matcher means allow-all).
	var matcher *netpolicy.Matcher
	if cfg.PacksDir != "" {
		matcher, err = netpolicy.NewMatcher(cfg.PacksDir)
		if err != nil {
			kernelTun.Close()
			return nil, "", fmt.Errorf("tunnel: loading policy templates: %w", err)
		}
		logger.Info("loaded policy templates", "dir", cfg.PacksDir)
	}

	g := &Gateway{
		cfg:         cfg,
		registry:    registry,
		matcher:     matcher,
		tnet:        tnet,
		dev:         nil, // no WireGuard device in utun mode
		kernelTun:   kernelTun,
		logger:      logger,
	}

	// Bridge goroutines ferry raw IP packets between the kernel utun and the
	// gVisor netstack. Each direction runs independently; both stop when their
	// source device returns an error (which happens on Close).
	go bridgePackets(kernelTun, stackTun, logger)
	go bridgePackets(stackTun, kernelTun, logger)

	logger.Info("utun gateway created", "utun", utunName, "addr", cfg.TunnelAddr)
	return g, utunName, nil
}

// bridgePackets reads IP packets from src and writes them to dst in a loop.
// It exits silently when src.Read returns an error (typically io.EOF or net.ErrClosed
// on device shutdown).
func bridgePackets(src, dst tun.Device, logger *slog.Logger) {
	const batchSize = 16
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	mtu := DefaultMTU + 4 // +4 for any internal header overhead
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}

	for {
		n, err := src.Read(bufs, sizes, 0)
		if err != nil {
			if logger != nil {
				logger.Debug("utun bridge read stopped", "err", err)
			}
			return
		}

		// Build write slices using the actual packet sizes.
		toWrite := make([][]byte, n)
		for i := 0; i < n; i++ {
			toWrite[i] = bufs[i][:sizes[i]]
		}

		if _, err := dst.Write(toWrite, 0); err != nil {
			if logger != nil {
				logger.Debug("utun bridge write stopped", "err", err)
			}
			return
		}
	}
}
