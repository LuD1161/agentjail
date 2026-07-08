//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/netns"
	"github.com/LuD1161/agentjail/internal/tunnel"
)

// tunnelSession bundles one shield's live transparent-tunnel objects so the
// exec path can run the agent inside the namespace and cleanup can tear it all
// down in the right order.
type tunnelSession struct {
	ns     *netns.Namespace
	gw     *tunnel.Gateway
	tun    *os.File
	dns    *dnsvip.Server
	cancel context.CancelFunc
}

// startTunnel sets up the unprivileged-userns transparent tunnel (ADR 0049,
// AGE-148): an isolated user+network namespace whose only route is a TUN
// device, with the agent's traffic pumped into a userspace forwarder. No host
// CAP_NET_ADMIN, no privileged daemon, no install password — the privileged
// network operation happens only inside namespaces this process created and
// owns.
//
// It is strictly fail-open: ANY failure returns (nil, false) and the caller
// falls back to netproxy. A broken or unavailable tunnel must never choke the
// agent's network (a hard constraint of this feature).
//
// NOTE (remaining integration gap): the forwarder intercepts TCP to any
// destination, but DNS-VIP resolution over the TUN (UDP) is not yet wired, so
// name resolution inside the namespace does not work end-to-end. --tunnel is
// therefore opt-in and experimental until the DNS-VIP/UDP slice lands. The
// registry is still passed to the gateway so per-VIP policy can attach once DNS
// is wired. See docs/reviews/2026-07-08-network-visibility-review.md (W1).
func startTunnel(ctx context.Context) (*tunnelSession, bool) {
	logger := slog.Default()

	// Create the owned user+net+mount namespaces and the in-namespace TUN,
	// receiving the open TUN fd back over SCM_RIGHTS.
	ns, tun, err := netns.CreateWithTUN(netns.TUNIfName, netns.TUNAddrCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield: transparent tunnel unavailable (%v)\n"+
				"  Falling back to netproxy mode.\n", err)
		return nil, false
	}

	registry := dnsvip.NewRegistry()
	tunnelCtx, cancel := context.WithCancel(ctx)

	// Forward gateway: a userspace gVisor stack that accepts a SYN to any
	// destination the agent dials (the S-F1 transparent-forwarder fix).
	gw, err := tunnel.NewForwardGateway(tunnel.Config{MTU: netns.TUNMTU}, registry, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield: could not create tunnel gateway (%v)\n"+
				"  Falling back to netproxy mode.\n", err)
		cancel()
		_ = tun.Close()
		_ = ns.Close()
		return nil, false
	}

	// Pump raw IP packets between the netns TUN fd and the forwarder.
	if err := gw.AttachTUN(tunnelCtx, tun); err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield: could not attach TUN to gateway (%v)\n"+
				"  Falling back to netproxy mode.\n", err)
		cancel()
		_ = gw.Close()
		_ = tun.Close()
		_ = ns.Close()
		return nil, false
	}

	go func() {
		if err := gw.ListenAndServe(tunnelCtx); err != nil && tunnelCtx.Err() == nil {
			logger.Error("tunnel gateway error", "err", err)
		}
	}()

	return &tunnelSession{ns: ns, gw: gw, tun: tun, cancel: cancel}, true
}

// cleanup tears the tunnel down. Order matters: stop the gateway/pump first (it
// holds the TUN fd), then close the fd, then SIGKILL the namespace holder so the
// kernel reclaims the namespaces. Safe on a nil receiver.
func (s *tunnelSession) cleanup() {
	if s == nil {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.gw != nil {
		_ = s.gw.Close() // also stops the fd pump (Gateway.pump)
	}
	if s.dns != nil {
		_ = s.dns.Close()
	}
	if s.tun != nil {
		_ = s.tun.Close()
	}
	if s.ns != nil {
		_ = s.ns.Close() // SIGKILL the holder -> namespaces torn down
	}
}
