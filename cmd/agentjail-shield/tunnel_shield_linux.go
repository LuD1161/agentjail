//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/netns"
	"github.com/LuD1161/agentjail/internal/tunnel"
)

// tunnelSession bundles one shield's live transparent-tunnel objects so the
// exec path can run the agent inside the namespace and cleanup can tear it all
// down in the right order.
type tunnelSession struct {
	ns        *netns.Namespace
	gw        *tunnel.Gateway
	tun       *os.File
	dns       *dnsvip.Server
	store     *mitm.RequestStore // non-nil when TLS interception is enabled
	caCleanup func()             // removes the temp CA cert dir; nil if no MITM
	cancel    context.CancelFunc
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

	// TLS interception (AGE-149): generate an in-memory CA, inject its public
	// cert into the agent's trust store, and route :443 through the MITM handler
	// so HTTPS is decrypted, policy-checked, and logged to network.db. This is
	// best-effort and fail-open: any failure here leaves a working plain-relay
	// tunnel rather than aborting.
	sess := &tunnelSession{ns: ns, gw: gw, tun: tun, cancel: cancel}
	if caDir, caCert, caKey, caCleanup, err := setupTunnelCA(ns); err != nil {
		logger.Warn("tunnel TLS interception disabled (CA setup failed); relaying HTTPS opaque", "err", err)
	} else {
		sess.caCleanup = caCleanup
		_ = caDir
		if store, serr := mitm.NewRequestStore(mitm.DefaultDBPath()); serr != nil {
			logger.Warn("tunnel TLS interception disabled (network.db open failed)", "err", serr)
		} else {
			sess.store = store
			h := mitm.NewMITMHandler(caCert, caKey, logger, func(rl *mitm.RequestLog) {
				if lerr := store.Log(rl); lerr != nil {
					logger.Debug("network.db log failed", "err", lerr)
				}
			})
			h.Matcher = gw.Matcher() // nil => observe/log only (no PacksDir configured)
			gw.SetMITM(h)
			logger.Info("tunnel TLS interception enabled", "db", mitm.DefaultDBPath())
		}
	}

	go func() {
		if err := gw.ListenAndServe(tunnelCtx); err != nil && tunnelCtx.Err() == nil {
			logger.Error("tunnel gateway error", "err", err)
		}
	}()

	return sess, true
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
	if s.store != nil {
		_ = s.store.Close()
	}
	if s.caCleanup != nil {
		s.caCleanup() // remove the temp CA cert dir (key was never on disk)
	}
	if s.ns != nil {
		_ = s.ns.Close() // SIGKILL the holder -> namespaces torn down
	}
}
