//go:build linux

// This file wires an already-open TUN device fd (opened by the shield inside
// the agent's network namespace and handed over) into the gateway's transparent
// forwarder via the fd<->forwarder packet pump. See ADR 0079 and AGE-148.
package tunnel

import (
	"context"
	"errors"
	"os"
)

// AttachTUN starts pumping IP packets between an already-open TUN device fd and
// this gateway's transparent forwarder. The caller (the shield) opened the TUN
// inside the agent's network namespace and handed the fd over; the gateway
// read()/write()s raw IP packets on it. AttachTUN takes ownership of running the
// pump but NOT of closing f — Close/DetachTUN stops the pump; the caller closes f.
// It must be called on a forward gateway (one built with NewForwardGateway);
// returns an error if there is no forward stack.
func (g *Gateway) AttachTUN(ctx context.Context, f *os.File) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return errors.New("tunnel: AttachTUN on a closed gateway")
	}
	if g.fwd == nil {
		return errors.New("tunnel: AttachTUN requires a forward gateway")
	}
	if g.pump != nil {
		return errors.New("tunnel: AttachTUN already attached to a TUN fd")
	}

	p := newFdPump(f, g.fwd, g.cfg.mtu())
	p.Start(ctx)
	g.pump = p

	g.logger.Info("tunnel: attached netns TUN fd to forward gateway", "mtu", g.cfg.mtu())
	return nil
}

// detachTUN stops the fd<->forwarder pump started by AttachTUN, if any, and
// clears it so a later Close does not double-close. It never closes the TUN fd
// (the caller owns it) — fdPump.Close only stops the pump goroutines. Safe to
// call when nothing is attached. Gateway.Close performs the same teardown for
// the pump under g.mu, so detachTUN is the explicit-detach companion.
func (g *Gateway) detachTUN() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.pump != nil {
		g.pump.Close()
		g.pump = nil
	}
}
