//go:build linux

// This file bridges a Linux TUN file descriptor to the transparent forwarder
// (forwardStack). See ADR 0075 for the network-interception design and AGE-148
// for the netns TUN handoff slice this belongs to.
//
// # fd <-> forwarder packet pump (AGE-148 slice 2b)
//
// The agent runs in a network namespace whose default route points at a TUN
// device. The kernel hands us each outbound IP packet the agent sends as one
// Read on the device fd (the device is opened with IFF_NO_PI, so there is no
// 4-byte packet-info prefix: one Read == exactly one IP packet). We inject that
// packet into the forwardStack, which intercepts every SYN regardless of
// destination. Replies the stack emits (SYN-ACKs, data, RSTs) are drained back
// out via ReadOutbound and written to the fd, where the kernel delivers them to
// the agent.
//
// fdPump owns neither the fd nor the forwardStack — the caller opened the TUN
// device and built the stack, and the caller closes both. fdPump owns only its
// two pump goroutines; Close stops them and waits for them to exit.
package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// fdPump copies raw IP packets between a TUN file descriptor and a
// forwardStack. The fd delivers one IP packet per Read (IFF_NO_PI); a stand-in
// SOCK_DGRAM socketpair in tests preserves that one-packet-per-read framing.
//
// Ownership: fdPump owns only its goroutines. The caller owns f and fs and is
// responsible for closing them. Close stops the pump — it cancels the outbound
// loop's context and sets a read deadline to interrupt any in-flight inbound
// Read — but never closes f or fs.
type fdPump struct {
	f   *os.File
	fs  *forwardStack
	mtu int

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// newFdPump wires a TUN fd to a forwardStack. mtu bounds the inbound read
// buffer; it should match the device MTU (and the mtu the forwardStack was
// built with). The pump does not start until Start is called.
func newFdPump(f *os.File, fs *forwardStack, mtu int) *fdPump {
	return &fdPump{f: f, fs: fs, mtu: mtu}
}

// Start launches the two pump goroutines and returns immediately. They run
// until ctx is cancelled, Close is called, or the fd is closed. Start must be
// called at most once.
func (p *fdPump) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	p.wg.Add(2)
	go p.inboundLoop(ctx)
	go p.outboundLoop(ctx)
}

// inboundLoop reads IP packets from the fd and injects them into the stack. It
// exits on ctx cancellation, on EOF/closed-fd, or on an unexpected read error.
// A read deadline set by Close surfaces as os.ErrDeadlineExceeded, which the
// top-of-loop ctx check then turns into a clean exit.
func (p *fdPump) inboundLoop(ctx context.Context) {
	defer p.wg.Done()

	buf := make([]byte, p.mtu)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := p.f.Read(buf)
		if n > 0 {
			// Copy: InjectInbound retains the slice inside the stack's
			// packet buffer, so it must not alias the reusable read buffer.
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			p.fs.InjectInbound(pkt)
		}
		if err != nil {
			// A closed fd (the caller's Close) or EOF is the normal exit
			// path; a deadline (our Close nudge) or EINTR just re-checks ctx
			// and retries. Anything else is logged once and ends the loop.
			switch {
			case errors.Is(err, io.EOF), errors.Is(err, os.ErrClosed), errors.Is(err, unix.EBADF):
				return
			case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, unix.EINTR):
				continue
			default:
				if ctx.Err() == nil {
					slog.Debug("tunnel: fd pump inbound read error", "error", err)
				}
				return
			}
		}
	}
}

// outboundLoop drains packets the stack emits and writes them to the fd. It
// exits when ReadOutbound returns nil (ctx done) or a write fails.
func (p *fdPump) outboundLoop(ctx context.Context) {
	defer p.wg.Done()

	for {
		pkt := p.fs.ReadOutbound(ctx)
		if pkt == nil {
			// ctx cancelled: the stack has no more packets to hand us.
			return
		}
		if _, err := p.f.Write(pkt); err != nil {
			if ctx.Err() == nil && !errors.Is(err, os.ErrClosed) {
				slog.Debug("tunnel: fd pump outbound write error", "error", err)
			}
			return
		}
	}
}

// Close stops both pump goroutines and waits for them to exit. It cancels the
// context (unblocking the outbound loop) and sets a read deadline in the past
// (interrupting any pending inbound Read) so the pump is self-terminating
// without the caller having to close the fd first. It does not close the fd or
// the forwardStack — the caller owns those. Close is safe to call even if Start
// was never called.
func (p *fdPump) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	// Best-effort: a fd that does not support deadlines (or is already
	// closed) just means the inbound loop unblocks when the caller closes it.
	_ = p.f.SetReadDeadline(time.Now())
	p.wg.Wait()
	return nil
}
