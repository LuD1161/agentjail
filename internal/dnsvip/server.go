package dnsvip

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Server is a minimal UDP DNS server that intercepts queries inside the
// WireGuard namespace and responds with VIPs from the Registry.
type Server struct {
	registry *Registry
	dns      *dns.Server
	addr     string

	// pc, when set via [PacketConn], is a pre-existing packet conn (e.g. a
	// gVisor netstack *gonet.UDPConn bound to the gateway VIP) that the
	// server reads from directly instead of using the dns library's own
	// recvmmsg-based UDP loop - which type-asserts *net.UDPConn on unix and
	// panics on a userspace netstack conn (see serveConn).
	pc net.PacketConn
}

// NewServer creates a DNS server bound to addr (e.g. "10.78.0.1:53").
// The server is not started until ListenAndServe is called.
func NewServer(addr string, registry *Registry) *Server {
	s := &Server{
		addr:     addr,
		registry: registry,
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNS)

	srv := dns.NewServer()
	srv.Addr = addr
	srv.Net = "udp"
	srv.Handler = mux
	s.dns = srv

	return s
}

// ListenAndServe serves DNS queries until the context is cancelled or Close is
// called. If a PacketConn was set via [PacketConn], the server reads from it
// directly (serveConn); otherwise it binds a new UDP socket via the dns library.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.pc != nil {
		return s.serveConn(ctx, s.pc)
	}

	// started is closed by NotifyStartedFunc once the dns.Server has finished
	// its internal init() and is ready to accept connections. The shutdown
	// goroutine must not call Shutdown() before that point or it races with
	// the init write in the dns library.
	started := make(chan struct{})
	s.dns.NotifyStartedFunc = func(_ context.Context) {
		close(started)
	}

	go func() {
		// Wait until the server is fully initialised before watching the
		// context; otherwise Shutdown() races with dns.Server.init().
		select {
		case <-started:
		case <-ctx.Done():
			// Context cancelled before the server even started; nothing to
			// shut down yet — ListenAndServe will return on its own.
			return
		}
		<-ctx.Done()
		s.dns.Shutdown(context.Background())
	}()

	return s.dns.ListenAndServe()
}

// serveConn is the read loop for a caller-supplied PacketConn (the netstack
// VIP conn). It hand-rolls the UDP DNS loop - read datagram, Unpack, build the
// reply, Pack, write it back - using only the dns library's message codec, so
// it never touches the library's recvmmsg path that requires a *net.UDPConn.
func (s *Server) serveConn(ctx context.Context, pc net.PacketConn) error {
	// Unblock a blocked ReadFrom when the context is cancelled.
	go func() {
		<-ctx.Done()
		_ = pc.SetReadDeadline(time.Now())
	}()

	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				// Deadline fired without cancellation (shouldn't normally
				// happen since we only set it on ctx.Done) - loop.
				continue
			}
			return err
		}

		req := new(dns.Msg)
		req.Data = append([]byte(nil), buf[:n]...)
		if err := req.Unpack(); err != nil {
			slog.Debug("dnsvip: unpack failed", "err", err)
			continue
		}

		resp := buildResponse(s.registry, req)
		if resp == nil {
			continue
		}
		if err := resp.Pack(); err != nil {
			slog.Debug("dnsvip: pack failed", "err", err)
			continue
		}
		if _, err := pc.WriteTo(resp.Data, addr); err != nil {
			slog.Debug("dnsvip: write failed", "err", err)
		}
	}
}

// Close shuts down the server.
func (s *Server) Close() error {
	// The PacketConn path shuts down via context cancellation; only the
	// library-bound path needs an explicit Shutdown (and calling it on an
	// unstarted server is a no-op we avoid).
	if s.pc == nil {
		s.dns.Shutdown(context.Background())
	}
	return nil
}

// Resolve answers a DNS query in wire format using the VIP registry, without
// touching any socket. It unmarshals query, runs the same A → reg.Allocate
// (and AAAA → NODATA) logic as the socket server, and returns the marshalled
// response bytes. It is the entry point for the in-stack UDP:53 interceptor
// (see internal/tunnel/forwarder.go), which cannot use the socket-backed
// dns.Server. An error is returned only when the query cannot be unpacked or
// the response cannot be packed; DNS-level failures (e.g. allocation errors)
// are surfaced as an Rcode in the returned bytes.
func Resolve(reg *Registry, query []byte) ([]byte, error) {
	r := new(dns.Msg)
	// This dns fork unpacks from / packs into the Msg's own Data buffer.
	r.Data = query
	if err := r.Unpack(); err != nil {
		return nil, err
	}
	resp := buildResponse(reg, r)
	if resp == nil {
		return nil, errNoQuestion
	}
	if err := resp.Pack(); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// errNoQuestion is returned by Resolve when the query carries no question
// section (nothing to answer).
var errNoQuestion = errors.New("dnsvip: query has no question")

// handleDNS processes a single DNS query and writes the response.
func (s *Server) handleDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
	resp := buildResponse(s.registry, r)
	if resp == nil {
		return
	}
	if _, err := io.Copy(w, resp); err != nil {
		slog.Debug("dnsvip: failed to write response", "err", err)
	}
}

// buildResponse runs the A/AAAA → registry allocation logic for a single DNS
// query and returns the response message. It returns nil when the query has no
// question (nothing to answer). It is shared by the socket server (handleDNS)
// and the socket-free Resolve entry point so the allocation/response-build
// logic lives in exactly one place.
func buildResponse(reg *Registry, r *dns.Msg) *dns.Msg {
	if len(r.Question) == 0 {
		return nil
	}

	q := r.Question[0]
	qtype := dns.RRToType(q)
	qname := q.Header().Name
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, r)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	switch qtype {
	case dns.TypeA:
		hostname := fqdnToHostname(qname)
		vip, err := reg.Allocate(hostname)
		if err != nil {
			slog.Warn("dnsvip: allocate failed", "host", hostname, "err", err)
			resp.Rcode = dns.RcodeServerFailure
		} else {
			addr, ok := netip.AddrFromSlice(vip.To4())
			if !ok {
				slog.Warn("dnsvip: invalid v4 address", "host", hostname)
				resp.Rcode = dns.RcodeServerFailure
			} else {
				a := &dns.A{
					Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 0},
					A:   rdata.A{Addr: addr},
				}
				resp.Answer = []dns.RR{a}
			}
		}

	case dns.TypeAAAA:
		// The transparent forward stack only routes IPv4 VIPs. Advertising an
		// AAAA record would hand a v6-preferring client an unroutable IPv6 VIP,
		// which it would dial and hang on until timeout (observed: curl -> 000).
		// So we never advertise AAAA VIPs: return NODATA (NOERROR with an empty
		// answer section), the correct DNS response for "name exists, no AAAA
		// record", which makes clients cleanly fall back to the A record. The
		// registry still allocates a v6 VIP alongside every v4 one (via
		// Allocate), so reverse lookups keep working if v6 routing is added.
		break

	default:
		resp.Rcode = dns.RcodeRefused
	}

	return resp
}

// fqdnToHostname strips the trailing dot from an FQDN.
func fqdnToHostname(fqdn string) string {
	if len(fqdn) > 0 && fqdn[len(fqdn)-1] == '.' {
		return fqdn[:len(fqdn)-1]
	}
	return fqdn
}

// PacketConn sets a pre-existing [net.PacketConn] for the server to read from
// instead of binding a new socket. Must be called before [ListenAndServe].
func (s *Server) PacketConn(pc net.PacketConn) {
	s.pc = pc
}
