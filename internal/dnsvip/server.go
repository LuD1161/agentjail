package dnsvip

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"

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

// ListenAndServe binds the UDP socket and serves DNS queries until the context
// is cancelled or Close is called. If a PacketConn was set via [PacketConn],
// the server uses that instead of binding a new socket.
func (s *Server) ListenAndServe(ctx context.Context) error {
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

// Close shuts down the server.
func (s *Server) Close() error {
	s.dns.Shutdown(context.Background())
	return nil
}

// Resolve answers a DNS query in wire format using the VIP registry, without
// touching any socket. It unmarshals query, runs the same A/AAAA → reg.Allocate
// / reg.AllocateV6 logic as the socket server, and returns the marshalled
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
		hostname := fqdnToHostname(qname)
		vip, err := reg.AllocateV6(hostname)
		if err != nil {
			slog.Warn("dnsvip: allocate v6 failed", "host", hostname, "err", err)
			resp.Rcode = dns.RcodeServerFailure
		} else {
			addr, ok := netip.AddrFromSlice(vip.To16())
			if !ok {
				slog.Warn("dnsvip: invalid v6 address", "host", hostname)
				resp.Rcode = dns.RcodeServerFailure
			} else {
				aaaa := &dns.AAAA{
					Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: 0},
					AAAA: rdata.AAAA{Addr: addr},
				}
				resp.Answer = []dns.RR{aaaa}
			}
		}

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

// PacketConn sets a pre-existing [net.PacketConn] for the server to use
// instead of binding a new socket. Must be called before [ListenAndServe].
func (s *Server) PacketConn(pc net.PacketConn) {
	s.dns.PacketConn = pc
}
