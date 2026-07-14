// Package netproxyapp is agentjail-netproxy — a localhost HTTPS forward proxy that
// enforces PER-SESSION egress filtering for sandboxed coding agents.
//
// One netproxy serves every shielded session on 127.0.0.1:9100. Agents running
// under agentjail-shield are restricted by the OS sandbox to reach only this
// port. Each session registers a per-session allowlist over the control socket
// (see control.go) and is identified on the data plane by an unguessable Token
// carried as the Proxy-Authorization credential (Basic, token as the username).
// The proxy keys the effective allowlist by that Token -- there is NO global
// fallback, so a CONNECT with a missing/unknown/expired token is denied.
//
// Design choices:
//   - stdlib only — no external deps beyond the repo module
//   - CONNECT-only — we tunnel HTTPS; plain HTTP GET is 405
//   - Wildcard matching: *.example.com matches foo.example.com but not example.com
//   - Per-session allowlists via the control plane (no SIGHUP global reload;
//     a policy change is a fresh session launch that re-registers)
//   - Connection cap: 256 concurrent tunnels; 503 when full (fd safety)
//   - Hot path: io.Copy in two goroutines; exits cleanly when either side closes
//
// See also: internal/netproxyapp/control.go (the control plane + registry)
// See also: internal/proxyctl (the shared typed protocol)
// See also: internal/shieldapp/shield_darwin.go (the parent that launches us)
package netproxyapp

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/hostgrant"
	"github.com/LuD1161/agentjail/internal/proxyctl"
	"github.com/LuD1161/agentjail/internal/store"
)

const (
	maxConcurrentConns = 256
	defaultAddr        = "127.0.0.1:9100"
	// reapInterval is how often expired session leases are swept from the
	// registry (they are already denied at lookup the instant they expire; the
	// sweep frees memory and emits the expiry audit event).
	reapInterval = time.Minute
	// maxRequestHeaders bounds the header lines read per CONNECT request so a
	// hostile client cannot stream headers forever (readLine also caps line size).
	maxRequestHeaders = 100
	// upstreamDialTimeout bounds how long a CONNECT waits to establish the
	// upstream TCP connection. Without a timeout, a slow or unreachable
	// upstream hangs the handling goroutine (and the client's tunnel request)
	// indefinitely.
	upstreamDialTimeout = 10 * time.Second
)

// Runtime host grant sentinel. The agent CLI (`agentjail allow host
// <h>`) issues a plain GET through its existing HTTPS_PROXY to this reserved
// authority to FILE a grant request; it is never forwarded upstream --
// handleConn intercepts it after the token/auth lookup but before the generic
// method dispatch (see isGrantSentinel). Hitting the sentinel grants nothing
// by itself, it only records intent for a human to approve/deny over the
// control socket.
const (
	// grantSentinelHost is the reserved authority matched by the sentinel.
	grantSentinelHost = "grant.agentjail.local"
	// grantSentinelPath is the path prefix the sentinel matches.
	grantSentinelPath = "/allow"
	// defaultGrantTTL is used when the sentinel request omits ttl.
	defaultGrantTTL = time.Hour
)

// allowlist holds a set of allowed hosts. One is built per registered session
// (see control.go); it is immutable for that session's lifetime.
type allowlist struct {
	mu    sync.RWMutex
	hosts []string
}

func (a *allowlist) load(hosts []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := make([]string, len(hosts))
	for i, h := range hosts {
		cp[i] = normalizeHost(h)
	}
	a.hosts = cp
}

// allowed returns true if host is in the allowlist (exact or wildcard match).
// host should already be stripped of port.
func (a *allowlist) allowed(host string) bool {
	h := normalizeHost(host)
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, pattern := range a.hosts {
		if matchHost(pattern, h) {
			return true
		}
	}
	return false
}

// normalizeHost lowercases the host and strips any trailing dot (root label).
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimRight(h, "."))
	// Strip port if caller passed host:port
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// matchHost checks whether pattern matches host.
//
// Matching rules:
//   - Exact: "api.github.com" matches "api.github.com"
//   - Wildcard: "*.example.com" matches "foo.example.com" and "foo.bar.example.com"
//     but NOT "example.com" (standard cert-style wildcard — requires at least
//     one label to the left of the dot)
//
// Both sides must already be normalized (lowercase, no trailing dot).
func matchHost(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}
	suffix := pattern[2:] // e.g. "example.com"
	if host == suffix {
		return false // bare domain — wildcard requires a subdomain
	}
	return strings.HasSuffix(host, "."+suffix)
}

// proxy is the forward proxy server. It holds the session registry (the sole
// source of per-session allowlists) and the audit emitter used by the control
// plane and the lease reaper.
type proxy struct {
	addr      string
	registry  *sessionRegistry
	emitter   audit.Emitter
	connCount atomic.Int64
	logger    *slog.Logger
	// durableAudit is true only when emitter is backed by a real, writable
	// store (never audit.NopEmitter). Threaded into the control server so
	// grant_approve can fail closed when audit is unavailable (ADR 0044).
	durableAudit bool
}

func newProxy(addr string, registry *sessionRegistry, emitter audit.Emitter, durableAudit bool, logger *slog.Logger) *proxy {
	return &proxy{
		addr:         addr,
		registry:     registry,
		emitter:      emitter,
		durableAudit: durableAudit,
		logger:       logger,
	}
}

// run acquires the control-plane singleton, serves the control socket, starts
// the lease reaper, and runs the data-plane accept loop. Acquiring the control
// socket is the authoritative singleton gate: if a live proxy already owns it,
// run returns an error and this netproxy refuses to start (the launching shield
// is expected to have fingerprinted and reused the existing proxy instead of
// spawning us).
func (p *proxy) run(ctx context.Context) error {
	cs, err := newControlServer(proxyctl.ControlSocketPath(), p.registry, p.emitter, p.durableAudit, version, p.logger)
	if err != nil {
		return fmt.Errorf("acquire control plane: %w", err)
	}
	defer cs.close()
	go cs.serve(ctx)
	go p.reapLoop(ctx)

	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.addr, err)
	}
	defer ln.Close()

	p.logger.Info("agentjail-netproxy listening", "addr", p.addr, "control_socket", cs.sockPath)

	// Context cancellation closes the listener.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil // clean shutdown
			default:
				p.logger.Error("accept error", "err", err)
				continue
			}
		}

		cur := p.connCount.Add(1)
		if cur > maxConcurrentConns {
			p.connCount.Add(-1)
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 503 Service Unavailable\r\nX-Agentjail-Deny: too-many-connections\r\n\r\ntoo many concurrent connections\n")
			conn.Close()
			continue
		}

		go func() {
			defer p.connCount.Add(-1)
			p.handleConn(conn)
		}()
	}
}

// reapLoop periodically sweeps expired session leases, expired runtime host
// grants, and stale pending grant requests, auditing each (best-effort; see
// ADR 0044 -- only grant_approved is fail-closed).
func (p *proxy) reapLoop(ctx context.Context) {
	t := time.NewTicker(reapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			res := p.registry.reap(time.Now())
			for range res.ExpiredSessions {
				_ = p.emitter.Emit(ctx, audit.Event{EventType: audit.NetproxySessionExpired, Actor: "netproxy"})
			}
			for _, g := range res.ExpiredGrants {
				_ = p.emitter.Emit(ctx, audit.Event{
					EventType: audit.NetproxyGrantExpired,
					Actor:     "netproxy",
					RefID:     g.GrantID,
					Detail:    map[string]string{"host": g.Host},
				})
			}
			if len(res.ExpiredSessions) > 0 || len(res.ExpiredGrants) > 0 {
				p.logger.Info("reaped",
					"expired_sessions", len(res.ExpiredSessions),
					"expired_grants", len(res.ExpiredGrants),
					"live_sessions", p.registry.count())
			}
		}
	}
}

// handleConn reads one HTTP request from conn and dispatches it.
// Only CONNECT is supported; anything else gets 405. A CONNECT must carry a
// valid session token in Proxy-Authorization; otherwise it is denied.
func (p *proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()

	line, err := readLine(conn)
	if err != nil {
		p.logger.Warn("read request line failed", "client", clientAddr, "err", err)
		return
	}

	method, target, _, ok := parseRequestLine(line)
	if !ok {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nbad request line\n")
		p.logger.Warn("bad request line", "client", clientAddr, "line", line)
		return
	}

	// Read headers, capturing the session token from Proxy-Authorization.
	token, err := readHeadersCaptureAuth(conn)
	if err != nil {
		p.logger.Warn("read headers failed", "client", clientAddr, "err", err)
		return
	}

	// Per-session auth: the token selects this session's allowlist. Missing,
	// malformed, unknown, or expired -> deny. There is NO global fallback.
	// Never log the token. This check runs BEFORE the method dispatch (Codex
	// r3 #2) so the grant sentinel below -- and every other request -- is
	// token-bound; only a valid session may even file a grant request.
	tok := proxyctl.Token(token)
	if !p.registry.sessionValid(tok, time.Now()) {
		_, _ = fmt.Fprintf(conn,
			"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"agentjail\"\r\nX-Agentjail-Deny: session-token\r\nContent-Type: text/plain\r\n\r\nmissing or unknown agentjail session token\n")
		p.logger.Warn("deny: unknown/missing session token", "client", clientAddr, "had_token", token != "")
		return
	}

	// Runtime host grant sentinel: a GET to grant.agentjail.local/allow
	// files a pending grant request for THIS session and is never forwarded
	// upstream. Matched before the generic method dispatch so it is not
	// rejected as a non-CONNECT method; a CONNECT to the sentinel authority is
	// NOT a grant request (method must be GET) -- it falls through to the
	// normal CONNECT path below and is denied like any other unlisted host.
	if isGrantSentinel(method, target) {
		p.handleGrantSentinel(conn, tok, target, clientAddr)
		return
	}

	if method != "CONNECT" {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Type: text/plain\r\n\r\nagentjail-netproxy only supports HTTPS CONNECT tunneling\n")
		// Log the request target so we can see WHICH host a client tried to reach
		// with a non-CONNECT method (e.g. a forward-proxy GET the tunnel-only
		// netproxy cannot serve). Target is the request-target, not a secret.
		p.logger.Warn("non-CONNECT request", "client", clientAddr, "method", method, "target", target)
		return
	}

	// Parse host and port from target (e.g. "api.github.com:443").
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nbad CONNECT target: missing host:port\n")
		p.logger.Warn("bad CONNECT target", "client", clientAddr, "target", target, "err", err)
		return
	}

	allowed := p.registry.allowedHost(tok, host, time.Now())
	decision := "allow"
	if !allowed {
		decision = "deny"
	}

	p.logger.Info("connect",
		"host", host,
		"port", port,
		"decision", decision,
		"client", clientAddr,
	)

	if !allowed {
		_, _ = fmt.Fprintf(conn,
			"HTTP/1.1 403 Forbidden\r\nX-Agentjail-Deny: host=%s\r\nContent-Type: text/plain\r\n\r\nhost not in this session's network.allowed_hosts\n",
			host,
		)
		return
	}

	// Dial the upstream target. A timeout is required here -- an unreachable
	// or slow-to-respond upstream must not hang this CONNECT (and the
	// goroutine handling it) indefinitely.
	upstream, err := net.DialTimeout("tcp", target, upstreamDialTimeout)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\ncould not connect to upstream: %v\n", err)
		p.logger.Error("upstream dial failed", "target", target, "err", err)
		return
	}
	defer upstream.Close()

	// Handshake complete: tell client the tunnel is up.
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection established\r\n\r\n")

	// Bidirectional copy until either side closes.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, conn)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// isGrantSentinel reports whether method+target is a runtime host grant
// request: a GET whose target authority is grantSentinelHost and
// whose path starts with grantSentinelPath. A CONNECT to the same authority
// is deliberately NOT a grant request -- only GET .../allow is (Codex r3 #2).
func isGrantSentinel(method, target string) bool {
	if method != http.MethodGet {
		return false
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	return normalizeHost(u.Hostname()) == grantSentinelHost && strings.HasPrefix(u.Path, grantSentinelPath)
}

// handleGrantSentinel files a pending runtime host grant request for tok's
// session and never forwards the request upstream. It validates the host
// (hostgrant.Validate), clamps/validates the requested ttl, bounds reason,
// enforces the per-session/global pending caps, and on success responds 202
// with the minted grant_id. Reject: invalid host/ttl -> 400; over a pending
// cap -> 429. The audit event (grant_requested) is best-effort -- the
// fail-closed record is grant_approved, emitted later by a human decision.
func (p *proxy) handleGrantSentinel(conn net.Conn, tok proxyctl.Token, target, clientAddr string) {
	u, err := url.Parse(target)
	if err != nil {
		writeHTTPError(conn, http.StatusBadRequest, "bad sentinel request target")
		return
	}
	q := u.Query()

	host, verr := hostgrant.Validate(q.Get("host"))
	if verr != nil {
		writeHTTPError(conn, http.StatusBadRequest, fmt.Sprintf("invalid host: %v", verr))
		return
	}

	ttl := defaultGrantTTL
	if raw := q.Get("ttl"); raw != "" {
		d, perr := time.ParseDuration(raw)
		if perr != nil || d <= 0 {
			writeHTTPError(conn, http.StatusBadRequest, fmt.Sprintf("invalid ttl: %q", raw))
			return
		}
		ttl = d
	}
	ttlMs := ttl.Milliseconds()
	if ttlMs > proxyctl.MaxGrantTTLMs {
		ttlMs = proxyctl.MaxGrantTTLMs
	}

	reason := q.Get("reason")
	if len(reason) > proxyctl.MaxReasonLen {
		writeHTTPError(conn, http.StatusBadRequest, fmt.Sprintf("reason exceeds %d bytes", proxyctl.MaxReasonLen))
		return
	}

	pg, err := p.registry.requestGrant(tok, host, ttlMs, reason, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, errPendingCapSession), errors.Is(err, errPendingCapGlobal):
			writeHTTPError(conn, http.StatusTooManyRequests, err.Error())
		default:
			writeHTTPError(conn, http.StatusBadRequest, err.Error())
		}
		p.logger.Warn("grant request rejected", "client", clientAddr, "host", host, "err", err)
		return
	}

	p.logger.Info("grant requested", "client", clientAddr, "grant_id", pg.GrantID, "host", pg.Host)
	_ = p.emitter.Emit(context.Background(), audit.Event{
		EventType: audit.NetproxyGrantRequested,
		Actor:     "netproxy",
		RefID:     pg.GrantID,
		Detail:    map[string]string{"host": pg.Host},
	})

	body := fmt.Sprintf(`{"grant_id":%q,"host":%q,"ttl_ms":%d}`, pg.GrantID, pg.Host, pg.TTLMs)
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

// writeHTTPError writes a minimal HTTP error response with the given status
// and a plain-text body.
func writeHTTPError(conn net.Conn, status int, msg string) {
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\n\r\n%s\n", status, http.StatusText(status), msg)
}

// readLine reads bytes from r until \n (or error), returning the line without
// the trailing \r\n.  Max line length is 8 KiB to prevent abuse.
func readLine(r io.Reader) (string, error) {
	const maxLine = 8 * 1024
	buf := make([]byte, 0, 256)
	b := make([]byte, 1)
	for len(buf) < maxLine {
		_, err := r.Read(b)
		if err != nil {
			return string(buf), err
		}
		if b[0] == '\n' {
			line := strings.TrimRight(string(buf), "\r")
			return line, nil
		}
		buf = append(buf, b[0])
	}
	return "", fmt.Errorf("request line too long (> %d bytes)", maxLine)
}

// readHeadersCaptureAuth reads HTTP headers until an empty line, returning the
// session token parsed from a Proxy-Authorization: Basic header (empty if none).
// It bounds the number of header lines it will read.
func readHeadersCaptureAuth(r io.Reader) (token string, err error) {
	for i := 0; i < maxRequestHeaders; i++ {
		line, err := readLine(r)
		if err != nil {
			return "", err
		}
		if line == "" {
			return token, nil // blank line = end of headers
		}
		if name, val, ok := splitHeader(line); ok && strings.EqualFold(name, "Proxy-Authorization") {
			if tk, ok := parseBasicToken(val); ok {
				token = tk
			}
		}
	}
	return "", fmt.Errorf("too many request headers (> %d)", maxRequestHeaders)
}

// splitHeader splits "Name: value" into its parts (value left-trimmed).
func splitHeader(line string) (name, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	return line[:i], strings.TrimSpace(line[i+1:]), true
}

// parseBasicToken extracts the username (= the agentjail session token) from a
// "Basic <base64(token:)>" Proxy-Authorization value. The password half is
// ignored; agentjail uses the username as the bearer token.
func parseBasicToken(v string) (string, bool) {
	const scheme = "basic "
	v = strings.TrimSpace(v)
	if len(v) < len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) {
		return "", false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(scheme):]))
	if err != nil {
		return "", false
	}
	creds := string(dec)
	if i := strings.IndexByte(creds, ':'); i >= 0 {
		return creds[:i], true
	}
	return creds, true
}

// parseRequestLine splits "METHOD target HTTP/1.x" into its components.
// Returns ok=false if the line is malformed.
func parseRequestLine(line string) (method, target, proto string, ok bool) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// defaultPolicyPath is retained only as the default for the deprecated --policy
// flag (policy is now resolved per-session by the shield and registered over
// the control socket; netproxy no longer reads policy.yaml).
func defaultPolicyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-policy.yaml"
	}
	return filepath.Join(home, ".agentjail", "policy.yaml")
}

// Run executes the agentjail-netproxy entrypoint with the given args (i.e.
// os.Args[1:]) and returns a process exit code.
func Run(args []string) int {
	fs := flag.NewFlagSet("agentjail-netproxy", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "listen address (default 127.0.0.1:9100)")
	// Deprecated: retained so existing shield invocations that pass --policy do
	// not error. netproxy no longer reads policy.yaml; the shield resolves the
	// per-session allowlist and registers it over the control socket.
	_ = fs.String("policy", defaultPolicyPath(), "DEPRECATED: ignored (policy is resolved per-session by the shield)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: agentjail-netproxy [--addr=HOST:PORT] [--log-level=LEVEL]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  --addr=HOST:PORT    listen address (default 127.0.0.1:9100)")
		fmt.Fprintln(os.Stderr, "  --log-level=LEVEL   log level: debug, info, warn, error (default info)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Per-session HTTPS forward proxy. Each shielded session registers its")
		fmt.Fprintln(os.Stderr, "allowlist over the control socket and is identified by a token carried")
		fmt.Fprintln(os.Stderr, "in Proxy-Authorization. Only HTTP CONNECT is supported (HTTPS tunneling).")
	}
	if err := fs.Parse(args); err != nil {
		return 64
	}

	var level slog.Level
	switch strings.ToLower(*logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Store-backed audit emitter (session register/expiry are best-effort). We
	// open the same WAL SQLite the daemon owns; netproxy runs outside the
	// sandbox, so the open succeeds. If it is unavailable, fall back to a no-op
	// so a missing/locked DB never stops the proxy from enforcing egress.
	var emitter audit.Emitter = audit.NopEmitter{}
	// durableAudit gates grant_approve (ADR 0044, Codex r3 #1): a live grant
	// must never be applied without a durable audit record, so approve is
	// refused whenever emitter is NOT backed by the real store below.
	durableAudit := false
	if home, _ := os.UserHomeDir(); home != "" {
		dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
		if st, err := store.Open(dbPath); err == nil {
			emitter = st
			durableAudit = true
			defer st.Close()
		} else {
			logger.Warn("audit store unavailable; session events not persisted", "err", err)
		}
	}

	p := newProxy(*addr, newSessionRegistry(), emitter, durableAudit, logger)
	if err := p.run(ctx); err != nil {
		logger.Error("proxy exited with error", "err", err)
		return 1
	}
	return 0
}
