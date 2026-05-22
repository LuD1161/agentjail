// Package main is agentjail-netproxy — a localhost HTTPS forward proxy that
// enforces per-host egress filtering for sandboxed coding agents.
//
// Agents running under agentjail-shield are restricted by sbpl to reach only
// localhost.  This proxy is started as a child of the shield on localhost:9100.
// The agent sets HTTPS_PROXY=http://127.0.0.1:9100 (or the shield sets it),
// so all HTTPS CONNECT requests flow through here.  The proxy enforces
// network.allowed_hosts from ~/.agentjail/policy.yaml.
//
// Design choices:
//   - stdlib only — no external deps; same module as the root go.mod
//   - CONNECT-only — we only need to tunnel HTTPS; plain HTTP GET would be 405
//   - Wildcard matching: *.example.com matches foo.example.com but not example.com
//   - Reload on SIGHUP: same pattern as agentjail-daemon
//   - Connection cap: 256 concurrent tunnels; 503 when full (fd safety)
//   - Hot path: io.Copy in two goroutines; exits cleanly when either side closes
//
// See also: cmd/agentjail-shield/shield_darwin.go (the parent that launches us)
// See also: docs/adr/0001-os-sandbox-enforcement-layer.md (shield context)
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

const (
	maxConcurrentConns = 256
	defaultAddr        = "127.0.0.1:9100"
)

// allowlist holds the current set of allowed hosts from policy.yaml.
// It is replaced atomically on SIGHUP.
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
	// Wildcard: strip the "*." prefix and check that host ends with ".suffix"
	// AND has at least one more label to the left.
	suffix := pattern[2:] // e.g. "example.com"
	if host == suffix {
		return false // bare domain — wildcard requires a subdomain
	}
	return strings.HasSuffix(host, "."+suffix)
}

// loadPolicy reads the policy file and returns the allowed host list.
// On error it returns an empty slice (fail-open for the proxy — if we
// can't read the policy, deny all would break the agent entirely; caller
// should log the error).
func loadPolicy(path string) ([]string, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return cfg.Network.AllowedHosts, nil
}

// proxy is the forward proxy server.
type proxy struct {
	addr       string
	policyPath string
	al         *allowlist
	connCount  atomic.Int64
	logger     *slog.Logger
}

func newProxy(addr, policyPath string, logger *slog.Logger) *proxy {
	return &proxy{
		addr:       addr,
		policyPath: policyPath,
		al:         &allowlist{},
		logger:     logger,
	}
}

func (p *proxy) reloadPolicy() {
	hosts, err := loadPolicy(p.policyPath)
	if err != nil {
		p.logger.Error("policy reload failed", "path", p.policyPath, "err", err)
		return
	}
	p.al.load(hosts)
	p.logger.Info("policy reloaded", "path", p.policyPath, "allowed_hosts_count", len(hosts))
}

func (p *proxy) run(ctx context.Context) error {
	// Initial policy load.
	p.reloadPolicy()

	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.addr, err)
	}
	defer ln.Close()

	p.logger.Info("agentjail-netproxy listening", "addr", p.addr, "policy", p.policyPath)

	// SIGHUP → reload policy.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				p.logger.Info("SIGHUP received — reloading policy")
				p.reloadPolicy()
			}
		}
	}()

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

// handleConn reads one HTTP request from conn and dispatches it.
// Only CONNECT is supported; anything else gets 405.
func (p *proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()

	// Read the request line manually.  We expect:
	//   CONNECT host:port HTTP/1.1\r\n
	//   [headers]\r\n
	//   \r\n
	//
	// We read byte-by-byte into a line buffer to avoid importing bufio
	// (stdlib only constraint is not that strict, but keeping it simple).
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

	// Drain remaining headers until empty line.
	if err := drainHeaders(conn); err != nil {
		p.logger.Warn("drain headers failed", "client", clientAddr, "err", err)
		return
	}

	if method != "CONNECT" {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Type: text/plain\r\n\r\nagentjail-netproxy only supports HTTPS CONNECT tunneling\n")
		p.logger.Warn("non-CONNECT request", "client", clientAddr, "method", method)
		return
	}

	// Parse host and port from target (e.g. "api.github.com:443").
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nbad CONNECT target: missing host:port\n")
		p.logger.Warn("bad CONNECT target", "client", clientAddr, "target", target, "err", err)
		return
	}

	allowed := p.al.allowed(host)
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
			"HTTP/1.1 403 Forbidden\r\nX-Agentjail-Deny: host=%s\r\nContent-Type: text/plain\r\n\r\nhost not in network.allowed_hosts\n",
			host,
		)
		return
	}

	// Dial the upstream target.
	upstream, err := net.Dial("tcp", target)
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
		// Half-close upstream write side so it sees EOF.
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
	// Wait for both directions to finish.
	<-done
	<-done
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
			// Strip trailing \r if present.
			line := strings.TrimRight(string(buf), "\r")
			return line, nil
		}
		buf = append(buf, b[0])
	}
	return "", fmt.Errorf("request line too long (> %d bytes)", maxLine)
}

// drainHeaders reads and discards HTTP headers until an empty line.
func drainHeaders(r io.Reader) error {
	for {
		line, err := readLine(r)
		if err != nil {
			return err
		}
		if line == "" {
			return nil // blank line = end of headers
		}
	}
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

func defaultPolicyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-policy.yaml"
	}
	return filepath.Join(home, ".agentjail", "policy.yaml")
}

func main() {
	addr := flag.String("addr", defaultAddr, "listen address (default 127.0.0.1:9100)")
	policyPath := flag.String("policy", defaultPolicyPath(), "path to policy.yaml")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: agentjail-netproxy [--addr=HOST:PORT] [--policy=PATH]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  --addr=HOST:PORT    listen address (default 127.0.0.1:9100)")
		fmt.Fprintln(os.Stderr, "  --policy=PATH       path to ~/.agentjail/policy.yaml")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "HTTPS forward proxy that enforces network.allowed_hosts from policy.yaml.")
		fmt.Fprintln(os.Stderr, "Only HTTP CONNECT is supported (HTTPS tunneling).")
		os.Exit(64)
	}
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	p := newProxy(*addr, *policyPath, logger)
	if err := p.run(ctx); err != nil {
		logger.Error("proxy exited with error", "err", err)
		os.Exit(1)
	}
}
