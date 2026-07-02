//go:build darwin

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/tunnel"
)

const (
	// utunGatewayIP is the daemon/gateway IP inside the tunnel.
	// The DNS-VIP server listens here; all VIPs are in the 10.78.x.y range.
	utunGatewayIP = "10.78.0.1"

	// utunClientIP is the IP assigned to the agent-facing side of the utun.
	utunClientIP = "10.78.0.2"

	// utunDNSAddr is the address the DNS-VIP server listens on.
	utunDNSAddr = utunGatewayIP + ":53"

	// utunNetworkService is the macOS network service name used with
	// networksetup. "Wi-Fi" covers the common case; wired-only setups may need
	// "Ethernet" or similar — improve detection in a follow-up.
	utunNetworkService = "Wi-Fi"
)

// darwinNamespaceHandler implements NamespaceHandler for macOS using a kernel
// utun device. The daemon (running as root via LaunchDaemon) creates one utun
// per session, configures IP addressing and default routes on it, and runs a
// gateway + DNS-VIP server to intercept and policy-check all agent traffic.
//
// Unlike Linux (which uses network namespaces), macOS has no per-process
// routing tables; the utun is system-wide. Only one active session is
// meaningful at a time, but the handler tracks sessions by ID for clean RPC
// symmetry with the Linux path.
type darwinNamespaceHandler struct {
	mu     sync.Mutex
	active map[string]*darwinSession
	audit  AuditFunc
	logger *slog.Logger
}

// darwinSession holds the live state for one active utun tunnel session.
type darwinSession struct {
	utunName  string
	gateway   *tunnel.Gateway
	dnsServer *dnsvip.Server
	cancelFn  context.CancelFunc
}

func newPlatformNamespaceHandler(audit AuditFunc, logger *slog.Logger) NamespaceHandler {
	return &darwinNamespaceHandler{
		active: make(map[string]*darwinSession),
		audit:  audit,
		logger: logger,
	}
}

// Create allocates a utun-based tunnel for the given session. Steps:
//  1. NewGatewayUTun — creates kernel utun + gVisor netstack bridge
//  2. ConfigureUTunRoutes — assigns IP and adds 0/1 + 128/1 routes
//  3. networksetup — points Wi-Fi DNS at the gateway's DNS-VIP server
//  4. Starts DNS-VIP server and gateway in background goroutines
func (h *darwinNamespaceHandler) Create(req CreateNamespaceReq) (*CreateNamespaceResp, error) {
	if req.SessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}

	h.mu.Lock()
	if _, exists := h.active[req.SessionID]; exists {
		h.mu.Unlock()
		return nil, fmt.Errorf("utun tunnel already exists for session %q", req.SessionID)
	}
	h.mu.Unlock()

	cfg := tunnel.Config{
		TunnelAddr: utunGatewayIP + "/16",
	}

	registry := dnsvip.NewRegistry()

	// Step 1: create utun + bridge to gVisor netstack.
	gw, utunName, err := tunnel.NewGatewayUTun(cfg, registry, h.logger)
	if err != nil {
		return nil, fmt.Errorf("create utun gateway: %w", err)
	}

	// Step 2: configure IP addresses and default routes on the utun.
	if err := tunnel.ConfigureUTunRoutes(utunName, utunClientIP, utunGatewayIP); err != nil {
		_ = gw.Close()
		return nil, fmt.Errorf("configure utun routes: %w", err)
	}

	// Step 3: point system DNS at the gateway's DNS-VIP server (best-effort;
	// if networksetup fails — e.g. no Wi-Fi — proceed without DNS interception).
	if dnsErr := setDNS(utunGatewayIP); dnsErr != nil {
		h.logger.Warn("could not set DNS servers; DNS-VIP interception disabled",
			"err", dnsErr)
	}

	// Step 4: start DNS-VIP server and gateway.
	dnsServer := dnsvip.NewServer(utunDNSAddr, registry)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if srvErr := dnsServer.ListenAndServe(ctx); srvErr != nil && ctx.Err() == nil {
			h.logger.Error("DNS-VIP server error", "session_id", req.SessionID, "err", srvErr)
		}
	}()

	go func() {
		if gwErr := gw.ListenAndServe(ctx); gwErr != nil && ctx.Err() == nil {
			h.logger.Error("utun gateway error", "session_id", req.SessionID, "err", gwErr)
		}
	}()

	sess := &darwinSession{
		utunName:  utunName,
		gateway:   gw,
		dnsServer: dnsServer,
		cancelFn:  cancel,
	}

	// TOCTOU guard: check again under the lock before registering.
	h.mu.Lock()
	if _, exists := h.active[req.SessionID]; exists {
		h.mu.Unlock()
		cancel()
		_ = dnsServer.Close()
		_ = gw.Close()
		tunnel.CleanupUTunRoutes(utunName)
		restoreDNS()
		return nil, fmt.Errorf("utun tunnel already exists for session %q", req.SessionID)
	}
	h.active[req.SessionID] = sess
	h.mu.Unlock()

	h.logger.Info("utun tunnel created",
		"session_id", req.SessionID,
		"utun", utunName,
		"gateway_ip", utunGatewayIP,
	)
	h.audit("utun_create", req.SessionID,
		fmt.Sprintf("utun=%s gateway_ip=%s", utunName, utunGatewayIP))

	return &CreateNamespaceResp{
		UTunName:  utunName,
		GatewayIP: utunGatewayIP,
		HostIP:    utunGatewayIP,
		NSIP:      utunClientIP,
	}, nil
}

// Destroy tears down the utun tunnel for the given session. Idempotent.
func (h *darwinNamespaceHandler) Destroy(req DestroyNamespaceReq) error {
	if req.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}

	h.mu.Lock()
	sess, exists := h.active[req.SessionID]
	if !exists {
		h.mu.Unlock()
		h.logger.Debug("destroy: no utun session (idempotent)", "session_id", req.SessionID)
		return nil
	}
	delete(h.active, req.SessionID)
	h.mu.Unlock()

	// Stop gateway and DNS-VIP server.
	sess.cancelFn()
	_ = sess.dnsServer.Close()
	_ = sess.gateway.Close()

	// Remove routes added by ConfigureUTunRoutes.
	tunnel.CleanupUTunRoutes(sess.utunName)

	// Restore system DNS (best-effort).
	restoreDNS()

	h.logger.Info("utun tunnel destroyed", "session_id", req.SessionID, "utun", sess.utunName)
	h.audit("utun_destroy", req.SessionID, "")

	return nil
}

// CleanupAll tears down all active utun sessions. Called on daemon shutdown.
func (h *darwinNamespaceHandler) CleanupAll() {
	h.mu.Lock()
	sessions := make([]string, 0, len(h.active))
	for sid := range h.active {
		sessions = append(sessions, sid)
	}
	h.mu.Unlock()

	for _, sid := range sessions {
		if err := h.Destroy(DestroyNamespaceReq{SessionID: sid}); err != nil {
			h.logger.Warn("cleanup: destroy failed", "session_id", sid, "err", err)
		}
	}

	h.logger.Info("utun cleanup complete", "count", len(sessions))
	h.audit("utun_cleanup_all", "", fmt.Sprintf("count=%d", len(sessions)))
}

// setDNS points the Wi-Fi DNS at the gateway IP using networksetup.
func setDNS(gatewayIP string) error {
	out, err := exec.Command("networksetup", "-setdnsservers", utunNetworkService, gatewayIP).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup -setdnsservers %s %s: %w (output: %s)",
			utunNetworkService, gatewayIP, err, out)
	}
	return nil
}

// restoreDNS restores the Wi-Fi DNS to system defaults using networksetup.
func restoreDNS() {
	exec.Command("networksetup", "-setdnsservers", utunNetworkService, "Empty").Run()
}
