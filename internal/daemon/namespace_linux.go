//go:build linux

package daemon

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/LuD1161/agentjail/internal/netns"
)

// linuxNamespaceHandler implements NamespaceHandler using the internal/netns
// package. It tracks active namespaces by session ID for cleanup on destroy
// or daemon shutdown.
type linuxNamespaceHandler struct {
	mu     sync.Mutex
	active map[string]*sessionNamespace
	audit  AuditFunc
	logger *slog.Logger
}

// sessionNamespace holds the netns.Namespace and associated metadata for
// one agent session.
type sessionNamespace struct {
	ns       *netns.Namespace
	hostVeth string
	nsVeth   string
}

func newPlatformNamespaceHandler(audit AuditFunc, logger *slog.Logger) NamespaceHandler {
	return &linuxNamespaceHandler{
		active: make(map[string]*sessionNamespace),
		audit:  audit,
		logger: logger,
	}
}

// Create creates a network namespace with a veth pair for the given session.
//
// The privilege model: namespace creation itself is unprivileged (CLONE_NEWUSER),
// but veth pair setup requires CAP_NET_ADMIN in the host namespace. The daemon
// runs with AmbientCapabilities=CAP_NET_ADMIN (see configs/agentjail-daemon.service),
// so this call succeeds without running as root.
func (h *linuxNamespaceHandler) Create(req CreateNamespaceReq) (*CreateNamespaceResp, error) {
	if req.SessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}

	h.mu.Lock()
	if _, exists := h.active[req.SessionID]; exists {
		h.mu.Unlock()
		return nil, fmt.Errorf("namespace already exists for session %q", req.SessionID)
	}
	h.mu.Unlock()

	// Step 1: Create the namespace (unprivileged).
	ns, err := netns.Create()
	if err != nil {
		return nil, fmt.Errorf("create namespace: %w", err)
	}

	// Step 2: Set up the veth pair (requires CAP_NET_ADMIN).
	hostVeth, nsVeth, err := ns.SetupVeth()
	if err != nil {
		// Clean up the namespace on veth failure.
		_ = ns.Close()
		return nil, fmt.Errorf("setup veth: %w", err)
	}

	// Track the namespace.
	h.mu.Lock()
	h.active[req.SessionID] = &sessionNamespace{
		ns:       ns,
		hostVeth: hostVeth,
		nsVeth:   nsVeth,
	}
	h.mu.Unlock()

	resp := &CreateNamespaceResp{
		NamespacePID: ns.PID(),
		HostVeth:     hostVeth,
		NSVeth:       nsVeth,
		HostIP:       netns.VethHostIP,
		NSIP:         netns.VethNsIP,
	}

	h.logger.Info("namespace created",
		"session_id", req.SessionID,
		"pid", resp.NamespacePID,
		"host_veth", resp.HostVeth,
		"ns_veth", resp.NSVeth,
	)
	h.audit("namespace_create", req.SessionID,
		fmt.Sprintf("pid=%d host_veth=%s ns_veth=%s", resp.NamespacePID, resp.HostVeth, resp.NSVeth))

	return resp, nil
}

// Destroy tears down the namespace for the given session. Idempotent.
func (h *linuxNamespaceHandler) Destroy(req DestroyNamespaceReq) error {
	if req.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}

	h.mu.Lock()
	sn, exists := h.active[req.SessionID]
	if !exists {
		h.mu.Unlock()
		// Idempotent: destroying a non-existent session is not an error.
		h.logger.Debug("destroy: no namespace for session (idempotent)", "session_id", req.SessionID)
		return nil
	}
	delete(h.active, req.SessionID)
	h.mu.Unlock()

	if err := sn.ns.Close(); err != nil {
		h.logger.Warn("namespace close error", "session_id", req.SessionID, "err", err)
		// Still emit audit: the namespace holder is being killed.
	}

	h.logger.Info("namespace destroyed", "session_id", req.SessionID)
	h.audit("namespace_destroy", req.SessionID, "")

	return nil
}

// CleanupAll tears down all active namespaces. Called on daemon shutdown.
func (h *linuxNamespaceHandler) CleanupAll() {
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

	h.logger.Info("namespace cleanup complete", "count", len(sessions))
	h.audit("namespace_cleanup_all", "", fmt.Sprintf("count=%d", len(sessions)))
}
