// Package daemon provides RPC handlers for the agentjail-daemon. The daemon
// runs as a privileged service (CAP_NET_ADMIN) and performs operations that
// unprivileged agents cannot, following the Docker pattern: dockerd holds
// privilege, the docker CLI does not.
//
// The namespace handler creates and destroys Linux network namespaces with
// veth pairs on behalf of agentjail-shield instances. Shield connects via
// Unix socket using Go's stdlib net/rpc package.
package daemon

import "log/slog"

// ──── Request / Response types (typed, no map[string]any) ───────────────────

// CreateNamespaceReq is the request to create a network namespace with a
// veth pair linking the host to the namespace.
type CreateNamespaceReq struct {
	SessionID string `json:"session_id"`
}

// CreateNamespaceResp is the response after successful namespace creation.
type CreateNamespaceResp struct {
	// Linux netns fields.
	NamespacePID int    `json:"namespace_pid"`
	HostVeth     string `json:"host_veth"`
	NSVeth       string `json:"ns_veth"`
	HostIP       string `json:"host_ip"`
	NSIP         string `json:"ns_ip"`

	// macOS utun fields (set by namespace_darwin.go; zero on Linux).
	UTunName  string `json:"utun_name,omitempty"`
	GatewayIP string `json:"gateway_ip,omitempty"`
}

// DestroyNamespaceReq is the request to tear down a previously created
// namespace for a session.
type DestroyNamespaceReq struct {
	SessionID string `json:"session_id"`
}

// DestroyNamespaceResp is the response after namespace destruction.
type DestroyNamespaceResp struct {
	OK bool `json:"ok"`
}

// ──── Namespace handler interface ───────────────────────────────────────────

// NamespaceHandler manages network namespace lifecycle for agent sessions.
// The interface lives in the consumer package (daemon) per the repo's
// interface-at-the-seam convention.
type NamespaceHandler interface {
	// Create creates a new network namespace with a veth pair for the given
	// session. Returns the namespace details or an error.
	Create(req CreateNamespaceReq) (*CreateNamespaceResp, error)

	// Destroy tears down the namespace for the given session. Idempotent:
	// destroying a non-existent session returns nil.
	Destroy(req DestroyNamespaceReq) error

	// CleanupAll tears down all active namespaces. Called on daemon shutdown.
	CleanupAll()
}

// AuditFunc is the signature for emitting audit events from the namespace
// handler. The daemon injects its own implementation (e.g. SQLite-backed).
type AuditFunc func(action, sessionID, detail string)

// NewNamespaceHandler returns the platform-appropriate NamespaceHandler.
// On Linux it manages real namespaces; on other platforms it returns
// ErrUnsupported for every operation.
//
// audit is called for every state change (create, destroy, cleanup).
// logger is used for structured logging within the handler.
func NewNamespaceHandler(audit AuditFunc, logger *slog.Logger) NamespaceHandler {
	return newPlatformNamespaceHandler(audit, logger)
}

// ──── net/rpc service adapter ───────────────────────────────────────────────

// NamespaceService wraps a NamespaceHandler and exposes Create and Destroy
// as exported methods with the signature required by net/rpc:
//
//	func (s *NamespaceService) Method(req *T, resp *U) error
//
// Register an instance with rpc.Register() on the daemon side;
// call via client.Call("NamespaceService.Create", &req, &resp) from the shield.
type NamespaceService struct {
	handler NamespaceHandler
}

// NewNamespaceService returns a NamespaceService backed by the given handler.
func NewNamespaceService(h NamespaceHandler) *NamespaceService {
	return &NamespaceService{handler: h}
}

// Create delegates to the underlying NamespaceHandler.Create and populates
// resp with the result.
func (s *NamespaceService) Create(req *CreateNamespaceReq, resp *CreateNamespaceResp) error {
	result, err := s.handler.Create(*req)
	if err != nil {
		return err
	}
	*resp = *result
	return nil
}

// Destroy delegates to the underlying NamespaceHandler.Destroy and populates
// resp with the result.
func (s *NamespaceService) Destroy(req *DestroyNamespaceReq, resp *DestroyNamespaceResp) error {
	if err := s.handler.Destroy(*req); err != nil {
		return err
	}
	resp.OK = true
	return nil
}
