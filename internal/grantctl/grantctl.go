// Package grantctl defines the typed control-plane protocol shared between
// agentjail-daemon and runtime host grant clients (e.g., agentjail-cli, sbpl
// generator for macOS sandbox policy).
//
// The daemon maintains a privileged grant control socket at
// ~/.agentjail/run/daemon-ctl.sock that only privileged or host-resident
// processes can access. Runtime host grant requests (for elevated network,
// filesystem, or capability access) flow through this socket: a sandboxed
// agent sends a grant request (via the hook, which forwards to daemon), the
// daemon holds it in a pending queue, and a human operator approves or denies
// it via `agentjail grants approve/deny`.
//
// The control plane traffic (registration, listing, approval) is JSON-encoded
// at the socket boundary; every field decodes into the typed structs below
// immediately. This package holds TYPES only -- no net/socket I/O. The
// daemon, CLI, and (future) sbpl generator each implement their own consumer-
// defined interfaces against these types.
//
// Grant lifecycle:
//   1. Agent calls grant request (via hook)
//   2. Hook forwards to daemon (which appends to pending queue)
//   3. Daemon holds pending GrantID until TTL expiry or approval/denial
//   4. Human calls `agentjail grants approve <id>` (CLI -> daemon-ctl.sock)
//   5. Daemon applies the grant and returns ClaimedGrant (bound to session's CWD)
//
// The grant TTL is enforced by the daemon; a grant is active only if still
// pending or recently approved and not yet expired.
package grantctl

import (
	"encoding/json"
	"time"
)

// RequestType enumerates the control-plane grant operations.
type RequestType string

const (
	// ReqGrantRequest submits a new runtime host grant request from the
	// sandboxed agent (via hook -> daemon). The daemon assigns a GrantID,
	// queues it, and returns the ID to the agent so it can poll or wait for
	// approval.
	ReqGrantRequest RequestType = "grant_request"
	// ReqGrantList lists all pending grant requests the daemon holds. Control-
	// socket only. Carries no authentication beyond socket access.
	ReqGrantList RequestType = "grant_list"
	// ReqGrantApprove claims a pending grant request by GrantID and applies it
	// to the owning session. Control-socket only. The daemon resolves
	// SessionID/CWD from its own in-memory grant map by GrantID.
	ReqGrantApprove RequestType = "grant_approve"
	// ReqGrantDeny discards a pending grant request by GrantID without
	// applying it. Control-socket only.
	ReqGrantDeny RequestType = "grant_deny"
	// ReqDaemonReload asks the daemon to reload policy.yaml and recompile the
	// Rego bundle in place -- what SIGHUP does, but with a response so the
	// caller learns whether the rules actually compiled.
	//
	// Control-socket ONLY, and deliberately so (ADR 0066): reload is cheap to
	// ask for and expensive to serve (a full Rego recompile), so on the
	// agent-reachable daemon.sock it is a fail-open DoS lever -- the sandboxed
	// agent must be able to reach that socket for hooks to work at all, the
	// hook's budget is ~30ms, and DaemonUnreachable defaults to Allow. This
	// socket is denied to the sandbox on both platforms, which is the actual
	// boundary; the same-UID peer check is identity, not authorization.
	ReqDaemonReload RequestType = "daemon_reload"
)

// Request is the control-plane request envelope (JSON on the socket).
type Request struct {
	Type      RequestType `json:"type"`
	SessionID string      `json:"session_id,omitempty"`
	CWD       string      `json:"cwd,omitempty"`
	Host      string      `json:"host,omitempty"`
	TTLMs     int64       `json:"ttl_ms,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	GrantID   string      `json:"grant_id,omitempty"`
}

// Response is the control-plane response envelope (JSON on the socket).
type Response struct {
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	GrantID string       `json:"grant_id,omitempty"`
	Grants  []GrantInfo  `json:"grants,omitempty"`
}

// GrantInfo describes one pending grant request, suitable for display to a
// human (e.g., in `agentjail grants list`). It includes only what a human
// needs to approve or deny: the host being requested, the TTL, the session ID
// (for disambiguation), CWD (context), and reason.
type GrantInfo struct {
	GrantID string `json:"grant_id"`
	Host    string `json:"host"`
	TTLMs   int64  `json:"ttl_ms"`
	// SessionID is a NON-SECRET handle for the requesting session, display-only.
	SessionID string `json:"session_id,omitempty"`
	// CWD is the session's working directory at request time, display-only.
	CWD string `json:"cwd,omitempty"`
	// Reason is the agent-supplied justification, display-only and bounded by
	// MaxReasonLen.
	Reason string `json:"reason,omitempty"`
}

// ClaimedGrant is the snapshot type returned when a grant is approved by the
// daemon. It includes all original grant metadata plus BoundCWD: the daemon-
// observed working directory at the moment the grant was claimed (used by the
// active tracker to bind the grant to a specific working directory session
// state). BoundCWD may be empty if the grant has not yet been bound (e.g.,
// during the initial approval handshake).
type ClaimedGrant struct {
	GrantID   string
	Host      string
	TTLMs     int64
	SessionID string
	CWD       string
	Reason    string
	// BoundCWD is the daemon-observed CWD from activeTracker at claim time.
	// Empty until the daemon binds the grant to a session state.
	BoundCWD string
}

// MarshalJSON marshals ClaimedGrant to JSON (omitting empty BoundCWD for
// cleaner output when unbound).
func (cg ClaimedGrant) MarshalJSON() ([]byte, error) {
	type Alias ClaimedGrant
	return json.Marshal(&struct {
		*Alias
		BoundCWD string `json:"bound_cwd,omitempty"`
	}{
		Alias:    (*Alias)(&cg),
		BoundCWD: cg.BoundCWD,
	})
}

// MaxControlMsgBytes bounds a single control-plane message (request or
// response) so neither peer can be forced to buffer unbounded data. Grant
// payloads are small (a single host or a list of pending requests).
const MaxControlMsgBytes = 64 * 1024

// MaxReasonLen bounds the agent-supplied --reason string in a grant request.
const MaxReasonLen = 256

// MaxGrantTTLMs is the hard ceiling on a single grant's TTL (24 hours, same
// horizon as daemon session leases). The daemon enforces this cap on any grant
// request.
const MaxGrantTTLMs int64 = 24 * 60 * 60 * 1000

// MaxPendingPerSession bounds how many outstanding grant requests a single
// session may have filed at once. This prevents a misbehaving agent from
// spamming the grant queue.
const MaxPendingPerSession = 16

// MaxPendingGlobal bounds the total outstanding grant requests across all
// sessions the daemon is serving. This prevents grant request DoS.
const MaxPendingGlobal = 256

// Milliseconds converts a time.Duration to milliseconds as int64.
func Milliseconds(d time.Duration) int64 {
	return d.Milliseconds()
}
