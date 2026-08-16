// Package grantctl defines the typed control-plane protocol shared between
// agentjail-daemon and runtime host grant clients (e.g., agentjail-cli, sbpl
// generator for macOS sandbox policy).
//
// The daemon maintains a privileged grant control socket at
// ~/.agentjail/run/daemon-ctl.sock. Its verbs are gated by the ctlauth control
// token, which the sandboxed agent cannot read; the socket path itself is not a
// boundary on Linux (ADR 0069). Runtime host grant requests (for elevated network,
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
//  1. Agent calls grant request (via hook)
//  2. Hook forwards to daemon (which appends to pending queue)
//  3. Daemon holds pending GrantID until TTL expiry or approval/denial
//  4. Human calls `agentjail grants approve <id>` (CLI -> daemon-ctl.sock)
//  5. Daemon applies the grant and returns ClaimedGrant (bound to session's CWD)
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
	// socket only; CtlToken required.
	ReqGrantList RequestType = "grant_list"
	// ReqGrantApprove claims a pending grant request by GrantID and applies it
	// to the owning session. Control-socket only; CtlToken required. The daemon
	// resolves SessionID/CWD from its own in-memory grant map by GrantID.
	ReqGrantApprove RequestType = "grant_approve"
	// ReqGrantDeny discards a pending grant request by GrantID without
	// applying it. Control-socket only; CtlToken required.
	ReqGrantDeny RequestType = "grant_deny"
	// ReqReviewSnapshot returns the bounded v1 projection used by the macOS
	// approval companion. Control-socket only; CtlToken required.
	ReqReviewSnapshot RequestType = "review_snapshot"
	// ReqDaemonReload asks the daemon to reload policy.yaml and recompile the
	// Rego bundle in place -- what SIGHUP does, but with a response so the
	// caller learns whether the rules actually compiled.
	//
	// Control-socket ONLY, and deliberately so (ADR 0066): reload is cheap to
	// ask for and expensive to serve (a full Rego recompile), so on the
	// agent-reachable daemon.sock it is a fail-open DoS lever -- the sandboxed
	// agent must be able to reach that socket for hooks to work at all, the
	// hook's budget is ~30ms, and DaemonUnreachable defaults to Allow. Moving it
	// here is necessary but not sufficient: on Linux the agent can reach this
	// socket too, so CtlToken is what actually gates it (ADR 0069).
	ReqDaemonReload RequestType = "daemon_reload"
	// ReqUpdateAudit records a completed or recovered manual update through the
	// daemon-owned audit store. Control-socket only; CtlToken required.
	ReqUpdateAudit RequestType = "update_audit"
	// ReqSessionLaunchRegister pins pre-sandbox launch metadata to the shield
	// process. A later verified agent descendant may bind its hook session ID.
	ReqSessionLaunchRegister RequestType = "session_launch_register"
	// ReqSessionLaunchUnregister revokes the calling shield's launch metadata.
	ReqSessionLaunchUnregister RequestType = "session_launch_unregister"
)

// UpdateAuditStatus is the fixed outcome vocabulary for manual-update audit
// events. The daemon maps each value to its own audit event type.
type UpdateAuditStatus string

const (
	UpdateAuditCompleted      UpdateAuditStatus = "completed"
	UpdateAuditRolledBack     UpdateAuditStatus = "rolled_back"
	UpdateAuditRollbackFailed UpdateAuditStatus = "rollback_failed"
)

// Request is the control-plane request envelope (JSON on the socket).
type Request struct {
	Type RequestType `json:"type"`
	// CtlToken authenticates the caller as a process outside the sandbox. Every
	// verb served on daemon-ctl.sock requires it (ADR 0069). ReqGrantRequest is
	// exempt: it is the agent's own verb and is served on daemon.sock.
	CtlToken string `json:"ctl_token,omitempty"`
	// ProtocolVersion is required for versioned review requests. Zero is not
	// an alias for v1. See ADR 0133-macos-menu-review.
	ProtocolVersion ProtocolVersion   `json:"protocol_version,omitempty"`
	SessionID       string            `json:"session_id,omitempty"`
	CWD             string            `json:"cwd,omitempty"`
	Host            string            `json:"host,omitempty"`
	TTLMs           int64             `json:"ttl_ms,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	GrantID         string            `json:"grant_id,omitempty"`
	UpdateStatus    UpdateAuditStatus `json:"update_status,omitempty"`
	UpdateVersion   string            `json:"update_version,omitempty"`
	UpdateOS        string            `json:"update_os,omitempty"`
	LaunchPID       int               `json:"launch_pid,omitempty"`
	LaunchRoot      string            `json:"launch_root,omitempty"`
	LaunchPath      string            `json:"launch_path,omitempty"`
}

// Response is the control-plane response envelope (JSON on the socket).
type Response struct {
	OK             bool              `json:"ok"`
	Error          string            `json:"error,omitempty"`
	GrantID        string            `json:"grant_id,omitempty"`
	Grants         []GrantInfo       `json:"grants,omitempty"`
	ReviewSnapshot *ReviewSnapshotV1 `json:"review_snapshot,omitempty"`
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

// ProtocolVersion identifies a versioned control-plane projection.
type ProtocolVersion uint32

// ReviewProtocolVersion is the only menu-review protocol version supported by
// this package.
const ReviewProtocolVersion ProtocolVersion = 1

// ReviewKind identifies the authority being reviewed.
type ReviewKind string

const (
	ReviewKindProjectHost ReviewKind = "project_host"
)

// ReviewScope describes when an approved review takes effect.
type ReviewScope string

const (
	ReviewScopeFutureProjectSessions ReviewScope = "future_project_sessions"
)

// ReviewContextState describes whether the daemon can represent verified
// authority context for an approval.
type ReviewContextState string

const (
	ReviewContextStateVerified        ReviewContextState = "verified"
	ReviewContextStateUnbound         ReviewContextState = "unbound"
	ReviewContextStateUnrepresentable ReviewContextState = "unrepresentable"
)

// ReviewID is the stable, non-secret handle for a pending review.
type ReviewID string

// UnixMilliseconds is a lossless Unix timestamp in milliseconds.
type UnixMilliseconds int64

// ReviewInfo is the bounded projection of a pending project-host grant.
// Authority fields are complete or absent; all strings remain untrusted.
type ReviewInfo struct {
	ReviewID        ReviewID           `json:"review_id"`
	Kind            ReviewKind         `json:"kind"`
	Host            string             `json:"host,omitempty"`
	ProjectPath     string             `json:"project_path,omitempty"`
	Reason          string             `json:"reason"`
	ReasonTruncated bool               `json:"reason_truncated"`
	ContextState    ReviewContextState `json:"context_state"`
	CreatedAtUnixMs UnixMilliseconds   `json:"created_at_unix_ms"`
	ExpiresAtUnixMs UnixMilliseconds   `json:"expires_at_unix_ms"`
	ApprovalScope   ReviewScope        `json:"approval_scope"`
	CanApprove      bool               `json:"can_approve"`
	CanDeny         bool               `json:"can_deny"`
}

// ReviewSnapshotV1 is one coherent, server-timestamped view of pending reviews.
type ReviewSnapshotV1 struct {
	ProtocolVersion   ProtocolVersion  `json:"protocol_version"`
	GeneratedAtUnixMs UnixMilliseconds `json:"generated_at_unix_ms"`
	TotalPending      int              `json:"total_pending"`
	Truncated         bool             `json:"truncated"`
	Reviews           []ReviewInfo     `json:"reviews"`
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

// Review projection limits keep three worst-case JSON-escaped reviews below
// MaxControlMsgBytes. Authority fields exceeding their limit are omitted and
// made deny-only. See ADR 0133-macos-menu-review.
const (
	MaxReviewHostBytes        = 255
	MaxReviewProjectPathBytes = 2048
	MaxReviewReasonBytes      = 256
	MaxReviewSnapshotItems    = 3
)

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
