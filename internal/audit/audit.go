// Package audit defines the unified audit event types and the Emitter
// interface (Plan 009). Components import this package to emit structured
// audit events; the concrete persistence lives in internal/store.
//
// This package must NOT import internal/store (circular dep).
package audit

import "context"

// Event type constants -- additive only, never rename/remove.
const (
	PolicyChangeRequested = "policy.change_requested"
	PolicyChanged         = "policy.changed"
	PolicyReloaded        = "policy.reloaded"
	ToolDiscovered        = "tool.discovered"
	ToolUpdated           = "tool.updated"
	SkillDiscovered       = "skill.discovered"
	SessionStarted        = "session.started"
	ShieldActivated       = "shield.activated"
	ShieldFailed          = "shield.failed"
	ShieldAuditFinding    = "shield.audit_finding"
	OAuthCompleted        = "oauth.completed"
	HookTampered          = "hook.tampered"
	HookReinjected        = "hook.reinjected"
	CredentialIssued      = "credential.issued"
	CredentialRevoked     = "credential.revoked"
	RetentionPurged       = "retention.purged"
	DaemonStarted         = "daemon.started"
	DaemonStopped         = "daemon.stopped"
	DaemonFailopen        = "daemon.failopen"
	UpdateCompleted       = "update.completed"
	// Session-aware netproxy control plane (per-session allowlists). A session
	// lease is registered by the shield over the control socket and reaped on
	// expiry regardless of traffic. Never put the session Token in Detail.
	NetproxySessionRegistered = "netproxy.session_registered"
	NetproxySessionExpired    = "netproxy.session_expired"
	// Runtime host grants (`/agentjail allow`, follow-up). Requested is
	// best-effort (filed by the agent-reachable data-plane sentinel);
	// Approved/Denied are the human, control-socket decisions -- Approved is
	// fail-closed (never emitted through a NopEmitter, see ADR 0044); Expired
	// is emitted by the reaper when a granted host's TTL lapses.
	NetproxyGrantRequested = "netproxy.grant_requested"
	NetproxyGrantApproved  = "netproxy.grant_approved"
	NetproxyGrantDenied    = "netproxy.grant_denied"
	NetproxyGrantExpired   = "netproxy.grant_expired"
	// Daemon-hosted runtime host grants (follow-up, ADR 0047). Requested is
	// best-effort; Denied is best-effort. Approval uses PolicyChangeRequested
	// (fail-closed) and PolicyChanged (best-effort) instead of a separate event.
	DaemonGrantRequested = "daemon.grant_requested"
	DaemonGrantDenied    = "daemon.grant_denied"
	// Per-folder policy overlays (direnv-style trust gate). Emitted by the
	// shield when it resolves a `./.agentjail/policy.yaml` for a session.
	ProjectOverlayApplied          = "project_overlay.applied"
	ProjectOverlayIgnoredUntrusted = "project_overlay.ignored_untrusted"
	// ShieldMetadataEgressExposed is emitted by the launch-time cloud-
	// metadata (IMDS) egress guard (main.go decideMetadataEgress) when the
	// metadata service is reachable through the shield's default
	// (port-only, --no-netproxy) egress path -- best-effort, fired whether
	// or not --audit-strict caused the launch to be refused. See ADR 0049.
	ShieldMetadataEgressExposed = "shield.metadata_egress_exposed"
)

// Event is one audit log entry.
type Event struct {
	EventType string
	Entity    string
	Detail    map[string]string
	Actor     string
	SessionID string
	RefID     string
}

// Emitter writes audit events. Components import this interface, not the store.
type Emitter interface {
	Emit(ctx context.Context, e Event) error
}

// NopEmitter discards events. Use ONLY for best-effort events, never for
// fail-closed policy mutations.
type NopEmitter struct{}

func (NopEmitter) Emit(context.Context, Event) error { return nil }
