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
