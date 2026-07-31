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
	// DecisionsDropped reports decisions the async writer could not persist
	// (buffer full or write error). Under-recording is otherwise invisible;
	// see ADR 0072.
	DecisionsDropped = "decisions.dropped"
	// TunnelALPNDowngraded reports that a client offered HTTP/2 and the
	// tunnel's interception served HTTP/1.1 instead. Emitted once per session:
	// a client that cannot fall back (gRPC) fails, and silently downgrading is
	// the kind of unstated behaviour ADR 0077 exists to prevent. See AGE-222.
	TunnelALPNDowngraded = "tunnel.alpn_downgraded"
	// TunnelBodiesUnencrypted reports that a session records bodies in the
	// clear because no KEK could be sealed. Detail carries fixed strings only;
	// Detail["reason"] is one of TunnelKeysLocked / TunnelKeysAbsent /
	// TunnelKeysError -- a locked keychain and an absent one need opposite
	// advice. See ADR 0092-persist-request-bodies (D5), AGE-254.
	TunnelBodiesUnencrypted = "tunnel.bodies_unencrypted"
	// Fixed vocabulary for TunnelBodiesUnencrypted's Detail["reason"].
	TunnelKeysLocked = "keychain_locked"
	TunnelKeysAbsent = "no_keychain"
	TunnelKeysError  = "keyring_error"
	DaemonStarted    = "daemon.started"
	DaemonStopped    = "daemon.stopped"
	DaemonFailopen   = "daemon.failopen"
	UpdateCompleted  = "update.completed"
	// Session-aware netproxy control plane (per-session allowlists). A session
	// lease is registered by the shield over the control socket and reaped on
	// expiry regardless of traffic. Never put the session Token in Detail.
	NetproxySessionRegistered = "netproxy.session_registered"
	NetproxySessionExpired    = "netproxy.session_expired"
	// Runtime host grants (`/agentjail allow`). Requested is
	// best-effort (filed by the agent-reachable data-plane sentinel);
	// Approved/Denied are the human, control-socket decisions -- Approved is
	// fail-closed (never emitted through a NopEmitter, see ADR 0044); Expired
	// is emitted by the reaper when a granted host's TTL lapses.
	NetproxyGrantRequested = "netproxy.grant_requested"
	NetproxyGrantApproved  = "netproxy.grant_approved"
	NetproxyGrantDenied    = "netproxy.grant_denied"
	NetproxyGrantExpired   = "netproxy.grant_expired"
	// Daemon-hosted runtime host grants (see ADR 0047). Requested is
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
	// HookFallbackWriteFailed is emitted (best-effort) when the daemon fails
	// to write the hook-fallback sidecar (ADR 0050) on startup or SIGHUP
	// reload. Never fatal — the hook falls back to "allow" when the sidecar
	// is missing/stale, so a write failure degrades observability, not
	// enforcement.
	HookFallbackWriteFailed = "hook_fallback.write_failed"
	// EnforcementModeChanged records the daemon entering or leaving monitor
	// mode (startup or SIGHUP reload). Monitor mode means deny/ask verdicts are
	// recorded but not acted on, so the window in which nothing was enforced
	// must be reconstructable from the audit log alone -- the decisions table
	// shows allow rows and cannot, by itself, say the mode was the reason.
	// Detail carries {"mode": "enforce"|"monitor"}. See ADR
	// 0091-monitor-mode-tools.
	EnforcementModeChanged = "enforcement.mode_changed"
	// Darwin NE-transparent-proxy tunnel lifecycle (AGE-149). Started/Stopped
	// bracket the AgentjailTunnel.app + system extension being driven up and
	// torn down; SessionRegistered/SessionUnregistered bracket this shield's
	// own PID being (un)registered with the extension's ancestor-match filter.
	// Detail carries mode/mitm/app_path and, on failure, failure_reason - fixed
	// strings only, never a key path or token. See ADR 0077, AGE-254.
	TunnelExtensionStarted    = "tunnel.extension_started"
	TunnelExtensionStopped    = "tunnel.extension_stopped"
	TunnelSessionRegistered   = "tunnel.session_registered"
	TunnelSessionUnregistered = "tunnel.session_unregistered"
	// Base-URL capture gateway lifecycle (AGE-259 / ADR 0109-baseurl-capture-gateway).
	// ProviderRouted: a registered provider agent's base URL was pointed at the local
	// capture gateway. StartFailed: the gateway could not bind/start/open its store and
	// launch was refused (fail-closed). Detail carries host/agent/provider only --
	// never a token, never the gateway nonce.
	GatewayProviderRouted = "gateway.provider_routed"
	GatewayStartFailed    = "gateway.start_failed"
	CodexApprovalMinted   = "codex_approval.minted"
	CodexPromptObserved   = "codex_approval.prompt_observed"
	CodexApprovalRedeemed = "codex_approval.redeemed"
	CodexApprovalRejected = "codex_approval.rejected"
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
