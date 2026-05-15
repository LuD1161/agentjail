// Package perm holds the Cerbos-shape permission model used by agentjail's
// internal façade in front of OPA.
//
// The wire shape mirrors Cerbos's gRPC types (Principal / Resource / Action /
// CheckResourcesRequest) so a future swap to a standalone PDP is a single
// config change. See docs/PERMISSIONS_SERVICE_PLAN.md §"Phased rollout" and
// docs/CERBOS_EVALUATION.md for the design rationale.
//
// Phase 1 is intentionally types-only. The Service that consumes these types
// lives next door in service.go; the adapter that builds them from a daemon
// Frame + Session lives in adapter.go. Neither file is required for the
// types here to be useful — downstream consumers can construct requests by
// hand for tests.
package perm

// Principal identifies "who is asking". In agentjail the principal is the
// session, not the human — two concurrent Claude Code sessions on the same
// laptop are distinct principals so ASK-mode dedup, bypass nonces, and
// cache buckets do not collide.
//
// ID is `<agent_slug>:<session_id>` — see adapter.PrincipalID.
type Principal struct {
	ID    string         `json:"id"`
	Roles []string       `json:"roles,omitempty"`
	Attr  map[string]any `json:"attr,omitempty"`
}

// Resource is the thing the principal wants to act on. Kind partitions the
// universe (subprocess / file / http_request / mcp_tool / credential); ID is
// a stable string that distinguishes resources within a kind (file path,
// host+path, capability id, ...).
type Resource struct {
	ID   string         `json:"id"`
	Kind string         `json:"kind"`
	Attr map[string]any `json:"attr,omitempty"`
}

// Action is the verb the principal wants to apply to the resource. The set
// is closed (exec / read / write / fetch / mcp_call / cred_use) and is
// derived from the originating hook + op via the action normalization table
// in adapter.go.
type Action string

const (
	ActionExec    Action = "exec"
	ActionRead    Action = "read"
	ActionWrite   Action = "write"
	ActionFetch   Action = "fetch"
	ActionMCPCall Action = "mcp_call"
	ActionCredUse Action = "cred_use"
)

// Context carries request-scoped attributes that do not belong to the
// principal or the resource — primarily the operator's $HOME (used by the
// legacy rules to construct "protected path" globs) and the cwd_repo (git
// root) snapshot taken at session start.
//
// Kept as a typed struct rather than a map[string]any so callers can not
// accidentally smuggle PII (auth tokens, full env) through this surface.
type Context struct {
	Home    string `json:"home,omitempty"`
	CwdRepo string `json:"cwd_repo,omitempty"`
}

// CheckResourcesRequest is the single-resource form of Cerbos's
// CheckResources call. agentjail only ever asks about one resource per
// hook event today, so we collapse the batch form into a scalar; if we ever
// need to ask "may I do these N things atomically?" the batch field can be
// added without breaking the wire shape (it stays nil in the v1 path).
type CheckResourcesRequest struct {
	RequestID string    `json:"request_id,omitempty"`
	Principal Principal `json:"principal"`
	Resource  Resource  `json:"resource"`
	Action    Action    `json:"action"`
	Context   Context   `json:"context,omitempty"`
}

// CheckResourcesResponse echoes the request id and reports the verdict.
//
// Effect uses the same vocabulary as the legacy policy.Decision.Action
// ("allow" | "deny" | "ask") rather than Cerbos's EFFECT_* constants
// because the two surfaces live in the same process today and translating
// at the boundary would add latency the audit log can already correlate
// via RequestID.
type CheckResourcesResponse struct {
	RequestID string `json:"request_id,omitempty"`
	Effect    string `json:"effect"`
	RuleID    string `json:"rule_id,omitempty"`
}
