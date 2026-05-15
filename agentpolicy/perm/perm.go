// Package perm is the public facade for the agentpolicy Cerbos-shape
// permission model. It re-exports the small set of symbols callers
// outside the agentpolicy module need so that the engine's internals
// stay inside agentpolicy/internal/perm.
//
// Wire-shape note: every type below is a type alias (not a new struct)
// so the JSON shapes on the decision RPC and audit log are
// byte-identical to the legacy internal/perm surface.
package perm

import (
	internalperm "github.com/LuD1161/agentjail/agentpolicy/internal/perm"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
)

// Re-exported domain types. See agentpolicy/internal/perm for full
// field documentation.
type (
	Action                 = internalperm.Action
	Principal              = internalperm.Principal
	Resource               = internalperm.Resource
	Context                = internalperm.Context
	CheckResourcesRequest  = internalperm.CheckResourcesRequest
	CheckResourcesResponse = internalperm.CheckResourcesResponse
	DisagreementEvent      = internalperm.DisagreementEvent
	Emitter                = internalperm.Emitter
	Service                = internalperm.Service
	FrameInput             = internalperm.FrameInput
	PrincipalCtx           = internalperm.PrincipalCtx
	SessionRef             = internalperm.SessionRef
)

// Action constants — re-exported.
const (
	ActionExec    = internalperm.ActionExec
	ActionRead    = internalperm.ActionRead
	ActionWrite   = internalperm.ActionWrite
	ActionFetch   = internalperm.ActionFetch
	ActionMCPCall = internalperm.ActionMCPCall
	ActionCredUse = internalperm.ActionCredUse
)

// Side-by-side eval query rule paths — re-exported.
const (
	LegacyDecisionQuery       = internalperm.LegacyDecisionQuery
	ExperimentalDecisionQuery = internalperm.ExperimentalDecisionQuery
)

// NewService constructs a Service around an existing policy.Engine.
// policy.Engine is a type alias for the internal engine, so passing
// either the public or internal type works.
func NewService(eng *policy.Engine, emit Emitter) *Service {
	return internalperm.NewService(eng, emit)
}

// FromFrame builds a CheckResourcesRequest from a wire frame plus a
// SessionRef and PrincipalCtx.
func FromFrame(f FrameInput, sess *SessionRef, pctx PrincipalCtx) CheckResourcesRequest {
	return internalperm.FromFrame(f, sess, pctx)
}

// BuildPrincipal projects a SessionRef + PrincipalCtx into a Principal.
func BuildPrincipal(sess *SessionRef, pctx PrincipalCtx) Principal {
	return internalperm.BuildPrincipal(sess, pctx)
}

// PrincipalID is the canonical "<agent_slug>:<session_id>" formatter.
func PrincipalID(agentSlug, sid string) string {
	return internalperm.PrincipalID(agentSlug, sid)
}

// NormalizeAction maps (hook, op) to an Action.
func NormalizeAction(hook, op string) Action {
	return internalperm.NormalizeAction(hook, op)
}

// BuildResource derives the Resource{Kind, ID, Attr} for a frame.
func BuildResource(f FrameInput) Resource {
	return internalperm.BuildResource(f)
}

// BuildPolicyInput projects a CheckResourcesRequest into the policy
// engine's Input shape.
func BuildPolicyInput(req CheckResourcesRequest) policy.Input {
	return internalperm.BuildPolicyInput(req)
}

// PrincipalToMap projects a Principal into the OPA-rule-friendly map.
func PrincipalToMap(p Principal) map[string]any {
	return internalperm.PrincipalToMap(p)
}

// ResourceToMap projects a Resource into the OPA-rule-friendly map.
func ResourceToMap(r Resource) map[string]any {
	return internalperm.ResourceToMap(r)
}
