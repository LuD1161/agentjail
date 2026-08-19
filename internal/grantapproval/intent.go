// Package grantapproval defines the agent-neutral approval prompt seam.
// See ADR 0141-runtime-grants.
package grantapproval

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/LuD1161/agentjail/internal/agentpolicy"
	"github.com/LuD1161/agentjail/internal/grant"
)

const maxDisplayText = 512

var (
	ErrInvalidIntent   = errors.New("invalid approval intent")
	ErrInvalidEvidence = errors.New("invalid approval evidence")
)

type RequestReference string
type GrantReference string
type AdapterID string
type AgentID string
type TurnID string
type ToolUseID string
type Nonce string

// Principal identifies the agent and exact session for a pending approval.
type Principal struct {
	agent   AgentID
	session grant.SessionID
}

func NewPrincipal(agent AgentID, session grant.SessionID) (Principal, error) {
	if !present(string(agent)) || !present(string(session)) {
		return Principal{}, ErrInvalidIntent
	}
	return Principal{agent: agent, session: session}, nil
}

func (p Principal) Agent() AgentID { return p.agent }

func (p Principal) Session() grant.SessionID { return p.session }

func (p Principal) Valid() bool {
	return present(string(p.agent)) && present(string(p.session))
}

// Binding ties an approval to the turn and, when supplied by the agent, tool
// invocation that requested it. A tool-use id never exists without a turn id.
type Binding struct {
	turn    TurnID
	toolUse ToolUseID
}

func NewBinding(turn TurnID, toolUse ToolUseID) (Binding, error) {
	if !present(string(turn)) && present(string(toolUse)) {
		return Binding{}, ErrInvalidIntent
	}
	return Binding{turn: turn, toolUse: toolUse}, nil
}

func (b Binding) Turn() TurnID { return b.turn }

func (b Binding) ToolUse() ToolUseID { return b.toolUse }

func (b Binding) Valid() bool {
	return present(string(b.turn)) || !present(string(b.toolUse))
}

// DisplayContext is bounded untrusted text shown alongside the trusted intent.
type DisplayContext struct {
	reason      string
	consequence string
}

func NewDisplayContext(reason, consequence string) (DisplayContext, error) {
	consequence = boundedDisplayText(consequence)
	if consequence == "" {
		return DisplayContext{}, ErrInvalidIntent
	}
	return DisplayContext{reason: boundedDisplayText(reason), consequence: consequence}, nil
}

func (c DisplayContext) Reason() string { return c.reason }

func (c DisplayContext) Consequence() string { return c.consequence }

// Intent is immutable policy approval intent. PolicyAction is always the
// canonical policy verdict; adapters may only report their rendered outcome.
type Intent struct {
	request     RequestReference
	grant       GrantReference
	principal   Principal
	policy      agentpolicy.Action
	action      grant.Action
	resource    grant.Resource
	scope       grant.Scope
	policyEpoch grant.PolicyEpoch
	binding     Binding
	display     DisplayContext
}

func NewIntent(
	request RequestReference,
	grantRef GrantReference,
	principal Principal,
	policyAction agentpolicy.Action,
	action grant.Action,
	resource grant.Resource,
	scope grant.Scope,
	policyEpoch grant.PolicyEpoch,
	binding Binding,
	display DisplayContext,
) (Intent, error) {
	if !present(string(request)) || !present(string(grantRef)) || !principal.Valid() ||
		policyAction != agentpolicy.ActionAsk || !action.Valid() || !resource.Valid() ||
		!validScope(scope) || policyEpoch == 0 || !binding.Valid() || display.Consequence() == "" {
		return Intent{}, ErrInvalidIntent
	}
	return Intent{
		request: request, grant: grantRef, principal: principal, policy: policyAction,
		action: action, resource: resource, scope: scope, policyEpoch: policyEpoch,
		binding: binding, display: display,
	}, nil
}

func (i Intent) Request() RequestReference { return i.request }

func (i Intent) Grant() GrantReference { return i.grant }

func (i Intent) Principal() Principal { return i.principal }

func (i Intent) PolicyAction() agentpolicy.Action { return i.policy }

func (i Intent) Action() grant.Action { return i.action }

func (i Intent) Resource() grant.Resource { return i.resource }

func (i Intent) Scope() grant.Scope { return i.scope }

func (i Intent) PolicyEpoch() grant.PolicyEpoch { return i.policyEpoch }

func (i Intent) Binding() Binding { return i.binding }

func (i Intent) Display() DisplayContext { return i.display }

// Prompt is the adapter's display projection. Trusted intent fields are
// rendered independently of the bounded untrusted reason.
type Prompt struct {
	Action      grant.Action
	Resource    grant.Resource
	Scope       grant.Scope
	Consequence string
	Reason      string
}

func (i Intent) Prompt() Prompt {
	return Prompt{
		Action: i.action, Resource: i.resource, Scope: i.scope,
		Consequence: i.display.Consequence(), Reason: i.display.Reason(),
	}
}

func (i Intent) Valid() bool {
	return i.request != "" && i.grant != "" && i.principal.Valid() &&
		i.policy == agentpolicy.ActionAsk && i.action.Valid() && i.resource.Valid() &&
		validScope(i.scope) && i.policyEpoch != 0 && i.binding.Valid() && i.display.Consequence() != ""
}

// Freshness proves that a native prompt crossed an agent-specific boundary
// after the policy decision. ToolCallEpoch must match the current session epoch
// at redemption; FreshAfter binds the process-start freshness boundary.
type Freshness struct {
	toolCallEpoch uint64
	freshAfter    uint64
	peerFresh     bool
}

func NewFreshness(toolCallEpoch, freshAfter uint64, peerFresh bool) (Freshness, error) {
	if toolCallEpoch == 0 || freshAfter == 0 {
		return Freshness{}, ErrInvalidEvidence
	}
	return Freshness{toolCallEpoch: toolCallEpoch, freshAfter: freshAfter, peerFresh: peerFresh}, nil
}

func (f Freshness) ToolCallEpoch() uint64 { return f.toolCallEpoch }

func (f Freshness) FreshAfter() uint64 { return f.freshAfter }

func (f Freshness) PeerFresh() bool { return f.peerFresh }

func (f Freshness) Valid() bool { return f.toolCallEpoch != 0 && f.freshAfter != 0 }

// Evidence is an adapter assertion, never an inferred approval. It repeats the
// complete immutable intent binding so an adapter cannot authorize a sibling
// request or a later tool call by presenting only a prompt observation.
type Evidence struct {
	adapter     AdapterID
	request     RequestReference
	grant       GrantReference
	principal   Principal
	action      grant.Action
	resource    grant.Resource
	scope       grant.Scope
	policyEpoch grant.PolicyEpoch
	binding     Binding
	nonce       Nonce
	freshness   Freshness
	observedAt  time.Time
}

func NewEvidence(
	adapter AdapterID,
	request RequestReference,
	grantRef GrantReference,
	principal Principal,
	action grant.Action,
	resource grant.Resource,
	scope grant.Scope,
	policyEpoch grant.PolicyEpoch,
	binding Binding,
	nonce Nonce,
	freshness Freshness,
	observedAt time.Time,
) (Evidence, error) {
	evidence := Evidence{
		adapter: adapter, request: request, grant: grantRef, principal: principal,
		action: action, resource: resource, scope: scope, policyEpoch: policyEpoch,
		binding: binding, nonce: nonce, freshness: freshness, observedAt: observedAt,
	}
	if !evidence.Valid() {
		return Evidence{}, ErrInvalidEvidence
	}
	return evidence, nil
}

func (e Evidence) Adapter() AdapterID { return e.adapter }

func (e Evidence) Request() RequestReference { return e.request }

func (e Evidence) Grant() GrantReference { return e.grant }

func (e Evidence) Principal() Principal { return e.principal }

func (e Evidence) Action() grant.Action { return e.action }

func (e Evidence) Resource() grant.Resource { return e.resource }

func (e Evidence) Scope() grant.Scope { return e.scope }

func (e Evidence) PolicyEpoch() grant.PolicyEpoch { return e.policyEpoch }

func (e Evidence) Binding() Binding { return e.binding }

func (e Evidence) Nonce() Nonce { return e.nonce }

func (e Evidence) Freshness() Freshness { return e.freshness }

func (e Evidence) ObservedAt() time.Time { return e.observedAt }

func (e Evidence) Valid() bool {
	return present(string(e.adapter)) && present(string(e.request)) && present(string(e.grant)) &&
		e.principal.Valid() && e.action.Valid() && e.resource.Valid() && validScope(e.scope) &&
		e.policyEpoch != 0 && e.binding.Valid() && present(string(e.nonce)) &&
		e.freshness.Valid() && !e.observedAt.IsZero()
}

func (e Evidence) Matches(intent Intent, adapter AdapterID) bool {
	return e.Valid() && intent.Valid() && e.adapter == adapter && e.request == intent.request &&
		e.grant == intent.grant && e.principal == intent.principal && e.action == intent.action &&
		e.resource == intent.resource && sameScope(e.scope, intent.scope) && e.policyEpoch == intent.policyEpoch &&
		e.binding == intent.binding
}

func validScope(scope grant.Scope) bool {
	switch scope.Kind() {
	case grant.ScopeOnce, grant.ScopeSession:
		_, hasExpiry := scope.ExpiresAt()
		return !hasExpiry
	case grant.ScopeTTL:
		expiresAt, hasExpiry := scope.ExpiresAt()
		return hasExpiry && !expiresAt.IsZero()
	default:
		return false
	}
}

func sameScope(left, right grant.Scope) bool {
	if left.Kind() != right.Kind() {
		return false
	}
	leftExpiry, leftHasExpiry := left.ExpiresAt()
	rightExpiry, rightHasExpiry := right.ExpiresAt()
	return leftHasExpiry == rightHasExpiry && (!leftHasExpiry || leftExpiry.Equal(rightExpiry))
}

func boundedDisplayText(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > maxDisplayText {
		return value[:maxDisplayText]
	}
	return value
}

func present(value string) bool {
	return strings.TrimSpace(value) != ""
}

func (p Prompt) String() string {
	return fmt.Sprintf("%s %s:%s (%s): %s", p.Action, p.Resource.Kind(), p.Resource.ID(), p.Scope.Kind(), p.Consequence)
}
