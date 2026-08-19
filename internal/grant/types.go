// Package grant defines runtime capability grant domain types.
// See ADR 0141-runtime-grants.
package grant

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidGrantID   = errors.New("invalid grant ID")
	ErrInvalidRequestID = errors.New("invalid grant request ID")
	ErrInvalidClaimID   = errors.New("invalid grant claim ID")
	ErrInvalidPrincipal = errors.New("invalid grant principal")
	ErrInvalidAction    = errors.New("invalid grant action")
	ErrInvalidResource  = errors.New("invalid grant resource")
	ErrInvalidScope     = errors.New("invalid grant scope")
	ErrInvalidRequest   = errors.New("invalid grant request")
)

type GrantID string
type RequestID string
type ClaimID string
type ApprovalReference string
type PrincipalID string
type SessionID string
type PolicyEpoch uint64
type Action string
type ResourceKind string
type ResourceID string
type ScopeKind string
type State string

func (id GrantID) Valid() bool {
	return present(string(id))
}

func (id RequestID) Valid() bool {
	return present(string(id))
}

func (id ClaimID) Valid() bool {
	return present(string(id))
}

const (
	ActionExec          Action = "exec"
	ActionRead          Action = "read"
	ActionWrite         Action = "write"
	ActionFetch         Action = "fetch"
	ActionConnect       Action = "connect"
	ActionMCPCall       Action = "mcp_call"
	ActionCredentialUse Action = "cred_use"

	ResourceSubprocess ResourceKind = "subprocess"
	ResourceFile       ResourceKind = "file"
	ResourceNetwork    ResourceKind = "network"
	ResourceMCPTool    ResourceKind = "mcp_tool"
	ResourceCredential ResourceKind = "credential"

	ScopeOnce    ScopeKind = "once"
	ScopeSession ScopeKind = "session"
	ScopeTTL     ScopeKind = "ttl"

	StateRequested        State = "requested"
	StateApproved         State = "approved"
	StateActive           State = "active"
	StateDenied           State = "denied"
	StateConsumed         State = "consumed"
	StateExpired          State = "expired"
	StateRevoked          State = "revoked"
	StateActivationFailed State = "activation_failed"
)

// Principal binds an agent identity to one runtime session.
type Principal struct {
	id        PrincipalID
	sessionID SessionID
}

func NewPrincipal(id PrincipalID, sessionID SessionID) (Principal, error) {
	if !present(string(id)) || !present(string(sessionID)) {
		return Principal{}, ErrInvalidPrincipal
	}
	return Principal{id: id, sessionID: sessionID}, nil
}

func (p Principal) ID() PrincipalID {
	return p.id
}

func (p Principal) SessionID() SessionID {
	return p.sessionID
}

func (p Principal) Valid() bool {
	return present(string(p.id)) && present(string(p.sessionID))
}

// Resource is a resource identity before or after adapter canonicalization.
type Resource struct {
	kind ResourceKind
	id   ResourceID
}

func NewResource(kind ResourceKind, id ResourceID) (Resource, error) {
	if !kind.Valid() || !present(string(id)) {
		return Resource{}, ErrInvalidResource
	}
	return Resource{kind: kind, id: id}, nil
}

func (r Resource) Kind() ResourceKind {
	return r.kind
}

func (r Resource) ID() ResourceID {
	return r.id
}

func (r Resource) Valid() bool {
	return r.kind.Valid() && present(string(r.id))
}

// Scope is a closed one-use, session, or TTL grant scope.
type Scope struct {
	kind      ScopeKind
	expiresAt time.Time
}

func OnceScope() Scope {
	return Scope{kind: ScopeOnce}
}

func SessionScope() Scope {
	return Scope{kind: ScopeSession}
}

func NewTTLScope(now, expiresAt time.Time) (Scope, error) {
	if now.IsZero() || expiresAt.IsZero() || !expiresAt.After(now) {
		return Scope{}, ErrInvalidScope
	}
	return Scope{kind: ScopeTTL, expiresAt: expiresAt}, nil
}

func (s Scope) Kind() ScopeKind {
	return s.kind
}

func (s Scope) ExpiresAt() (time.Time, bool) {
	if s.kind != ScopeTTL {
		return time.Time{}, false
	}
	return s.expiresAt, true
}

func (s Scope) ValidAt(now time.Time) bool {
	switch s.kind {
	case ScopeOnce, ScopeSession:
		return s.expiresAt.IsZero()
	case ScopeTTL:
		return !now.IsZero() && !s.expiresAt.IsZero() && s.expiresAt.After(now)
	default:
		return false
	}
}

func (s Scope) ExpiredAt(now time.Time) bool {
	return s.kind == ScopeTTL && !now.Before(s.expiresAt)
}

// Request is immutable authority intent before approval or activation.
type Request struct {
	principal   Principal
	action      Action
	resource    AdaptedResource
	scope       Scope
	policyEpoch PolicyEpoch
	requestedAt time.Time
}

func NewRequest(
	principal Principal,
	action Action,
	resource AdaptedResource,
	scope Scope,
	policyEpoch PolicyEpoch,
	requestedAt time.Time,
) (Request, error) {
	if !principal.Valid() || requestedAt.IsZero() || policyEpoch == 0 {
		return Request{}, ErrInvalidRequest
	}
	if !resource.Valid() {
		return Request{}, ErrInvalidResource
	}
	if !action.Valid() || !actionSupportsResource(action, resource.resource.kind) {
		return Request{}, fmt.Errorf("%w: %s on %s", ErrInvalidAction, action, resource.resource.kind)
	}
	if !scope.ValidAt(requestedAt) {
		return Request{}, ErrInvalidScope
	}
	return Request{
		principal:   principal,
		action:      action,
		resource:    resource,
		scope:       scope,
		policyEpoch: policyEpoch,
		requestedAt: requestedAt,
	}, nil
}

func (r Request) Principal() Principal {
	return r.principal
}

func (r Request) Action() Action {
	return r.action
}

func (r Request) Resource() Resource {
	return r.resource.Resource()
}

func (r Request) Activation() ActivationRequirement {
	return r.resource.Activation()
}

func (r Request) Scope() Scope {
	return r.scope
}

func (r Request) PolicyEpoch() PolicyEpoch {
	return r.policyEpoch
}

func (r Request) RequestedAt() time.Time {
	return r.requestedAt
}

func (a Action) Valid() bool {
	switch a {
	case ActionExec, ActionRead, ActionWrite, ActionFetch, ActionConnect,
		ActionMCPCall, ActionCredentialUse:
		return true
	default:
		return false
	}
}

func (k ResourceKind) Valid() bool {
	switch k {
	case ResourceSubprocess, ResourceFile, ResourceNetwork, ResourceMCPTool,
		ResourceCredential:
		return true
	default:
		return false
	}
}

func (s State) Valid() bool {
	switch s {
	case StateRequested, StateApproved, StateActive, StateDenied, StateConsumed,
		StateExpired, StateRevoked, StateActivationFailed:
		return true
	default:
		return false
	}
}

func actionSupportsResource(action Action, kind ResourceKind) bool {
	switch kind {
	case ResourceSubprocess:
		return action == ActionExec
	case ResourceFile:
		return action == ActionRead || action == ActionWrite
	case ResourceNetwork:
		return action == ActionFetch || action == ActionConnect
	case ResourceMCPTool:
		return action == ActionMCPCall
	case ResourceCredential:
		return action == ActionCredentialUse
	default:
		return false
	}
}

func present(value string) bool {
	return strings.TrimSpace(value) != ""
}
