package hostconnector

import (
	"context"
	"errors"
	"sync"

	"github.com/LuD1161/agentjail/internal/grant"
)

// AccessFactory maps one configured connector to its canonical runtime-grant
// access. The daemon owns this mapping because it owns policy epoch and the
// configured resource identity; connector callers never supply a resource.
type AccessFactory interface {
	Access(Binding, ConnectorID) (grant.Access, error)
}

// GrantAuthorizer adapts the generic runtime authority to connector use
// leases. It is deliberately explicit about Claim/Commit so one-use grants do
// not become reusable merely because a connector route activated successfully.
type GrantAuthorizer struct {
	authority grant.Authority
	access    AccessFactory
}

func NewGrantAuthorizer(authority grant.Authority, access AccessFactory) (*GrantAuthorizer, error) {
	if authority == nil || access == nil {
		return nil, ErrActivation
	}
	return &GrantAuthorizer{authority: authority, access: access}, nil
}

func (a *GrantAuthorizer) Begin(_ context.Context, binding Binding, id ConnectorID, scope grant.Scope) (UseLease, error) {
	access, err := a.access.Access(binding, id)
	if err != nil {
		return nil, err
	}
	if scope.Kind() == grant.ScopeOnce {
		claim, err := a.authority.Claim(access)
		if err != nil {
			return nil, err
		}
		return &grantUseLease{authority: a.authority, access: access, claim: claim}, nil
	}
	if _, err := a.authority.Authorize(access); err != nil {
		return nil, err
	}
	return &grantUseLease{authority: a.authority, access: access}, nil
}

type grantUseLease struct {
	mu        sync.Mutex
	authority grant.Authority
	access    grant.Access
	claim     grant.Claim
	used      bool
	closed    bool
}

func (l *grantUseLease) Use(_ context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return grant.ErrGrantRevoked
	}
	if l.claim.ID().Valid() {
		if l.used {
			return grant.ErrClaimAlreadyCommitted
		}
		if _, err := l.authority.Commit(l.claim); err != nil {
			return err
		}
		l.used = true
		return nil
	}
	_, err := l.authority.Authorize(l.access)
	return err
}

func (l *grantUseLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if !l.claim.ID().Valid() || l.used {
		return nil
	}
	err := l.authority.Rollback(l.claim)
	if errors.Is(err, grant.ErrClaimAlreadyRolledBack) {
		return nil
	}
	return err
}
