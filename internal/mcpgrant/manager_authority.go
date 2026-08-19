package mcpgrant

import (
	"context"
	"errors"

	"github.com/LuD1161/agentjail/internal/grant"
)

// ManagerAuthority adapts the generic runtime lifecycle to the MCP gate.
// It owns no policy or approval surface; those remain outside the agent path.
// See ADR 0141-runtime-grants.
type ManagerAuthority struct{ manager *grant.Manager }

func NewManagerAuthority(manager *grant.Manager) *ManagerAuthority {
	return &ManagerAuthority{manager: manager}
}

func (a *ManagerAuthority) Claim(_ context.Context, request ClaimRequest, adapter grant.ResourceAdapter) (Lease, ClaimStatus, error) {
	if a == nil || a.manager == nil || !request.Valid() || adapter == nil || adapter.Kind() != grant.ResourceMCPTool {
		return nil, ClaimUnavailable, errors.New("MCP runtime authority is unavailable")
	}
	access, err := grant.NewAccess(request.Principal, request.Action, request.Resource, request.PolicyEpoch)
	if err != nil {
		return nil, ClaimUnavailable, err
	}
	_, err = a.manager.AuthorizeWithAdapter(access, adapter)
	if err == nil {
		return sessionLease{}, ClaimAuthorized, nil
	}
	if !errors.Is(err, grant.ErrClaimRequired) {
		return nil, claimStatus(err), err
	}
	claim, err := a.manager.ClaimWithAdapter(access, adapter)
	if err != nil {
		return nil, claimStatus(err), err
	}
	return &onceLease{manager: a.manager, claim: claim}, ClaimAuthorized, nil
}

func claimStatus(err error) ClaimStatus {
	switch {
	case errors.Is(err, grant.ErrGrantExpired):
		return ClaimExpired
	case errors.Is(err, grant.ErrGrantAlreadyClaimed), errors.Is(err, grant.ErrClaimAlreadyCommitted), errors.Is(err, grant.ErrClaimAlreadyRolledBack):
		return ClaimReplayed
	case errors.Is(err, grant.ErrStalePolicyEpoch):
		return ClaimEpochMismatch
	case errors.Is(err, grant.ErrAccessMismatch), errors.Is(err, grant.ErrGrantNotFound), errors.Is(err, grant.ErrGrantNotActive), errors.Is(err, grant.ErrGrantRevoked):
		return ClaimMissing
	default:
		return ClaimUnavailable
	}
}

type sessionLease struct{}

func (sessionLease) Commit(context.Context, ForwardEvidence) error { return nil }
func (sessionLease) Rollback(context.Context) error                { return nil }

type onceLease struct {
	manager *grant.Manager
	claim   grant.Claim
}

func (l *onceLease) Commit(_ context.Context, _ ForwardEvidence) error {
	if l == nil || l.manager == nil {
		return errors.New("MCP runtime authority is unavailable")
	}
	_, err := l.manager.Commit(l.claim)
	return err
}

func (l *onceLease) Rollback(context.Context) error {
	if l == nil || l.manager == nil {
		return errors.New("MCP runtime authority is unavailable")
	}
	return l.manager.Rollback(l.claim)
}
