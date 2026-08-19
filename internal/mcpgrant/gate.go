package mcpgrant

import (
	"context"
	"errors"
	"sync"

	"github.com/LuD1161/agentjail/internal/grant"
)

var ErrLeaseResolved = errors.New("MCP forwarding lease already resolved")

type PolicyVerdict string

const (
	PolicyDeny  PolicyVerdict = "deny"
	PolicyAllow PolicyVerdict = "allow"
	PolicyAsk   PolicyVerdict = "ask"
)

func (v PolicyVerdict) Valid() bool { return v == PolicyDeny || v == PolicyAllow || v == PolicyAsk }

type EffectiveVerdict string

const (
	EffectivePolicyDenied EffectiveVerdict = "policy_denied"
	EffectivePolicyAllow  EffectiveVerdict = "policy_allowed"
	EffectiveGrantAllow   EffectiveVerdict = "grant_allowed"
	EffectiveGrantMissing EffectiveVerdict = "grant_missing"
	EffectiveGrantExpired EffectiveVerdict = "grant_expired"
	EffectiveGrantReplay  EffectiveVerdict = "grant_replayed"
	EffectiveGrantSession EffectiveVerdict = "grant_session_mismatch"
	EffectiveGrantEpoch   EffectiveVerdict = "grant_stale_epoch"
	EffectiveGrantFailed  EffectiveVerdict = "grant_unavailable"
)

type FinalVerdict string

const (
	FinalDenied              FinalVerdict = "denied"
	FinalForwardAuthorized   FinalVerdict = "forward_authorized"
	FinalServerUnconfigured  FinalVerdict = "server_unconfigured"
	FinalUpstreamUnavailable FinalVerdict = "upstream_unavailable"
)

type ClaimStatus string

const (
	ClaimAuthorized      ClaimStatus = "authorized"
	ClaimMissing         ClaimStatus = "missing"
	ClaimExpired         ClaimStatus = "expired"
	ClaimReplayed        ClaimStatus = "replayed"
	ClaimSessionMismatch ClaimStatus = "session_mismatch"
	ClaimEpochMismatch   ClaimStatus = "stale_epoch"
	ClaimUnavailable     ClaimStatus = "unavailable"
)

// ClaimRequest binds a runtime-grant lookup to exactly one MCP tool call.
type ClaimRequest struct {
	Principal   grant.Principal
	Action      grant.Action
	Resource    grant.Resource
	PolicyEpoch grant.PolicyEpoch
}

func (r ClaimRequest) Valid() bool {
	return r.Principal.Valid() && r.Action == grant.ActionMCPCall && r.Resource.Valid() &&
		r.Resource.Kind() == grant.ResourceMCPTool && r.PolicyEpoch != 0
}

// Authority is owned by the MCP gate consumer. Its implementation must check
// active state and exact principal, session, action, resource, and policy epoch.
// For a one-use grant, Claim reserves only; Commit must consume it atomically.
type Authority interface {
	Claim(context.Context, ClaimRequest, grant.ResourceAdapter) (Lease, ClaimStatus, error)
}

// Lease has the only path by which a claimed grant can be committed or rolled
// back. The caller must confirm that forwarding began or succeeded explicitly.
type Lease interface {
	Commit(context.Context, ForwardEvidence) error
	Rollback(context.Context) error
}

type ForwardEvidence string

const (
	ForwardingBegan     ForwardEvidence = "forwarding_began"
	ForwardingSucceeded ForwardEvidence = "forwarding_succeeded"
)

func (e ForwardEvidence) Valid() bool { return e == ForwardingBegan || e == ForwardingSucceeded }

// ServerRegistry exposes only servers fixed at session startup; it provides no
// registration operation, so unknown servers remain fail-closed.
type ServerRegistry interface {
	Configured(ServerID) bool
}

// Upstream reports connector reachability independently of authorization.
type Upstream interface {
	Available(context.Context, ServerID) bool
}

// Gate is a transport-neutral decision point placed immediately before a real
// MCP forwarding boundary. It does not implement a proxy.
type Gate struct {
	servers   ServerRegistry
	upstream  Upstream
	authority Authority
	adapter   Adapter
}

func NewGate(servers ServerRegistry, upstream Upstream, authority Authority) Gate {
	return Gate{servers: servers, upstream: upstream, authority: authority, adapter: Adapter{}}
}

// Check evaluates canonical policy before runtime authority. Policy allow does
// not create or consume a grant; only policy ask may claim an active grant.
func (g Gate) Check(ctx context.Context, principal grant.Principal, epoch grant.PolicyEpoch, policy PolicyVerdict, call Call) Result {
	result := Result{Canonical: policy, Final: FinalDenied}
	if !policy.Valid() || !principal.Valid() || epoch == 0 || !call.Valid() {
		result.Effective = EffectivePolicyDenied
		return result
	}
	if policy == PolicyDeny {
		result.Effective = EffectivePolicyDenied
		return result
	}
	if g.servers == nil || !g.servers.Configured(call.Server()) {
		result.Effective = effectiveForPolicy(policy)
		result.Final = FinalServerUnconfigured
		return result
	}
	if g.upstream == nil || !g.upstream.Available(ctx, call.Server()) {
		result.Effective = effectiveForPolicy(policy)
		result.Final = FinalUpstreamUnavailable
		return result
	}
	if policy == PolicyAllow {
		result.Effective = EffectivePolicyAllow
		result.Final = FinalForwardAuthorized
		return result
	}

	resource, err := call.Resource()
	if err != nil || g.authority == nil {
		result.Effective, result.Claim = EffectiveGrantFailed, ClaimUnavailable
		return result
	}
	lease, status, err := g.authority.Claim(ctx, ClaimRequest{
		Principal: principal, Action: grant.ActionMCPCall, Resource: resource, PolicyEpoch: epoch,
	}, g.adapter)
	result.Claim = status
	if err != nil || status != ClaimAuthorized || lease == nil {
		result.Effective = effectiveForClaim(status)
		return result
	}
	result.Effective = EffectiveGrantAllow
	result.Final = FinalForwardAuthorized
	result.Lease = &forwardLease{lease: lease}
	return result
}

func effectiveForPolicy(policy PolicyVerdict) EffectiveVerdict {
	if policy == PolicyAllow {
		return EffectivePolicyAllow
	}
	return EffectiveGrantMissing
}

func effectiveForClaim(status ClaimStatus) EffectiveVerdict {
	switch status {
	case ClaimExpired:
		return EffectiveGrantExpired
	case ClaimReplayed:
		return EffectiveGrantReplay
	case ClaimSessionMismatch:
		return EffectiveGrantSession
	case ClaimEpochMismatch:
		return EffectiveGrantEpoch
	case ClaimMissing:
		return EffectiveGrantMissing
	default:
		return EffectiveGrantFailed
	}
}

// Result keeps canonical policy, effective authority, and final forwarding
// outcomes separate for decision/audit callers.
type Result struct {
	Canonical PolicyVerdict
	Effective EffectiveVerdict
	Final     FinalVerdict
	Claim     ClaimStatus
	Lease     ForwardLease
}

// ForwardLease serializes confirmation or rollback of an authority claim.
type ForwardLease interface {
	Confirm(context.Context, ForwardEvidence) error
	Rollback(context.Context) error
}

type forwardLease struct {
	mu       sync.Mutex
	lease    Lease
	resolved bool
}

func (l *forwardLease) Confirm(ctx context.Context, evidence ForwardEvidence) error {
	if !evidence.Valid() {
		return errors.New("invalid MCP forwarding evidence")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.resolved {
		return ErrLeaseResolved
	}
	if err := l.lease.Commit(ctx, evidence); err != nil {
		return err
	}
	l.resolved = true
	return nil
}

func (l *forwardLease) Rollback(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.resolved {
		return ErrLeaseResolved
	}
	if err := l.lease.Rollback(ctx); err != nil {
		return err
	}
	l.resolved = true
	return nil
}

// StaticServers is an immutable first-release registry of session-start MCP servers.
type StaticServers struct{ servers []ServerID }

func NewStaticServers(servers ...ServerID) (StaticServers, error) {
	result := StaticServers{servers: append([]ServerID(nil), servers...)}
	for _, server := range result.servers {
		if err := validateServerID(server); err != nil {
			return StaticServers{}, err
		}
	}
	return result, nil
}

func (s StaticServers) Configured(server ServerID) bool {
	for _, configured := range s.servers {
		if configured == server {
			return true
		}
	}
	return false
}
