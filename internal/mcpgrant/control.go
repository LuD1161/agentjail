package mcpgrant

import (
	"context"
	"errors"
	"time"

	"github.com/LuD1161/agentjail/internal/grant"
)

var ErrApprovalUnavailable = errors.New("MCP grant approval is unavailable for this agent")

// Control is the trusted-side lifecycle seam for MCP grants. It deliberately
// has no hook, socket, or agent-controlled approval operation.
type Control struct {
	manager grant.Authority
	adapter Adapter
}

func NewControl(manager grant.Authority) *Control {
	return &Control{manager: manager, adapter: Adapter{}}
}

// Request creates an eligible pending MCP grant. Callers must already have the
// canonical ask decision; an agent cannot turn this into a self-approval path.
func (c *Control) Request(ctx context.Context, principal grant.Principal, call Call, scope grant.Scope, epoch grant.PolicyEpoch, now time.Time) (grant.Grant, error) {
	if c == nil || c.manager == nil {
		return grant.Grant{}, ErrApprovalUnavailable
	}
	resource, err := call.Resource()
	if err != nil {
		return grant.Grant{}, err
	}
	adapted, err := grant.AdaptResource(c.adapter, grant.ActionMCPCall, resource)
	if err != nil {
		return grant.Grant{}, err
	}
	request, err := grant.NewRequest(principal, grant.ActionMCPCall, adapted, scope, epoch, now)
	if err != nil {
		return grant.Grant{}, err
	}
	decision, err := grant.NewCanonicalDecision(grant.VerdictAsk, grant.DenyNone)
	if err != nil {
		return grant.Grant{}, err
	}
	return c.manager.Request(ctx, request, decision)
}

// ApproveAndActivate is intentionally for a trusted companion or verified
// native adapter. It has no agent-facing transport and cannot infer approval.
func (c *Control) ApproveAndActivate(ctx context.Context, id grant.GrantID, approval grant.ApprovalReference) (grant.Grant, error) {
	if c == nil || c.manager == nil {
		return grant.Grant{}, ErrApprovalUnavailable
	}
	if _, err := c.manager.Approve(ctx, id, approval); err != nil {
		return grant.Grant{}, err
	}
	return c.manager.Activate(ctx, id)
}
