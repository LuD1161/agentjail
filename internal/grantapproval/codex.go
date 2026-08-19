package grantapproval

import (
	"context"
	"sync"
	"time"

	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/grant"
)

const CodexAdapterID AdapterID = "codex"

// CodexShellRequest contains the exact in-memory shell operation protected by
// the already verified approval-exec boundary. It is not prompt display text.
type CodexShellRequest struct {
	Intent   Intent
	Command  approvalexec.Command
	CWD      string
	AgentPID int
	Now      time.Time
}

// CodexPrompt is the fixed broker command and typed evidence nonce returned to
// the hook. The original command stays only in approvalexec.Manager memory.
type CodexPrompt struct {
	Prompt    Prompt
	Challenge Nonce
	Command   string
	Outcome   Outcome
}

type codexPending struct {
	intent Intent
	meta   approvalexec.Metadata
}

// CodexAdapter maps only one-use subprocess execution to Codex's native
// execpolicy prompt. Other resources and scopes fail closed until a separately
// compatibility-tested transport exists.
type CodexAdapter struct {
	manager *approvalexec.Manager
	mu      sync.Mutex
	pending map[Nonce]codexPending
}

var _ PromptAdapter = (*CodexAdapter)(nil)

func NewCodexAdapter(manager *approvalexec.Manager) *CodexAdapter {
	return &CodexAdapter{manager: manager, pending: make(map[Nonce]codexPending)}
}

func (a *CodexAdapter) AdapterID() AdapterID { return CodexAdapterID }

func (a *CodexAdapter) Project(ctx context.Context, intent Intent) (Prompt, Outcome) {
	if outcome := contextOutcome(ctx); outcome != OutcomePending {
		return Prompt{}, outcome
	}
	if !intent.Valid() || intent.PolicyAction() != "ask" {
		return Prompt{}, OutcomeMalformedEvidence
	}
	if intent.Action() != grant.ActionExec || intent.Resource().Kind() != grant.ResourceSubprocess ||
		intent.Scope().Kind() != grant.ScopeOnce {
		return intent.Prompt(), OutcomeUnsupported
	}
	return intent.Prompt(), OutcomePending
}

// Verify only validates exact generic evidence. Begin, Observe, and Redeem
// perform the native approval-exec state transitions.
func (a *CodexAdapter) Verify(ctx context.Context, intent Intent, evidence Evidence) Outcome {
	if outcome := contextOutcome(ctx); outcome != OutcomePending {
		return outcome
	}
	if !evidence.Matches(intent, a.AdapterID()) {
		return OutcomeMalformedEvidence
	}
	return OutcomePending
}

func (a *CodexAdapter) Begin(ctx context.Context, request CodexShellRequest) CodexPrompt {
	prompt, outcome := a.Project(ctx, request.Intent)
	if outcome != OutcomePending {
		return CodexPrompt{Prompt: prompt, Outcome: outcome}
	}
	if a.manager == nil || request.Command == "" || request.CWD == "" || request.AgentPID <= 0 || request.Now.IsZero() {
		return CodexPrompt{Prompt: prompt, Outcome: OutcomeMalformedEvidence}
	}
	meta, err := a.manager.Mint(approvalexec.MintRequest{
		SessionID: approvalexec.SessionID(request.Intent.Principal().Session()),
		TurnID:    approvalexec.TurnID(request.Intent.Binding().Turn()),
		ToolUseID: approvalexec.ToolUseID(request.Intent.Binding().ToolUse()),
		Operation: approvalexec.ShellCommandOperation,
		Command:   request.Command,
		CWD:       request.CWD,
		AgentPID:  request.AgentPID,
		RuleID:    string(request.Intent.Request()),
		Now:       request.Now,
	})
	if err != nil {
		return CodexPrompt{Prompt: prompt, Outcome: OutcomeDenied}
	}
	nonce := Nonce(meta.ChallengeID)
	a.mu.Lock()
	a.pending[nonce] = codexPending{intent: request.Intent, meta: meta}
	a.mu.Unlock()
	invocation := approvalexec.BrokerInvocation{Operation: meta.Operation, ChallengeID: meta.ChallengeID}
	return CodexPrompt{Prompt: prompt, Challenge: nonce, Command: approvalexec.BrokerCommand(invocation), Outcome: OutcomePending}
}

// Observe binds Codex PermissionRequest to the generic request. Seeing the
// prompt is intentionally still pending; it is not user authorization.
func (a *CodexAdapter) Observe(ctx context.Context, evidence Evidence, now time.Time) Outcome {
	if outcome := contextOutcome(ctx); outcome != OutcomePending {
		a.cancel(evidence.Nonce())
		return outcome
	}
	pending, ok := a.lookup(evidence.Nonce())
	if !ok || !evidence.Matches(pending.intent, a.AdapterID()) || now.IsZero() {
		a.cancel(evidence.Nonce())
		return OutcomeMalformedEvidence
	}
	_, err := a.manager.ObservePrompt(approvalexec.ObserveRequest{
		ChallengeID: pending.meta.ChallengeID,
		Operation:   approvalexec.ShellCommandOperation,
		SessionID:   approvalexec.SessionID(evidence.Principal().Session()),
		TurnID:      approvalexec.TurnID(evidence.Binding().Turn()),
		CWD:         pending.meta.CWD,
		FreshAfter:  evidence.Freshness().FreshAfter(),
		Now:         now,
	})
	if err != nil {
		a.forget(evidence.Nonce())
		return OutcomeDenied
	}
	return OutcomePending
}

// Redeem returns allow-once only after exact evidence and approvalexec's
// one-use, session, epoch, and fresh-process checks succeed.
func (a *CodexAdapter) Redeem(ctx context.Context, evidence Evidence, now time.Time) (approvalexec.Redemption, Outcome) {
	if outcome := contextOutcome(ctx); outcome != OutcomePending {
		a.cancel(evidence.Nonce())
		return approvalexec.Redemption{}, outcome
	}
	pending, ok := a.lookup(evidence.Nonce())
	if !ok || !evidence.Matches(pending.intent, a.AdapterID()) || now.IsZero() {
		a.cancel(evidence.Nonce())
		return approvalexec.Redemption{}, OutcomeMalformedEvidence
	}
	redemption, err := a.manager.Redeem(approvalexec.RedeemRequest{
		ChallengeID:     pending.meta.ChallengeID,
		Operation:       approvalexec.ShellCommandOperation,
		VerifiedSession: approvalexec.SessionID(evidence.Principal().Session()),
		PeerChainFresh:  evidence.Freshness().PeerFresh(),
		CurrentEpoch:    evidence.Freshness().ToolCallEpoch(),
		Now:             now,
	})
	a.forget(evidence.Nonce())
	if err != nil {
		return approvalexec.Redemption{}, OutcomeDenied
	}
	return redemption, OutcomeAllowOnce
}

func (a *CodexAdapter) lookup(nonce Nonce) (codexPending, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pending, ok := a.pending[nonce]
	return pending, ok
}

func (a *CodexAdapter) forget(nonce Nonce) {
	a.mu.Lock()
	delete(a.pending, nonce)
	a.mu.Unlock()
}

func (a *CodexAdapter) cancel(nonce Nonce) {
	if a.manager != nil && nonce != "" {
		a.manager.Burn(approvalexec.ChallengeID(nonce))
	}
	a.forget(nonce)
}
