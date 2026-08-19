package grantapproval

import "context"

// Outcome is the adapter result. Only an explicit allow outcome can advance a
// request; prompt visibility, a retry, or a successful operation are absent.
type Outcome string

const (
	OutcomePending           Outcome = "pending"
	OutcomeAllowOnce         Outcome = "allow_once"
	OutcomeAllowSession      Outcome = "allow_session"
	OutcomeAllowTTL          Outcome = "allow_ttl"
	OutcomeDenied            Outcome = "denied"
	OutcomeTimedOut          Outcome = "timed_out"
	OutcomeCancelled         Outcome = "cancelled"
	OutcomeUnsupported       Outcome = "unsupported"
	OutcomeMalformedEvidence Outcome = "malformed_evidence"
)

func (o Outcome) Authorizes() bool {
	return o == OutcomeAllowOnce || o == OutcomeAllowSession || o == OutcomeAllowTTL
}

// PromptAdapter is owned by the consuming approval transport. The policy
// action stays on Intent; adapters only project a prompt and verify evidence.
type PromptAdapter interface {
	AdapterID() AdapterID
	Project(context.Context, Intent) (Prompt, Outcome)
	Verify(context.Context, Intent, Evidence) Outcome
}

func contextOutcome(ctx context.Context) Outcome {
	if ctx == nil || ctx.Err() == nil {
		return OutcomePending
	}
	if ctx.Err() == context.DeadlineExceeded {
		return OutcomeTimedOut
	}
	return OutcomeCancelled
}
