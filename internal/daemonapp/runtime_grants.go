package daemonapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LuD1161/agentjail/internal/agentpolicy"
	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grant"
	"github.com/LuD1161/agentjail/internal/grantapproval"
	"github.com/LuD1161/agentjail/internal/policyeval"
	"github.com/LuD1161/agentjail/internal/store"
)

const (
	runtimeGrantCapacityGlobal     = 128
	runtimeGrantCapacityPerSession = 16
)

// daemonGrantAuthority is the daemon-owned authorization seam. It intentionally
// exposes only the lifecycle transitions the Codex shell transport consumes.
type daemonGrantAuthority interface {
	Request(context.Context, grant.Request, grant.CanonicalDecision) (grant.Grant, error)
	Approve(context.Context, grant.GrantID, grant.ApprovalReference) (grant.Grant, error)
	Activate(context.Context, grant.GrantID) (grant.Grant, error)
	FailActivation(context.Context, grant.GrantID) (grant.Grant, error)
	Deny(context.Context, grant.GrantID) (grant.Grant, error)
	Claim(grant.Access) (grant.Claim, error)
	Commit(grant.Claim) (grant.Grant, error)
	RevokeSession(grant.SessionID) int
	Reap() int
}

type daemonGrantClock struct{}

func (daemonGrantClock) Now() time.Time { return time.Now() }

// daemonGrantAudit projects generic lifecycle state into the daemon's durable
// audit log. Policy decisions remain only in decisions. See ADR 0141-runtime-grants.
type daemonGrantAudit struct{ store store.EventStore }

func (a daemonGrantAudit) EmitLifecycle(ctx context.Context, event grant.LifecycleEvent) error {
	if a.store == nil {
		return fmt.Errorf("runtime grant audit store unavailable")
	}
	var eventType string
	switch event.Type {
	case grant.LifecycleApproved:
		eventType = audit.RuntimeGrantApproved
	case grant.LifecycleActivated:
		eventType = audit.RuntimeGrantActivated
	default:
		return fmt.Errorf("unsupported runtime grant lifecycle event %q", event.Type)
	}
	detail := map[string]string{
		"action":       string(event.Action),
		"resource_ref": string(event.Resource.ID()),
		"scope":        string(event.Scope.Kind()),
		"policy_epoch": strconv.FormatUint(uint64(event.PolicyEpoch), 10),
		"request_ref":  runtimeGrantReference(string(event.RequestID)),
		"approval_ref": runtimeGrantReference(string(event.Approval)),
	}
	if expiry, ok := event.Scope.ExpiresAt(); ok {
		detail["expires_at"] = expiry.UTC().Format(time.RFC3339Nano)
	}
	return a.store.Emit(ctx, audit.Event{
		EventType: eventType,
		Entity:    "runtime_grant",
		Actor:     "daemon",
		SessionID: string(event.Principal.SessionID()),
		RefID:     runtimeGrantReference(string(event.GrantID)),
		Detail:    detail,
	})
}

func newDaemonGrantAuthority(eventStore store.EventStore) (daemonGrantAuthority, error) {
	if eventStore == nil {
		return nil, fmt.Errorf("runtime grant audit store unavailable")
	}
	ids, err := grant.NewCryptoIDSource(rand.Reader)
	if err != nil {
		return nil, err
	}
	return grant.NewManager(grant.ManagerConfig{
		Clock: daemonGrantClock{},
		IDs:   ids,
		Audit: daemonGrantAudit{store: eventStore},
		Capacity: grant.Capacity{
			Global:     runtimeGrantCapacityGlobal,
			PerSession: runtimeGrantCapacityPerSession,
		},
	})
}

func runtimeGrantReference(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

type subprocessGrantAdapter struct{}

func (subprocessGrantAdapter) Kind() grant.ResourceKind { return grant.ResourceSubprocess }

func (subprocessGrantAdapter) Canonicalize(resource grant.Resource) (grant.Resource, error) {
	identity := string(resource.ID())
	if resource.Kind() != grant.ResourceSubprocess || !strings.HasPrefix(identity, "sha256:") || len(identity) != len("sha256:")+64 {
		return grant.Resource{}, grant.ErrInvalidResource
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(identity, "sha256:")); err != nil {
		return grant.Resource{}, grant.ErrInvalidResource
	}
	return resource, nil
}

func (subprocessGrantAdapter) Equivalent(left, right grant.Resource) bool { return left == right }

func (subprocessGrantAdapter) Covers(granted, requested grant.Resource) bool {
	return granted == requested
}

func (subprocessGrantAdapter) ActivationFor(grant.Action, grant.Resource) (grant.ActivationRequirement, error) {
	return grant.ActivationNotRequired, nil
}

func codexSubprocessResource(command, cwd string) (grant.AdaptedResource, error) {
	canonicalCWD := policyeval.CanonicalizeCWD(cwd)
	if command == "" || canonicalCWD == "" {
		return grant.AdaptedResource{}, grant.ErrInvalidResource
	}
	// Length framing keeps command/CWD identities unambiguous without retaining
	// command text in the generic lifecycle or audit records.
	identity := fmt.Sprintf("%d:%s%d:%s", len(command), command, len(canonicalCWD), canonicalCWD)
	sum := sha256.Sum256([]byte(identity))
	resource, err := grant.NewResource(grant.ResourceSubprocess, grant.ResourceID("sha256:"+hex.EncodeToString(sum[:])))
	if err != nil {
		return grant.AdaptedResource{}, err
	}
	return grant.AdaptResource(subprocessGrantAdapter{}, grant.ActionExec, resource)
}

type codexGrantPending struct {
	grant  grant.Grant
	intent grantapproval.Intent
}

type codexGrantPendings struct {
	mu    sync.Mutex
	items map[approvalexec.ChallengeID]codexGrantPending
}

func (p *codexGrantPendings) put(challenge approvalexec.ChallengeID, pending codexGrantPending) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.items == nil {
		p.items = make(map[approvalexec.ChallengeID]codexGrantPending)
	}
	p.items[challenge] = pending
}

func (p *codexGrantPendings) get(challenge approvalexec.ChallengeID) (codexGrantPending, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pending, ok := p.items[challenge]
	return pending, ok
}

func (p *codexGrantPendings) take(challenge approvalexec.ChallengeID) (codexGrantPending, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pending, ok := p.items[challenge]
	delete(p.items, challenge)
	return pending, ok
}

func (p *codexGrantPendings) takeSession(session grant.SessionID) []struct {
	challenge approvalexec.ChallengeID
	pending   codexGrantPending
} {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]struct {
		challenge approvalexec.ChallengeID
		pending   codexGrantPending
	}, 0)
	for challenge, pending := range p.items {
		if pending.intent.Principal().Session() == session {
			result = append(result, struct {
				challenge approvalexec.ChallengeID
				pending   codexGrantPending
			}{challenge: challenge, pending: pending})
			delete(p.items, challenge)
		}
	}
	return result
}

func (s *server) runtimePolicyEpoch() grant.PolicyEpoch {
	epoch := s.policyEpoch.Load()
	if epoch == 0 {
		return 1
	}
	return grant.PolicyEpoch(epoch)
}

func (s *server) beginCodexRuntimeGrant(ctx context.Context, req policyeval.Request, resp *policyeval.Response, agentPID int) bool {
	if resp == nil || resp.PolicyAction != string(agentpolicy.ActionAsk) || req.SessionID == "" || req.TurnID == "" || req.ToolUseID == "" || agentPID <= 0 {
		return false
	}
	command, ok := req.ToolInput["command"].(string)
	if !ok || command == "" {
		return false
	}
	resource, err := codexSubprocessResource(command, req.CWD)
	if err != nil {
		return false
	}
	principalID := grant.PrincipalID("codex:" + strconv.Itoa(agentPID))
	principal, err := grant.NewPrincipal(principalID, grant.SessionID(req.SessionID))
	if err != nil {
		return false
	}
	request, err := grant.NewRequest(principal, grant.ActionExec, resource, grant.OnceScope(), s.runtimePolicyEpoch(), time.Now())
	if err != nil {
		return false
	}
	decision, err := grant.NewCanonicalDecision(grant.VerdictAsk, grant.DenyNone)
	if err != nil {
		return false
	}
	runtimeGrant, err := s.grantAuthority.Request(ctx, request, decision)
	if err != nil {
		return false
	}

	approvalPrincipal, err := grantapproval.NewPrincipal(grantapproval.AgentID(principalID), principal.SessionID())
	if err != nil {
		s.cancelCodexRuntimeGrant("", codexGrantPending{grant: runtimeGrant})
		return false
	}
	binding, err := grantapproval.NewBinding(grantapproval.TurnID(req.TurnID), grantapproval.ToolUseID(req.ToolUseID))
	if err != nil {
		s.cancelCodexRuntimeGrant("", codexGrantPending{grant: runtimeGrant})
		return false
	}
	display, err := grantapproval.NewDisplayContext(resp.Reason, "execute one shell command")
	if err != nil {
		s.cancelCodexRuntimeGrant("", codexGrantPending{grant: runtimeGrant})
		return false
	}
	requestRef := grantapproval.RequestReference(runtimeGrantReference(resp.RuleID + ":" + string(runtimeGrant.RequestID())))
	intent, err := grantapproval.NewIntent(
		requestRef,
		grantapproval.GrantReference(runtimeGrant.ID()),
		approvalPrincipal,
		agentpolicy.ActionAsk,
		grant.ActionExec,
		resource.Resource(),
		grant.OnceScope(),
		s.runtimePolicyEpoch(),
		binding,
		display,
	)
	if err != nil {
		s.cancelCodexRuntimeGrant("", codexGrantPending{grant: runtimeGrant})
		return false
	}
	prompt := s.grantApprovals.Begin(ctx, grantapproval.CodexShellRequest{
		Intent: intent, Command: approvalexec.Command(command), CWD: req.CWD, AgentPID: agentPID, Now: time.Now(),
	})
	if prompt.Outcome != grantapproval.OutcomePending || prompt.Challenge == "" {
		s.cancelCodexRuntimeGrant("", codexGrantPending{grant: runtimeGrant})
		return false
	}
	challenge := approvalexec.ChallengeID(prompt.Challenge)
	meta, err := s.approvals.Inspect(challenge, time.Now())
	if err != nil || meta.Operation != approvalexec.ShellCommandOperation {
		s.cancelCodexRuntimeGrant(challenge, codexGrantPending{grant: runtimeGrant})
		return false
	}
	pending := codexGrantPending{grant: runtimeGrant, intent: intent}
	s.grantPending.put(challenge, pending)
	if err := s.emitApprovalAudit(ctx, audit.CodexApprovalMinted, meta); err != nil {
		s.cancelCodexRuntimeGrant(challenge, pending)
		return false
	}
	resp.ApprovalChallenge = string(challenge)
	resp.ApprovalOperation = string(meta.Operation)
	resp.ApprovalDisplay = approvalDisplayCommand(req.ToolInput)
	slog.Info("codex runtime grant requested", "session_id", req.SessionID, "rule_ref", runtimeGrantReference(resp.RuleID))
	return true
}

func (s *server) codexEvidence(pending codexGrantPending, nonce grantapproval.Nonce, epoch, freshAfter uint64, peerFresh bool, now time.Time) (grantapproval.Evidence, error) {
	freshness, err := grantapproval.NewFreshness(epoch, freshAfter, peerFresh)
	if err != nil {
		return grantapproval.Evidence{}, err
	}
	return grantapproval.NewEvidence(
		grantapproval.CodexAdapterID,
		pending.intent.Request(), pending.intent.Grant(), pending.intent.Principal(), pending.intent.Action(),
		pending.intent.Resource(), pending.intent.Scope(), pending.intent.PolicyEpoch(), pending.intent.Binding(),
		nonce, freshness, now,
	)
}

func (s *server) cancelCodexRuntimeGrant(challenge approvalexec.ChallengeID, pending codexGrantPending) {
	if challenge != "" && s.grantApprovals != nil {
		s.grantApprovals.Cancel(grantapproval.Nonce(challenge))
	}
	if s.grantAuthority != nil && pending.grant.ID().Valid() {
		_, _ = s.grantAuthority.Deny(context.Background(), pending.grant.ID())
		_ = s.grantAuthority.Reap()
	}
}

func (s *server) activateCodexRuntimeGrant(ctx context.Context, pending codexGrantPending, meta approvalexec.Metadata) error {
	if s.grantAuthority == nil {
		return fmt.Errorf("runtime grant authority unavailable")
	}
	if _, err := s.grantAuthority.Approve(ctx, pending.grant.ID(), grant.ApprovalReference(runtimeGrantReference(string(meta.ChallengeID)))); err != nil {
		return err
	}
	if _, err := s.grantAuthority.Activate(ctx, pending.grant.ID()); err != nil {
		return err
	}
	request := pending.grant.Request()
	access, err := grant.NewAccess(request.Principal(), request.Action(), request.Resource(), s.runtimePolicyEpoch())
	if err != nil {
		return err
	}
	claim, err := s.grantAuthority.Claim(access)
	if err != nil {
		return err
	}
	_, err = s.grantAuthority.Commit(claim)
	return err
}

func (s *server) failCodexRuntimeRedemption(pending codexGrantPending) {
	if s.grantAuthority == nil || !pending.grant.ID().Valid() {
		return
	}
	_, _ = s.grantAuthority.FailActivation(context.Background(), pending.grant.ID())
	_, _ = s.grantAuthority.Deny(context.Background(), pending.grant.ID())
	// A failure after activation or claim must not retain executable authority.
	s.grantAuthority.RevokeSession(pending.grant.Request().Principal().SessionID())
	s.grantAuthority.Reap()
}

func (s *server) revokeCodexSession(sessionID string, agentPID int) {
	if sessionID == "" || agentPID <= 0 || s.activeSessions == nil {
		return
	}
	trackedSession, _, active := s.activeSessions.findSessionByPID(agentPID)
	if !active || trackedSession != sessionID {
		return
	}
	for _, entry := range s.grantPending.takeSession(grant.SessionID(sessionID)) {
		s.cancelCodexRuntimeGrant(entry.challenge, entry.pending)
	}
	if s.grantAuthority != nil {
		s.grantAuthority.RevokeSession(grant.SessionID(sessionID))
		s.grantAuthority.Reap()
	}
}

func (s *server) revokeRuntimeGrants() {
	if s.activeSessions == nil {
		return
	}
	for _, session := range s.activeSessions.list() {
		for _, entry := range s.grantPending.takeSession(grant.SessionID(session.SessionID)) {
			s.cancelCodexRuntimeGrant(entry.challenge, entry.pending)
		}
		if s.grantAuthority != nil {
			s.grantAuthority.RevokeSession(grant.SessionID(session.SessionID))
		}
	}
	if s.grantAuthority != nil {
		s.grantAuthority.Reap()
	}
}
