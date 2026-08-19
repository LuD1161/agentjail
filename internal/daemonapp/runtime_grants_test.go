package daemonapp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/agentpolicy"
	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/grant"
	"github.com/LuD1161/agentjail/internal/grantapproval"
	"github.com/LuD1161/agentjail/internal/policyeval"
	"github.com/LuD1161/agentjail/internal/store"
)

func TestCodexSubprocessResourceFingerprintsExactIntent(t *testing.T) {
	first, err := codexSubprocessResource("curl https://user:secret@example.test", "/repo")
	if err != nil {
		t.Fatal(err)
	}
	second, err := codexSubprocessResource("curl https://user:secret@example.test", "/other")
	if err != nil {
		t.Fatal(err)
	}
	if first.Resource() == second.Resource() {
		t.Fatal("different working directories produced the same subprocess identity")
	}
	if strings.Contains(string(first.Resource().ID()), "secret") {
		t.Fatalf("resource identity leaked command text: %q", first.Resource().ID())
	}
}

func TestNewDaemonGrantAuthorityRequiresDurableStore(t *testing.T) {
	if _, err := newDaemonGrantAuthority(nil); err == nil {
		t.Fatal("newDaemonGrantAuthority(nil) succeeded")
	}
}

func TestDaemonRuntimeGrantCreatedOnlyForCanonicalAsk(t *testing.T) {
	srv, manager, closeStore := newRuntimeGrantTestServer(t)
	defer closeStore()

	request := runtimeGrantTestRequest()
	for _, action := range []agentpolicy.Action{agentpolicy.ActionAllow, agentpolicy.ActionDeny} {
		response := policyeval.Response{PolicyAction: string(action), Reason: "not eligible"}
		if srv.beginCodexRuntimeGrant(context.Background(), request, &response, os.Getpid()) {
			t.Fatalf("beginCodexRuntimeGrant() accepted canonical %s", action)
		}
	}

	response := policyeval.Response{
		Action: "ask", PolicyAction: string(agentpolicy.ActionAsk), EffectiveAction: "ask", Adapter: "codex",
		RuleID: "command_policy/test", Reason: "approval required",
	}
	if !srv.beginCodexRuntimeGrant(context.Background(), request, &response, os.Getpid()) {
		t.Fatal("beginCodexRuntimeGrant() rejected an eligible canonical ask")
	}
	if response.ApprovalChallenge == "" || response.ApprovalOperation != string(approvalexec.ShellCommandOperation) {
		t.Fatalf("response = %+v, want shell approval challenge", response)
	}
	if response.Action != "ask" || response.PolicyAction != "ask" || response.EffectiveAction != "ask" || response.Adapter != "codex" {
		t.Fatalf("runtime grant changed canonical/effective decision fields: %+v", response)
	}
	if manager.Reap() != 0 {
		t.Fatal("eligible runtime grant was unexpectedly terminal")
	}
}

func TestRuntimeGrantAuditFailureFailsClosed(t *testing.T) {
	resource, err := codexSubprocessResource("echo safe", "/repo")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := grant.NewPrincipal("codex:1", "session")
	if err != nil {
		t.Fatal(err)
	}
	request, err := grant.NewRequest(principal, grant.ActionExec, resource, grant.OnceScope(), 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ids, err := grant.NewCryptoIDSource(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := grant.NewManager(grant.ManagerConfig{
		Clock: daemonGrantClock{}, IDs: ids, Audit: daemonGrantAudit{}, Capacity: grant.Capacity{Global: 2, PerSession: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := grant.NewCanonicalDecision(grant.VerdictAsk, grant.DenyNone)
	runtimeGrant, err := manager.Request(context.Background(), request, decision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Approve(context.Background(), runtimeGrant.ID(), "approval-ref"); !errors.Is(err, grant.ErrAuditFailed) {
		t.Fatalf("Approve() error = %v, want durable audit failure", err)
	}
}

func TestCodexRuntimeGrantPromptStaysPendingThenConsumesOnce(t *testing.T) {
	srv, manager, closeStore := newRuntimeGrantTestServer(t)
	defer closeStore()
	srv.approvals.BeginToolCall("session")

	request := runtimeGrantTestRequest()
	response := policyeval.Response{PolicyAction: string(agentpolicy.ActionAsk), RuleID: "command_policy/test", Reason: "approval required"}
	if !srv.beginCodexRuntimeGrant(context.Background(), request, &response, os.Getpid()) {
		t.Fatal("beginCodexRuntimeGrant() rejected eligible ask")
	}
	challenge := approvalexec.ChallengeID(response.ApprovalChallenge)
	pending, ok := srv.grantPending.get(challenge)
	if !ok {
		t.Fatal("missing pending runtime grant")
	}
	now := time.Now()
	evidence, err := srv.codexEvidence(pending, grantapproval.Nonce(challenge), srv.approvals.CurrentEpoch("session"), 1, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := srv.grantApprovals.Observe(context.Background(), evidence, now); outcome != grantapproval.OutcomePending {
		t.Fatalf("Observe() = %q, want pending", outcome)
	}
	if current, err := manager.Lookup(pending.grant.ID()); err != nil || current.State() != grant.StateRequested {
		t.Fatalf("prompt observation grant = %+v, %v; want requested", current, err)
	}
	redemption, outcome := srv.grantApprovals.Redeem(context.Background(), evidence, now)
	if outcome != grantapproval.OutcomeAllowOnce || redemption.Command != "echo approved" {
		t.Fatalf("Redeem() = %+v, %q; want exact one-use redemption", redemption, outcome)
	}
	if err := srv.activateCodexRuntimeGrant(context.Background(), pending, approvalexec.Metadata{ChallengeID: challenge}); err != nil {
		t.Fatal(err)
	}
	if current, err := manager.Lookup(pending.grant.ID()); err != nil || current.State() != grant.StateConsumed {
		t.Fatalf("consumed grant = %+v, %v; want consumed", current, err)
	}
	access, err := grant.NewAccess(pending.grant.Request().Principal(), grant.ActionExec, pending.grant.Request().Resource(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Claim(access); !errors.Is(err, grant.ErrGrantNotActive) {
		t.Fatalf("replay Claim() error = %v, want inactive consumed grant", err)
	}
	events, err := srv.eventStore.ListAuditLog(context.Background(), store.AuditLogFilter{SessionID: "session", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, event := range events {
		joined += event.EventType + " " + event.Detail + " "
	}
	if !strings.Contains(joined, "runtime_grant.approved") || !strings.Contains(joined, "runtime_grant.activated") {
		t.Fatalf("lifecycle audit events = %q", joined)
	}
	if strings.Contains(joined, "echo approved") {
		t.Fatalf("lifecycle audit leaked command: %q", joined)
	}
}

func TestVerifiedSessionStopRevokesPendingRuntimeGrant(t *testing.T) {
	srv, manager, closeStore := newRuntimeGrantTestServer(t)
	defer closeStore()
	tracker := newActiveTracker(t.TempDir())
	tracker.sessions["session"] = &sessionState{PID: os.Getpid(), CWD: "/repo"}
	srv.activeSessions = tracker

	request := runtimeGrantTestRequest()
	response := policyeval.Response{PolicyAction: string(agentpolicy.ActionAsk), RuleID: "command_policy/test", Reason: "approval required"}
	if !srv.beginCodexRuntimeGrant(context.Background(), request, &response, os.Getpid()) {
		t.Fatal("beginCodexRuntimeGrant() rejected eligible ask")
	}
	challenge := approvalexec.ChallengeID(response.ApprovalChallenge)
	pending, ok := srv.grantPending.get(challenge)
	if !ok {
		t.Fatal("missing pending runtime grant")
	}
	srv.revokeCodexSession("session", os.Getpid())
	if _, ok := srv.grantPending.get(challenge); ok {
		t.Fatal("session stop retained pending runtime grant")
	}
	if _, err := manager.Lookup(pending.grant.ID()); !errors.Is(err, grant.ErrGrantNotFound) {
		t.Fatalf("revoked grant lookup error = %v, want not found after reap", err)
	}
}

func newRuntimeGrantTestServer(t *testing.T) (*server, *grant.Manager, func()) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newDaemonGrantAuthority(st)
	if err != nil {
		_ = st.Close()
		t.Fatal(err)
	}
	manager, ok := authority.(*grant.Manager)
	if !ok {
		_ = st.Close()
		t.Fatal("daemon authority is not grant.Manager")
	}
	approvals := approvalexec.NewManager(bytes.NewReader(bytes.Repeat([]byte{2}, 64)), time.Minute, time.Minute)
	srv := &server{
		approvals:      approvals,
		eventStore:     st,
		grantAuthority: authority,
		grantApprovals: grantapproval.NewCodexAdapter(approvals),
	}
	srv.policyEpoch.Store(1)
	return srv, manager, func() { _ = st.Close() }
}

func runtimeGrantTestRequest() policyeval.Request {
	return policyeval.Request{
		Agent: "codex", SessionID: "session", TurnID: "turn", ToolUseID: "tool", CWD: "/repo",
		ToolInput: map[string]interface{}{"command": "echo approved"},
	}
}
