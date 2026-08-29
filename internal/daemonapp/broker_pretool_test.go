package daemonapp

import (
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/policyeval"
)

func TestPendingBrokerPreToolAllowsOnlyBoundPendingTransport(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	manager := approvalexec.NewManager(strings.NewReader(strings.Repeat("a", 64)), time.Minute, time.Minute)
	manager.BeginToolCall("session")
	meta, err := manager.Mint(approvalexec.MintRequest{
		SessionID: "session", TurnID: "turn", ToolUseID: "tool", Operation: approvalexec.HostProxyOperation,
		Command: "agentjail proxy -- cat /outside/data.csv", CWD: "/project", AgentPID: 42,
		RuleID: "command_policy/confirm-host-proxy", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &server{approvals: manager}
	req := policyeval.Request{SessionID: "session", TurnID: "turn", CWD: "/project"}
	invocation := approvalexec.BrokerInvocation{Operation: meta.Operation, ChallengeID: meta.ChallengeID}
	epoch := manager.CurrentEpoch("session")

	if !srv.pendingBrokerPreTool(req, invocation, 42, now) {
		t.Fatal("bound pending broker transport was denied")
	}
	if got := manager.CurrentEpoch("session"); got != epoch {
		t.Fatalf("broker transport advanced tool-call epoch: got %d want %d", got, epoch)
	}

	for _, test := range []struct {
		name       string
		req        policyeval.Request
		invocation approvalexec.BrokerInvocation
		pid        int
	}{
		{name: "wrong session", req: policyeval.Request{SessionID: "other", TurnID: "turn", CWD: "/project"}, invocation: invocation, pid: 42},
		{name: "wrong turn", req: policyeval.Request{SessionID: "session", TurnID: "other", CWD: "/project"}, invocation: invocation, pid: 42},
		{name: "wrong cwd", req: policyeval.Request{SessionID: "session", TurnID: "turn", CWD: "/other"}, invocation: invocation, pid: 42},
		{name: "unverified process", req: req, invocation: invocation, pid: 0},
		{name: "wrong process", req: req, invocation: invocation, pid: 43},
		{name: "wrong operation", req: req, invocation: approvalexec.BrokerInvocation{Operation: approvalexec.ShellCommandOperation, ChallengeID: meta.ChallengeID}, pid: 42},
		{name: "unknown challenge", req: req, invocation: approvalexec.BrokerInvocation{Operation: meta.Operation, ChallengeID: approvalexec.ChallengeID(strings.Repeat("Z", 43))}, pid: 42},
	} {
		t.Run(test.name, func(t *testing.T) {
			if srv.pendingBrokerPreTool(test.req, test.invocation, test.pid, now) {
				t.Fatal("mismatched broker transport was allowed")
			}
		})
	}
}

func TestPendingBrokerPreToolRejectsObservedChallenge(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	manager := approvalexec.NewManager(strings.NewReader(strings.Repeat("b", 64)), time.Minute, time.Minute)
	manager.BeginToolCall("session")
	meta, err := manager.Mint(approvalexec.MintRequest{
		SessionID: "session", TurnID: "turn", ToolUseID: "tool", Operation: approvalexec.HostProxyOperation,
		Command: "agentjail proxy -- cat /outside/data.csv", CWD: "/project", AgentPID: 42,
		RuleID: "command_policy/confirm-host-proxy", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ObservePrompt(approvalexec.ObserveRequest{
		ChallengeID: meta.ChallengeID, Operation: meta.Operation, SessionID: meta.SessionID,
		TurnID: meta.TurnID, CWD: meta.CWD, FreshAfter: 1, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	srv := &server{approvals: manager}
	invocation := approvalexec.BrokerInvocation{Operation: meta.Operation, ChallengeID: meta.ChallengeID}
	if srv.pendingBrokerPreTool(policyeval.Request{SessionID: "session", TurnID: "turn", CWD: "/project"}, invocation, 42, now) {
		t.Fatal("observed challenge was allowed through PreToolUse again")
	}
}
