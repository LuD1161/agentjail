package grantapproval

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/agentpolicy"
	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/grant"
)

const (
	codexCompatibilityVersion = "0.148.0"
	codexCompatibilityDate    = "2026-08-19"
	codexHooksSource          = "https://learn.chatgpt.com/docs/hooks"
	codexRulesSource          = "https://learn.chatgpt.com/docs/agent-configuration/rules"
)

func TestCodexCompatibilityFixture(t *testing.T) {
	// Current native prompt contract. See ADR 0141-runtime-grants.
	if codexCompatibilityVersion == "" || codexCompatibilityDate == "" ||
		!strings.HasPrefix(codexHooksSource, "https://learn.chatgpt.com/") ||
		!strings.HasPrefix(codexRulesSource, "https://learn.chatgpt.com/") {
		t.Fatal("Codex compatibility fixture is incomplete")
	}
}

func codexFixture(t *testing.T) (*CodexAdapter, Intent, time.Time) {
	t.Helper()
	now := time.Unix(100, 0)
	manager := approvalexec.NewManager(bytes.NewReader(make([]byte, 64)), time.Second, time.Minute)
	manager.BeginToolCall("session-a")
	adapter := NewCodexAdapter(manager)
	principal, err := NewPrincipal("codex", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := grant.NewResource(grant.ResourceSubprocess, "shell-command")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBinding("turn-a", "tool-a")
	if err != nil {
		t.Fatal(err)
	}
	display, err := NewDisplayContext("publish the reviewed change", "runs once inside the existing sandbox; no isolation is widened")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := NewIntent(
		"request-a", "grant-a", principal, agentpolicy.ActionAsk, grant.ActionExec,
		resource, grant.OnceScope(), 7, binding, display,
	)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, intent, now
}

func begin(t *testing.T, adapter *CodexAdapter, intent Intent, now time.Time) CodexPrompt {
	t.Helper()
	prompt := adapter.Begin(context.Background(), CodexShellRequest{
		Intent: intent, Command: "git push origin topic", CWD: "/repo", AgentPID: 42, Now: now,
	})
	if prompt.Outcome != OutcomePending {
		t.Fatalf("Begin() outcome = %q", prompt.Outcome)
	}
	return prompt
}

func evidence(t *testing.T, intent Intent, nonce Nonce, epoch uint64, peerFresh bool, now time.Time) Evidence {
	t.Helper()
	freshness, err := NewFreshness(epoch, 11, peerFresh)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewEvidence(
		CodexAdapterID, intent.Request(), intent.Grant(), intent.Principal(), intent.Action(), intent.Resource(),
		intent.Scope(), intent.PolicyEpoch(), intent.Binding(), nonce, freshness, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestCodexAllowOnceBindsExactShellRequest(t *testing.T) {
	adapter, intent, now := codexFixture(t)
	prompt := begin(t, adapter, intent, now)
	if want := "agentjail approval-exec --operation shell-command --challenge "; !strings.HasPrefix(prompt.Command, want) {
		t.Fatalf("broker command = %q, want %q prefix", prompt.Command, want)
	}
	if prompt.Prompt.Action != grant.ActionExec || prompt.Prompt.Resource != intent.Resource() ||
		prompt.Prompt.Scope != intent.Scope() || prompt.Prompt.Consequence == "" {
		t.Fatalf("prompt projection lost concrete intent: %#v", prompt.Prompt)
	}
	proof := evidence(t, intent, prompt.Challenge, 1, true, now)
	if got := adapter.Observe(context.Background(), proof, now); got != OutcomePending {
		t.Fatalf("Observe() = %q, want pending", got)
	}
	redemption, got := adapter.Redeem(context.Background(), proof, now)
	if got != OutcomeAllowOnce || !got.Authorizes() || redemption.Command != "git push origin topic" || redemption.CWD != "/repo" {
		t.Fatalf("Redeem() = (%#v, %q)", redemption, got)
	}
	if _, got := adapter.Redeem(context.Background(), proof, now); got == OutcomeAllowOnce {
		t.Fatal("replayed evidence authorized")
	}
}

func TestCodexEvidenceRejectsSiblingAndCrossBindings(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence
	}{
		{
			name: "wrong adapter",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				result, err := NewEvidence("claude", proof.Request(), proof.Grant(), proof.Principal(), proof.Action(), proof.Resource(), proof.Scope(), proof.PolicyEpoch(), proof.Binding(), proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
		{
			name: "sibling request",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				result, err := NewEvidence(CodexAdapterID, "request-b", proof.Grant(), proof.Principal(), proof.Action(), proof.Resource(), proof.Scope(), proof.PolicyEpoch(), proof.Binding(), proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
		{
			name: "cross session",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				principal, err := NewPrincipal("codex", "session-b")
				if err != nil {
					t.Fatal(err)
				}
				result, err := NewEvidence(CodexAdapterID, proof.Request(), proof.Grant(), principal, proof.Action(), proof.Resource(), proof.Scope(), proof.PolicyEpoch(), proof.Binding(), proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
		{
			name: "cross turn",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				binding, err := NewBinding("turn-b", "tool-a")
				if err != nil {
					t.Fatal(err)
				}
				result, err := NewEvidence(CodexAdapterID, proof.Request(), proof.Grant(), proof.Principal(), proof.Action(), proof.Resource(), proof.Scope(), proof.PolicyEpoch(), binding, proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
		{
			name: "cross tool use",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				binding, err := NewBinding("turn-a", "tool-b")
				if err != nil {
					t.Fatal(err)
				}
				result, err := NewEvidence(CodexAdapterID, proof.Request(), proof.Grant(), proof.Principal(), proof.Action(), proof.Resource(), proof.Scope(), proof.PolicyEpoch(), binding, proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
		{
			name: "stale policy epoch",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				result, err := NewEvidence(CodexAdapterID, proof.Request(), proof.Grant(), proof.Principal(), proof.Action(), proof.Resource(), proof.Scope(), 8, proof.Binding(), proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
		{
			name: "wrong action",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				result, err := NewEvidence(CodexAdapterID, proof.Request(), proof.Grant(), proof.Principal(), grant.ActionRead, proof.Resource(), proof.Scope(), proof.PolicyEpoch(), proof.Binding(), proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
		{
			name: "wrong resource",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				resource, err := grant.NewResource(grant.ResourceSubprocess, "different-shell-command")
				if err != nil {
					t.Fatal(err)
				}
				result, err := NewEvidence(CodexAdapterID, proof.Request(), proof.Grant(), proof.Principal(), proof.Action(), resource, proof.Scope(), proof.PolicyEpoch(), proof.Binding(), proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
		{
			name: "wrong scope",
			build: func(t *testing.T, intent Intent, nonce Nonce, now time.Time) Evidence {
				proof := evidence(t, intent, nonce, 1, true, now)
				result, err := NewEvidence(CodexAdapterID, proof.Request(), proof.Grant(), proof.Principal(), proof.Action(), proof.Resource(), grant.SessionScope(), proof.PolicyEpoch(), proof.Binding(), proof.Nonce(), proof.Freshness(), proof.ObservedAt())
				if err != nil {
					t.Fatal(err)
				}
				return result
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter, intent, now := codexFixture(t)
			prompt := begin(t, adapter, intent, now)
			proof := tc.build(t, intent, prompt.Challenge, now)
			if got := adapter.Observe(context.Background(), proof, now); got != OutcomeMalformedEvidence {
				t.Fatalf("Observe() = %q, want malformed evidence", got)
			}
			if _, got := adapter.Redeem(context.Background(), evidence(t, intent, prompt.Challenge, 1, true, now), now); got == OutcomeAllowOnce {
				t.Fatal("failed evidence left sibling authorization usable")
			}
		})
	}
}

func TestCodexEvidenceRejectsStaleFreshness(t *testing.T) {
	for _, tc := range []struct {
		name      string
		epoch     uint64
		peerFresh bool
	}{
		{name: "later tool call epoch", epoch: 2, peerFresh: true},
		{name: "stale process chain", epoch: 1, peerFresh: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter, intent, now := codexFixture(t)
			prompt := begin(t, adapter, intent, now)
			proof := evidence(t, intent, prompt.Challenge, tc.epoch, tc.peerFresh, now)
			if got := adapter.Observe(context.Background(), proof, now); got != OutcomePending {
				t.Fatalf("Observe() = %q", got)
			}
			if _, got := adapter.Redeem(context.Background(), proof, now); got != OutcomeDenied {
				t.Fatalf("Redeem() = %q, want denied", got)
			}
		})
	}
}

func TestCodexExpiredPromptCannotAuthorize(t *testing.T) {
	adapter, intent, now := codexFixture(t)
	prompt := begin(t, adapter, intent, now)
	proof := evidence(t, intent, prompt.Challenge, 1, true, now.Add(2*time.Second))
	if got := adapter.Observe(context.Background(), proof, now.Add(2*time.Second)); got != OutcomeDenied {
		t.Fatalf("Observe(expired) = %q, want denied", got)
	}
	if _, got := adapter.Redeem(context.Background(), proof, now.Add(2*time.Second)); got == OutcomeAllowOnce {
		t.Fatal("expired prompt authorized")
	}
}

func TestCodexCancellationTimeoutAndMalformedEvidenceFailClosed(t *testing.T) {
	adapter, intent, now := codexFixture(t)
	prompt := begin(t, adapter, intent, now)
	proof := evidence(t, intent, prompt.Challenge, 1, true, now)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := adapter.Observe(cancelled, proof, now); got != OutcomeCancelled {
		t.Fatalf("Observe(cancelled) = %q", got)
	}
	if _, got := adapter.Redeem(context.Background(), proof, now); got == OutcomeAllowOnce {
		t.Fatal("cancelled prompt redeemed")
	}

	adapter, intent, now = codexFixture(t)
	deadline, cancelDeadline := context.WithDeadline(context.Background(), now.Add(-time.Second))
	defer cancelDeadline()
	if got := adapter.Begin(deadline, CodexShellRequest{Intent: intent, Command: "git push", CWD: "/repo", AgentPID: 42, Now: now}).Outcome; got != OutcomeTimedOut {
		t.Fatalf("Begin(timeout) = %q", got)
	}
	if _, got := adapter.Redeem(context.Background(), Evidence{}, now); got != OutcomeMalformedEvidence {
		t.Fatalf("Redeem(malformed) = %q", got)
	}
}

func TestCodexUnsupportedScopeAndResourceFailClosed(t *testing.T) {
	adapter, intent, now := codexFixture(t)
	sessionIntent, err := NewIntent(intent.Request(), intent.Grant(), intent.Principal(), intent.PolicyAction(), intent.Action(), intent.Resource(), grant.SessionScope(), intent.PolicyEpoch(), intent.Binding(), intent.Display())
	if err != nil {
		t.Fatal(err)
	}
	if got := adapter.Begin(context.Background(), CodexShellRequest{Intent: sessionIntent, Command: "git push", CWD: "/repo", AgentPID: 42, Now: now}).Outcome; got != OutcomeUnsupported {
		t.Fatalf("session scope = %q", got)
	}
	file, err := grant.NewResource(grant.ResourceFile, "/repo/config")
	if err != nil {
		t.Fatal(err)
	}
	fileIntent, err := NewIntent(intent.Request(), intent.Grant(), intent.Principal(), intent.PolicyAction(), grant.ActionRead, file, grant.OnceScope(), intent.PolicyEpoch(), intent.Binding(), intent.Display())
	if err != nil {
		t.Fatal(err)
	}
	if got := adapter.Begin(context.Background(), CodexShellRequest{Intent: fileIntent, Command: "cat config", CWD: "/repo", AgentPID: 42, Now: now}).Outcome; got != OutcomeUnsupported {
		t.Fatalf("file resource = %q", got)
	}
}

func TestIntentBoundsUntrustedReasonAndPreservesPolicyAction(t *testing.T) {
	adapter, intent, _ := codexFixture(t)
	display, err := NewDisplayContext(strings.Repeat("x", maxDisplayText+20)+"\x00", intent.Display().Consequence())
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := NewIntent(intent.Request(), intent.Grant(), intent.Principal(), intent.PolicyAction(), intent.Action(), intent.Resource(), intent.Scope(), intent.PolicyEpoch(), intent.Binding(), display)
	if err != nil {
		t.Fatal(err)
	}
	prompt, got := adapter.Project(context.Background(), bounded)
	if got != OutcomePending || len(prompt.Reason) != maxDisplayText || strings.ContainsRune(prompt.Reason, '\x00') {
		t.Fatalf("bounded prompt = %#v, %q", prompt, got)
	}
	if bounded.PolicyAction() != agentpolicy.ActionAsk {
		t.Fatalf("policy action changed to %q", bounded.PolicyAction())
	}
}

func TestBurnInvalidatesApprovalExecChallenge(t *testing.T) {
	manager := approvalexec.NewManager(bytes.NewReader(make([]byte, 64)), time.Second, time.Minute)
	manager.BeginToolCall("session")
	now := time.Unix(100, 0)
	meta, err := manager.Mint(approvalexec.MintRequest{SessionID: "session", TurnID: "turn", ToolUseID: "tool", Operation: approvalexec.ShellCommandOperation, Command: "echo", CWD: "/repo", AgentPID: 1, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	manager.Burn(meta.ChallengeID)
	if _, err := manager.Inspect(meta.ChallengeID, now); !errors.Is(err, approvalexec.ErrNotFound) {
		t.Fatalf("Burn() left challenge available: %v", err)
	}
}
