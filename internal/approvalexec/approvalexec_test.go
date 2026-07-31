package approvalexec

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func mintFixture(t *testing.T) (*Manager, Metadata, time.Time) {
	t.Helper()
	now := time.Unix(100, 0)
	m := NewManager(bytes.NewReader(make([]byte, 64)), time.Second, time.Minute)
	m.BeginToolCall("session")
	meta, err := m.Mint(MintRequest{
		SessionID: "session", TurnID: "turn", ToolUseID: "tool",
		Operation: GitPushOperation, Command: "git push", CWD: "/repo", AgentPID: 42, RuleID: "git_push", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, meta, now
}

func TestManagerHappyPathAndReplay(t *testing.T) {
	m, meta, now := mintFixture(t)
	if _, err := m.ObservePrompt(ObserveRequest{
		ChallengeID: meta.ChallengeID, Operation: GitPushOperation, SessionID: "session", TurnID: "turn",
		CWD: "/repo", FreshAfter: 10, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := m.Redeem(RedeemRequest{
		ChallengeID: meta.ChallengeID, Operation: GitPushOperation, VerifiedSession: "session",
		PeerChainFresh: true, CurrentEpoch: 1, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != "git push" {
		t.Fatalf("command = %q", got.Command)
	}
	if _, err := m.Redeem(RedeemRequest{ChallengeID: meta.ChallengeID, Operation: GitPushOperation, Now: now}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestManagerRejectsPendingAndBurnsIt(t *testing.T) {
	m, meta, now := mintFixture(t)
	_, err := m.Redeem(RedeemRequest{ChallengeID: meta.ChallengeID, Operation: GitPushOperation, Now: now})
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("error = %v", err)
	}
	if _, err := m.Inspect(meta.ChallengeID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("challenge survived failed redeem: %v", err)
	}
}

func TestManagerRejectsForgedPromptAndBurnsChallenge(t *testing.T) {
	m, meta, now := mintFixture(t)
	_, err := m.ObservePrompt(ObserveRequest{
		ChallengeID: meta.ChallengeID, Operation: GitPushOperation, SessionID: "other-session", TurnID: "turn",
		CWD: "/repo", FreshAfter: 10, Now: now,
	})
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("forged prompt error = %v, want binding mismatch", err)
	}
	if _, err := m.Inspect(meta.ChallengeID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forged prompt left challenge usable: %v", err)
	}
}

func TestManagerRejectsOperationMismatchAndBurnsChallenge(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage string
	}{
		{name: "prompt", stage: "prompt"},
		{name: "redemption", stage: "redemption"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, meta, now := mintFixture(t)
			if tc.stage == "prompt" {
				_, err := m.ObservePrompt(ObserveRequest{
					ChallengeID: meta.ChallengeID, Operation: ShellCommandOperation,
					SessionID: "session", TurnID: "turn", CWD: "/repo", FreshAfter: 10, Now: now,
				})
				if !errors.Is(err, ErrBinding) {
					t.Fatalf("ObservePrompt() error = %v, want binding mismatch", err)
				}
			} else {
				if _, err := m.ObservePrompt(ObserveRequest{
					ChallengeID: meta.ChallengeID, Operation: GitPushOperation,
					SessionID: "session", TurnID: "turn", CWD: "/repo", FreshAfter: 10, Now: now,
				}); err != nil {
					t.Fatal(err)
				}
				_, err := m.Redeem(RedeemRequest{
					ChallengeID: meta.ChallengeID, Operation: ShellCommandOperation,
					VerifiedSession: "session", PeerChainFresh: true, CurrentEpoch: 1, Now: now,
				})
				if !errors.Is(err, ErrBinding) {
					t.Fatalf("Redeem() error = %v, want binding mismatch", err)
				}
			}
			if _, err := m.Inspect(meta.ChallengeID, now); !errors.Is(err, ErrNotFound) {
				t.Fatalf("operation mismatch left challenge usable: %v", err)
			}
		})
	}
}

func TestManagerRejectsUnknownOperation(t *testing.T) {
	m := NewManager(bytes.NewReader(make([]byte, 32)), time.Second, time.Minute)
	m.BeginToolCall("session")
	_, err := m.Mint(MintRequest{
		SessionID: "session", TurnID: "turn", ToolUseID: "tool", Operation: "unknown",
		Command: "echo test", CWD: "/repo", AgentPID: 42, Now: time.Unix(100, 0),
	})
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("Mint() error = %v, want binding mismatch", err)
	}
}

func TestBrokerCommandRoundTripsSupportedOperations(t *testing.T) {
	valid := ChallengeID("A" + strings.Repeat("B", 42))
	for _, operation := range []Operation{GitPushOperation, ShellCommandOperation} {
		invocation := BrokerInvocation{Operation: operation, ChallengeID: valid}
		got, ok := ParseBrokerCommand(BrokerCommand(invocation))
		if !ok || got != invocation {
			t.Fatalf("canonical broker command = %#v, %v", got, ok)
		}
	}
}

func TestParseBrokerCommandRejectsShellSyntax(t *testing.T) {
	valid := ChallengeID("A" + strings.Repeat("B", 42))
	for _, command := range []string{
		"agentjail approval-exec --operation git-push --challenge " + string(valid) + "; git push",
		"agentjail approval-exec --operation git-push --challenge '" + string(valid) + "'",
		"agentjail approval-exec --operation git-push --challenge " + string(valid) + " extra",
		"agentjail approval-exec --operation shell-command --challenge " + string(valid) + " && true",
		"agentjail approval-exec --operation unknown --challenge " + string(valid),
		"agentjail approval-exec --operation git-push --challenge short",
	} {
		if _, ok := ParseBrokerCommand(command); ok {
			t.Fatalf("accepted non-canonical broker command %q", command)
		}
	}
}

func TestManagerRejectsLaterToolCallAndStaleProcess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		later bool
		fresh bool
		want  error
	}{
		{name: "later tool", later: true, fresh: true, want: ErrBinding},
		{name: "old process chain", fresh: false, want: ErrStaleExecution},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, meta, now := mintFixture(t)
			if _, err := m.ObservePrompt(ObserveRequest{
				ChallengeID: meta.ChallengeID, Operation: GitPushOperation, SessionID: "session", TurnID: "turn",
				CWD: "/repo", FreshAfter: 10, Now: now,
			}); err != nil {
				t.Fatal(err)
			}
			epoch := uint64(1)
			if tc.later {
				epoch = m.BeginToolCall("session")
			}
			_, err := m.Redeem(RedeemRequest{
				ChallengeID: meta.ChallengeID, Operation: GitPushOperation, VerifiedSession: "session",
				PeerChainFresh: tc.fresh, CurrentEpoch: epoch, Now: now,
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestManagerConcurrentRedeemHasOneWinner(t *testing.T) {
	m, meta, now := mintFixture(t)
	if _, err := m.ObservePrompt(ObserveRequest{
		ChallengeID: meta.ChallengeID, Operation: GitPushOperation, SessionID: "session", TurnID: "turn",
		CWD: "/repo", FreshAfter: 10, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var wins int
	var mu sync.Mutex
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Redeem(RedeemRequest{
				ChallengeID: meta.ChallengeID, Operation: GitPushOperation, VerifiedSession: "session",
				PeerChainFresh: true, CurrentEpoch: 1, Now: now,
			}); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins = %d, want 1", wins)
	}
}

func TestManagerBoundsPendingChallengesPerSession(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewManager(nil, time.Second, time.Minute)
	m.BeginToolCall("session")
	for i := 0; i < maxSessionChallenges; i++ {
		if _, err := m.Mint(MintRequest{
			SessionID: "session", TurnID: TurnID("turn-" + string(rune('a'+i))),
			ToolUseID: ToolUseID("tool-" + string(rune('a'+i))),
			Operation: GitPushOperation, Command: "git push", CWD: "/repo", AgentPID: 42, Now: now,
		}); err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}
	if _, err := m.Mint(MintRequest{
		SessionID: "session", TurnID: "overflow", ToolUseID: "overflow",
		Operation: GitPushOperation, Command: "git push", CWD: "/repo", AgentPID: 42, Now: now,
	}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow error = %v, want capacity", err)
	}
	if _, err := m.Mint(MintRequest{
		SessionID: "session", TurnID: "after-expiry", ToolUseID: "after-expiry",
		Operation: GitPushOperation, Command: "git push", CWD: "/repo", AgentPID: 42, Now: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("expired entries were not reaped: %v", err)
	}
}
