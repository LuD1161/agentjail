package mcpgrant

import (
	"context"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/grant"
)

type authorityClock struct{ now time.Time }

func (c *authorityClock) Now() time.Time { return c.now }

type authorityAudit struct{}

func (authorityAudit) EmitLifecycle(context.Context, grant.LifecycleEvent) error { return nil }

func newRuntimeManager(t *testing.T, now time.Time) (*grant.Manager, *authorityClock) {
	t.Helper()
	clock := &authorityClock{now: now}
	manager, err := grant.NewManager(grant.ManagerConfig{
		Clock: clock, Audit: authorityAudit{}, Capacity: grant.Capacity{Global: 16, PerSession: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, clock
}

func activateCall(t *testing.T, manager *grant.Manager, principal grant.Principal, call Call, scope grant.Scope, epoch grant.PolicyEpoch) grant.Grant {
	t.Helper()
	control := NewControl(manager)
	requested, err := control.Request(context.Background(), principal, call, scope, epoch, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	active, err := control.ApproveAndActivate(context.Background(), requested.ID(), "trusted-companion")
	if err != nil {
		t.Fatal(err)
	}
	return active
}

func runtimeGate(t *testing.T, manager *grant.Manager) Gate {
	t.Helper()
	servers, err := NewStaticServers("filesystem")
	if err != nil {
		t.Fatal(err)
	}
	return NewGate(servers, availableUpstream(true), NewManagerAuthority(manager))
}

func runtimePrincipal(t *testing.T, session string) grant.Principal {
	t.Helper()
	principal, err := grant.NewPrincipal("codex", grant.SessionID(session))
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func TestManagerAuthoritySessionAndCoverage(t *testing.T) {
	now := time.Unix(100, 0)
	manager, _ := newRuntimeManager(t, now)
	principal := runtimePrincipal(t, "session-a")
	granted := mustCall(t, "filesystem", "read_file", `{"path":"/repo/a"}`)
	activateCall(t, manager, principal, granted, grant.SessionScope(), 7)
	call, err := ParseHookCall("mcp__filesystem__read_file", map[string]interface{}{
		"path": "/repo/a", "_meta": map[string]interface{}{"progressToken": "untrusted"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := runtimeGate(t, manager).Check(context.Background(), principal, 7, PolicyAsk, call)
	if result.Canonical != PolicyAsk || result.Effective != EffectiveGrantAllow || result.Final != FinalForwardAuthorized || result.Lease == nil {
		t.Fatalf("session grant did not authorize: %#v", result)
	}
	if err := result.Lease.Confirm(context.Background(), ForwardingBegan); err != nil {
		t.Fatal(err)
	}
	if repeat := runtimeGate(t, manager).Check(context.Background(), principal, 7, PolicyAsk, call); repeat.Final != FinalForwardAuthorized {
		t.Fatalf("session scope was consumed: %#v", repeat)
	}

	otherArguments := mustCall(t, "filesystem", "read_file", `{"path":"/repo/b"}`)
	if denied := runtimeGate(t, manager).Check(context.Background(), principal, 7, PolicyAsk, otherArguments); denied.Final != FinalDenied {
		t.Fatalf("strict grant widened: %#v", denied)
	}
}

func TestManagerAuthorityOnceExpiryReplaySessionAndEpoch(t *testing.T) {
	now := time.Unix(100, 0)
	manager, clock := newRuntimeManager(t, now)
	principal := runtimePrincipal(t, "session-a")
	call := mustCall(t, "filesystem", "read_file", `{}`)
	activateCall(t, manager, principal, call, grant.OnceScope(), 7)
	gate := runtimeGate(t, manager)
	first := gate.Check(context.Background(), principal, 7, PolicyAsk, call)
	if first.Final != FinalForwardAuthorized || first.Lease == nil {
		t.Fatalf("once grant did not authorize: %#v", first)
	}
	if err := first.Lease.Confirm(context.Background(), ForwardingBegan); err != nil {
		t.Fatal(err)
	}
	if replay := gate.Check(context.Background(), principal, 7, PolicyAsk, call); replay.Effective != EffectiveGrantReplay || replay.Final != FinalDenied {
		t.Fatalf("replay was not denied: %#v", replay)
	}
	if crossSession := gate.Check(context.Background(), runtimePrincipal(t, "session-b"), 7, PolicyAsk, call); crossSession.Final != FinalDenied {
		t.Fatalf("cross-session use authorized: %#v", crossSession)
	}

	ttl, err := grant.NewTTLScope(clock.now, clock.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ttlCall := mustCall(t, "filesystem", "read_file", `{"path":"/ttl"}`)
	activateCall(t, manager, principal, ttlCall, ttl, 9)
	if stale := gate.Check(context.Background(), principal, 8, PolicyAsk, ttlCall); stale.Effective != EffectiveGrantEpoch || stale.Final != FinalDenied {
		t.Fatalf("stale epoch authorized: %#v", stale)
	}
	clock.now = clock.now.Add(2 * time.Second)
	if expired := gate.Check(context.Background(), principal, 9, PolicyAsk, ttlCall); expired.Effective != EffectiveGrantExpired || expired.Final != FinalDenied {
		t.Fatalf("expired grant authorized: %#v", expired)
	}
}

func TestManagerAuthorityUsesAdapterCoverage(t *testing.T) {
	now := time.Unix(100, 0)
	manager, _ := newRuntimeManager(t, now)
	principal := runtimePrincipal(t, "session-a")
	resource, err := NewResource("filesystem", "read_file", AnyArguments())
	if err != nil {
		t.Fatal(err)
	}
	adapted, err := grant.AdaptResource(Adapter{}, grant.ActionMCPCall, resource)
	if err != nil {
		t.Fatal(err)
	}
	request, err := grant.NewRequest(principal, grant.ActionMCPCall, adapted, grant.SessionScope(), 7, now)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := grant.NewCanonicalDecision(grant.VerdictAsk, grant.DenyNone)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := manager.Request(context.Background(), request, decision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Approve(context.Background(), pending.ID(), "trusted-companion"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(context.Background(), pending.ID()); err != nil {
		t.Fatal(err)
	}
	call := mustCall(t, "filesystem", "read_file", `{"path":"/any-covered"}`)
	if got := runtimeGate(t, manager).Check(context.Background(), principal, 7, PolicyAsk, call); got.Final != FinalForwardAuthorized {
		t.Fatalf("any-argument grant did not cover exact call: %#v", got)
	}
}

func TestParseHookCallRejectsInvalidMetadataAndNames(t *testing.T) {
	if _, err := ParseHookCall("mcp__filesystem__read_file", map[string]interface{}{"_meta": "not-an-object"}); err == nil {
		t.Fatal("scalar _meta accepted")
	}
	for _, tool := range []string{"mcp__filesystem", "mcp__filesystem__", "mcp__bad/name__read", "Bash"} {
		if _, err := ParseHookCall(tool, map[string]interface{}{}); err == nil {
			t.Fatalf("invalid hook tool %q accepted", tool)
		}
	}
}

func TestParseHookCallRejectsNonJSONAndInvalidUnicodeValues(t *testing.T) {
	invalidUTF8 := string([]byte{0xff})
	for _, input := range []map[string]interface{}{
		{"path": invalidUTF8},
		{"path": 1},
		{"path": map[string]interface{}{"nested": make(chan int)}},
		{"_meta": map[string]interface{}{"progress": invalidUTF8}},
	} {
		if _, err := ParseHookCall("mcp__filesystem__read_file", input); err == nil {
			t.Fatalf("invalid hook input %#v was accepted", input)
		}
	}
	first, err := ParseHookCall("mcp__filesystem__read_file", map[string]interface{}{
		"depth": float64(1), "path": "/repo/a", "_meta": map[string]interface{}{"progress": "opaque"},
	})
	if err != nil {
		t.Fatal(err)
	}
	second := mustCall(t, "filesystem", "read_file", `{"depth":1,"path":"/repo/a"}`)
	if first.ArgumentsDigest() != second.ArgumentsDigest() {
		t.Fatal("hook input did not canonicalize to the strict call authority")
	}
}

func TestControlWithoutAuthorityFailsClosed(t *testing.T) {
	principal := runtimePrincipal(t, "session-a")
	call := mustCall(t, "filesystem", "read_file", `{}`)
	if _, err := NewControl(nil).Request(context.Background(), principal, call, grant.SessionScope(), 1, time.Unix(100, 0)); err != ErrApprovalUnavailable {
		t.Fatalf("Request without authority error = %v", err)
	}
}
