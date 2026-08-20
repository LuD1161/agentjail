package mcpgrant

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/LuD1161/agentjail/internal/grant"
)

func TestAdapterExactScope(t *testing.T) {
	adapter := Adapter{}
	first, err := StrictArguments([]byte(`{"path":"/repo/a","depth":1}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := StrictArguments([]byte(` { "depth" : 1, "path" : "/repo/a" } `))
	if err != nil {
		t.Fatal(err)
	}
	granted, err := NewResource("filesystem", "read_file", first)
	if err != nil {
		t.Fatal(err)
	}
	equivalent, err := NewResource("filesystem", "read_file", second)
	if err != nil {
		t.Fatal(err)
	}
	if !adapter.Equivalent(granted, equivalent) || !adapter.Covers(granted, equivalent) {
		t.Fatal("equivalent canonical arguments did not match")
	}
	otherServer := mustResource(t, "github", "read_file", second)
	otherTool := mustResource(t, "filesystem", "write_file", second)
	otherArguments := mustResource(t, "filesystem", "read_file", mustStrict(t, `{"path":"/repo/b","depth":1}`))
	for _, requested := range []grant.Resource{otherServer, otherTool, otherArguments} {
		if adapter.Covers(granted, requested) {
			t.Fatalf("grant widened to %q", requested.ID())
		}
	}
	any := mustResource(t, "filesystem", "read_file", AnyArguments())
	if !adapter.Covers(any, otherArguments) || adapter.Covers(granted, any) {
		t.Fatal("argument constraint coverage is incorrect")
	}
	adapted, err := grant.AdaptResource(adapter, grant.ActionMCPCall, granted)
	if err != nil || adapted.Activation() != grant.ActivationNotRequired {
		t.Fatalf("adapt MCP resource: adapted=%#v err=%v", adapted, err)
	}
}

func TestParseCallParamsMetadataDoesNotChangeAuthority(t *testing.T) {
	withoutMeta, err := ParseCallParams("filesystem", []byte(`{"name":"read_file","arguments":{"path":"/repo/a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	withMeta, err := ParseCallParams("filesystem", []byte(`{"_meta":{"progressToken":"opaque","nested":[true,false]},"arguments":{"path":"/repo/a"},"name":"read_file"}`))
	if err != nil {
		t.Fatal(err)
	}
	first, err := withoutMeta.Resource()
	if err != nil {
		t.Fatal(err)
	}
	second, err := withMeta.Resource()
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() {
		t.Fatalf("metadata changed authority: %q != %q", first.ID(), second.ID())
	}
}

func TestParseCallParamsDefaultsOmittedArgumentsToEmptyObject(t *testing.T) {
	call, err := ParseCallParams("filesystem", []byte(`{"name":"list_roots","_meta":{"progressToken":7}}`))
	if err != nil {
		t.Fatal(err)
	}
	expected := mustCall(t, "filesystem", "list_roots", `{}`)
	resource, err := call.Resource()
	if err != nil {
		t.Fatal(err)
	}
	want, err := expected.Resource()
	if err != nil {
		t.Fatal(err)
	}
	if resource.ID() != want.ID() {
		t.Fatalf("omitted arguments resource=%q want=%q", resource.ID(), want.ID())
	}
}

func TestRejectAmbiguousOrInvalidJSON(t *testing.T) {
	tooLarge := []byte(`{"x":"` + strings.Repeat("x", MaxCallParamsBytes) + `"}`)
	tests := []struct {
		name string
		call func() error
	}{
		{"duplicate top level", func() error {
			_, err := ParseCallParams("filesystem", []byte(`{"name":"read_file","name":"write_file","arguments":{}}`))
			return err
		}},
		{"duplicate nested", func() error {
			_, err := NewCall("filesystem", "read_file", []byte(`{"path":"a","path":"b"}`))
			return err
		}},
		{"non-object arguments", func() error {
			_, err := ParseCallParams("filesystem", []byte(`{"name":"read_file","arguments":[]}`))
			return err
		}},
		{"non-object metadata", func() error {
			_, err := ParseCallParams("filesystem", []byte(`{"name":"read_file","_meta":true}`))
			return err
		}},
		{"invalid UTF-8", func() error {
			_, err := NewCall("filesystem", "read_file", []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})
			return err
		}},
		{"invalid JSON", func() error { _, err := NewCall("filesystem", "read_file", []byte(`{"path":`)); return err }},
		{"trailing JSON", func() error { _, err := NewCall("filesystem", "read_file", []byte(`{} {}`)); return err }},
		{"non-finite number", func() error { _, err := NewCall("filesystem", "read_file", []byte(`{"x":NaN}`)); return err }},
		{"oversized arguments", func() error { _, err := NewCall("filesystem", "read_file", tooLarge); return err }},
		{"oversized parameters", func() error { _, err := ParseCallParams("filesystem", tooLarge); return err }},
		{"ambiguous server", func() error { _, err := NewCall("filesystem/other", "read_file", []byte(`{}`)); return err }},
		{"ambiguous tool", func() error { _, err := NewCall("filesystem", " read_file", []byte(`{}`)); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
}

func TestGatePolicyAndGrantOutcomes(t *testing.T) {
	principal, err := grant.NewPrincipal("codex", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	call, err := NewCall("filesystem", "read_file", []byte(`{"path":"/repo/a"}`))
	if err != nil {
		t.Fatal(err)
	}
	servers, err := NewStaticServers("filesystem")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("deny precedes everything", func(t *testing.T) {
		authority := &fakeAuthority{status: ClaimAuthorized, lease: &fakeLease{}}
		gate := NewGate(servers, availableUpstream(true), authority)
		result := gate.Check(context.Background(), principal, 7, PolicyDeny, call)
		if result.Canonical != PolicyDeny || result.Effective != EffectivePolicyDenied || result.Final != FinalDenied || authority.calls != 0 {
			t.Fatalf("unexpected deny result: %#v calls=%d", result, authority.calls)
		}
	})

	t.Run("allow does not claim", func(t *testing.T) {
		authority := &fakeAuthority{status: ClaimMissing}
		gate := NewGate(servers, availableUpstream(true), authority)
		result := gate.Check(context.Background(), principal, 7, PolicyAllow, call)
		if result.Effective != EffectivePolicyAllow || result.Final != FinalForwardAuthorized || result.Lease != nil || authority.calls != 0 {
			t.Fatalf("unexpected allow result: %#v calls=%d", result, authority.calls)
		}
	})

	for _, test := range []struct {
		name      string
		status    ClaimStatus
		effective EffectiveVerdict
	}{
		{"missing", ClaimMissing, EffectiveGrantMissing},
		{"expired", ClaimExpired, EffectiveGrantExpired},
		{"replayed", ClaimReplayed, EffectiveGrantReplay},
		{"cross session", ClaimSessionMismatch, EffectiveGrantSession},
		{"stale epoch", ClaimEpochMismatch, EffectiveGrantEpoch},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &fakeAuthority{status: test.status}
			gate := NewGate(servers, availableUpstream(true), authority)
			result := gate.Check(context.Background(), principal, 7, PolicyAsk, call)
			if result.Effective != test.effective || result.Final != FinalDenied || result.Claim != test.status || authority.calls != 1 {
				t.Fatalf("unexpected ask result: %#v calls=%d", result, authority.calls)
			}
		})
	}

	t.Run("unknown server fails closed", func(t *testing.T) {
		unknownCall := mustCall(t, "unknown", "read_file", `{}`)
		authority := &fakeAuthority{status: ClaimAuthorized, lease: &fakeLease{}}
		result := NewGate(servers, availableUpstream(true), authority).Check(context.Background(), principal, 7, PolicyAsk, unknownCall)
		if result.Final != FinalServerUnconfigured || authority.calls != 0 {
			t.Fatalf("unexpected unknown-server result: %#v calls=%d", result, authority.calls)
		}
	})

	t.Run("unavailable upstream cannot succeed", func(t *testing.T) {
		authority := &fakeAuthority{status: ClaimAuthorized, lease: &fakeLease{}}
		result := NewGate(servers, availableUpstream(false), authority).Check(context.Background(), principal, 7, PolicyAsk, call)
		if result.Final != FinalUpstreamUnavailable || result.Lease != nil || authority.calls != 0 {
			t.Fatalf("unexpected unavailable result: %#v calls=%d", result, authority.calls)
		}
	})
}

func TestForwardLeaseCommitAndRollback(t *testing.T) {
	principal, _ := grant.NewPrincipal("codex", "session-a")
	call := mustCall(t, "filesystem", "read_file", `{}`)
	servers, _ := NewStaticServers("filesystem")
	lease := &fakeLease{}
	result := NewGate(servers, availableUpstream(true), &fakeAuthority{status: ClaimAuthorized, lease: lease}).Check(context.Background(), principal, 7, PolicyAsk, call)
	if result.Lease == nil {
		t.Fatal("authorized ask did not return forwarding lease")
	}
	if err := result.Lease.Confirm(context.Background(), ForwardingBegan); err != nil {
		t.Fatal(err)
	}
	if lease.commits != 1 || lease.evidence != ForwardingBegan {
		t.Fatalf("commit not forwarded: %#v", lease)
	}
	if err := result.Lease.Rollback(context.Background()); !errors.Is(err, ErrLeaseResolved) {
		t.Fatalf("rollback after commit error=%v", err)
	}

	rollbackLease := &fakeLease{}
	result = NewGate(servers, availableUpstream(true), &fakeAuthority{status: ClaimAuthorized, lease: rollbackLease}).Check(context.Background(), principal, 7, PolicyAsk, call)
	if err := result.Lease.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rollbackLease.rollbacks != 1 {
		t.Fatalf("rollback count=%d", rollbackLease.rollbacks)
	}
}

func TestForwardLeaseRace(t *testing.T) {
	principal, _ := grant.NewPrincipal("codex", "session-a")
	call := mustCall(t, "filesystem", "read_file", `{}`)
	servers, _ := NewStaticServers("filesystem")
	lease := &fakeLease{}
	result := NewGate(servers, availableUpstream(true), &fakeAuthority{status: ClaimAuthorized, lease: lease}).Check(context.Background(), principal, 7, PolicyAsk, call)
	var group sync.WaitGroup
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			if index%2 == 0 {
				_ = result.Lease.Confirm(context.Background(), ForwardingSucceeded)
				return
			}
			_ = result.Lease.Rollback(context.Background())
		}(index)
	}
	group.Wait()
	if lease.commits+lease.rollbacks != 1 {
		t.Fatalf("lease resolved %d times", lease.commits+lease.rollbacks)
	}
}

func mustStrict(t *testing.T, arguments string) ArgumentConstraint {
	t.Helper()
	constraint, err := StrictArguments([]byte(arguments))
	if err != nil {
		t.Fatal(err)
	}
	return constraint
}

func mustResource(t *testing.T, server ServerID, tool ToolID, constraint ArgumentConstraint) grant.Resource {
	t.Helper()
	resource, err := NewResource(server, tool, constraint)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func mustCall(t *testing.T, server ServerID, tool ToolID, arguments string) Call {
	t.Helper()
	call, err := NewCall(server, tool, []byte(arguments))
	if err != nil {
		t.Fatal(err)
	}
	return call
}

type fakeAuthority struct {
	status ClaimStatus
	lease  Lease
	err    error
	calls  int
}

func (a *fakeAuthority) Claim(_ context.Context, request ClaimRequest, adapter grant.ResourceAdapter) (Lease, ClaimStatus, error) {
	a.calls++
	if !request.Valid() || adapter.Kind() != grant.ResourceMCPTool {
		return nil, ClaimUnavailable, errors.New("invalid claim request")
	}
	return a.lease, a.status, a.err
}

type fakeLease struct {
	commits   int
	rollbacks int
	evidence  ForwardEvidence
}

func (l *fakeLease) Commit(_ context.Context, evidence ForwardEvidence) error {
	l.commits++
	l.evidence = evidence
	return nil
}

func (l *fakeLease) Rollback(context.Context) error {
	l.rollbacks++
	return nil
}

type boolUpstream bool

func availableUpstream(available bool) boolUpstream             { return boolUpstream(available) }
func (u boolUpstream) Available(context.Context, ServerID) bool { return bool(u) }
