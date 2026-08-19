package grant

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestScopeConstructors(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)

	if scope := OnceScope(); scope.Kind() != ScopeOnce || !scope.ValidAt(now) {
		t.Fatalf("OnceScope() = %#v, want valid once scope", scope)
	}
	if scope := SessionScope(); scope.Kind() != ScopeSession || !scope.ValidAt(now) {
		t.Fatalf("SessionScope() = %#v, want valid session scope", scope)
	}

	expiresAt := now.Add(5 * time.Minute)
	scope, err := NewTTLScope(now, expiresAt)
	if err != nil {
		t.Fatalf("NewTTLScope() error = %v", err)
	}
	if got, ok := scope.ExpiresAt(); !ok || !got.Equal(expiresAt) {
		t.Fatalf("ExpiresAt() = %v, %t; want %v, true", got, ok, expiresAt)
	}
	if scope.ExpiredAt(expiresAt.Add(-time.Nanosecond)) {
		t.Fatal("TTL scope expired before its deadline")
	}
	if !scope.ExpiredAt(expiresAt) {
		t.Fatal("TTL scope remained active at its deadline")
	}

	for _, test := range []struct {
		name      string
		now       time.Time
		expiresAt time.Time
	}{
		{name: "zero now", expiresAt: expiresAt},
		{name: "zero expiry", now: now},
		{name: "equal", now: now, expiresAt: now},
		{name: "past", now: now, expiresAt: now.Add(-time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewTTLScope(test.now, test.expiresAt); !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("NewTTLScope() error = %v, want %v", err, ErrInvalidScope)
			}
		})
	}
}

func TestNewRequestAcceptsSupportedActionResourcePairs(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	principal, err := NewPrincipal("codex", "session-1")
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}

	tests := []struct {
		action Action
		kind   ResourceKind
	}{
		{ActionExec, ResourceSubprocess},
		{ActionRead, ResourceFile},
		{ActionWrite, ResourceFile},
		{ActionFetch, ResourceNetwork},
		{ActionConnect, ResourceNetwork},
		{ActionMCPCall, ResourceMCPTool},
		{ActionCredentialUse, ResourceCredential},
	}
	for _, test := range tests {
		t.Run(string(test.action)+"/"+string(test.kind), func(t *testing.T) {
			resource := mustAdapt(t, test.action, test.kind, "resource-1", ActivationNotRequired)
			request, requestErr := NewRequest(
				principal,
				test.action,
				resource,
				SessionScope(),
				1,
				now,
			)
			if requestErr != nil {
				t.Fatalf("NewRequest() error = %v", requestErr)
			}
			if request.Action() != test.action || request.Resource() != resource.Resource() {
				t.Fatalf("NewRequest() = %#v, want %s on %#v", request, test.action, resource)
			}
		})
	}
}

func TestNewRequestRejectsInvalidBindings(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	principal, err := NewPrincipal("codex", "session-1")
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	file := mustAdapt(t, ActionRead, ResourceFile, "/workspace/secret", ActivationNotRequired)

	if _, err := NewRequest(
		principal,
		ActionExec,
		file,
		OnceScope(),
		1,
		now,
	); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("NewRequest(exec file) error = %v, want %v", err, ErrInvalidAction)
	}
	if _, err := NewRequest(
		principal,
		ActionRead,
		file,
		OnceScope(),
		0,
		now,
	); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NewRequest(zero epoch) error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestAdaptResourcePreservesAuthority(t *testing.T) {
	requested, err := NewResource(ResourceNetwork, "Chrome-CDP")
	if err != nil {
		t.Fatalf("NewResource() error = %v", err)
	}
	adapter := testAdapter{
		kind:       ResourceNetwork,
		canonical:  "chrome-cdp",
		equivalent: true,
		covers:     true,
		activation: ActivationRequired,
	}

	adapted, err := AdaptResource(adapter, ActionConnect, requested)
	if err != nil {
		t.Fatalf("AdaptResource() error = %v", err)
	}
	if adapted.Resource().ID() != "chrome-cdp" {
		t.Fatalf("canonical resource = %q, want chrome-cdp", adapted.Resource().ID())
	}
	if adapted.Activation() != ActivationRequired {
		t.Fatalf("activation = %q, want %q", adapted.Activation(), ActivationRequired)
	}
}

func TestAdaptResourceRejectsWidening(t *testing.T) {
	requested, err := NewResource(ResourceNetwork, "chrome-cdp")
	if err != nil {
		t.Fatalf("NewResource() error = %v", err)
	}
	adapter := testAdapter{
		kind:       ResourceNetwork,
		canonical:  "*",
		equivalent: false,
		covers:     true,
		activation: ActivationRequired,
	}

	if _, err := AdaptResource(adapter, ActionConnect, requested); !errors.Is(err, ErrResourceWidened) {
		t.Fatalf("AdaptResource() error = %v, want %v", err, ErrResourceWidened)
	}
}

func TestAdaptResourceRejectsKindChange(t *testing.T) {
	requested, err := NewResource(ResourceNetwork, "chrome-cdp")
	if err != nil {
		t.Fatalf("NewResource() error = %v", err)
	}
	adapter := testAdapter{
		kind:          ResourceNetwork,
		canonical:     "/workspace",
		canonicalKind: ResourceFile,
		equivalent:    true,
		covers:        true,
		activation:    ActivationRequired,
	}

	if _, err := AdaptResource(adapter, ActionConnect, requested); !errors.Is(err, ErrAdapterKind) {
		t.Fatalf("AdaptResource() error = %v, want %v", err, ErrAdapterKind)
	}
}

type testAdapter struct {
	kind          ResourceKind
	canonical     ResourceID
	canonicalKind ResourceKind
	equivalent    bool
	covers        bool
	activation    ActivationRequirement
}

func (a testAdapter) Kind() ResourceKind {
	return a.kind
}

func (a testAdapter) Canonicalize(Resource) (Resource, error) {
	kind := a.canonicalKind
	if kind == "" {
		kind = a.kind
	}
	return NewResource(kind, a.canonical)
}

func (a testAdapter) Equivalent(left, right Resource) bool {
	if !a.equivalent {
		return false
	}
	return left.Kind() == right.Kind() && strings.EqualFold(string(left.ID()), string(right.ID()))
}

func (a testAdapter) Covers(Resource, Resource) bool {
	return a.covers
}

func (a testAdapter) ActivationFor(Action, Resource) (ActivationRequirement, error) {
	return a.activation, nil
}

func mustAdapt(
	t *testing.T,
	action Action,
	kind ResourceKind,
	id ResourceID,
	activation ActivationRequirement,
) AdaptedResource {
	t.Helper()
	requested, err := NewResource(kind, id)
	if err != nil {
		t.Fatalf("NewResource() error = %v", err)
	}
	adapted, err := AdaptResource(testAdapter{
		kind:       kind,
		canonical:  id,
		equivalent: true,
		covers:     true,
		activation: activation,
	}, action, requested)
	if err != nil {
		t.Fatalf("AdaptResource() error = %v", err)
	}
	return adapted
}
