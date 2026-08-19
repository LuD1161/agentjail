package hostconnector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grant"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

type fakeAuthorizer struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (a *fakeAuthorizer) Authorize(_ context.Context, _ Binding, _ ConnectorID, _ grant.Scope) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	return a.err
}

func (a *fakeAuthorizer) Calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

type fakeAdapter struct {
	mu         sync.Mutex
	closeErr   error
	closeCalls int
}

func (a *fakeAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closeCalls++
	return a.closeErr
}

func (a *fakeAdapter) CloseCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closeCalls
}

type fakeBackend struct {
	mu      sync.Mutex
	err     error
	adapter *fakeAdapter
	calls   int
	started chan struct{}
	release <-chan struct{}
}

func (b *fakeBackend) Activate(_ context.Context, _ Activation) (Adapter, error) {
	b.mu.Lock()
	b.calls++
	started := b.started
	release := b.release
	err := b.err
	adapter := b.adapter
	b.mu.Unlock()
	if started != nil {
		close(started)
	}
	if release != nil {
		<-release
	}
	if err != nil {
		return nil, err
	}
	return adapter, nil
}

func (b *fakeBackend) Calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

type fakeAuditor struct {
	mu       sync.Mutex
	errState LifecycleState
	events   []Transition
}

func (a *fakeAuditor) Record(_ context.Context, transition Transition) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, transition)
	if transition.State == a.errState {
		return errors.New("durable audit unavailable")
	}
	return nil
}

func (a *fakeAuditor) states() []LifecycleState {
	a.mu.Lock()
	defer a.mu.Unlock()
	states := make([]LifecycleState, 0, len(a.events))
	for _, event := range a.events {
		states = append(states, event.State)
	}
	return states
}

func newTestManager(t *testing.T) (*Manager, Binding, *fakeClock, *fakeAuthorizer, *fakeBackend, *fakeAuditor) {
	t.Helper()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	principal, err := grant.NewPrincipal("codex", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBinding(principal)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := NewDestination("127.0.0.1", 9225, "/json/version")
	if err != nil {
		t.Fatal(err)
	}
	connector, err := NewConnector("chrome-cdp", TransportCDP, destination, ProbeChromeCDP)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry([]Connector{connector})
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: now}
	authorizer := &fakeAuthorizer{}
	backend := &fakeBackend{adapter: &fakeAdapter{}}
	auditor := &fakeAuditor{}
	manager, err := NewManager(registry, authorizer, backend, auditor, clock)
	if err != nil {
		t.Fatal(err)
	}
	return manager, binding, clock, authorizer, backend, auditor
}

func TestAuthorizationWithoutActivationCannotBeUsed(t *testing.T) {
	manager, binding, _, authorizer, backend, _ := newTestManager(t)
	if err := authorizer.Authorize(context.Background(), binding, "chrome-cdp", grant.SessionScope()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrInactive) {
		t.Fatalf("Use() error = %v, want inactive", err)
	}
	if backend.Calls() != 0 {
		t.Fatal("Use activated a bridge")
	}
}

func TestActivateUnknownConnectorDoesNotCallAuthorityOrBackend(t *testing.T) {
	manager, binding, _, authorizer, backend, _ := newTestManager(t)
	if err := manager.Activate(context.Background(), binding, "agent-selected-host", grant.SessionScope()); !errors.Is(err, ErrUnknownConnector) {
		t.Fatalf("Activate() error = %v, want unknown connector", err)
	}
	if authorizer.Calls() != 0 || backend.Calls() != 0 {
		t.Fatalf("unknown connector reached dependencies: authorizer=%d backend=%d", authorizer.Calls(), backend.Calls())
	}
}

func TestActivateFailedBackendNeverBecomesUsable(t *testing.T) {
	for _, failure := range []string{"bind", "dial", "probe"} {
		t.Run(failure, func(t *testing.T) {
			manager, binding, _, _, backend, _ := newTestManager(t)
			backend.err = errors.New(failure + " failed")
			if err := manager.Activate(context.Background(), binding, "chrome-cdp", grant.SessionScope()); !errors.Is(err, ErrActivation) {
				t.Fatalf("Activate() error = %v, want activation failure", err)
			}
			if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrInactive) {
				t.Fatalf("Use() error = %v, want inactive", err)
			}
			snapshot, err := manager.Snapshot(binding, "chrome-cdp")
			if err != nil || snapshot.State != StateActivationFailed {
				t.Fatalf("Snapshot() = %#v, %v", snapshot, err)
			}
		})
	}
}

func TestActivationAuditFailureFailsClosedBeforeBackend(t *testing.T) {
	manager, binding, _, _, backend, auditor := newTestManager(t)
	auditor.errState = StateActivating
	if err := manager.Activate(context.Background(), binding, "chrome-cdp", grant.SessionScope()); !errors.Is(err, ErrAudit) {
		t.Fatalf("Activate() error = %v, want audit failure", err)
	}
	if backend.Calls() != 0 {
		t.Fatal("backend was called after durable audit failure")
	}
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrInactive) {
		t.Fatalf("Use() error = %v, want inactive", err)
	}
}

func TestUseRequiresExactPrincipalSessionAndConnector(t *testing.T) {
	manager, binding, _, _, _, _ := newTestManager(t)
	if err := manager.Activate(context.Background(), binding, "chrome-cdp", grant.SessionScope()); err != nil {
		t.Fatal(err)
	}
	otherPrincipal, err := grant.NewPrincipal("other-agent", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	otherBinding, err := NewBinding(otherPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		binding Binding
		id      ConnectorID
	}{
		{binding: otherBinding, id: "chrome-cdp"},
		{binding: binding, id: "other-connector"},
	} {
		if _, err := manager.Use(context.Background(), request.binding, request.id); err == nil {
			t.Fatalf("Use(%q) unexpectedly succeeded", request.id)
		}
	}
	otherSession, err := grant.NewPrincipal("codex", "session-b")
	if err != nil {
		t.Fatal(err)
	}
	otherSessionBinding, err := NewBinding(otherSession)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Use(context.Background(), otherSessionBinding, "chrome-cdp"); err == nil {
		t.Fatal("cross-session use unexpectedly succeeded")
	}
}

func TestExpiryBoundaryClosesConnectorAndRejectsUse(t *testing.T) {
	manager, binding, clock, _, backend, _ := newTestManager(t)
	expiresAt := clock.Now().Add(time.Minute)
	scope, err := grant.NewTTLScope(clock.Now(), expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Activate(context.Background(), binding, "chrome-cdp", scope); err != nil {
		t.Fatal(err)
	}
	clock.Set(expiresAt)
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrExpired) {
		t.Fatalf("Use() error = %v, want expired", err)
	}
	if backend.adapter.CloseCalls() != 1 {
		t.Fatal("expiry did not close the adapter")
	}
}

func TestOneUseConsumesAndCleansUp(t *testing.T) {
	manager, binding, _, _, backend, _ := newTestManager(t)
	if err := manager.Activate(context.Background(), binding, "chrome-cdp", grant.OnceScope()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("reuse error = %v, want revoked", err)
	}
	if backend.adapter.CloseCalls() != 1 {
		t.Fatal("one-use consumption did not close the adapter")
	}
}

func TestRevokeRejectsBeforeCleanupFailure(t *testing.T) {
	manager, binding, _, _, backend, _ := newTestManager(t)
	backend.adapter.closeErr = errors.New("bridge cleanup failed")
	if err := manager.Activate(context.Background(), binding, "chrome-cdp", grant.SessionScope()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Revoke(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrCleanup) {
		t.Fatalf("Revoke() error = %v, want cleanup failure", err)
	}
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Use() error = %v, want revoked", err)
	}
}

func TestSessionEndRejectsAndClosesConnector(t *testing.T) {
	manager, binding, _, _, backend, _ := newTestManager(t)
	if err := manager.Activate(context.Background(), binding, "chrome-cdp", grant.SessionScope()); err != nil {
		t.Fatal(err)
	}
	if err := manager.EndSession(context.Background(), binding.Principal().SessionID()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Use() error = %v, want revoked", err)
	}
	if backend.adapter.CloseCalls() != 1 {
		t.Fatal("session end did not close the adapter")
	}
}

func TestReadyAuditFailureClosesAdapterWithoutActiveAuthority(t *testing.T) {
	manager, binding, _, _, backend, auditor := newTestManager(t)
	auditor.errState = StateActive
	if err := manager.Activate(context.Background(), binding, "chrome-cdp", grant.SessionScope()); !errors.Is(err, ErrAudit) {
		t.Fatalf("Activate() error = %v, want durable audit failure", err)
	}
	if backend.adapter.CloseCalls() != 1 {
		t.Fatal("adapter remained installed after active audit failure")
	}
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrInactive) {
		t.Fatalf("Use() error = %v, want inactive", err)
	}
}

func TestRevokeDuringActivationClosesLateAdapter(t *testing.T) {
	manager, binding, _, _, backend, _ := newTestManager(t)
	backend.started = make(chan struct{})
	release := make(chan struct{})
	backend.release = release
	activate := make(chan error, 1)
	go func() {
		activate <- manager.Activate(context.Background(), binding, "chrome-cdp", grant.SessionScope())
	}()
	<-backend.started
	if _, err := manager.Use(context.Background(), binding, "chrome-cdp"); !errors.Is(err, ErrInactive) {
		t.Fatalf("Use() during activation error = %v, want inactive", err)
	}
	if err := manager.Revoke(context.Background(), binding, "chrome-cdp"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-activate; !errors.Is(err, ErrRevoked) {
		t.Fatalf("Activate() error = %v, want revoked", err)
	}
	if backend.adapter.CloseCalls() != 1 {
		t.Fatal("late adapter was not closed")
	}
}

func TestAuditTransitionExcludesDestination(t *testing.T) {
	manager, binding, _, _, _, auditor := newTestManager(t)
	if err := manager.Activate(context.Background(), binding, "chrome-cdp", grant.SessionScope()); err != nil {
		t.Fatal(err)
	}
	for _, state := range auditor.states() {
		if state != StateActivating && state != StateActive {
			t.Fatalf("unexpected activation state %q", state)
		}
	}
}

type captureEmitter struct {
	event audit.Event
}

func (e *captureEmitter) Emit(_ context.Context, event audit.Event) error {
	e.event = event
	return nil
}

func TestAuditEmitterDoesNotRecordDestination(t *testing.T) {
	_, binding, _, _, _, _ := newTestManager(t)
	emitter := &captureEmitter{}
	if err := (AuditEmitter{Emitter: emitter}).Record(context.Background(), Transition{
		ConnectorID: "chrome-cdp", Binding: binding, State: StateActive,
	}); err != nil {
		t.Fatal(err)
	}
	if emitter.event.EventType != audit.HostConnectorActivated || emitter.event.RefID != "chrome-cdp" {
		t.Fatalf("event = %#v", emitter.event)
	}
	if len(emitter.event.Detail) != 1 || emitter.event.Detail["state"] != "active" {
		t.Fatalf("event detail = %#v", emitter.event.Detail)
	}
}

func TestConfiguredDestinationRejectsAgentLikeInput(t *testing.T) {
	for _, destination := range []struct {
		host string
		path string
	}{
		{host: "https://host.example", path: "/json/version"},
		{host: "host.example:9225", path: "/json/version"},
		{host: "host.example", path: "https://host.example/json/version"},
		{host: "host.example", path: "/json/version?token=secret"},
	} {
		if _, err := NewDestination(destination.host, 9225, destination.path); !errors.Is(err, ErrInvalidConnector) {
			t.Fatalf("NewDestination(%q, %q) error = %v", destination.host, destination.path, err)
		}
	}
}
