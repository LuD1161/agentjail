package grant

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

type sequenceIDs struct {
	mu      sync.Mutex
	request int
	grant   int
	claim   int
}

func (s *sequenceIDs) NewRequestID() (RequestID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.request++
	return RequestID(fmt.Sprintf("request-%d", s.request)), nil
}

func (s *sequenceIDs) NewGrantID() (GrantID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grant++
	return GrantID(fmt.Sprintf("grant-%d", s.grant)), nil
}

func (s *sequenceIDs) NewClaimID() (ClaimID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claim++
	return ClaimID(fmt.Sprintf("claim-%d", s.claim)), nil
}

type recordingAudit struct {
	mu     sync.Mutex
	events []LifecycleEvent
	fail   LifecycleEventType
}

func (a *recordingAudit) EmitLifecycle(_ context.Context, event LifecycleEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail == event.Type {
		return errors.New("audit unavailable")
	}
	a.events = append(a.events, event)
	return nil
}

func (a *recordingAudit) Events() []LifecycleEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]LifecycleEvent(nil), a.events...)
}

func setupManager(t *testing.T, capacity Capacity) (*Manager, *testClock, *recordingAudit) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)}
	audit := &recordingAudit{}
	manager, err := NewManager(ManagerConfig{Clock: clock, IDs: &sequenceIDs{}, Audit: audit, Capacity: capacity})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager, clock, audit
}

func askDecision(t *testing.T) CanonicalDecision {
	t.Helper()
	decision, err := NewCanonicalDecision(VerdictAsk, DenyNone)
	if err != nil {
		t.Fatalf("NewCanonicalDecision() error = %v", err)
	}
	return decision
}

func requestFor(t *testing.T, now time.Time, session SessionID, scope Scope, epoch PolicyEpoch) Request {
	t.Helper()
	principal, err := NewPrincipal("agent", session)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	resource := mustAdapt(t, ActionConnect, ResourceNetwork, "chrome-cdp", ActivationRequired)
	request, err := NewRequest(principal, ActionConnect, resource, scope, epoch, now)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return request
}

func activeGrant(t *testing.T, manager *Manager, request Request) Grant {
	t.Helper()
	grant, err := manager.Request(context.Background(), request, askDecision(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := manager.Approve(context.Background(), grant.ID(), "approval-1"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	grant, err = manager.Activate(context.Background(), grant.ID())
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	return grant
}

func accessFor(t *testing.T, request Request, epoch PolicyEpoch) Access {
	t.Helper()
	access, err := NewAccess(request.Principal(), request.Action(), request.Resource(), epoch)
	if err != nil {
		t.Fatalf("NewAccess() error = %v", err)
	}
	return access
}

func TestManagerLifecycleAuditsAuthorityCreation(t *testing.T) {
	manager, clock, audit := setupManager(t, Capacity{Global: 4, PerSession: 2})
	request := requestFor(t, clock.Now(), "session-1", SessionScope(), 7)
	grant, err := manager.Request(context.Background(), request, askDecision(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if grant.ID() == "" || grant.RequestID() == "" || grant.State() != StateRequested {
		t.Fatalf("Request() = %#v, want identified requested grant", grant)
	}
	if _, err := manager.Approve(context.Background(), grant.ID(), "native-proof"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if _, err := manager.Authorize(accessFor(t, request, 7)); !errors.Is(err, ErrGrantNotActive) {
		t.Fatalf("Authorize(approved) error = %v, want %v", err, ErrGrantNotActive)
	}
	grant, err = manager.Activate(context.Background(), grant.ID())
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if grant.State() != StateActive {
		t.Fatalf("Activate() state = %q, want %q", grant.State(), StateActive)
	}
	if _, err := manager.Authorize(accessFor(t, request, 7)); err != nil {
		t.Fatalf("Authorize(active) error = %v", err)
	}
	events := audit.Events()
	if len(events) != 2 || events[0].Type != LifecycleApproved || events[1].Type != LifecycleActivated {
		t.Fatalf("audit events = %#v, want approval then activation", events)
	}
	if events[0].GrantID != grant.ID() || events[0].RequestID != grant.RequestID() || !events[0].At.Equal(clock.Now()) {
		t.Fatalf("approval event = %#v, want bound timestamped lifecycle record", events[0])
	}
}

func TestManagerEligibilityAndInvalidTransitionsFailClosed(t *testing.T) {
	manager, clock, _ := setupManager(t, Capacity{Global: 4, PerSession: 2})
	request := requestFor(t, clock.Now(), "session-1", SessionScope(), 1)
	for _, test := range []struct {
		verdict Verdict
		deny    DenyPrecedence
		want    error
	}{
		{VerdictAllow, DenyNone, ErrCanonicalAllow},
		{VerdictDeny, DenyExplicit, ErrPolicyDenied},
		{VerdictDeny, DenyLocked, ErrPolicyDenied},
	} {
		decision, err := NewCanonicalDecision(test.verdict, test.deny)
		if err != nil {
			t.Fatalf("NewCanonicalDecision() error = %v", err)
		}
		if _, err := manager.Request(context.Background(), request, decision); !errors.Is(err, test.want) {
			t.Fatalf("Request(%s) error = %v, want %v", test.verdict, err, test.want)
		}
	}
	grant, err := manager.Request(context.Background(), request, askDecision(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(context.Background(), grant.ID()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Activate(requested) error = %v, want %v", err, ErrInvalidTransition)
	}
	if _, err := manager.Deny(context.Background(), grant.ID()); err != nil {
		t.Fatalf("Deny() error = %v", err)
	}
	if _, err := manager.Approve(context.Background(), grant.ID(), "proof"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Approve(denied) error = %v, want %v", err, ErrInvalidTransition)
	}
	second, err := manager.Request(context.Background(), request, askDecision(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Approve(context.Background(), second.ID(), "proof"); err != nil {
		t.Fatal(err)
	}
	if got, err := manager.FailActivation(context.Background(), second.ID()); err != nil || got.State() != StateActivationFailed {
		t.Fatalf("FailActivation() = %#v, %v; want activation_failed", got, err)
	}
}

func TestManagerAuditFailureDoesNotExposeAuthority(t *testing.T) {
	manager, clock, audit := setupManager(t, Capacity{Global: 4, PerSession: 2})
	request := requestFor(t, clock.Now(), "session-1", SessionScope(), 1)
	grant, err := manager.Request(context.Background(), request, askDecision(t))
	if err != nil {
		t.Fatal(err)
	}
	audit.fail = LifecycleApproved
	if _, err := manager.Approve(context.Background(), grant.ID(), "proof"); !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("Approve(audit fail) error = %v, want %v", err, ErrAuditFailed)
	}
	got, err := manager.Lookup(grant.ID())
	if err != nil || got.State() != StateRequested {
		t.Fatalf("failed approval yielded %#v, %v; want requested", got, err)
	}
	audit.fail = ""
	if _, err := manager.Approve(context.Background(), grant.ID(), "proof"); err != nil {
		t.Fatal(err)
	}
	audit.fail = LifecycleActivated
	if _, err := manager.Activate(context.Background(), grant.ID()); !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("Activate(audit fail) error = %v, want %v", err, ErrAuditFailed)
	}
	got, err = manager.Lookup(grant.ID())
	if err != nil || got.State() != StateApproved {
		t.Fatalf("failed activation yielded %#v, %v; want approved", got, err)
	}
}

func TestAuthorityCreatingAuditMayReenterManager(t *testing.T) {
	manager, clock, _ := setupManager(t, Capacity{Global: 4, PerSession: 2})
	manager.audit = reentrantAudit{manager: manager}
	request := requestFor(t, clock.Now(), "session-1", SessionScope(), 1)
	pending, err := manager.Request(context.Background(), request, askDecision(t))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := manager.Approve(context.Background(), pending.ID(), "proof")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("approval audit deadlocked while reentering manager")
	}
	if _, err := manager.Activate(context.Background(), pending.ID()); err != nil {
		t.Fatal(err)
	}
}

type reentrantAudit struct{ manager *Manager }

func (a reentrantAudit) EmitLifecycle(_ context.Context, event LifecycleEvent) error {
	_, err := a.manager.Lookup(event.GrantID)
	return err
}

type collidingIDs struct {
	request int
	grant   int
}

func (s *collidingIDs) NewRequestID() (RequestID, error) {
	s.request++
	return RequestID("request-collision"), nil
}

func (s *collidingIDs) NewGrantID() (GrantID, error) {
	s.grant++
	return GrantID(fmt.Sprintf("grant-%d", s.grant)), nil
}

func (s *collidingIDs) NewClaimID() (ClaimID, error) { return "claim", nil }

func TestManagerRejectsLiveRequestIDCollision(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)}
	manager, err := NewManager(ManagerConfig{
		Clock: clock, IDs: &collidingIDs{}, Audit: &recordingAudit{}, Capacity: Capacity{Global: 4, PerSession: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := requestFor(t, clock.Now(), "session-1", SessionScope(), 1)
	if _, err := manager.Request(context.Background(), request, askDecision(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Request(context.Background(), request, askDecision(t)); !errors.Is(err, ErrInvalidRequestID) {
		t.Fatalf("duplicate request ID error = %v, want %v", err, ErrInvalidRequestID)
	}
}

func TestManagerExpiryEpochAndSessionBinding(t *testing.T) {
	manager, clock, _ := setupManager(t, Capacity{Global: 4, PerSession: 2})
	scope, err := NewTTLScope(clock.Now(), clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	request := requestFor(t, clock.Now(), "session-1", scope, 3)
	activeGrant(t, manager, request)
	if _, err := manager.Authorize(accessFor(t, request, 2)); !errors.Is(err, ErrStalePolicyEpoch) {
		t.Fatalf("Authorize(stale epoch) error = %v, want %v", err, ErrStalePolicyEpoch)
	}
	other := requestFor(t, clock.Now(), "session-2", scope, 3)
	if _, err := manager.Authorize(accessFor(t, other, 3)); !errors.Is(err, ErrAccessMismatch) {
		t.Fatalf("Authorize(other session) error = %v, want %v", err, ErrAccessMismatch)
	}
	otherPrincipal, err := NewPrincipal("other-agent", "session-1")
	if err != nil {
		t.Fatal(err)
	}
	otherPrincipalAccess, err := NewAccess(otherPrincipal, request.Action(), request.Resource(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Authorize(otherPrincipalAccess); !errors.Is(err, ErrAccessMismatch) {
		t.Fatalf("Authorize(other principal) error = %v, want %v", err, ErrAccessMismatch)
	}
	clock.Set(clock.Now().Add(time.Minute))
	if _, err := manager.Authorize(accessFor(t, request, 3)); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("Authorize(at expiry) error = %v, want %v", err, ErrGrantExpired)
	}
	if got := manager.Reap(); got != 1 {
		t.Fatalf("Reap() = %d, want expired record cleanup", got)
	}
}

func TestManagerRejectsFutureRequestTimestamp(t *testing.T) {
	manager, clock, _ := setupManager(t, Capacity{Global: 4, PerSession: 2})
	request := requestFor(t, clock.Now().Add(time.Second), "session-1", SessionScope(), 1)
	if _, err := manager.Request(context.Background(), request, askDecision(t)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Request(future timestamp) error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestManagerOneUseClaimCommitRollbackAndReplay(t *testing.T) {
	manager, clock, _ := setupManager(t, Capacity{Global: 4, PerSession: 2})
	request := requestFor(t, clock.Now(), "session-1", OnceScope(), 1)
	grant := activeGrant(t, manager, request)
	access := accessFor(t, request, 1)
	if _, err := manager.Authorize(access); !errors.Is(err, ErrClaimRequired) {
		t.Fatalf("Authorize(one-use) error = %v, want %v", err, ErrClaimRequired)
	}
	claim, err := manager.Claim(access)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Claim(access); !errors.Is(err, ErrGrantAlreadyClaimed) {
		t.Fatalf("second Claim() error = %v, want %v", err, ErrGrantAlreadyClaimed)
	}
	if err := manager.Rollback(claim); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if err := manager.Rollback(claim); !errors.Is(err, ErrClaimAlreadyRolledBack) {
		t.Fatalf("second Rollback() error = %v, want %v", err, ErrClaimAlreadyRolledBack)
	}
	claim, err = manager.Claim(access)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := manager.Commit(claim); err != nil || got.State() != StateConsumed {
		t.Fatalf("Commit() = %#v, %v; want consumed", got, err)
	}
	if _, err := manager.Commit(claim); !errors.Is(err, ErrClaimAlreadyCommitted) {
		t.Fatalf("replay Commit() error = %v, want %v", err, ErrClaimAlreadyCommitted)
	}
	if _, err := manager.Lookup(grant.ID()); err != nil {
		t.Fatalf("Lookup(consumed) error = %v", err)
	}
}

func TestManagerOneUseClaimIsAtomic(t *testing.T) {
	manager, clock, _ := setupManager(t, Capacity{Global: 4, PerSession: 2})
	request := requestFor(t, clock.Now(), "session-1", OnceScope(), 1)
	activeGrant(t, manager, request)
	access := accessFor(t, request, 1)
	const workers = 32
	start := make(chan struct{})
	results := make(chan Claim, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			claim, err := manager.Claim(access)
			if err == nil {
				results <- claim
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	count := 0
	var claim Claim
	for got := range results {
		count++
		claim = got
	}
	if count != 1 {
		t.Fatalf("successful concurrent claims = %d, want 1", count)
	}
	if _, err := manager.Commit(claim); err != nil {
		t.Fatalf("Commit(winning claim) error = %v", err)
	}
}

func TestManagerConcurrentClaimAndRevokeFailClosed(t *testing.T) {
	manager, clock, _ := setupManager(t, Capacity{Global: 4, PerSession: 2})
	request := requestFor(t, clock.Now(), "session-1", OnceScope(), 1)
	activeGrant(t, manager, request)
	access := accessFor(t, request, 1)
	start := make(chan struct{})
	claims := make(chan Claim, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		if claim, err := manager.Claim(access); err == nil {
			claims <- claim
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		manager.RevokeSession("session-1")
	}()
	close(start)
	wg.Wait()
	close(claims)
	for claim := range claims {
		if _, err := manager.Commit(claim); !errors.Is(err, ErrGrantRevoked) {
			t.Fatalf("Commit(claim after revoke) error = %v, want %v", err, ErrGrantRevoked)
		}
	}
}

func TestManagerRevokeSessionAndCapacity(t *testing.T) {
	manager, clock, _ := setupManager(t, Capacity{Global: 2, PerSession: 1})
	first := requestFor(t, clock.Now(), "session-1", SessionScope(), 1)
	grant := activeGrant(t, manager, first)
	if _, err := manager.Request(context.Background(), requestFor(t, clock.Now(), "session-1", SessionScope(), 1), askDecision(t)); !errors.Is(err, ErrSessionCapacity) {
		t.Fatalf("Request(over session cap) error = %v, want %v", err, ErrSessionCapacity)
	}
	second := requestFor(t, clock.Now(), "session-2", SessionScope(), 1)
	if _, err := manager.Request(context.Background(), second, askDecision(t)); err != nil {
		t.Fatalf("Request(second session) error = %v", err)
	}
	if _, err := manager.Request(context.Background(), requestFor(t, clock.Now(), "session-3", SessionScope(), 1), askDecision(t)); !errors.Is(err, ErrGlobalCapacity) {
		t.Fatalf("Request(over global cap) error = %v, want %v", err, ErrGlobalCapacity)
	}
	if got := manager.RevokeSession("session-1"); got != 1 {
		t.Fatalf("RevokeSession() = %d, want 1", got)
	}
	if _, err := manager.Authorize(accessFor(t, first, 1)); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Authorize(revoked) error = %v, want %v", err, ErrGrantRevoked)
	}
	if _, err := manager.Lookup(grant.ID()); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Lookup(revoked) error = %v, want %v", err, ErrGrantRevoked)
	}
	if _, err := manager.Request(context.Background(), requestFor(t, clock.Now(), "session-3", SessionScope(), 1), askDecision(t)); err != nil {
		t.Fatalf("Request(after revoke frees capacity) error = %v", err)
	}
}
