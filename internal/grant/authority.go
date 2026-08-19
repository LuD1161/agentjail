package grant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	ErrInvalidCapacity        = errors.New("invalid grant capacity")
	ErrInvalidIDSource        = errors.New("invalid grant ID source")
	ErrInvalidAuditEmitter    = errors.New("invalid grant audit emitter")
	ErrIneligibleDecision     = errors.New("grant request is not eligible for runtime approval")
	ErrCanonicalAllow         = errors.New("canonical allow does not create a runtime grant")
	ErrPolicyDenied           = errors.New("policy deny cannot be overridden by a runtime grant")
	ErrGrantNotFound          = errors.New("grant not found")
	ErrInvalidTransition      = errors.New("invalid grant lifecycle transition")
	ErrInvalidApproval        = errors.New("invalid grant approval reference")
	ErrAuditFailed            = errors.New("durable grant audit failed")
	ErrGrantExpired           = errors.New("grant expired")
	ErrGrantRevoked           = errors.New("grant revoked")
	ErrGrantNotActive         = errors.New("grant is not active")
	ErrAccessMismatch         = errors.New("grant access does not match authority")
	ErrStalePolicyEpoch       = errors.New("grant policy epoch is stale")
	ErrClaimRequired          = errors.New("one-use grant requires a claim")
	ErrClaimNotFound          = errors.New("grant claim not found")
	ErrClaimAlreadyCommitted  = errors.New("grant claim already committed")
	ErrClaimAlreadyRolledBack = errors.New("grant claim already rolled back")
	ErrGrantAlreadyClaimed    = errors.New("grant is already claimed")
	ErrGlobalCapacity         = errors.New("global runtime grant capacity exceeded")
	ErrSessionCapacity        = errors.New("per-session runtime grant capacity exceeded")
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictAsk   Verdict = "ask"
	VerdictDeny  Verdict = "deny"
)

type DenyPrecedence string

const (
	DenyNone     DenyPrecedence = "none"
	DenyExplicit DenyPrecedence = "explicit"
	DenyLocked   DenyPrecedence = "locked"
)

// CanonicalDecision is the evaluator result, kept out of lifecycle audit
// because canonical policy decisions are already recorded separately.
type CanonicalDecision struct {
	verdict Verdict
	deny    DenyPrecedence
}

func NewCanonicalDecision(verdict Verdict, deny DenyPrecedence) (CanonicalDecision, error) {
	switch verdict {
	case VerdictAllow, VerdictAsk:
		if deny != DenyNone {
			return CanonicalDecision{}, ErrIneligibleDecision
		}
	case VerdictDeny:
		if deny != DenyExplicit && deny != DenyLocked {
			return CanonicalDecision{}, ErrIneligibleDecision
		}
	default:
		return CanonicalDecision{}, ErrIneligibleDecision
	}
	return CanonicalDecision{verdict: verdict, deny: deny}, nil
}

func (d CanonicalDecision) Verdict() Verdict               { return d.verdict }
func (d CanonicalDecision) DenyPrecedence() DenyPrecedence { return d.deny }

func (d CanonicalDecision) eligible() error {
	if d.verdict == VerdictAsk && d.deny == DenyNone {
		return nil
	}
	if d.verdict == VerdictAllow {
		return ErrCanonicalAllow
	}
	if d.verdict == VerdictDeny && (d.deny == DenyExplicit || d.deny == DenyLocked) {
		return ErrPolicyDenied
	}
	return ErrIneligibleDecision
}

// Clock is injected because expiry is an authorization boundary.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// IDSource makes lifecycle tests deterministic while production uses crypto/rand.
type IDSource interface {
	NewRequestID() (RequestID, error)
	NewGrantID() (GrantID, error)
	NewClaimID() (ClaimID, error)
}

type CryptoIDSource struct{ reader io.Reader }

func NewCryptoIDSource(reader io.Reader) (CryptoIDSource, error) {
	if reader == nil {
		return CryptoIDSource{}, ErrInvalidIDSource
	}
	return CryptoIDSource{reader: reader}, nil
}

func (s CryptoIDSource) NewRequestID() (RequestID, error) {
	id, err := s.next()
	return RequestID(id), err
}
func (s CryptoIDSource) NewGrantID() (GrantID, error) { id, err := s.next(); return GrantID(id), err }
func (s CryptoIDSource) NewClaimID() (ClaimID, error) { id, err := s.next(); return ClaimID(id), err }

func (s CryptoIDSource) next() (string, error) {
	if s.reader == nil {
		return "", ErrInvalidIDSource
	}
	var raw [16]byte
	if _, err := io.ReadFull(s.reader, raw[:]); err != nil {
		return "", fmt.Errorf("read grant ID entropy: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

type LifecycleEventType string

const (
	LifecycleApproved  LifecycleEventType = "grant.approved"
	LifecycleActivated LifecycleEventType = "grant.activated"
)

// LifecycleEvent is the bounded, non-secret projection needed by durable audit.
type LifecycleEvent struct {
	Type        LifecycleEventType
	GrantID     GrantID
	RequestID   RequestID
	Principal   Principal
	Action      Action
	Resource    Resource
	Scope       Scope
	PolicyEpoch PolicyEpoch
	Approval    ApprovalReference
	At          time.Time
}

// LifecycleAudit is a consumer-defined persistence seam; this domain does not
// import the store or duplicate its wire-shaped events. See ADR 0141-runtime-grants.
type LifecycleAudit interface {
	EmitLifecycle(context.Context, LifecycleEvent) error
}

type Capacity struct{ Global, PerSession int }

func (c Capacity) valid() bool { return c.Global > 0 && c.PerSession > 0 && c.PerSession <= c.Global }

type ManagerConfig struct {
	Clock    Clock
	IDs      IDSource
	Audit    LifecycleAudit
	Capacity Capacity
}

// Authority is the runtime seam consumed by adapters and enforcement points.
type Authority interface {
	Request(context.Context, Request, CanonicalDecision) (Grant, error)
	Approve(context.Context, GrantID, ApprovalReference) (Grant, error)
	Activate(context.Context, GrantID) (Grant, error)
	FailActivation(context.Context, GrantID) (Grant, error)
	Deny(context.Context, GrantID) (Grant, error)
	Authorize(Access) (Grant, error)
	Claim(Access) (Claim, error)
	Commit(Claim) (Grant, error)
	Rollback(Claim) error
	Lookup(GrantID) (Grant, error)
	RevokeSession(SessionID) int
	Reap() int
}

type Manager struct {
	mu       sync.Mutex
	clock    Clock
	ids      IDSource
	audit    LifecycleAudit
	capacity Capacity
	grants   map[GrantID]*grantRecord
	claims   map[ClaimID]*claimRecord
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.IDs == nil {
		ids, err := NewCryptoIDSource(rand.Reader)
		if err != nil {
			return nil, err
		}
		cfg.IDs = ids
	}
	if cfg.Audit == nil {
		return nil, ErrInvalidAuditEmitter
	}
	if !cfg.Capacity.valid() {
		return nil, ErrInvalidCapacity
	}
	return &Manager{clock: cfg.Clock, ids: cfg.IDs, audit: cfg.Audit, capacity: cfg.Capacity, grants: make(map[GrantID]*grantRecord), claims: make(map[ClaimID]*claimRecord)}, nil
}

// Grant is an immutable lifecycle snapshot returned by Manager operations.
type Grant struct {
	id          GrantID
	requestID   RequestID
	request     Request
	state       State
	approval    ApprovalReference
	approvedAt  time.Time
	activatedAt time.Time
	deniedAt    time.Time
	terminalAt  time.Time
}

func (g Grant) ID() GrantID                         { return g.id }
func (g Grant) RequestID() RequestID                { return g.requestID }
func (g Grant) Request() Request                    { return g.request }
func (g Grant) State() State                        { return g.state }
func (g Grant) Approval() (ApprovalReference, bool) { return g.approval, g.approval != "" }
func (g Grant) ApprovedAt() (time.Time, bool)       { return g.approvedAt, !g.approvedAt.IsZero() }
func (g Grant) ActivatedAt() (time.Time, bool)      { return g.activatedAt, !g.activatedAt.IsZero() }
func (g Grant) DeniedAt() (time.Time, bool)         { return g.deniedAt, !g.deniedAt.IsZero() }
func (g Grant) TerminalAt() (time.Time, bool)       { return g.terminalAt, !g.terminalAt.IsZero() }

type grantRecord struct {
	grant   Grant
	claimed bool
}

// Access binds a use to one principal/session, canonical resource, action, and epoch.
type Access struct {
	principal Principal
	action    Action
	resource  Resource
	epoch     PolicyEpoch
}

func NewAccess(principal Principal, action Action, resource Resource, epoch PolicyEpoch) (Access, error) {
	if !principal.Valid() || !resource.Valid() || !action.Valid() || !actionSupportsResource(action, resource.Kind()) || epoch == 0 {
		return Access{}, ErrAccessMismatch
	}
	return Access{principal: principal, action: action, resource: resource, epoch: epoch}, nil
}

func (a Access) Principal() Principal     { return a.principal }
func (a Access) Action() Action           { return a.action }
func (a Access) Resource() Resource       { return a.resource }
func (a Access) PolicyEpoch() PolicyEpoch { return a.epoch }

// Claim is the only rollback contract for a one-use grant. See ADR 0141-runtime-grants.
type Claim struct {
	id      ClaimID
	grantID GrantID
}

func (c Claim) ID() ClaimID      { return c.id }
func (c Claim) GrantID() GrantID { return c.grantID }

type claimStatus uint8

const (
	claimPending claimStatus = iota
	claimCommitted
	claimRolledBack
)

type claimRecord struct {
	grantID GrantID
	status  claimStatus
}

func (m *Manager) Request(_ context.Context, request Request, decision CanonicalDecision) (Grant, error) {
	if err := decision.eligible(); err != nil {
		return Grant{}, err
	}
	if !request.principal.Valid() || !request.resource.Valid() || !request.action.Valid() || !request.scope.ValidAt(request.requestedAt) || request.policyEpoch == 0 {
		return Grant{}, ErrInvalidRequest
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	if request.requestedAt.After(now) {
		return Grant{}, ErrInvalidRequest
	}
	requestID, err := m.ids.NewRequestID()
	if err != nil || !requestID.Valid() {
		return Grant{}, idError(err, ErrInvalidRequestID)
	}
	grantID, err := m.ids.NewGrantID()
	if err != nil || !grantID.Valid() {
		return Grant{}, idError(err, ErrInvalidGrantID)
	}
	m.expireAllLocked(now)
	m.cleanupTerminalLocked()
	if m.liveCountLocked() >= m.capacity.Global {
		return Grant{}, ErrGlobalCapacity
	}
	if m.liveCountForSessionLocked(request.principal.SessionID()) >= m.capacity.PerSession {
		return Grant{}, ErrSessionCapacity
	}
	if _, exists := m.grants[grantID]; exists {
		return Grant{}, ErrInvalidGrantID
	}
	grant := Grant{id: grantID, requestID: requestID, request: request, state: StateRequested}
	m.grants[grantID] = &grantRecord{grant: grant}
	return grant, nil
}

func (m *Manager) Approve(ctx context.Context, id GrantID, approval ApprovalReference) (Grant, error) {
	if !id.Valid() {
		return Grant{}, ErrGrantNotFound
	}
	if !present(string(approval)) {
		return Grant{}, ErrInvalidApproval
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.recordLocked(id, m.clock.Now())
	if err != nil {
		return Grant{}, err
	}
	if record.grant.state != StateRequested {
		return Grant{}, ErrInvalidTransition
	}
	now := m.clock.Now()
	if err := m.audit.EmitLifecycle(ctx, m.eventFor(record.grant, LifecycleApproved, approval, now)); err != nil {
		return Grant{}, fmt.Errorf("%w: approve grant: %v", ErrAuditFailed, err)
	}
	record.grant.state, record.grant.approval, record.grant.approvedAt = StateApproved, approval, now
	return record.grant, nil
}

func (m *Manager) Activate(ctx context.Context, id GrantID) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.recordLocked(id, m.clock.Now())
	if err != nil {
		return Grant{}, err
	}
	if record.grant.state != StateApproved {
		return Grant{}, ErrInvalidTransition
	}
	now := m.clock.Now()
	if err := m.audit.EmitLifecycle(ctx, m.eventFor(record.grant, LifecycleActivated, record.grant.approval, now)); err != nil {
		return Grant{}, fmt.Errorf("%w: activate grant: %v", ErrAuditFailed, err)
	}
	record.grant.state, record.grant.activatedAt = StateActive, now
	return record.grant, nil
}

func (m *Manager) FailActivation(_ context.Context, id GrantID) (Grant, error) {
	return m.transition(id, StateApproved, StateActivationFailed)
}

func (m *Manager) Deny(_ context.Context, id GrantID) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.recordLocked(id, m.clock.Now())
	if err != nil {
		return Grant{}, err
	}
	if record.grant.state != StateRequested {
		return Grant{}, ErrInvalidTransition
	}
	now := m.clock.Now()
	m.terminalLocked(record, StateDenied, now)
	record.grant.deniedAt = now
	return record.grant, nil
}

func (m *Manager) transition(id GrantID, from, to State) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.recordLocked(id, m.clock.Now())
	if err != nil {
		return Grant{}, err
	}
	if record.grant.state != from {
		return Grant{}, ErrInvalidTransition
	}
	m.terminalLocked(record, to, m.clock.Now())
	return record.grant, nil
}

func (m *Manager) Lookup(id GrantID) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.recordLocked(id, m.clock.Now())
	if err != nil {
		return Grant{}, err
	}
	return record.grant, nil
}

func (m *Manager) Authorize(access Access) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.findAccessLocked(access, m.clock.Now(), nil)
	if err != nil {
		return Grant{}, err
	}
	if record.grant.request.scope.Kind() == ScopeOnce {
		return Grant{}, ErrClaimRequired
	}
	return record.grant, nil
}

func (m *Manager) Claim(access Access) (Claim, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.findAccessLocked(access, m.clock.Now(), nil)
	if err != nil {
		return Claim{}, err
	}
	if record.grant.request.scope.Kind() != ScopeOnce {
		return Claim{}, ErrClaimRequired
	}
	if record.claimed {
		return Claim{}, ErrGrantAlreadyClaimed
	}
	id, err := m.ids.NewClaimID()
	if err != nil || !id.Valid() {
		return Claim{}, idError(err, ErrInvalidClaimID)
	}
	if _, exists := m.claims[id]; exists {
		return Claim{}, ErrClaimNotFound
	}
	record.claimed = true
	m.claims[id] = &claimRecord{grantID: record.grant.id, status: claimPending}
	return Claim{id: id, grantID: record.grant.id}, nil
}

// AuthorizeWithAdapter applies a resource adapter's non-widening coverage
// contract while retaining the exact principal, action, and epoch binding.
// See ADR 0141-runtime-grants.
func (m *Manager) AuthorizeWithAdapter(access Access, adapter ResourceAdapter) (Grant, error) {
	if adapter == nil || adapter.Kind() != access.Resource().Kind() {
		return Grant{}, ErrAdapterKind
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.findAccessLocked(access, m.clock.Now(), adapter)
	if err != nil {
		return Grant{}, err
	}
	if record.grant.request.scope.Kind() == ScopeOnce {
		return Grant{}, ErrClaimRequired
	}
	return record.grant, nil
}

// ClaimWithAdapter atomically reserves a one-use grant whose resource covers
// the requested resource under the supplied adapter.
func (m *Manager) ClaimWithAdapter(access Access, adapter ResourceAdapter) (Claim, error) {
	if adapter == nil || adapter.Kind() != access.Resource().Kind() {
		return Claim{}, ErrAdapterKind
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.findAccessLocked(access, m.clock.Now(), adapter)
	if err != nil {
		return Claim{}, err
	}
	if record.grant.request.scope.Kind() != ScopeOnce {
		return Claim{}, ErrClaimRequired
	}
	if record.claimed {
		return Claim{}, ErrGrantAlreadyClaimed
	}
	id, err := m.ids.NewClaimID()
	if err != nil || !id.Valid() {
		return Claim{}, idError(err, ErrInvalidClaimID)
	}
	if _, exists := m.claims[id]; exists {
		return Claim{}, ErrClaimNotFound
	}
	record.claimed = true
	m.claims[id] = &claimRecord{grantID: record.grant.id, status: claimPending}
	return Claim{id: id, grantID: record.grant.id}, nil
}

func (m *Manager) Commit(claim Claim) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, claimed, err := m.claimLocked(claim)
	if err != nil {
		return Grant{}, err
	}
	if claimed.status == claimCommitted {
		return Grant{}, ErrClaimAlreadyCommitted
	}
	if claimed.status == claimRolledBack {
		return Grant{}, ErrClaimAlreadyRolledBack
	}
	if m.expireLocked(record, m.clock.Now()) {
		claimed.status, record.claimed = claimRolledBack, false
		return Grant{}, ErrGrantExpired
	}
	if record.grant.state == StateRevoked {
		claimed.status, record.claimed = claimRolledBack, false
		return Grant{}, ErrGrantRevoked
	}
	if record.grant.state != StateActive || !record.claimed {
		return Grant{}, ErrInvalidTransition
	}
	m.terminalLocked(record, StateConsumed, m.clock.Now())
	record.claimed, claimed.status = false, claimCommitted
	return record.grant, nil
}

func (m *Manager) Rollback(claim Claim) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, claimed, err := m.claimLocked(claim)
	if err != nil {
		return err
	}
	if claimed.status == claimCommitted {
		return ErrClaimAlreadyCommitted
	}
	if claimed.status == claimRolledBack {
		return ErrClaimAlreadyRolledBack
	}
	if m.expireLocked(record, m.clock.Now()) {
		claimed.status, record.claimed = claimRolledBack, false
		return ErrGrantExpired
	}
	if record.grant.state == StateRevoked {
		claimed.status, record.claimed = claimRolledBack, false
		return ErrGrantRevoked
	}
	if record.grant.state != StateActive || !record.claimed {
		return ErrInvalidTransition
	}
	record.claimed, claimed.status = false, claimRolledBack
	return nil
}

func (m *Manager) RevokeSession(sessionID SessionID) int {
	if !present(string(sessionID)) {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	m.expireAllLocked(now)
	n := 0
	for _, record := range m.grants {
		if record.grant.request.principal.SessionID() == sessionID && isLive(record.grant.state) {
			m.terminalLocked(record, StateRevoked, now)
			record.claimed = false
			n++
		}
	}
	return n
}

// Reap removes terminal records. Each lookup and use separately checks expiry
// under lock, so this cleanup cannot create an authorization window.
func (m *Manager) Reap() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireAllLocked(m.clock.Now())
	return m.cleanupTerminalLocked()
}

func (m *Manager) recordLocked(id GrantID, now time.Time) (*grantRecord, error) {
	record, ok := m.grants[id]
	if !ok {
		return nil, ErrGrantNotFound
	}
	if m.expireLocked(record, now) {
		return nil, ErrGrantExpired
	}
	if record.grant.state == StateRevoked {
		return nil, ErrGrantRevoked
	}
	return record, nil
}

func (m *Manager) findAccessLocked(access Access, now time.Time, adapter ResourceAdapter) (*grantRecord, error) {
	if !access.principal.Valid() || !access.resource.Valid() || !access.action.Valid() || access.epoch == 0 {
		return nil, ErrAccessMismatch
	}
	matched := false
	expired := false
	stale := false
	revoked := false
	inactive := false
	consumed := false
	for _, record := range m.grants {
		grant := record.grant
		if grant.request.principal != access.principal || grant.request.action != access.action {
			continue
		}
		if adapter == nil && grant.request.resource.Resource() != access.resource {
			continue
		}
		if adapter != nil && !adapter.Covers(grant.request.resource.Resource(), access.resource) {
			continue
		}
		matched = true
		if m.expireLocked(record, now) {
			expired = true
			continue
		}
		if grant.request.policyEpoch != access.epoch {
			stale = true
			continue
		}
		if grant.state == StateRevoked {
			revoked = true
			continue
		}
		if grant.state == StateConsumed {
			consumed = true
			continue
		}
		if grant.state != StateActive {
			inactive = true
			continue
		}
		return record, nil
	}
	if !matched {
		return nil, ErrAccessMismatch
	}
	if expired {
		return nil, ErrGrantExpired
	}
	if stale {
		return nil, ErrStalePolicyEpoch
	}
	if revoked {
		return nil, ErrGrantRevoked
	}
	if consumed {
		if adapter != nil {
			return nil, ErrGrantAlreadyClaimed
		}
		return nil, ErrGrantNotActive
	}
	if inactive {
		return nil, ErrGrantNotActive
	}
	return nil, ErrAccessMismatch
}

func (m *Manager) claimLocked(claim Claim) (*grantRecord, *claimRecord, error) {
	if !claim.id.Valid() || !claim.grantID.Valid() {
		return nil, nil, ErrClaimNotFound
	}
	claimed, ok := m.claims[claim.id]
	if !ok || claimed.grantID != claim.grantID {
		return nil, nil, ErrClaimNotFound
	}
	record, ok := m.grants[claim.grantID]
	if !ok {
		return nil, nil, ErrGrantNotFound
	}
	return record, claimed, nil
}

func (m *Manager) expireAllLocked(now time.Time) {
	for _, record := range m.grants {
		m.expireLocked(record, now)
	}
}

func (m *Manager) cleanupTerminalLocked() int {
	removed := 0
	for id, record := range m.grants {
		if !isLive(record.grant.state) {
			delete(m.grants, id)
			for claimID, claim := range m.claims {
				if claim.grantID == id {
					delete(m.claims, claimID)
				}
			}
			removed++
		}
	}
	return removed
}

func (m *Manager) expireLocked(record *grantRecord, now time.Time) bool {
	if isLive(record.grant.state) && record.grant.request.scope.ExpiredAt(now) {
		m.terminalLocked(record, StateExpired, now)
		record.claimed = false
		return true
	}
	return record.grant.state == StateExpired
}

func (m *Manager) terminalLocked(record *grantRecord, state State, now time.Time) {
	record.grant.state, record.grant.terminalAt = state, now
}
func (m *Manager) liveCountLocked() int {
	n := 0
	for _, record := range m.grants {
		if isLive(record.grant.state) {
			n++
		}
	}
	return n
}
func (m *Manager) liveCountForSessionLocked(id SessionID) int {
	n := 0
	for _, record := range m.grants {
		if isLive(record.grant.state) && record.grant.request.principal.SessionID() == id {
			n++
		}
	}
	return n
}
func (m *Manager) eventFor(grant Grant, typ LifecycleEventType, approval ApprovalReference, at time.Time) LifecycleEvent {
	return LifecycleEvent{Type: typ, GrantID: grant.id, RequestID: grant.requestID, Principal: grant.request.principal, Action: grant.request.action, Resource: grant.request.resource.Resource(), Scope: grant.request.scope, PolicyEpoch: grant.request.policyEpoch, Approval: approval, At: at}
}

func isLive(state State) bool {
	return state == StateRequested || state == StateApproved || state == StateActive
}
func idError(err, fallback error) error {
	if err != nil {
		return fmt.Errorf("grant ID generation: %w", err)
	}
	return fallback
}
