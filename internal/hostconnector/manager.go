package hostconnector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/LuD1161/agentjail/internal/grant"
)

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func SystemClock() Clock { return systemClock{} }

type recordKey struct {
	principalID grant.PrincipalID
	sessionID   grant.SessionID
	connectorID ConnectorID
}

type record struct {
	connector Connector
	binding   Binding
	scope     grant.Scope
	state     LifecycleState
	adapter   Adapter
	lease     UseLease
}

// Manager is the activation authority for configured host connectors.
// Authorization is delegated to the runtime grant lifecycle; this manager
// does not infer authorization from a bridge or successful probe.
type Manager struct {
	mu         sync.Mutex
	registry   *Registry
	authorizer Authorizer
	backend    Backend
	auditor    Auditor
	clock      Clock
	records    map[recordKey]*record
}

func NewManager(registry *Registry, authorizer Authorizer, backend Backend, auditor Auditor, clock Clock) (*Manager, error) {
	if registry == nil || authorizer == nil || backend == nil || auditor == nil || clock == nil {
		return nil, ErrActivation
	}
	return &Manager{
		registry: registry, authorizer: authorizer, backend: backend, auditor: auditor,
		clock: clock, records: make(map[recordKey]*record),
	}, nil
}

// Activate verifies authorization, installs the host-side bridge, and runs its
// backend-owned readiness probe. A usable state is recorded only after both
// durable audit and backend activation succeed.
func (m *Manager) Activate(ctx context.Context, binding Binding, id ConnectorID, scope grant.Scope) error {
	if !binding.valid() || !scope.ValidAt(m.clock.Now()) {
		return ErrActivation
	}
	connector, err := m.registry.Lookup(id)
	if err != nil {
		return err
	}
	key := keyFor(binding, id)
	m.mu.Lock()
	if _, exists := m.records[key]; exists {
		m.mu.Unlock()
		return ErrAlreadyActivating
	}
	record := &record{connector: connector, binding: binding, scope: scope, state: StateActivating}
	m.records[key] = record
	m.mu.Unlock()

	if err := m.record(ctx, record, StateActivating); err != nil {
		m.fail(ctx, key, record)
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	lease, err := m.authorizer.Begin(ctx, binding, id, scope)
	if err != nil || lease == nil {
		m.fail(ctx, key, record)
		return fmt.Errorf("%w: authorization: %v", ErrActivation, err)
	}
	record.lease = lease

	adapter, err := m.backend.Activate(ctx, Activation{connector: connector, binding: binding})
	if err != nil || adapter == nil {
		m.fail(ctx, key, record)
		_ = lease.Close()
		if err == nil {
			err = ErrActivation
		}
		return fmt.Errorf("%w: %v", ErrActivation, err)
	}

	m.mu.Lock()
	if m.records[key] != record || record.state != StateActivating {
		state := record.state
		m.mu.Unlock()
		_ = adapter.Close()
		_ = lease.Close()
		return stateError(state)
	}
	// Keep revocation and use behind this durable transition: no caller can
	// observe active authority before its audit record exists.
	if err := m.record(ctx, record, StateActive); err != nil {
		m.mu.Unlock()
		_ = adapter.Close()
		_ = lease.Close()
		m.fail(ctx, key, record)
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	record.adapter = adapter
	record.state = StateActive
	m.mu.Unlock()
	return nil
}

// Use synchronously verifies the exact principal, session, and connector.
// It returns no endpoint; a later MCP boundary can use this proof without
// gaining a generic host TCP forwarding capability.
func (m *Manager) Use(ctx context.Context, binding Binding, id ConnectorID) (Use, error) {
	if !binding.valid() {
		return Use{}, ErrInactive
	}
	key := keyFor(binding, id)
	m.mu.Lock()
	record, ok := m.records[key]
	if !ok || !record.binding.equal(binding) {
		m.mu.Unlock()
		return Use{}, ErrInactive
	}
	if record.scope.ExpiredAt(m.clock.Now()) {
		adapter := m.transitionLocked(record, StateExpired)
		m.mu.Unlock()
		return Use{}, m.finishTerminal(ctx, record, adapter, ErrExpired)
	}
	if record.state != StateActive {
		state := record.state
		m.mu.Unlock()
		return Use{}, stateError(state)
	}
	if err := record.lease.Use(ctx); err != nil {
		adapter := m.transitionLocked(record, StateRevoked)
		m.mu.Unlock()
		return Use{}, m.finishTerminal(ctx, record, adapter, err)
	}
	use := Use{ConnectorID: id, Transport: record.connector.Transport()}
	if record.scope.Kind() != grant.ScopeOnce {
		m.mu.Unlock()
		return use, nil
	}
	adapter := m.transitionLocked(record, StateConsumed)
	m.mu.Unlock()
	if err := m.finishTerminal(ctx, record, adapter, nil); err != nil {
		return Use{}, err
	}
	return use, nil
}

// Revoke rejects all future use before attempting bridge cleanup. Cleanup
// errors are returned to the caller but can never restore active authority.
func (m *Manager) Revoke(ctx context.Context, binding Binding, id ConnectorID) error {
	if !binding.valid() {
		return ErrInactive
	}
	m.mu.Lock()
	record, ok := m.records[keyFor(binding, id)]
	if !ok || !record.binding.equal(binding) {
		m.mu.Unlock()
		return ErrInactive
	}
	adapter := m.transitionLocked(record, StateRevoked)
	m.mu.Unlock()
	return m.finishTerminal(ctx, record, adapter, nil)
}

// EndSession revokes every connector bound to the session before cleanup.
func (m *Manager) EndSession(ctx context.Context, sessionID grant.SessionID) error {
	if sessionID == "" {
		return ErrInvalidBinding
	}
	m.mu.Lock()
	terminals := make([]terminal, 0)
	for _, record := range m.records {
		if record.binding.Principal().SessionID() == sessionID {
			terminals = append(terminals, terminal{record: record, adapter: m.transitionLocked(record, StateRevoked)})
		}
	}
	m.mu.Unlock()
	var errs []error
	for _, item := range terminals {
		if err := m.finishTerminal(ctx, item.record, item.adapter, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) Snapshot(binding Binding, id ConnectorID) (Snapshot, error) {
	if !binding.valid() {
		return Snapshot{}, ErrInactive
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.records[keyFor(binding, id)]
	if !ok || !record.binding.equal(binding) {
		return Snapshot{}, ErrInactive
	}
	return Snapshot{ConnectorID: id, Binding: binding, State: record.state}, nil
}

type terminal struct {
	record  *record
	adapter Adapter
}

func (m *Manager) transitionLocked(record *record, state LifecycleState) Adapter {
	if record.state != StateActive && record.state != StateActivating {
		return nil
	}
	record.state = state
	adapter := record.adapter
	record.adapter = nil
	lease := record.lease
	record.lease = nil
	if lease != nil {
		return &terminalAdapter{adapter: adapter, lease: lease}
	}
	return adapter
}

type terminalAdapter struct {
	adapter Adapter
	lease   UseLease
}

func (a *terminalAdapter) Close() error {
	var errs []error
	if a.adapter != nil {
		errs = append(errs, a.adapter.Close())
	}
	if a.lease != nil {
		errs = append(errs, a.lease.Close())
	}
	return errors.Join(errs...)
}

func (m *Manager) finishTerminal(ctx context.Context, record *record, adapter Adapter, prior error) error {
	var errs []error
	if prior != nil {
		errs = append(errs, prior)
	}
	if adapter != nil {
		if err := adapter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%w: %v", ErrCleanup, err))
		}
	}
	if err := m.record(ctx, record, record.state); err != nil {
		errs = append(errs, fmt.Errorf("%w: %v", ErrAudit, err))
	}
	return errors.Join(errs...)
}

func (m *Manager) fail(ctx context.Context, key recordKey, record *record) {
	m.mu.Lock()
	recorded := false
	if m.records[key] == record && record.state == StateActivating {
		record.state = StateActivationFailed
		recorded = true
	}
	m.mu.Unlock()
	if recorded {
		_ = m.record(ctx, record, StateActivationFailed)
	}
}

func (m *Manager) record(ctx context.Context, record *record, state LifecycleState) error {
	return m.auditor.Record(ctx, Transition{ConnectorID: record.connector.ID(), Binding: record.binding, State: state})
}

func keyFor(binding Binding, id ConnectorID) recordKey {
	principal := binding.Principal()
	return recordKey{principalID: principal.ID(), sessionID: principal.SessionID(), connectorID: id}
}

func stateError(state LifecycleState) error {
	switch state {
	case StateExpired:
		return ErrExpired
	case StateRevoked, StateConsumed:
		return ErrRevoked
	default:
		return ErrInactive
	}
}
