// Package approvalexec owns one-use Codex approval challenges.
package approvalexec

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type ChallengeID string
type SessionID string
type TurnID string
type ToolUseID string
type Command string
type State string
type Operation string

const (
	GitPushOperation      Operation = "git-push"
	ShellCommandOperation Operation = "shell-command"
	HostProxyOperation    Operation = "host-proxy"

	StatePending         State = "pending"
	StatePromptObserved  State = "prompt_observed"
	DefaultPendingTTL          = 30 * time.Second
	DefaultObservedTTL         = 5 * time.Minute
	maxChallenges              = 1024
	maxSessionChallenges       = 16
)

var (
	ErrNotFound       = errors.New("approval challenge not found")
	ErrInvalidState   = errors.New("approval challenge is not redeemable")
	ErrExpired        = errors.New("approval challenge expired")
	ErrBinding        = errors.New("approval challenge binding mismatch")
	ErrStaleExecution = errors.New("approval challenge execution is stale")
	ErrCapacity       = errors.New("approval challenge capacity reached")
	ErrCollision      = errors.New("approval challenge identifier collision")
)

type MintRequest struct {
	SessionID SessionID
	TurnID    TurnID
	ToolUseID ToolUseID
	Operation Operation
	Command   Command
	CWD       string
	AgentPID  int
	RuleID    string
	Now       time.Time
}

type ObserveRequest struct {
	ChallengeID ChallengeID
	Operation   Operation
	SessionID   SessionID
	TurnID      TurnID
	CWD         string
	FreshAfter  uint64
	Now         time.Time
}

type Metadata struct {
	ChallengeID ChallengeID
	Operation   Operation
	SessionID   SessionID
	TurnID      TurnID
	ToolUseID   ToolUseID
	CWD         string
	AgentPID    int
	RuleID      string
	State       State
	FreshAfter  uint64
}

type RedeemRequest struct {
	ChallengeID     ChallengeID
	Operation       Operation
	VerifiedSession SessionID
	PeerChainFresh  bool
	CurrentEpoch    uint64
	Now             time.Time
}

type Redemption struct {
	Operation Operation
	Command   Command
	CWD       string
	ToolUseID ToolUseID
	SessionID SessionID
	RuleID    string
}

// BrokerInvocation is the exact, static command shape Codex's managed rule
// may prompt for. It never includes the original shell command.
type BrokerInvocation struct {
	Operation   Operation
	ChallengeID ChallengeID
}

func validOperation(operation Operation) bool {
	switch operation {
	case GitPushOperation, ShellCommandOperation, HostProxyOperation:
		return true
	default:
		return false
	}
}

// ValidOperation reports whether operation has an exact broker command shape.
func ValidOperation(operation Operation) bool {
	return validOperation(operation)
}

type challenge struct {
	Metadata
	command   Command
	epoch     uint64
	expiresAt time.Time
}

type Manager struct {
	mu          sync.Mutex
	random      io.Reader
	pendingTTL  time.Duration
	observedTTL time.Duration
	challenges  map[ChallengeID]*challenge
	epochs      map[SessionID]uint64
}

func NewManager(random io.Reader, pendingTTL, observedTTL time.Duration) *Manager {
	if random == nil {
		random = rand.Reader
	}
	if pendingTTL <= 0 {
		pendingTTL = DefaultPendingTTL
	}
	if observedTTL <= 0 {
		observedTTL = DefaultObservedTTL
	}
	return &Manager{
		random:      random,
		pendingTTL:  pendingTTL,
		observedTTL: observedTTL,
		challenges:  make(map[ChallengeID]*challenge),
		epochs:      make(map[SessionID]uint64),
	}
}

// BeginToolCall advances the session epoch. A rewritten broker invocation does
// not trigger a second PreToolUse; every later tool call invalidates it.
func (m *Manager) BeginToolCall(sessionID SessionID) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epochs[sessionID]++
	return m.epochs[sessionID]
}

func (m *Manager) CurrentEpoch(sessionID SessionID) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epochs[sessionID]
}

func (m *Manager) Mint(req MintRequest) (Metadata, error) {
	if req.SessionID == "" || req.TurnID == "" || req.ToolUseID == "" ||
		!validOperation(req.Operation) ||
		req.Command == "" || req.CWD == "" || req.AgentPID <= 0 {
		return Metadata{}, fmt.Errorf("mint approval challenge: %w", ErrBinding)
	}
	var raw [32]byte
	if _, err := io.ReadFull(m.random, raw[:]); err != nil {
		return Metadata{}, fmt.Errorf("mint approval challenge: random: %w", err)
	}
	id := ChallengeID(base64.RawURLEncoding.EncodeToString(raw[:]))

	m.mu.Lock()
	defer m.mu.Unlock()
	m.reapLocked(req.Now)
	if len(m.challenges) >= maxChallenges {
		return Metadata{}, ErrCapacity
	}
	sessionCount := 0
	for _, existing := range m.challenges {
		if existing.SessionID == req.SessionID {
			sessionCount++
		}
	}
	if sessionCount >= maxSessionChallenges {
		return Metadata{}, ErrCapacity
	}
	if _, exists := m.challenges[id]; exists {
		return Metadata{}, ErrCollision
	}
	meta := Metadata{
		ChallengeID: id,
		Operation:   req.Operation,
		SessionID:   req.SessionID,
		TurnID:      req.TurnID,
		ToolUseID:   req.ToolUseID,
		CWD:         req.CWD,
		AgentPID:    req.AgentPID,
		RuleID:      req.RuleID,
		State:       StatePending,
	}
	m.challenges[id] = &challenge{
		Metadata:  meta,
		command:   req.Command,
		epoch:     m.epochs[req.SessionID],
		expiresAt: req.Now.Add(m.pendingTTL),
	}
	return meta, nil
}

func (m *Manager) reapLocked(now time.Time) {
	for id, ch := range m.challenges {
		if !now.Before(ch.expiresAt) {
			delete(m.challenges, id)
		}
	}
}

func (m *Manager) ObservePrompt(req ObserveRequest) (Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.challenges[req.ChallengeID]
	if !ok {
		return Metadata{}, ErrNotFound
	}
	if !req.Now.Before(ch.expiresAt) {
		delete(m.challenges, req.ChallengeID)
		return Metadata{}, ErrExpired
	}
	if ch.State != StatePending {
		return Metadata{}, ErrInvalidState
	}
	if ch.Operation != req.Operation || ch.SessionID != req.SessionID || ch.TurnID != req.TurnID ||
		ch.CWD != req.CWD || req.FreshAfter == 0 {
		delete(m.challenges, req.ChallengeID)
		return Metadata{}, ErrBinding
	}
	ch.State = StatePromptObserved
	ch.FreshAfter = req.FreshAfter
	ch.expiresAt = req.Now.Add(m.observedTTL)
	return ch.Metadata, nil
}

func (m *Manager) Inspect(id ChallengeID, now time.Time) (Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.challenges[id]
	if !ok {
		return Metadata{}, ErrNotFound
	}
	if !now.Before(ch.expiresAt) {
		delete(m.challenges, id)
		return Metadata{}, ErrExpired
	}
	return ch.Metadata, nil
}

// Burn invalidates a challenge without executing it. Adapter cancellation and
// malformed generic evidence must never leave a native prompt redeemable.
func (m *Manager) Burn(id ChallengeID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.challenges, id)
}

// Redeem burns the challenge on every attempt. A failed or disconnected broker
// can never retry with the same authorization.
func (m *Manager) Redeem(req RedeemRequest) (Redemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.challenges[req.ChallengeID]
	if !ok {
		return Redemption{}, ErrNotFound
	}
	delete(m.challenges, req.ChallengeID)
	if !req.Now.Before(ch.expiresAt) {
		return Redemption{}, ErrExpired
	}
	if ch.State != StatePromptObserved {
		return Redemption{}, ErrInvalidState
	}
	if ch.Operation != req.Operation || ch.SessionID != req.VerifiedSession || ch.epoch != req.CurrentEpoch {
		return Redemption{}, ErrBinding
	}
	if !req.PeerChainFresh {
		return Redemption{}, ErrStaleExecution
	}
	return Redemption{
		Operation: ch.Operation, Command: ch.command, CWD: ch.CWD, ToolUseID: ch.ToolUseID,
		SessionID: ch.SessionID, RuleID: ch.RuleID,
	}, nil
}

func BrokerCommand(invocation BrokerInvocation) string {
	return "agentjail approval-exec --operation " + string(invocation.Operation) + " --challenge " + string(invocation.ChallengeID)
}

func ParseBrokerCommand(command string) (BrokerInvocation, bool) {
	fields := strings.Fields(command)
	if len(fields) != 6 || fields[0] != "agentjail" || fields[1] != "approval-exec" ||
		fields[2] != "--operation" || !validOperation(Operation(fields[3])) ||
		fields[4] != "--challenge" || !challengePattern.MatchString(fields[5]) {
		return BrokerInvocation{}, false
	}
	return BrokerInvocation{Operation: Operation(fields[3]), ChallengeID: ChallengeID(fields[5])}, true
}
