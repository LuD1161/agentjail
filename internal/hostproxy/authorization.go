package hostproxy

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrAuthorization = errors.New("host proxy authorization unavailable or invalid")
	ErrReplay        = errors.New("host proxy authorization already used")
)

type Authorization struct {
	Proof      Proof
	SessionID  SessionID
	Target     Target
	CWD        string
	Root       string
	Path       string
	BrokerPID  int
	FreshAfter uint64
	ExpiresAt  time.Time
}

type RedeemRequest struct {
	Proof          Proof
	SessionID      SessionID
	Target         Target
	CWD            string
	PeerPID        int
	PeerChainFresh bool
	CurrentTime    time.Time
}

type Manager struct {
	mu      sync.Mutex
	random  io.Reader
	ttl     time.Duration
	records map[Proof]Authorization
}

func NewManager(random io.Reader, ttl time.Duration) *Manager {
	if random == nil {
		random = rand.Reader
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Manager{random: random, ttl: ttl, records: make(map[Proof]Authorization)}
}

func (m *Manager) Issue(auth Authorization, now time.Time) (Authorization, error) {
	if auth.SessionID == "" || auth.Target.Executable == "" || len(auth.Target.Argv) == 0 ||
		auth.CWD == "" || auth.Root == "" || auth.Path == "" || auth.BrokerPID <= 1 || auth.FreshAfter == 0 {
		return Authorization{}, ErrAuthorization
	}
	var raw [32]byte
	if _, err := io.ReadFull(m.random, raw[:]); err != nil {
		return Authorization{}, err
	}
	auth.Target.Argv = append([]string(nil), auth.Target.Argv...)
	auth.Proof = Proof(base64.RawURLEncoding.EncodeToString(raw[:]))
	auth.ExpiresAt = now.Add(m.ttl)
	m.mu.Lock()
	defer m.mu.Unlock()
	for proof, existing := range m.records {
		if !now.Before(existing.ExpiresAt) {
			delete(m.records, proof)
		}
	}
	if _, exists := m.records[auth.Proof]; exists {
		return Authorization{}, ErrAuthorization
	}
	m.records[auth.Proof] = auth
	return auth, nil
}

func (m *Manager) Redeem(req RedeemRequest) (Authorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	auth, ok := m.records[req.Proof]
	if !ok {
		return Authorization{}, ErrReplay
	}
	delete(m.records, req.Proof)
	if !req.CurrentTime.Before(auth.ExpiresAt) || auth.SessionID != req.SessionID ||
		auth.CWD != req.CWD || auth.BrokerPID != req.PeerPID || !req.PeerChainFresh ||
		auth.Target.Executable != req.Target.Executable || !equalStrings(auth.Target.Argv, req.Target.Argv) {
		return Authorization{}, ErrAuthorization
	}
	auth.Target.Argv = append([]string(nil), auth.Target.Argv...)
	return auth, nil
}

func (m *Manager) Inspect(proof Proof, now time.Time) (Authorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	auth, ok := m.records[proof]
	if !ok || !now.Before(auth.ExpiresAt) {
		return Authorization{}, ErrAuthorization
	}
	auth.Target.Argv = append([]string(nil), auth.Target.Argv...)
	return auth, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
