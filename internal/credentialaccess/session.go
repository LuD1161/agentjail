package credentialaccess

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

const DefaultSessionTTL = 12 * time.Hour

type sessionEntry struct {
	Session   Session
	ExpiresAt time.Time
}

// Sessions tracks narrow agent-facing broker capabilities in memory.
type Sessions struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]sessionEntry
	now     func() time.Time
}

func NewSessions() *Sessions {
	return &Sessions{entries: make(map[[sha256.Size]byte]sessionEntry), now: time.Now}
}

func (s *Sessions) Register(session Session, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 || ttl > DefaultSessionTTL {
		ttl = DefaultSessionTTL
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	expires := s.now().Add(ttl)
	s.mu.Lock()
	s.entries[sha256.Sum256([]byte(token))] = sessionEntry{Session: session, ExpiresAt: expires}
	s.mu.Unlock()
	return token, expires, nil
}

func (s *Sessions) Lookup(token string) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return Session{}, false
	}
	if !entry.ExpiresAt.After(s.now()) {
		delete(s.entries, key)
		return Session{}, false
	}
	return entry.Session, true
}

func (s *Sessions) Remove(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.entries, sha256.Sum256([]byte(token)))
	s.mu.Unlock()
}
