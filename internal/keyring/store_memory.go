package keyring

import (
	"fmt"
	"sync"
)

// MemoryStore is an in-process Store for tests and CI, where no keychain
// exists. It is NEVER selected by Open() -- a caller must name it, so a
// keychain-less host can never silently degrade to a process-lifetime key.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string][]byte
}

// NewMemoryStore returns an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string][]byte)}
}

func (m *MemoryStore) Name() string { return "memory" }

func (m *MemoryStore) Tier() Tier { return TierMemory }

func (m *MemoryStore) Get(account string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[account]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errNotFound, account)
	}
	return append([]byte(nil), v...), nil
}

func (m *MemoryStore) Set(account string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[account] = append([]byte(nil), secret...)
	return nil
}

// Forget drops an item, letting tests reach ErrUnknownKEK without reaching
// into the map.
func (m *MemoryStore) Forget(account string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, account)
}
