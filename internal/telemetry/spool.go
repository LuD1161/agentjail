package telemetry

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Spool is an append-only JSONL buffer of pending events. It is concurrency-safe
// within a process; cross-process appends rely on POSIX atomic O_APPEND writes.
type Spool struct {
	p         Paths
	maxEvents int
	maxBytes  int
	mu        sync.Mutex
}

func NewSpool(p Paths, maxEvents, maxBytes int) *Spool {
	return &Spool{p: p, maxEvents: maxEvents, maxBytes: maxBytes}
}

// Append writes one event as a JSON line, then enforces the cap (drop-oldest).
func (s *Spool) Append(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.p.Base, 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.p.Spool(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return s.enforceCapLocked()
}

func (s *Spool) enforceCapLocked() error {
	lines, err := s.readLinesLocked()
	if err != nil {
		return err
	}
	total := 0
	for _, l := range lines {
		total += len(l) + 1
	}
	drop := 0
	for (len(lines)-drop) > s.maxEvents || (total > s.maxBytes && len(lines)-drop > 1) {
		total -= len(lines[drop]) + 1
		drop++
	}
	if drop == 0 {
		return nil
	}
	kept := strings.Join(lines[drop:], "\n")
	if kept != "" {
		kept += "\n"
	}
	if err := s.atomicWriteLocked(s.p.Spool(), []byte(kept)); err != nil {
		return err
	}
	return s.bumpDroppedLocked(drop)
}

func (s *Spool) readLinesLocked() ([]string, error) {
	f, err := os.Open(s.p.Spool())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if t := sc.Text(); t != "" {
			out = append(out, t)
		}
	}
	return out, sc.Err()
}

func (s *Spool) atomicWriteLocked(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Spool) bumpDroppedLocked(n int) error {
	cur := 0
	if b, err := os.ReadFile(s.p.Dropped()); err == nil {
		cur, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	return s.atomicWriteLocked(s.p.Dropped(), []byte(strconv.Itoa(cur+n)))
}

// ReadAll returns all spooled events.
func (s *Spool) ReadAll() ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lines, err := s.readLinesLocked()
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, l := range lines {
		var e Event
		if json.Unmarshal([]byte(l), &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// Truncate clears the spool.
func (s *Spool) Truncate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.p.Spool()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DrainDropped returns the dropped-event counter and resets it to zero.
func (s *Spool) DrainDropped() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.p.Dropped())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if rmErr := os.Remove(s.p.Dropped()); rmErr != nil && !os.IsNotExist(rmErr) {
		return n, rmErr
	}
	return n, nil
}
