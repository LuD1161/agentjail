package mitm

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/LuD1161/agentjail/internal/audit"
)

func TestOffersH2(t *testing.T) {
	for _, tc := range []struct {
		name   string
		protos []string
		want   bool
	}{
		{"empty", nil, false},
		{"http/1.1 only", []string{"http/1.1"}, false},
		{"h2 first", []string{"h2", "http/1.1"}, true},
		{"h2 second", []string{"http/1.1", "h2"}, true},
		// h2c is cleartext h2 and cannot appear in a TLS ClientHello; treating
		// it as an h2 offer would notice a downgrade that is not happening.
		{"h2c is not h2 over TLS", []string{"h2c"}, false},
		{"h3 is not h2", []string{"h3"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := offersH2(tc.protos); got != tc.want {
				t.Errorf("offersH2(%v) = %v, want %v", tc.protos, got, tc.want)
			}
		})
	}
}

// countingEmitter records events without a store.
type countingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *countingEmitter) Emit(_ context.Context, e audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *countingEmitter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// An agent opens many connections; the downgrade is a property of the session,
// so it is stated once. Per-connection it would be noise, and noise gets
// filtered out and stops being a notice at all. AGE-222.
func TestH2DowngradeNoticeIsOncePerSession(t *testing.T) {
	em := &countingEmitter{}
	h := &MITMHandler{Logger: slog.Default(), Audit: em}

	for i := 0; i < 5; i++ {
		h.noteH2Downgrade("api.example.com", []string{"h2", "http/1.1"})
	}

	if got := em.count(); got != 1 {
		t.Fatalf("emitted %d audit events, want exactly 1 per session", got)
	}

	e := em.events[0]
	if e.EventType != audit.TunnelALPNDowngraded {
		t.Errorf("EventType = %q, want %q", e.EventType, audit.TunnelALPNDowngraded)
	}
	if e.Detail["offered"] != "h2,http/1.1" {
		t.Errorf("Detail[offered] = %q, want the client's ALPN list", e.Detail["offered"])
	}
	if e.Detail["served"] != "http/1.1" {
		t.Errorf("Detail[served] = %q, want http/1.1", e.Detail["served"])
	}
}

// The notice must never be load-bearing: a handler with no emitter still works.
func TestH2DowngradeNoticeSurvivesNilAudit(t *testing.T) {
	h := &MITMHandler{Logger: slog.Default()} // Audit nil
	h.noteH2Downgrade("api.example.com", []string{"h2"})
	// Reaching here without a panic is the assertion.
}

// Concurrent ClientHellos must still yield exactly one notice.
func TestH2DowngradeNoticeIsRaceFree(t *testing.T) {
	em := &countingEmitter{}
	h := &MITMHandler{Logger: slog.Default(), Audit: em}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.noteH2Downgrade("api.example.com", []string{"h2", "http/1.1"})
		}()
	}
	wg.Wait()

	if got := em.count(); got != 1 {
		t.Errorf("emitted %d events under concurrency, want 1", got)
	}
}
