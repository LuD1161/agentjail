package shieldapp

import (
	"context"
	"errors"
	"testing"

	"github.com/LuD1161/agentjail/internal/audit"
)

func TestEnsureLocalUI(t *testing.T) {
	tests := []struct {
		name      string
		reachable bool
		startErr  error
		wantStart bool
		wantEvent string
	}{
		{name: "already running", reachable: true},
		{name: "starts", wantStart: true, wantEvent: audit.LocalUIStarted},
		{name: "start fails", startErr: errors.New("boom"), wantStart: true, wantEvent: audit.LocalUIStartFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := &recordingEmitter{}
			started := false
			ensureLocalUIWith(context.Background(), emitter,
				func() bool { return tt.reachable },
				func() error { started = true; return tt.startErr },
			)
			if started != tt.wantStart {
				t.Fatalf("started = %v, want %v", started, tt.wantStart)
			}
			if tt.wantEvent == "" {
				if len(emitter.events) != 0 {
					t.Fatalf("events = %v, want none", emitter.events)
				}
				return
			}
			if len(emitter.events) != 1 || emitter.events[0].EventType != tt.wantEvent {
				t.Fatalf("events = %v, want %s", emitter.events, tt.wantEvent)
			}
		})
	}
}
