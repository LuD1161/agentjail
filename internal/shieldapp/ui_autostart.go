package shieldapp

import (
	"context"
	"log/slog"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/localui"
)

const localUIProbeTimeout = 200 * time.Millisecond

func ensureLocalUI(ctx context.Context, emitter audit.Emitter) {
	ensureLocalUIWith(ctx, emitter,
		func() bool { return localui.Reachable(localui.DefaultAddr, localUIProbeTimeout) },
		startDetachedLocalUI,
	)
}

func ensureLocalUIWith(ctx context.Context, emitter audit.Emitter, reachable func() bool, start func() error) {
	if reachable() {
		return
	}
	if err := start(); err != nil {
		slog.Warn("local UI auto-start failed", "err", err)
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.LocalUIStartFailed,
			Entity:    "web_ui",
			Detail:    map[string]string{"addr": localui.DefaultAddr, "reason": "start_failed"},
			Actor:     "shield",
		})
		return
	}
	slog.Info("local UI auto-started", "url", localui.DefaultURL)
	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.LocalUIStarted,
		Entity:    "web_ui",
		Detail:    map[string]string{"addr": localui.DefaultAddr},
		Actor:     "shield",
	})
}
