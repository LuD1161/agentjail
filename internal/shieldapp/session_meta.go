package shieldapp

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/LuD1161/agentjail/internal/claudesess"
	"github.com/LuD1161/agentjail/internal/mitm"
)

// sessionMeta returns the label fields stamped onto every captured network
// row: the agent binary's name (e.g. "claude") and the directory the shield
// launched it from. Both ride the same every-row pattern as OwnerPID
// (ADR 0100) so the UI can render friendly session names.
func sessionMeta(agentPath string) (agent, cwd string) {
	agent = filepath.Base(agentPath)
	cwd, _ = os.Getwd()
	return agent, cwd
}

// watchClaudeSession resolves which Claude session this shield launch became:
// the agent's session metadata appears a few seconds AFTER launch, so a
// background poll waits for a live claude process descending from this shield
// pid, then (1) flips ref so every subsequent capture row carries the Claude
// session id, and (2) backfills the rows already written. This is the
// unified-session-id bridge (AGE-111): one coding session, one identifier
// across the monitor and network tabs.
func watchClaudeSession(ctx context.Context, store *mitm.RequestStore, networkSessionID string, ref *mitm.ClaudeSessionRef) {
	self := os.Getpid()
	go func() {
		deadline := time.NewTimer(5 * time.Minute)
		defer deadline.Stop()
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-deadline.C:
				return
			case <-tick.C:
				m, ok := claudesess.DescendantOf(claudesess.Load(), self)
				if !ok || m.SessionID == "" {
					continue
				}
				ref.Set(m.SessionID)
				if store != nil {
					_ = store.BackfillClaudeSession(context.Background(), networkSessionID, m.SessionID)
				}
				return
			}
		}
	}()
}
