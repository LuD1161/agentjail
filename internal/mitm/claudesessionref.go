package mitm

import "sync/atomic"

// ClaudeSessionRef holds the Claude session id the shield resolves a few
// seconds AFTER capture starts (the agent process must exist before its
// session metadata does). The MITM handler, h2 path, and capture gateway all
// read it per-row, so one Set flips every subsequent row to the unified id;
// rows logged before that are covered by RequestStore.BackfillClaudeSession.
type ClaudeSessionRef struct {
	v atomic.Value
}

// Set records the resolved id. Safe to call from the shield's watcher
// goroutine while requests are being logged.
func (r *ClaudeSessionRef) Set(id string) { r.v.Store(id) }

// Get returns the resolved id, or "" while unresolved. Nil-receiver safe so
// handlers without a wired ref (tests) need no guard.
func (r *ClaudeSessionRef) Get() string {
	if r == nil {
		return ""
	}
	s, _ := r.v.Load().(string)
	return s
}
