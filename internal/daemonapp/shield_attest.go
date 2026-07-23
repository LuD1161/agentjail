package daemonapp

import (
	"regexp"
	"sync"
	"time"

	"github.com/LuD1161/agentjail/internal/procutil"
)

// shieldAttestTTL backstops a recycled PID; PID-liveness is the real gate.
const shieldAttestTTL = 24 * time.Hour

// downgradableRules: filesystem-scoped deny rules the OS sandbox already
// enforces. The allowlist and why everything else stays strict: ADR 0111.
var downgradableRules = map[string]bool{
	"command_policy/no-bash-touch-sensitive-path":           true,
	"command_policy/no-rm-rf-absolute":                      true,
	"command_policy/no-recursive-delete-of-protected-paths": true,
	"command_policy/no-find-delete-in-home":                 true,
	"command_policy/no-ssh-keygen-outside-tmp":              true,
}

// shieldAttestTracker records PIDs running agentjail-shield; the eval path
// downgrades a decision only when the agent descends from a live one. Entries
// are pre-authenticated by the ctlToken check at the socket. See ADR 0111.
type shieldAttestTracker struct {
	mu      sync.Mutex
	expires map[int]time.Time
}

func newShieldAttestTracker() *shieldAttestTracker {
	return &shieldAttestTracker{expires: map[int]time.Time{}}
}

// attest records pid as a live shield until now+shieldAttestTTL.
func (t *shieldAttestTracker) attest(pid int, now time.Time) {
	if pid <= 1 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expires[pid] = now.Add(shieldAttestTTL)
}

// isShielded reports whether agentPID descends from a live, unexpired attested
// shield PID. Dead/expired entries are pruned here so a recycled PID cannot
// inherit an old attestation.
func (t *shieldAttestTracker) isShielded(agentPID int, now time.Time) bool {
	if agentPID <= 1 {
		return false
	}
	t.mu.Lock()
	live := make([]int, 0, len(t.expires))
	for pid, exp := range t.expires {
		if now.After(exp) || !procutil.Alive(pid) {
			delete(t.expires, pid)
			continue
		}
		live = append(live, pid)
	}
	t.mu.Unlock()

	for _, shieldPID := range live {
		if _, ok := procutil.FindAncestorPID(agentPID, func(p int) bool { return p == shieldPID }); ok {
			return true
		}
	}
	return false
}

// escalatesPrivilege reports whether cmd invokes a privilege-escalation tool.
// The file sandbox governs the agent's own UID, so an escalating command can
// read root-only files in allow-default dirs (e.g. /etc) that the downgraded
// rule would otherwise have blocked — so such a command is never downgraded.
// See ADR 0111.
func escalatesPrivilege(cmd string) bool {
	return privEscToken.MatchString(cmd)
}

// privEscToken matches sudo/doas/su/run0 as whole command tokens (start, or
// after a shell separator/pipe), so a path like ./sudoku or a --user=sudo flag
// does not trip it.
var privEscToken = regexp.MustCompile(`(^|[\s;&|(])(sudo|doas|run0|su)(\s|$)`)

// maybeDowngrade parks a sandbox-redundant deny in WouldAction and returns
// allow, but only for a shield-attested agent whose command does not escalate
// privilege; other verdicts pass through. See ADR 0111.
func (t *shieldAttestTracker) maybeDowngrade(action, ruleID, cmd string, agentPID int, now time.Time) (newAction, wouldAction string, downgraded bool) {
	if action != "" && action != actionAllow && downgradableRules[ruleID] &&
		!escalatesPrivilege(cmd) && t.isShielded(agentPID, now) {
		return actionAllow, action, true
	}
	return action, "", false
}
