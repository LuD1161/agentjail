// audit.go — append-only audit log for policy mutations.
//
// appendAuditEvent writes a structured JSON line to path (typically
// ~/.agentjail/audit.log). The file is opened with O_APPEND|O_CREATE|O_WRONLY
// at 0600 so same-user processes can append but cannot unilaterally truncate.
//
// IMPORTANT: If the append write FAILS the caller MUST abort the mutation
// (do not call Save after appendAuditEvent returns an error). This is
// fail-closed on auditability: a weakened guardrail must never be silent.
//
// This is best-effort provenance, NOT tamper resistance. A same-user
// process can still rewrite the file; real tamper-proofing (daemon-owned
// append API or platform immutable flag) is future work and is not claimed
// here.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
)

// auditEvent is the structured record written to audit.log.
type auditEvent struct {
	Time   string `json:"time"`   // RFC3339
	Action string `json:"action"` // "disable" | "enable"
	RuleID string `json:"rule_id"`
	PID    int    `json:"pid"`
	PPID   int    `json:"ppid"`
	CWD    string `json:"cwd"`
}

// appendAuditEvent appends one JSON audit line to logPath.
// It returns an error if:
//   - the file cannot be opened for appending
//   - the JSON encoding fails
//   - the write to the file fails
//
// Callers MUST check the error and abort the mutation if it is non-nil.
func appendAuditEvent(logPath, action, ruleID string) error {
	cwd, _ := os.Getwd() // best-effort; empty string on error

	ev := auditEvent{
		Time:   time.Now().UTC().Format(time.RFC3339),
		Action: action,
		RuleID: ruleID,
		PID:    os.Getpid(),
		PPID:   os.Getppid(),
		CWD:    cwd,
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}
	line = append(line, '\n')

	// O_APPEND ensures concurrent writes from separate processes do not
	// interleave within a single line (POSIX atomic-append guarantee for
	// writes ≤ PIPE_BUF).
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", logPath, err)
	}
	defer f.Close()

	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("audit: write to %s: %w", logPath, err)
	}
	if st, err := store.Open(filepath.Join(filepath.Dir(logPath), "agentjail.db")); err == nil {
		defer st.Close()
		_ = st.RecordAuditEvent(context.Background(), store.AuditRecord{
			Ts:     time.Now().UTC(),
			Action: action,
			RuleID: ruleID,
			User:   os.Getenv("USER"),
		})
	}
	return nil
}
