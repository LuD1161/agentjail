// audit.go — audit helpers for policy mutations.
//
// appendAuditEvent records a policy mutation in the unified audit_log via
// the SQLite store. The flat-file audit.log path is kept as a parameter for
// backward compatibility with callers that resolve it, but no flat file is
// written (legacy flat files are imported into audit_log at migration time).
//
// IMPORTANT: If the write FAILS the caller MUST abort the mutation
// (do not call Save after appendAuditEvent returns an error). This is
// fail-closed on auditability: a weakened guardrail must never be silent.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/store"
)

// appendAuditEvent records one policy-mutation audit event in the unified
// audit_log via the SQLite store. logPath is used only to locate the DB
// (agentjail.db in the same directory); no flat file is written.
//
// Callers MUST check the error and abort the mutation if it is non-nil.
func appendAuditEvent(logPath, action, ruleID string) error {
	st, err := store.Open(filepath.Join(filepath.Dir(logPath), "agentjail.db"))
	if err != nil {
		return fmt.Errorf("audit: open store: %w", err)
	}
	defer st.Close()
	return st.RecordAuditEvent(context.Background(), store.AuditRecord{
		Ts:     time.Now().UTC(),
		Action: action,
		RuleID: ruleID,
		User:   os.Getenv("USER"),
	})
}

// emitPolicyAudit emits a structured audit event via the unified audit emitter
// (Plan 009).
func emitPolicyAudit(emitter audit.Emitter, eventType, entity, actor string, detail map[string]string) error {
	return emitter.Emit(context.Background(), audit.Event{
		EventType: eventType,
		Entity:    entity,
		Actor:     actor,
		Detail:    detail,
	})
}
