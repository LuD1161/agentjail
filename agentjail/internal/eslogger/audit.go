package eslogger

import (
	"fmt"
	"strings"
	"time"
)

// AuditKind is the kind identifier for an audit event emitted by this package.
type AuditKind string

const (
	// KindTamperDetected is emitted when the reconcile job finds an ES exec
	// event that was not observed by any agentjail capture surface (PATH
	// shim, runtime hook). It is the primary tamper-evidence signal: the
	// kernel saw an exec that our user-space instrumentation did not.
	KindTamperDetected AuditKind = "tamper.detected"
)

// AuditEvent is a structured audit record produced from a tamper-evidence
// finding. It carries the minimum fields needed to render a tail line and
// to ingest the event into a downstream audit store.
//
// Wire shape is additive: new fields may be added; existing fields are never
// renamed or removed (see docs/ENGINEERING.md §6 "Wire shapes are frozen and
// additively evolved").
type AuditEvent struct {
	Kind      AuditKind `json:"kind"`
	Timestamp time.Time `json:"timestamp"`

	// ExecPath is the absolute path of the executable that ES observed but
	// agentjail did not.
	ExecPath string   `json:"exec_path"`
	PID      int      `json:"pid"`
	PPID     int      `json:"ppid"`
	Argv     []string `json:"argv,omitempty"`

	// DeltaKind is the underlying diff kind ("es_only", "aw_only", "mismatch").
	// Today only "es_only" is emitted; future variants pass through without
	// code changes to TamperDetectedFromFinding.
	DeltaKind string `json:"delta_kind"`

	// Reason is the human-readable explanation produced by the diff engine.
	Reason string `json:"reason"`
}

// TamperDetectedFromFinding converts a retained reconcile Finding into an
// AuditEvent with Kind = KindTamperDetected. The ObservedAt timestamp on the
// Finding (when the reconcile job ran and retained the delta) becomes the
// AuditEvent's Timestamp, which is the earliest time at which agentjail can
// assert "this exec was missed".
func TamperDetectedFromFinding(f Finding) AuditEvent {
	return AuditEvent{
		Kind:      KindTamperDetected,
		Timestamp: f.ObservedAt,
		ExecPath:  f.Delta.ExecPath,
		PID:       f.Delta.PID,
		PPID:      f.Delta.PPID,
		Argv:      f.Delta.Argv,
		DeltaKind: f.Delta.Kind,
		Reason:    f.Delta.Reason,
	}
}

// FormatTail formats an AuditEvent as a single terminal output line for
// `agentjail tail`. The line uses the [TAMPER] glyph as a distinct visual
// marker so the event stands out in a mixed audit stream.
//
// Output format:
//
//	<RFC3339> [TAMPER] <exec_path> pid=<pid> ppid=<ppid> argv=[…] reason=<reason>
//
// The [TAMPER] glyph is ASCII-safe and grep-friendly. Callers can pipe
// `agentjail tail | grep TAMPER` to isolate tamper events without needing
// terminal color support.
func FormatTail(e AuditEvent) string {
	ts := e.Timestamp.UTC().Format(time.RFC3339)
	argv := ""
	if len(e.Argv) > 0 {
		argv = fmt.Sprintf(" argv=[%s]", strings.Join(e.Argv, " "))
	}
	return fmt.Sprintf("%s [TAMPER] %s pid=%d ppid=%d%s reason=%s",
		ts, e.ExecPath, e.PID, e.PPID, argv, e.Reason)
}
