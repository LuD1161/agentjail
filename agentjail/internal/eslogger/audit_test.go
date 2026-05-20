package eslogger

import (
	"strings"
	"testing"
	"time"
)

// TestKindTamperDetectedDefined verifies that the KindTamperDetected constant
// has the correct string value and that AuditKind is a distinct type.
func TestKindTamperDetectedDefined(t *testing.T) {
	const want = "tamper.detected"
	if string(KindTamperDetected) != want {
		t.Fatalf("KindTamperDetected = %q; want %q", KindTamperDetected, want)
	}
}

// TestTamperDetectedFromFinding verifies that a Finding is correctly mapped
// to an AuditEvent with Kind = KindTamperDetected and all fields projected.
func TestTamperDetectedFromFinding(t *testing.T) {
	observedAt := time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC)
	f := Finding{
		ObservedAt: observedAt,
		Delta: Delta{
			Kind:     "es_only",
			Time:     time.Date(2026, 5, 23, 16, 40, 0, 0, time.UTC),
			PID:      42,
			PPID:     7,
			ExecPath: "/bin/sh",
			Argv:     []string{"/bin/sh", "-c", "id"},
			Reason:   "endpoint security observed exec; agentjail capture did not",
		},
	}

	ev := TamperDetectedFromFinding(f)

	if ev.Kind != KindTamperDetected {
		t.Errorf("Kind = %q; want %q", ev.Kind, KindTamperDetected)
	}
	if !ev.Timestamp.Equal(observedAt) {
		t.Errorf("Timestamp = %v; want %v", ev.Timestamp, observedAt)
	}
	if ev.ExecPath != "/bin/sh" {
		t.Errorf("ExecPath = %q; want /bin/sh", ev.ExecPath)
	}
	if ev.PID != 42 {
		t.Errorf("PID = %d; want 42", ev.PID)
	}
	if ev.PPID != 7 {
		t.Errorf("PPID = %d; want 7", ev.PPID)
	}
	if len(ev.Argv) != 3 || ev.Argv[0] != "/bin/sh" {
		t.Errorf("Argv = %v; want [/bin/sh -c id]", ev.Argv)
	}
	if ev.DeltaKind != "es_only" {
		t.Errorf("DeltaKind = %q; want es_only", ev.DeltaKind)
	}
	if ev.Reason == "" {
		t.Errorf("Reason must not be empty")
	}
}

// TestFormatTailGlyph verifies that FormatTail includes the [TAMPER] glyph
// and renders the key fields.
func TestFormatTailGlyph(t *testing.T) {
	ev := AuditEvent{
		Kind:      KindTamperDetected,
		Timestamp: time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC),
		ExecPath:  "/bin/sh",
		PID:       42,
		PPID:      7,
		Argv:      []string{"/bin/sh", "-c", "id"},
		DeltaKind: "es_only",
		Reason:    "endpoint security observed exec; agentjail capture did not",
	}

	line := FormatTail(ev)

	if !strings.Contains(line, "[TAMPER]") {
		t.Errorf("FormatTail output missing [TAMPER] glyph: %q", line)
	}
	if !strings.Contains(line, "/bin/sh") {
		t.Errorf("FormatTail output missing exec_path: %q", line)
	}
	if !strings.Contains(line, "pid=42") {
		t.Errorf("FormatTail output missing pid: %q", line)
	}
	if !strings.Contains(line, "ppid=7") {
		t.Errorf("FormatTail output missing ppid: %q", line)
	}
	if !strings.Contains(line, "2026-05-23T16:41:00Z") {
		t.Errorf("FormatTail output missing timestamp: %q", line)
	}
}

// TestFormatTailNoArgv verifies that FormatTail omits the argv field when
// there are no arguments (empty slice).
func TestFormatTailNoArgv(t *testing.T) {
	ev := AuditEvent{
		Kind:      KindTamperDetected,
		Timestamp: time.Date(2026, 5, 23, 16, 41, 0, 0, time.UTC),
		ExecPath:  "/bin/true",
		PID:       1,
		PPID:      0,
		Argv:      nil,
		DeltaKind: "es_only",
		Reason:    "endpoint security observed exec; agentjail capture did not",
	}

	line := FormatTail(ev)

	if !strings.Contains(line, "[TAMPER]") {
		t.Errorf("FormatTail output missing [TAMPER] glyph: %q", line)
	}
	if strings.Contains(line, "argv=") {
		t.Errorf("FormatTail should not emit argv= when argv is empty: %q", line)
	}
}
