package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
	"github.com/LuD1161/agentjail/internal/ui"
)

func testRows() []store.DecisionRecord {
	base := time.Date(2026, 6, 23, 14, 15, 59, 0, time.UTC)
	return []store.DecisionRecord{
		{ID: 1, Ts: base, SessionID: "s1", Action: "allow", ToolName: "Bash", RuleID: "default-allow", Summary: "ls -la"},
		{ID: 2, Ts: base.Add(3 * time.Second), SessionID: "s1", Action: "allow", ToolName: "Read", RuleID: "default-allow", Summary: "read file.go"},
		{ID: 3, Ts: base.Add(6 * time.Second), SessionID: "s1", Action: "deny", ToolName: "Bash", RuleID: "no-rm-rf", Summary: "rm -rf /", Reason: "matched dangerous-command pattern"},
		{ID: 4, Ts: base.Add(9 * time.Second), SessionID: "s1", Action: "allow", ToolName: "Edit", RuleID: "default-allow", Summary: "edit main.go"},
		{ID: 5, Ts: base.Add(12 * time.Second), SessionID: "s1", Action: "ask", ToolName: "Bash", RuleID: "net-access", Summary: "curl example.com"},
	}
}

func TestFilterRows_EmptyFilter(t *testing.T) {
	rows := testRows()
	got := filterRows(rows, "")
	if len(got) != len(rows) {
		t.Fatalf("expected %d rows, got %d", len(rows), len(got))
	}
}

func TestFilterRows_ExactMatch(t *testing.T) {
	rows := testRows()
	got := filterRows(rows, "deny")
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Action != "deny" {
		t.Fatalf("expected deny, got %s", got[0].Action)
	}
}

func TestFilterRows_CaseInsensitive(t *testing.T) {
	rows := testRows()
	got := filterRows(rows, "DENY")
	if len(got) != 1 {
		t.Fatalf("expected 1 row for case-insensitive match, got %d", len(got))
	}
}

func TestFilterRows_PartialMatch(t *testing.T) {
	rows := testRows()
	got := filterRows(rows, "Bash")
	if len(got) != 3 {
		t.Fatalf("expected 3 Bash rows, got %d", len(got))
	}
}

func TestFilterRows_NoMatch(t *testing.T) {
	rows := testRows()
	got := filterRows(rows, "zzzznotfound")
	if len(got) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(got))
	}
}

func TestComputeStats(t *testing.T) {
	rows := testRows()
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, false, false)
	if m.allowCount != 3 {
		t.Fatalf("expected 3 allow, got %d", m.allowCount)
	}
	if m.denyCount != 1 {
		t.Fatalf("expected 1 deny, got %d", m.denyCount)
	}
	if m.askCount != 1 {
		t.Fatalf("expected 1 ask, got %d", m.askCount)
	}
}

func TestNewReplayModel_LastID(t *testing.T) {
	rows := testRows()
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, false, false)
	if m.lastID != 5 {
		t.Fatalf("expected lastID=5, got %d", m.lastID)
	}
}

func TestNewReplayModel_EmptyRows(t *testing.T) {
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(nil, &mockReadOnlyStore{}, "s1", u, false, false)
	if m.lastID != 0 {
		t.Fatalf("expected lastID=0, got %d", m.lastID)
	}
	if len(m.filtered) != 0 {
		t.Fatalf("expected 0 filtered, got %d", len(m.filtered))
	}
}

func TestRenderDocument_NoExpansion(t *testing.T) {
	rows := testRows()
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, false, false)
	doc := m.renderDocument()
	lines := strings.Split(doc, "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines (no expansion), got %d", len(lines))
	}
}

func TestRenderDocument_WithExpansion(t *testing.T) {
	rows := testRows()
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, false, false)
	m.expandedID = 3 // deny row with reason
	doc := m.renderDocument()
	lines := strings.Split(doc, "\n")
	// 5 rows + reason detail + rule detail = 7 lines
	if len(lines) != 7 {
		t.Fatalf("expected 7 lines with expansion, got %d: %v", len(lines), lines)
	}
}

func TestRenderDocument_VerboseExpansion(t *testing.T) {
	rows := testRows()
	rows[2].ToolInputRedacted = "rm -rf /important" // add redacted input
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, true, false)
	m.expandedID = 3
	doc := m.renderDocument()
	if !strings.Contains(doc, "input: rm -rf /important") {
		t.Fatalf("verbose expansion should show tool input: %q", doc)
	}
}

func TestLineOffsets_CorrectMapping(t *testing.T) {
	rows := testRows()
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, false, false)
	m.renderDocument()
	// No expansion: each row maps to consecutive line numbers
	for i := 0; i < 5; i++ {
		if m.lineOffsets[i] != i {
			t.Fatalf("lineOffsets[%d] = %d, expected %d", i, m.lineOffsets[i], i)
		}
	}
}

func TestLineOffsets_WithExpansion(t *testing.T) {
	rows := testRows()
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, false, false)
	m.expandedID = 3 // deny row at index 2 -- adds 2 detail lines (reason + rule)
	m.renderDocument()
	if m.lineOffsets[0] != 0 {
		t.Fatalf("lineOffsets[0] = %d, expected 0", m.lineOffsets[0])
	}
	if m.lineOffsets[1] != 1 {
		t.Fatalf("lineOffsets[1] = %d, expected 1", m.lineOffsets[1])
	}
	if m.lineOffsets[2] != 2 {
		t.Fatalf("lineOffsets[2] = %d, expected 2 (expanded row)", m.lineOffsets[2])
	}
	// After expanded row (2 detail lines), next row starts at line 5
	if m.lineOffsets[3] != 5 {
		t.Fatalf("lineOffsets[3] = %d, expected 5", m.lineOffsets[3])
	}
}

func TestDuration(t *testing.T) {
	rows := testRows()
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, false, false)
	d := m.duration()
	if d != "12s" {
		t.Fatalf("expected 12s, got %s", d)
	}
}

func TestClampCursor(t *testing.T) {
	rows := testRows()
	var buf bytes.Buffer
	u := ui.NewNoColor(&buf)
	m := newReplayModel(rows, &mockReadOnlyStore{}, "s1", u, false, false)
	m.cursor = 100
	m.clampCursor()
	if m.cursor != 4 {
		t.Fatalf("expected cursor clamped to 4, got %d", m.cursor)
	}
	m.cursor = -5
	m.clampCursor()
	if m.cursor != 0 {
		t.Fatalf("expected cursor clamped to 0, got %d", m.cursor)
	}
}
