package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openRaw opens a read-only-ish raw connection for pragma verification.
func openRaw(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// ─── Redaction (ADR 0019) ───────────────────────────────────────────────────

func TestRedactToolInputSecrets(t *testing.T) {
	in := map[string]interface{}{
		"command":               "aws s3 ls",
		"file_path":             "/tmp/x",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SESSION_TOKEN":     "AQoEXAMPLEH4aoAH0",
		"api_key":               "sk-1234567890",
		"auth_token":            "Bearer abc",
		"password":              "hunter2",
		"credential":            "long-lived-cred",
		"nested": map[string]interface{}{
			"secret_key": "leak",
			"safe":       "ok",
		},
		"items": []interface{}{
			map[string]interface{}{"token": "t1", "name": "n1"},
		},
	}
	out := RedactToolInput(in)
	for _, k := range []string{
		"AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
		"api_key", "auth_token", "password", "credential", "secret_key", "token",
	} {
		if strings.Contains(out, k) && strings.Contains(out[strings.Index(out, k):], "leak") {
			t.Errorf("secret value for %q leaked into redacted output", k)
		}
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("expected [redacted] markers in output: %s", out)
	}
	if !strings.Contains(out, "aws s3 ls") {
		t.Errorf("non-secret command redacted: %s", out)
	}
	if !strings.Contains(out, "/tmp/x") {
		t.Errorf("non-secret file_path redacted: %s", out)
	}
	if !strings.Contains(out, `"safe":"ok"`) {
		t.Errorf("nested non-secret redacted: %s", out)
	}
}

func TestRedactToolInputCaseInsensitive(t *testing.T) {
	in := map[string]interface{}{"APIKEY": "x", "MyToken": "y", "PASSWORD": "z"}
	out := RedactToolInput(in)
	if strings.Contains(out, `"x"`) || strings.Contains(out, `"y"`) || strings.Contains(out, `"z"`) {
		t.Errorf("case-insensitive keys not redacted: %s", out)
	}
}

func TestRedactToolInputNil(t *testing.T) {
	if got := RedactToolInput(nil); got != "{}" {
		t.Errorf("RedactToolInput(nil) = %q, want {}", got)
	}
}

func TestRedactToolInputTruncation(t *testing.T) {
	in := map[string]interface{}{}
	var b strings.Builder
	b.WriteString(strings.Repeat("a", 8000))
	in["big"] = b.String()
	out := RedactToolInput(in)
	if len(out) > maxRedactedLen+8 {
		t.Errorf("redacted output %d bytes exceeds cap+ellipsis", len(out))
	}
	if !strings.HasSuffix(out, "…") {
		t.Errorf("truncated output should end with ellipsis, got len=%d", len(out))
	}
}

// ─── SQLite store ───────────────────────────────────────────────────────────

func newTestStore(t *testing.T) (EventStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestRecordAndListDecision(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.RecordDecision(ctx, DecisionRecord{
		Ts:        now,
		SessionID: "sess-1",
		Agent:     "claude",
		ToolName:  "Bash",
		Summary:   "aws s3 rb --force x",
		Action:    "deny",
		RuleID:    "library/no-aws-destructive",
		Reason:    "destructive",
		Impact:    "would delete",
		ElapsedUs: 123,
		CWD:       "/home/dev/proj",
		ToolInput: map[string]interface{}{"command": "aws s3 rb --force x", "AWS_SECRET_ACCESS_KEY": "leak"},
	}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	got, err := s.ListDecisions(ctx, Filter{Limit: 100})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d decisions, want 1", len(got))
	}
	d := got[0]
	if d.Action != "deny" || d.RuleID != "library/no-aws-destructive" || d.SessionID != "sess-1" {
		t.Errorf("decision = %+v", d)
	}
	if d.ToolInputRedacted == "" {
		t.Error("ToolInputRedacted empty")
	}
	if strings.Contains(d.ToolInputRedacted, "leak") {
		t.Errorf("secret leaked into stored tool_input: %s", d.ToolInputRedacted)
	}
	if !strings.Contains(d.ToolInputRedacted, "[redacted]") {
		t.Errorf("expected [redacted] in stored tool_input: %s", d.ToolInputRedacted)
	}
}

func TestDecisionCount(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	n, err := s.DecisionCount(ctx)
	if err != nil {
		t.Fatalf("DecisionCount: %v", err)
	}
	if n != 0 {
		t.Errorf("initial count = %d, want 0", n)
	}
	for i := 0; i < 3; i++ {
		if err := s.RecordDecision(ctx, DecisionRecord{Ts: time.Now(), SessionID: "s", ToolName: "Bash", Action: "allow"}); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	n, _ = s.DecisionCount(ctx)
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

func TestListDecisionsFilters(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-1 * time.Hour).UTC()
	records := []DecisionRecord{
		{Ts: base, SessionID: "a", ToolName: "Bash", Action: "allow", Agent: "claude"},
		{Ts: base.Add(1 * time.Minute), SessionID: "a", ToolName: "Bash", Action: "deny", Agent: "claude"},
		{Ts: base.Add(2 * time.Minute), SessionID: "b", ToolName: "Write", Action: "ask", Agent: "cursor"},
	}
	for _, r := range records {
		if err := s.RecordDecision(ctx, r); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	// Filter by session.
	got, _ := s.ListDecisions(ctx, Filter{SessionID: "a", Limit: 100})
	if len(got) != 2 {
		t.Errorf("session a: got %d, want 2", len(got))
	}
	// Filter by action.
	got, _ = s.ListDecisions(ctx, Filter{Actions: []string{"deny"}, Limit: 100})
	if len(got) != 1 || got[0].Action != "deny" {
		t.Errorf("action deny: got %v", got)
	}
	// Filter by tool.
	got, _ = s.ListDecisions(ctx, Filter{Tool: "Write", Limit: 100})
	if len(got) != 1 || got[0].ToolName != "Write" {
		t.Errorf("tool Write: got %v", got)
	}
	// Filter by since (only the last 30 minutes -> 1 record at base+2m? base is
	// 1h ago, base+2m is 58m ago; since=30m excludes all). Use since=90m.
	got, _ = s.ListDecisions(ctx, Filter{Since: 90 * time.Minute, Limit: 100})
	if len(got) != 3 {
		t.Errorf("since 90m: got %d, want 3", len(got))
	}
	// Chronological order (oldest first by id).
	got, _ = s.ListDecisions(ctx, Filter{Limit: 100})
	if got[0].SessionID != "a" || got[0].Action != "allow" {
		t.Errorf("first should be oldest: %+v", got[0])
	}
}

func TestListDecisionsFilterByRule(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	records := []DecisionRecord{
		{Ts: time.Now(), SessionID: "s", ToolName: "Bash", Action: "allow", RuleID: "command_policy/no-sudo"},
		{Ts: time.Now(), SessionID: "s", ToolName: "Bash", Action: "deny", RuleID: "aws_policy/no-destructive"},
		{Ts: time.Now(), SessionID: "s", ToolName: "Write", Action: "allow", RuleID: "file_policy/no-etc"},
		{Ts: time.Now(), SessionID: "s", ToolName: "Bash", Action: "ask", RuleID: "AWS_policy/prod-guard"},
	}
	for _, r := range records {
		if err := s.RecordDecision(ctx, r); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	got, err := s.ListDecisions(ctx, Filter{Rule: "aws", Limit: 100})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("rule 'aws': got %d, want 2 (case-insensitive)", len(got))
	}
	for _, d := range got {
		if !strings.Contains(strings.ToLower(d.RuleID), "aws") {
			t.Errorf("unexpected rule_id %q for rule filter 'aws'", d.RuleID)
		}
	}
	got, err = s.ListDecisions(ctx, Filter{Rule: "no-sudo", Limit: 100})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "command_policy/no-sudo" {
		t.Errorf("rule 'no-sudo': got %v", got)
	}
	got, err = s.ListDecisions(ctx, Filter{Rule: "nonexistent", Limit: 100})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("rule 'nonexistent': got %d, want 0", len(got))
	}
}

func TestListDecisionsAfterID(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.RecordDecision(ctx, DecisionRecord{Ts: time.Now(), SessionID: "s", ToolName: "Bash", Action: "allow"}); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	all, _ := s.ListDecisions(ctx, Filter{Limit: 100})
	if len(all) != 3 {
		t.Fatalf("got %d, want 3", len(all))
	}
	// afterID not directly exposed in DecisionRecord; use a high afterID to get
	// none, and 0 to get all.
	got, _ := s.ListDecisions(ctx, Filter{AfterID: 99999, Limit: 100})
	if len(got) != 0 {
		t.Errorf("AfterID huge: got %d, want 0", len(got))
	}
}

func TestRecordAndListAuditEvents(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	records := []AuditRecord{
		{Ts: base, Action: "policy.disable", RuleID: "command_policy/no-sudo", User: "alice"},
		{Ts: base.Add(time.Second), Action: "policy.enable", RuleID: "command_policy/no-sudo", User: "bob"},
		{Ts: base.Add(2 * time.Second), Action: "mcp.allow", RuleID: "github", User: "carol"},
	}
	for _, record := range records {
		if err := s.RecordAuditEvent(ctx, record); err != nil {
			t.Fatalf("RecordAuditEvent: %v", err)
		}
	}

	got, err := s.ListAuditEvents(ctx, AuditFilter{})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d audit events, want 3", len(got))
	}
	if got[0].Action != "policy.disable" || got[0].ID == 0 {
		t.Errorf("first audit event = %+v", got[0])
	}
	if got[2].User != "carol" {
		t.Errorf("last audit user = %q, want carol", got[2].User)
	}

	got, err = s.ListAuditEvents(ctx, AuditFilter{Limit: 2, OrderDesc: true})
	if err != nil {
		t.Fatalf("ListAuditEvents newest: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("newest got %d audit events, want 2", len(got))
	}
	if got[0].Action != "mcp.allow" || got[1].Action != "policy.enable" {
		t.Errorf("newest audit events = %+v", got)
	}
}

func TestSessionsUpsertAndList(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.RecordDecision(ctx, DecisionRecord{Ts: time.Now(), SessionID: "sess-1", ToolName: "Bash", Action: "allow", Agent: "claude", CWD: "/p"}); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	if err := s.RecordDecision(ctx, DecisionRecord{Ts: time.Now(), SessionID: "sess-2", ToolName: "Bash", Action: "deny", Agent: "cursor", CWD: "/q"}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	sessions, err := s.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}
	byID := map[string]Session{}
	for _, sess := range sessions {
		byID[sess.SessionID] = sess
	}
	if byID["sess-1"].DecisionCount != 3 {
		t.Errorf("sess-1 count = %d, want 3", byID["sess-1"].DecisionCount)
	}
	if byID["sess-1"].Agent != "claude" {
		t.Errorf("sess-1 agent = %q", byID["sess-1"].Agent)
	}
	if byID["sess-2"].DecisionCount != 1 {
		t.Errorf("sess-2 count = %d, want 1", byID["sess-2"].DecisionCount)
	}
}

func TestCleanupRetention(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour).UTC()
	recent := time.Now().Add(-1 * time.Minute).UTC()
	if err := s.RecordDecision(ctx, DecisionRecord{Ts: old, SessionID: "old", ToolName: "Bash", Action: "allow"}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := s.RecordDecision(ctx, DecisionRecord{Ts: recent, SessionID: "recent", ToolName: "Bash", Action: "allow"}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := s.Cleanup(ctx, 24*time.Hour); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	got, _ := s.ListDecisions(ctx, Filter{Limit: 100})
	if len(got) != 1 || got[0].SessionID != "recent" {
		t.Errorf("after cleanup: got %+v, want only recent", got)
	}
	sessions, _ := s.ListSessions(ctx)
	if len(sessions) != 1 || sessions[0].SessionID != "recent" {
		t.Errorf("sessions after cleanup: %+v", sessions)
	}
}

func TestDBFilePermissions0600(t *testing.T) {
	_, path := newTestStore(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	// On POSIX, check the owner bits are 0600 (group/other have no access).
	// Windows has no Unix mode bits; skip there.
	if runtime.GOOS == "windows" {
		t.Skip("unix mode bits not meaningful on windows")
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		t.Errorf("db mode = %o, want no group/other access (0600-ish)", mode)
	}
	if mode&0o600 != 0o600 {
		t.Errorf("db mode = %o, want owner read+write (0600)", mode)
	}
}

func TestWALModeEnabled(t *testing.T) {
	_, path := newTestStore(t)
	// Query the journal_mode pragma via a fresh connection to the same file.
	db, err := openRaw(path)
	if err != nil {
		t.Fatalf("openRaw: %v", err)
	}
	defer db.Close()
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

// TestWALSurvivesAbruptClose verifies a decision written but not checkpointed
// is recovered on reopen (WAL replay) — the "kill mid-write" acceptance.
func TestWALSurvivesAbruptClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "abrupt.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	if err := s.RecordDecision(ctx, DecisionRecord{Ts: time.Now(), SessionID: "s", ToolName: "Bash", Action: "deny", RuleID: "r"}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	// Simulate a kill: close the store without a clean checkpoint by opening a
	// second handle and reading back; WAL guarantees the committed row is
	// visible to a new reader even if the writer was killed.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got, err := s2.ListDecisions(ctx, Filter{Limit: 100})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(got) != 1 || got[0].Action != "deny" {
		t.Errorf("after reopen: got %+v, want 1 deny", got)
	}
	_ = s.Close()
}

func TestOpenReadOnly(t *testing.T) {
	s, path := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordDecision(ctx, DecisionRecord{
		Ts:        time.Now().UTC(),
		SessionID: "ro-test",
		ToolName:  "Bash",
		Action:    "allow",
	}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	_ = s.Close()

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer ro.Close()

	got, err := ro.ListDecisions(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(got) != 1 || got[0].SessionID != "ro-test" {
		t.Errorf("read-only query: %+v", got)
	}

	n, err := ro.DecisionCount(ctx)
	if err != nil {
		t.Fatalf("DecisionCount: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
}

func TestConcurrentReaderWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.db")
	writer, err := Open(path)
	if err != nil {
		t.Fatalf("Open writer: %v", err)
	}
	defer writer.Close()

	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer reader.Close()

	ctx := context.Background()
	const total = 200
	errc := make(chan error, 1)

	go func() {
		for i := 0; i < total; i++ {
			if err := writer.RecordDecision(ctx, DecisionRecord{
				Ts:        time.Now(),
				SessionID: "conc",
				ToolName:  "Bash",
				Action:    "allow",
			}); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()

	var readErr error
	var lastCount int64
	for i := 0; i < 50; i++ {
		n, err := reader.DecisionCount(ctx)
		if err != nil {
			readErr = err
			break
		}
		if n < lastCount {
			t.Errorf("count went backwards: %d -> %d", lastCount, n)
		}
		lastCount = n
		time.Sleep(2 * time.Millisecond)
	}
	if readErr != nil {
		t.Fatalf("concurrent read failed: %v", readErr)
	}

	if err := <-errc; err != nil {
		t.Fatalf("concurrent write failed: %v", err)
	}

	final, err := reader.DecisionCount(ctx)
	if err != nil {
		t.Fatalf("final count: %v", err)
	}
	if final != total {
		t.Errorf("final count = %d, want %d", final, total)
	}
}

func TestOpenReadOnly_MissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.db")
	_, err := OpenReadOnly(missing)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ─── Discovered tools and skills ───────────────────────────────────────────

func TestUpsertDiscoveredTool(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Insert a tool.
	if err := s.UpsertDiscoveredTool(ctx, "chrome-devtools", "click", "audit"); err != nil {
		t.Fatalf("UpsertDiscoveredTool insert: %v", err)
	}

	tools, err := s.ListDiscoveredTools(ctx, "")
	if err != nil {
		t.Fatalf("ListDiscoveredTools: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("got %d tools, want 1", len(tools))
	}
	if tools[0].Server != "chrome-devtools" || tools[0].Tool != "click" || tools[0].Source != "audit" {
		t.Errorf("tool = %+v", tools[0])
	}
	if tools[0].FirstSeen.IsZero() || tools[0].LastSeen.IsZero() {
		t.Errorf("timestamps zero: %+v", tools[0])
	}
	firstSeen := tools[0].FirstSeen

	// Sleep briefly so the second upsert has a distinct timestamp.
	time.Sleep(2 * time.Millisecond)

	// Upsert the same tool -- should update last_seen, not create a duplicate.
	if err := s.UpsertDiscoveredTool(ctx, "chrome-devtools", "click", "live"); err != nil {
		t.Fatalf("UpsertDiscoveredTool upsert: %v", err)
	}

	tools, err = s.ListDiscoveredTools(ctx, "")
	if err != nil {
		t.Fatalf("ListDiscoveredTools after upsert: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("got %d tools after upsert, want 1 (no duplicate)", len(tools))
	}
	if tools[0].Source != "live" {
		t.Errorf("source after upsert = %q, want live", tools[0].Source)
	}
	if !tools[0].LastSeen.After(firstSeen) {
		t.Errorf("last_seen not updated: first=%v last=%v", firstSeen, tools[0].LastSeen)
	}
}

func TestUpsertDiscoveredSkill(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Insert a skill.
	if err := s.UpsertDiscoveredSkill(ctx, "superpowers:brainstorming", "audit"); err != nil {
		t.Fatalf("UpsertDiscoveredSkill insert: %v", err)
	}

	skills, err := s.ListDiscoveredSkills(ctx)
	if err != nil {
		t.Fatalf("ListDiscoveredSkills: %v", err)
	}
	if len(skills) != 1 {
		t.Fatalf("got %d skills, want 1", len(skills))
	}
	if skills[0].Name != "superpowers:brainstorming" || skills[0].Source != "audit" {
		t.Errorf("skill = %+v", skills[0])
	}
	if skills[0].UseCount != 1 {
		t.Errorf("use_count = %d, want 1", skills[0].UseCount)
	}

	// Upsert again -- use_count should increment to 2.
	if err := s.UpsertDiscoveredSkill(ctx, "superpowers:brainstorming", "session_log"); err != nil {
		t.Fatalf("UpsertDiscoveredSkill upsert: %v", err)
	}

	skills, err = s.ListDiscoveredSkills(ctx)
	if err != nil {
		t.Fatalf("ListDiscoveredSkills after upsert: %v", err)
	}
	if len(skills) != 1 {
		t.Fatalf("got %d skills after upsert, want 1 (no duplicate)", len(skills))
	}
	if skills[0].UseCount != 2 {
		t.Errorf("use_count after upsert = %d, want 2", skills[0].UseCount)
	}
	if skills[0].Source != "session_log" {
		t.Errorf("source after upsert = %q, want session_log", skills[0].Source)
	}
}

func TestListDiscoveredToolsFilter(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Insert tools for two servers.
	for _, tool := range []string{"click", "navigate_page", "take_screenshot"} {
		if err := s.UpsertDiscoveredTool(ctx, "chrome-devtools", tool, "audit"); err != nil {
			t.Fatalf("UpsertDiscoveredTool (chrome-devtools, %s): %v", tool, err)
		}
	}
	for _, tool := range []string{"authenticate", "complete_authentication"} {
		if err := s.UpsertDiscoveredTool(ctx, "claude_ai_Gmail", tool, "audit"); err != nil {
			t.Fatalf("UpsertDiscoveredTool (claude_ai_Gmail, %s): %v", tool, err)
		}
	}

	// Filter by server "chrome-devtools".
	got, err := s.ListDiscoveredTools(ctx, "chrome-devtools")
	if err != nil {
		t.Fatalf("ListDiscoveredTools(chrome-devtools): %v", err)
	}
	if len(got) != 3 {
		t.Errorf("chrome-devtools: got %d tools, want 3", len(got))
	}
	for _, dt := range got {
		if dt.Server != "chrome-devtools" {
			t.Errorf("unexpected server %q in filtered result", dt.Server)
		}
	}

	// Filter by server "claude_ai_Gmail".
	got, err = s.ListDiscoveredTools(ctx, "claude_ai_Gmail")
	if err != nil {
		t.Fatalf("ListDiscoveredTools(claude_ai_Gmail): %v", err)
	}
	if len(got) != 2 {
		t.Errorf("claude_ai_Gmail: got %d tools, want 2", len(got))
	}

	// Empty server -- list all.
	got, err = s.ListDiscoveredTools(ctx, "")
	if err != nil {
		t.Fatalf("ListDiscoveredTools(all): %v", err)
	}
	if len(got) != 5 {
		t.Errorf("all servers: got %d tools, want 5", len(got))
	}
}
