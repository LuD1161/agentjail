package daemonapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/store"
)

func TestLocalActivityProjectionIsBoundedRedactedAndSessionExact(t *testing.T) {
	root := t.TempDir()
	eventStore, err := store.Open(filepath.Join(root, "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer eventStore.Close()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, row := range []store.DecisionRecord{
		{Ts: now, SessionID: "session-1", Agent: "codex", CWD: "/Users/private/secret-project", ToolName: "Bash", Summary: "git status", ToolInput: map[string]interface{}{"command": "curl -H 'Authorization: Bearer sk-proj-abc123def456ghi789' https://api.example.com"}, Action: "allow", RuleID: "command_policy/default-allow"},
		{Ts: now, SessionID: "session-10", Agent: "codex", CWD: "/Users/private/other", ToolName: "Read", Summary: "unrelated", Action: "allow"},
	} {
		if err := eventStore.RecordDecision(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}
	networkPath := filepath.Join(root, "network.db")
	networkStore, err := mitm.NewRequestStore(networkPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := networkStore.Log(&mitm.RequestLog{
		Ts: now, Host: "api.example.com", Method: "GET", Path: "/v1/items?token=secret-value",
		URL: "https://api.example.com/v1/items?token=secret-value", StatusCode: 200,
		SessionID: "capture-1", ClaudeSessionID: "session-1", Agent: "codex",
		Cwd: "/Users/private/secret-project", PolicyAction: "allow",
	}); err != nil {
		t.Fatal(err)
	}
	if err := networkStore.Close(); err != nil {
		t.Fatal(err)
	}

	projector := &localActivityProjector{
		store:   eventStore,
		network: &lazyNetworkReader{path: networkPath},
	}
	defer projector.Close()

	network, err := projector.NetworkSnapshot(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !network.Available || len(network.Events) != 1 {
		t.Fatalf("network snapshot = %+v", network)
	}
	event := network.Events[0]
	if event.Path != "/v1/items" || event.SessionID != "session-1" || event.Project != "secret-project" {
		t.Fatalf("network event = %+v", event)
	}
	if event.Path == "/v1/items?token=secret-value" {
		t.Fatal("query credential reached network projection")
	}

	logs, err := projector.SessionLogSnapshot(context.Background(), grantctl.SessionLogQueryV1{SessionID: "session-1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if logs.SelectedSessionID != "session-1" || len(logs.Entries) != 1 || logs.Entries[0].Summary != "git status" {
		t.Fatalf("session log = %+v", logs)
	}
	detail, err := projector.SessionActionDetail(context.Background(), "session-1", logs.Entries[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail.Command, "sk-proj-abc123def456ghi789") || !strings.Contains(detail.Command, "api.example.com") {
		t.Fatalf("session command was not safely projected: %q", detail.Command)
	}
	if _, err := projector.SessionActionDetail(context.Background(), "session-10", logs.Entries[0].ID); !errors.Is(err, errActivityActionNotFound) {
		t.Fatalf("cross-session action detail error = %v", err)
	}
	if len(logs.Sessions) != 2 || logs.Sessions[0].Project == "/Users/private/secret-project" {
		t.Fatalf("session projection exposed full path: %+v", logs.Sessions)
	}
}

func TestActivityResponsesRequireSupportedVersions(t *testing.T) {
	now := time.Now()
	if response := networkSnapshotResponse(nil, 0, now); response.OK || response.Error != "network_snapshot requires protocol_version" {
		t.Fatalf("missing network version response = %+v", response)
	}
	if response := sessionLogSnapshotResponse(nil, grantctl.SessionLogProtocolVersion+1, grantctl.SessionLogQueryV1{}, now); response.OK {
		t.Fatalf("unsupported log version response = %+v", response)
	}
	if response := sessionLogSnapshotResponse(nil, grantctl.SessionLogProtocolVersion, grantctl.SessionLogQueryV1{SessionID: string(make([]byte, grantctl.MaxDashboardSessionIDBytes+1))}, now); response.OK || response.Error != "invalid session log query" {
		t.Fatalf("oversized session response = %+v", response)
	}
	for _, query := range []grantctl.SessionLogQueryV1{
		{BeforeID: -1},
		{Search: string(make([]byte, grantctl.MaxSessionSearchBytes+1))},
		{Actions: []string{"permit"}},
		{Actions: []string{"deny", "deny"}},
	} {
		if response := sessionLogSnapshotResponse(nil, grantctl.SessionLogProtocolVersion, query, now); response.OK || response.Error != "invalid session log query" {
			t.Fatalf("invalid query response = %+v", response)
		}
	}
	if response := sessionActionDetailResponse(nil, grantctl.SessionActionDetailProtocolVersion, "session-1", 0); response.OK || response.Error != "invalid session action detail selector" {
		t.Fatalf("invalid action detail response = %+v", response)
	}
}

func TestSessionLogProjectionPagesAndSearchesWholeSession(t *testing.T) {
	eventStore, err := store.Open(filepath.Join(t.TempDir(), "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer eventStore.Close()
	for index := 0; index < 520; index++ {
		summary := fmt.Sprintf("action-%03d", index)
		if index == 0 {
			summary = "oldest corpus needle"
		}
		if err := eventStore.RecordDecision(context.Background(), store.DecisionRecord{
			Ts: time.Now().Add(time.Duration(index) * time.Millisecond), SessionID: "paged-session",
			Agent: "codex", CWD: "/tmp/project", ToolName: "Bash", Summary: summary,
			Action: "allow", RuleID: "command_policy/default-allow",
		}); err != nil {
			t.Fatal(err)
		}
	}
	projector := &localActivityProjector{store: eventStore}
	first, err := projector.SessionLogSnapshot(context.Background(), grantctl.SessionLogQueryV1{SessionID: "paged-session"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.TotalMatches != 520 || !first.HasMore || first.NextBeforeID == 0 || len(first.Entries) == 0 {
		t.Fatalf("first page metadata = %+v", first)
	}
	second, err := projector.SessionLogSnapshot(context.Background(), grantctl.SessionLogQueryV1{
		SessionID: "paged-session", BeforeID: first.NextBeforeID,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Entries) == 0 || second.Entries[0].ID >= first.NextBeforeID {
		t.Fatalf("second page did not advance cursor: first=%d second=%+v", first.NextBeforeID, second.Entries)
	}
	searched, err := projector.SessionLogSnapshot(context.Background(), grantctl.SessionLogQueryV1{
		SessionID: "paged-session", Search: "corpus needle",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if searched.TotalMatches != 1 || len(searched.Entries) != 1 || searched.Entries[0].Summary != "oldest corpus needle" || searched.HasMore {
		t.Fatalf("whole-session search = %+v", searched)
	}
}

func TestSessionLogProjectionStopsBeforeControlFrameLimit(t *testing.T) {
	eventStore, err := store.Open(filepath.Join(t.TempDir(), "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer eventStore.Close()
	for index := 0; index < 200; index++ {
		if err := eventStore.RecordDecision(context.Background(), store.DecisionRecord{
			Ts: time.Now(), SessionID: "large-session", Agent: "codex", CWD: "/tmp/project",
			ToolName: "Bash", Summary: strings.Repeat("s", grantctl.MaxActivityTextBytes),
			Action: "allow", RuleID: strings.Repeat("r", grantctl.MaxActivityTextBytes),
			Reason: strings.Repeat("x", grantctl.MaxActivityTextBytes),
		}); err != nil {
			t.Fatal(err)
		}
	}
	projector := &localActivityProjector{store: eventStore}
	snapshot, err := projector.SessionLogSnapshot(context.Background(), grantctl.SessionLogQueryV1{SessionID: "large-session"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Truncated || len(snapshot.Entries) >= 200 {
		t.Fatalf("snapshot was not truncated: entries=%d truncated=%v", len(snapshot.Entries), snapshot.Truncated)
	}
	if !snapshot.HasMore || snapshot.NextBeforeID != snapshot.Entries[len(snapshot.Entries)-1].ID || snapshot.TotalMatches != 200 {
		t.Fatalf("snapshot page metadata = %+v", snapshot)
	}
	if len(encoded) > grantctl.MaxSessionLogSnapshotBytes {
		t.Fatalf("snapshot bytes = %d, max %d", len(encoded), grantctl.MaxSessionLogSnapshotBytes)
	}
}

func TestNetworkProjectionTreatsAbsentHistoryAsAvailableState(t *testing.T) {
	projector := &localActivityProjector{
		store:   nil,
		network: &lazyNetworkReader{path: filepath.Join(t.TempDir(), "missing.db")},
	}
	snapshot, err := projector.NetworkSnapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Available || snapshot.Events == nil || len(snapshot.Events) != 0 {
		t.Fatalf("absent snapshot = %+v", snapshot)
	}
}
