package daemonapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/procutil"
	"github.com/LuD1161/agentjail/internal/store"
)

type activitySnapshotProjector interface {
	NetworkSnapshot(context.Context, time.Time) (grantctl.NetworkSnapshotV1, error)
	SessionLogSnapshot(context.Context, grantctl.SessionLogQueryV1, time.Time) (grantctl.SessionLogSnapshotV1, error)
	SessionActionDetail(context.Context, string, int64) (grantctl.SessionActionDetailV1, error)
	Close() error
}

type localActivityProjector struct {
	store          store.EventStore
	activeSessions *activeTracker
	network        *lazyNetworkReader
}

func newLocalActivityProjector(eventStore store.EventStore, activeSessions *activeTracker) activitySnapshotProjector {
	if eventStore == nil {
		return nil
	}
	return &localActivityProjector{
		store: eventStore, activeSessions: activeSessions,
		network: &lazyNetworkReader{path: mitm.DefaultDBPath()},
	}
}

type lazyNetworkReader struct {
	mu    sync.Mutex
	path  string
	store *mitm.RequestStore
}

func (r *lazyNetworkReader) Query(ctx context.Context, filter mitm.RequestFilter) ([]mitm.RequestLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store == nil {
		opened, err := mitm.OpenReadOnly(r.path)
		if err != nil {
			return nil, err
		}
		r.store = opened
	}
	return r.store.Query(ctx, filter)
}

func (r *lazyNetworkReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store == nil {
		return nil
	}
	err := r.store.Close()
	r.store = nil
	return err
}

func (p *localActivityProjector) Close() error {
	if p.network == nil {
		return nil
	}
	return p.network.Close()
}

func (p *localActivityProjector) NetworkSnapshot(ctx context.Context, now time.Time) (grantctl.NetworkSnapshotV1, error) {
	snapshot := grantctl.NetworkSnapshotV1{
		ProtocolVersion:   grantctl.NetworkProtocolVersion,
		GeneratedAtUnixMs: grantctl.UnixMilliseconds(now.UnixMilli()),
		Events:            make([]grantctl.NetworkEventV1, 0),
	}
	rows, err := p.network.Query(ctx, mitm.RequestFilter{Limit: grantctl.MaxNetworkEvents})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return snapshot, nil
		}
		return grantctl.NetworkSnapshotV1{}, fmt.Errorf("query network activity: %w", err)
	}
	snapshot.Available = true
	for _, row := range rows {
		sessionID := row.SessionID
		if row.ClaudeSessionID != "" {
			sessionID = row.ClaudeSessionID
		}
		snapshot.Events = append(snapshot.Events, grantctl.NetworkEventV1{
			ID: row.ID, TimestampUnixMs: grantctl.UnixMilliseconds(row.Ts.UnixMilli()),
			Host: activityText(row.Host), Method: activityText(row.Method), Path: safeNetworkPath(row.Path),
			StatusCode: nonnegativeInt(row.StatusCode), RequestSize: nonnegative64(row.RequestSize),
			ResponseSize: nonnegative64(row.ResponseSize), ElapsedMs: nonnegative64(row.ElapsedMs),
			Error: activityText(row.Error), SessionID: activityText(sessionID), Agent: activityText(row.Agent),
			Project: dashboardProjectName(row.Cwd), ToolName: activityText(row.ToolName),
			PolicyAction: activityText(row.PolicyAction), PolicyReason: activityText(row.PolicyReason),
			Service: activityText(row.Service), Verb: activityText(row.Verb), ResourceType: activityText(row.ResourceType),
		})
	}
	return snapshot, nil
}

func (p *localActivityProjector) SessionLogSnapshot(ctx context.Context, query grantctl.SessionLogQueryV1, now time.Time) (grantctl.SessionLogSnapshotV1, error) {
	sessions, err := p.store.ListSessionsFiltered(ctx, store.SessionFilter{Limit: grantctl.MaxActivitySessions})
	if err != nil {
		return grantctl.SessionLogSnapshotV1{}, fmt.Errorf("list activity sessions: %w", err)
	}
	active := make(map[string]struct{})
	if p.activeSessions != nil {
		for _, entry := range p.activeSessions.list() {
			if procutil.Alive(entry.PID) {
				active[entry.SessionID] = struct{}{}
			}
		}
	}
	snapshot := grantctl.SessionLogSnapshotV1{
		ProtocolVersion:   grantctl.SessionLogProtocolVersion,
		GeneratedAtUnixMs: grantctl.UnixMilliseconds(now.UnixMilli()),
		Sessions:          make([]grantctl.ActivitySessionV1, 0, len(sessions)),
		Entries:           make([]grantctl.SessionActionV1, 0),
		Truncated:         false,
	}
	selected := ""
	for _, session := range sessions {
		_, isActive := active[session.SessionID]
		projected := grantctl.ActivitySessionV1{
			SessionID: activitySessionID(session.SessionID), Agent: boundedDashboardLabel(session.Agent, grantctl.MaxDashboardLabelBytes),
			Project: dashboardProjectName(session.CWD), StartedAtUnixMs: grantctl.UnixMilliseconds(session.StartTs.UnixMilli()),
			AuditedCalls: session.DecisionCount, Active: isActive,
		}
		if !session.EndTs.IsZero() {
			projected.EndedAtUnixMs = grantctl.UnixMilliseconds(session.EndTs.UnixMilli())
		}
		snapshot.Sessions = append(snapshot.Sessions, projected)
		if session.SessionID == query.SessionID {
			selected = session.SessionID
		}
	}
	if selected == "" && len(sessions) > 0 {
		selected = sessions[0].SessionID
	}
	if selected == "" {
		return snapshot, nil
	}
	snapshot.SelectedSessionID = activitySessionID(selected)
	filter := store.Filter{
		ExactSessionID:  selected,
		ResolvedActions: query.Actions,
		Search:          store.DecisionSearch(query.Search),
		OrderDesc:       true,
	}
	totalMatches, err := p.store.CountDecisions(ctx, filter)
	if err != nil {
		return grantctl.SessionLogSnapshotV1{}, fmt.Errorf("count session actions: %w", err)
	}
	snapshot.TotalMatches = int(totalMatches)
	filter.AfterID = query.BeforeID
	filter.Limit = grantctl.MaxSessionLogEntries + 1
	rows, err := p.store.ListDecisions(ctx, filter)
	if err != nil {
		return grantctl.SessionLogSnapshotV1{}, fmt.Errorf("list session actions: %w", err)
	}
	if len(rows) > 0 {
		snapshot.HasMore = true
		snapshot.Truncated = true
		snapshot.NextBeforeID = rows[0].ID
	}
	baseJSON, err := json.Marshal(snapshot)
	if err != nil {
		return grantctl.SessionLogSnapshotV1{}, fmt.Errorf("encode session activity base: %w", err)
	}
	snapshot.HasMore = false
	snapshot.Truncated = false
	snapshot.NextBeforeID = 0
	entriesBytes := 0
	for _, row := range rows {
		if len(snapshot.Entries) >= grantctl.MaxSessionLogEntries {
			snapshot.HasMore = true
			break
		}
		projected := grantctl.SessionActionV1{
			ID: row.ID, TimestampUnixMs: grantctl.UnixMilliseconds(row.Ts.UnixMilli()),
			ToolName: activityText(row.ToolName), Summary: activityText(row.Summary), Action: activityText(row.Action),
			RuleID: activityText(row.RuleID), Reason: activityText(row.Reason), Impact: activityText(row.Impact),
			ElapsedUs: nonnegative64(row.ElapsedUs), WouldAction: activityText(row.WouldAction),
			PolicyAction: activityText(row.PolicyAction), EffectiveAction: activityText(row.EffectiveAction),
			Adapter: activityText(row.Adapter), TranslationReason: activityText(row.TranslationReason),
			FinalAction: activityText(row.FinalAction), Enforcer: activityText(row.Enforcer),
		}
		encoded, marshalErr := json.Marshal(projected)
		if marshalErr != nil {
			return grantctl.SessionLogSnapshotV1{}, fmt.Errorf("encode session action: %w", marshalErr)
		}
		separator := 0
		if len(snapshot.Entries) > 0 {
			separator = 1
		}
		if len(baseJSON)-2+entriesBytes+separator+len(encoded) > grantctl.MaxSessionLogSnapshotBytes {
			snapshot.HasMore = true
			break
		}
		snapshot.Entries = append(snapshot.Entries, projected)
		entriesBytes += separator + len(encoded)
	}
	if len(rows) > len(snapshot.Entries) {
		snapshot.HasMore = true
	}
	if snapshot.HasMore && len(snapshot.Entries) > 0 {
		snapshot.NextBeforeID = snapshot.Entries[len(snapshot.Entries)-1].ID
	}
	snapshot.Truncated = snapshot.HasMore
	return snapshot, nil
}

type redactedActivityInput struct {
	Command string `json:"command"`
}

func activityCommand(row store.DecisionRecord) string {
	if row.ToolName != "Bash" || row.ToolInputRedacted == "" {
		return ""
	}
	var input redactedActivityInput
	if err := json.Unmarshal([]byte(row.ToolInputRedacted), &input); err != nil {
		return ""
	}
	return boundedActivityText(input.Command, grantctl.MaxSessionCommandBytes)
}

var errActivityActionNotFound = errors.New("session action not found")

func (p *localActivityProjector) SessionActionDetail(ctx context.Context, sessionID string, actionID int64) (grantctl.SessionActionDetailV1, error) {
	rows, err := p.store.ListDecisions(ctx, store.Filter{DecisionID: actionID, ExactSessionID: sessionID, Limit: 1})
	if err != nil {
		return grantctl.SessionActionDetailV1{}, fmt.Errorf("read session action: %w", err)
	}
	if len(rows) != 1 {
		return grantctl.SessionActionDetailV1{}, errActivityActionNotFound
	}
	return grantctl.SessionActionDetailV1{
		ProtocolVersion: grantctl.SessionActionDetailProtocolVersion,
		ActionID:        rows[0].ID,
		SessionID:       activitySessionID(rows[0].SessionID),
		Command:         activityCommand(rows[0]),
	}, nil
}

func activitySessionID(value string) string {
	return boundedActivityText(value, grantctl.MaxDashboardSessionIDBytes)
}

func activityText(value string) string {
	return boundedActivityText(value, grantctl.MaxActivityTextBytes)
}

func boundedActivityText(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}

func safeNetworkPath(value string) string {
	if parsed, err := url.ParseRequestURI(value); err == nil {
		return activityText(parsed.EscapedPath())
	}
	path, _, _ := strings.Cut(value, "?")
	path, _, _ = strings.Cut(path, "#")
	return activityText(path)
}

func nonnegative64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func nonnegativeInt(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func networkSnapshotResponse(projector activitySnapshotProjector, version grantctl.ProtocolVersion, now time.Time) grantctl.Response {
	if version == 0 {
		return grantctl.Response{OK: false, Error: "network_snapshot requires protocol_version"}
	}
	if version != grantctl.NetworkProtocolVersion {
		return grantctl.Response{OK: false, Error: fmt.Sprintf("unsupported network protocol version %d", version)}
	}
	if projector == nil {
		return grantctl.Response{OK: false, Error: "network snapshot unavailable"}
	}
	snapshot, err := projector.NetworkSnapshot(context.Background(), now)
	if err != nil {
		return grantctl.Response{OK: false, Error: "network snapshot unavailable"}
	}
	return grantctl.Response{OK: true, NetworkSnapshot: &snapshot}
}

func sessionLogSnapshotResponse(projector activitySnapshotProjector, version grantctl.ProtocolVersion, query grantctl.SessionLogQueryV1, now time.Time) grantctl.Response {
	if version == 0 {
		return grantctl.Response{OK: false, Error: "session_log_snapshot requires protocol_version"}
	}
	if version != grantctl.SessionLogProtocolVersion {
		return grantctl.Response{OK: false, Error: fmt.Sprintf("unsupported session log protocol version %d", version)}
	}
	if len(query.SessionID) > grantctl.MaxDashboardSessionIDBytes || query.BeforeID < 0 || len(query.Search) > grantctl.MaxSessionSearchBytes || !validSessionLogActions(query.Actions) {
		return grantctl.Response{OK: false, Error: "invalid session log query"}
	}
	if projector == nil {
		return grantctl.Response{OK: false, Error: "session log snapshot unavailable"}
	}
	snapshot, err := projector.SessionLogSnapshot(context.Background(), query, now)
	if err != nil {
		return grantctl.Response{OK: false, Error: "session log snapshot unavailable"}
	}
	return grantctl.Response{OK: true, SessionLogSnapshot: &snapshot}
}

func validSessionLogActions(actions []string) bool {
	if len(actions) > 4 {
		return false
	}
	seen := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		switch action {
		case "allow", "ask", "deny", "block":
		default:
			return false
		}
		if _, duplicate := seen[action]; duplicate {
			return false
		}
		seen[action] = struct{}{}
	}
	return true
}

func sessionActionDetailResponse(projector activitySnapshotProjector, version grantctl.ProtocolVersion, sessionID string, actionID int64) grantctl.Response {
	if version == 0 {
		return grantctl.Response{OK: false, Error: "session_action_detail requires protocol_version"}
	}
	if version != grantctl.SessionActionDetailProtocolVersion {
		return grantctl.Response{OK: false, Error: fmt.Sprintf("unsupported session action detail protocol version %d", version)}
	}
	if sessionID == "" || len(sessionID) > grantctl.MaxDashboardSessionIDBytes || actionID <= 0 {
		return grantctl.Response{OK: false, Error: "invalid session action detail selector"}
	}
	if projector == nil {
		return grantctl.Response{OK: false, Error: "session action detail unavailable"}
	}
	detail, err := projector.SessionActionDetail(context.Background(), sessionID, actionID)
	if err != nil {
		if errors.Is(err, errActivityActionNotFound) {
			return grantctl.Response{OK: false, Error: "session action not found"}
		}
		return grantctl.Response{OK: false, Error: "session action detail unavailable"}
	}
	return grantctl.Response{OK: true, SessionActionDetail: &detail}
}
