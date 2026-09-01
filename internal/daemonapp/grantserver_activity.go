package daemonapp

import (
	"context"
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
	SessionLogSnapshot(context.Context, string, time.Time) (grantctl.SessionLogSnapshotV1, error)
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

func (p *localActivityProjector) SessionLogSnapshot(ctx context.Context, requestedSessionID string, now time.Time) (grantctl.SessionLogSnapshotV1, error) {
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
		if session.SessionID == requestedSessionID {
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
	rows, err := p.store.ListDecisions(ctx, store.Filter{
		ExactSessionID: selected, Limit: grantctl.MaxSessionLogEntries, OrderDesc: true,
	})
	if err != nil {
		return grantctl.SessionLogSnapshotV1{}, fmt.Errorf("list session actions: %w", err)
	}
	for _, row := range rows {
		snapshot.Entries = append(snapshot.Entries, grantctl.SessionActionV1{
			ID: row.ID, TimestampUnixMs: grantctl.UnixMilliseconds(row.Ts.UnixMilli()),
			ToolName: activityText(row.ToolName), Summary: activityText(row.Summary), Action: activityText(row.Action),
			RuleID: activityText(row.RuleID), Reason: activityText(row.Reason), Impact: activityText(row.Impact),
			ElapsedUs: nonnegative64(row.ElapsedUs), WouldAction: activityText(row.WouldAction),
			PolicyAction: activityText(row.PolicyAction), EffectiveAction: activityText(row.EffectiveAction),
			Adapter: activityText(row.Adapter), TranslationReason: activityText(row.TranslationReason),
			FinalAction: activityText(row.FinalAction), Enforcer: activityText(row.Enforcer),
		})
	}
	return snapshot, nil
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

func sessionLogSnapshotResponse(projector activitySnapshotProjector, version grantctl.ProtocolVersion, sessionID string, now time.Time) grantctl.Response {
	if version == 0 {
		return grantctl.Response{OK: false, Error: "session_log_snapshot requires protocol_version"}
	}
	if version != grantctl.SessionLogProtocolVersion {
		return grantctl.Response{OK: false, Error: fmt.Sprintf("unsupported session log protocol version %d", version)}
	}
	if len(sessionID) > grantctl.MaxDashboardSessionIDBytes {
		return grantctl.Response{OK: false, Error: "invalid session_id"}
	}
	if projector == nil {
		return grantctl.Response{OK: false, Error: "session log snapshot unavailable"}
	}
	snapshot, err := projector.SessionLogSnapshot(context.Background(), sessionID, now)
	if err != nil {
		return grantctl.Response{OK: false, Error: "session log snapshot unavailable"}
	}
	return grantctl.Response{OK: true, SessionLogSnapshot: &snapshot}
}
