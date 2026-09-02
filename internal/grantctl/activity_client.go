package grantctl

import (
	"encoding/json"
	"fmt"
	"time"
)

func NetworkSnapshot(sockPath, ctlToken string, timeout time.Duration) (NetworkSnapshotV1, error) {
	resp, err := roundTrip(sockPath, Request{
		Type: ReqNetworkSnapshot, CtlToken: ctlToken, ProtocolVersion: NetworkProtocolVersion,
	}, timeout)
	if err != nil {
		return NetworkSnapshotV1{}, err
	}
	if !resp.OK {
		return NetworkSnapshotV1{}, fmt.Errorf("network snapshot refused: %s", resp.Error)
	}
	if resp.NetworkSnapshot == nil || resp.NetworkSnapshot.ProtocolVersion != NetworkProtocolVersion {
		return NetworkSnapshotV1{}, fmt.Errorf("unsupported or missing network protocol version")
	}
	if err := validateNetworkSnapshotV1(*resp.NetworkSnapshot); err != nil {
		return NetworkSnapshotV1{}, fmt.Errorf("invalid network snapshot: %w", err)
	}
	return *resp.NetworkSnapshot, nil
}

func SessionActionDetail(sockPath, ctlToken, sessionID string, actionID int64, timeout time.Duration) (SessionActionDetailV1, error) {
	resp, err := roundTrip(sockPath, Request{
		Type: ReqSessionActionDetail, CtlToken: ctlToken, ProtocolVersion: SessionActionDetailProtocolVersion,
		SessionID: sessionID, ActionID: actionID,
	}, timeout)
	if err != nil {
		return SessionActionDetailV1{}, err
	}
	if !resp.OK {
		return SessionActionDetailV1{}, fmt.Errorf("session action detail refused: %s", resp.Error)
	}
	if resp.SessionActionDetail == nil || resp.SessionActionDetail.ProtocolVersion != SessionActionDetailProtocolVersion {
		return SessionActionDetailV1{}, fmt.Errorf("unsupported or missing session action detail protocol version")
	}
	if err := validateSessionActionDetailV1(*resp.SessionActionDetail); err != nil {
		return SessionActionDetailV1{}, fmt.Errorf("invalid session action detail: %w", err)
	}
	if resp.SessionActionDetail.SessionID != sessionID || resp.SessionActionDetail.ActionID != actionID {
		return SessionActionDetailV1{}, fmt.Errorf("session action detail selector mismatch")
	}
	return *resp.SessionActionDetail, nil
}

func SessionLogSnapshot(sockPath, ctlToken, sessionID string, timeout time.Duration) (SessionLogSnapshotV1, error) {
	return SessionLogPage(sockPath, ctlToken, SessionLogQueryV1{SessionID: sessionID}, timeout)
}

func SessionLogPage(sockPath, ctlToken string, query SessionLogQueryV1, timeout time.Duration) (SessionLogSnapshotV1, error) {
	resp, err := roundTrip(sockPath, Request{
		Type: ReqSessionLogSnapshot, CtlToken: ctlToken, ProtocolVersion: SessionLogProtocolVersion,
		SessionID: query.SessionID, BeforeID: query.BeforeID, Search: query.Search, Actions: query.Actions,
	}, timeout)
	if err != nil {
		return SessionLogSnapshotV1{}, err
	}
	if !resp.OK {
		return SessionLogSnapshotV1{}, fmt.Errorf("session log snapshot refused: %s", resp.Error)
	}
	if resp.SessionLogSnapshot == nil || resp.SessionLogSnapshot.ProtocolVersion != SessionLogProtocolVersion {
		return SessionLogSnapshotV1{}, fmt.Errorf("unsupported or missing session log protocol version")
	}
	if err := validateSessionLogSnapshotV1(*resp.SessionLogSnapshot); err != nil {
		return SessionLogSnapshotV1{}, fmt.Errorf("invalid session log snapshot: %w", err)
	}
	return *resp.SessionLogSnapshot, nil
}

func validateNetworkSnapshotV1(snapshot NetworkSnapshotV1) error {
	if snapshot.Events == nil || len(snapshot.Events) > MaxNetworkEvents {
		return fmt.Errorf("network events are missing or exceed item limit")
	}
	for _, event := range snapshot.Events {
		if event.ID <= 0 || event.Host == "" || event.TimestampUnixMs <= 0 || event.StatusCode < 0 ||
			event.RequestSize < 0 || event.ResponseSize < 0 || event.ElapsedMs < 0 {
			return fmt.Errorf("invalid network event")
		}
		for _, value := range networkEventText(event) {
			if len(value) > MaxActivityTextBytes {
				return fmt.Errorf("network event text exceeds limit")
			}
		}
	}
	return nil
}

func validateSessionLogSnapshotV1(snapshot SessionLogSnapshotV1) error {
	if snapshot.Sessions == nil || snapshot.Entries == nil || len(snapshot.Sessions) > MaxActivitySessions || len(snapshot.Entries) > MaxSessionLogEntries {
		return fmt.Errorf("session log arrays are missing or exceed item limits")
	}
	if snapshot.TotalMatches < len(snapshot.Entries) || snapshot.NextBeforeID < 0 ||
		(snapshot.HasMore && (len(snapshot.Entries) == 0 || snapshot.NextBeforeID != snapshot.Entries[len(snapshot.Entries)-1].ID)) ||
		(!snapshot.HasMore && snapshot.NextBeforeID != 0) || snapshot.Truncated != snapshot.HasMore {
		return fmt.Errorf("invalid session log page metadata")
	}
	known := snapshot.SelectedSessionID == ""
	for _, session := range snapshot.Sessions {
		if session.SessionID == "" || len(session.SessionID) > MaxDashboardSessionIDBytes || session.AuditedCalls < 0 ||
			len(session.Agent) > MaxDashboardLabelBytes || len(session.Project) > MaxDashboardLabelBytes {
			return fmt.Errorf("invalid activity session")
		}
		known = known || session.SessionID == snapshot.SelectedSessionID
	}
	if !known {
		return fmt.Errorf("selected session is not in session list")
	}
	for _, entry := range snapshot.Entries {
		if entry.ID <= 0 || entry.TimestampUnixMs <= 0 || entry.ToolName == "" || entry.Action == "" || entry.ElapsedUs < 0 {
			return fmt.Errorf("invalid session action")
		}
		for _, value := range sessionActionText(entry) {
			if len(value) > MaxActivityTextBytes {
				return fmt.Errorf("session action text exceeds limit")
			}
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > MaxSessionLogSnapshotBytes {
		return fmt.Errorf("session log snapshot exceeds byte limit")
	}
	return nil
}

func validateSessionActionDetailV1(detail SessionActionDetailV1) error {
	if detail.ProtocolVersion != SessionActionDetailProtocolVersion || detail.ActionID <= 0 || detail.SessionID == "" ||
		len(detail.SessionID) > MaxDashboardSessionIDBytes || len(detail.Command) > MaxSessionCommandBytes {
		return fmt.Errorf("invalid session action detail")
	}
	return nil
}

func networkEventText(event NetworkEventV1) []string {
	return []string{event.Host, event.Method, event.Path, event.Error, event.SessionID, event.Agent, event.Project, event.ToolName, event.PolicyAction, event.PolicyReason, event.Service, event.Verb, event.ResourceType}
}

func sessionActionText(entry SessionActionV1) []string {
	return []string{entry.ToolName, entry.Summary, entry.Action, entry.RuleID, entry.Reason, entry.Impact, entry.WouldAction, entry.PolicyAction, entry.EffectiveAction, entry.Adapter, entry.TranslationReason, entry.FinalAction, entry.Enforcer}
}
