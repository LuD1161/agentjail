package grantctl

import (
	"fmt"
	"net"
	"time"
)

// roundTrip sends one request over the control socket and reads one response,
// using timeout for both the dial and the reply. Suitable for verbs the daemon
// answers from memory; see roundTripSlow for ones it has to work for.
func roundTrip(sockPath string, req Request, timeout time.Duration) (Response, error) {
	return roundTripSlow(sockPath, req, timeout, timeout)
}

// roundTripSlow is roundTrip with the dial budget and the reply budget split.
//
// The two measure different things and must not share a number. dialTimeout
// answers "is anyone listening?" and should stay short so an absent daemon fails
// fast. replyTimeout must cover however long the daemon takes to SERVE the verb
// — for daemon_reload that is a full Rego recompile, which can exceed a dial
// budget sized in milliseconds.
//
// Collapsing them makes a slow refusal indistinguishable from an absent daemon:
// the caller times out mid-compile, reports "unreachable", and falls back to
// another delivery path — losing the compile verdict that says the operator's
// policy was rejected and never took effect.
func roundTripSlow(sockPath string, req Request, dialTimeout, replyTimeout time.Duration) (Response, error) {
	conn, err := net.DialTimeout("unix", sockPath, dialTimeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(replyTimeout))

	if err := WriteRequestFrame(conn, req); err != nil {
		return Response{}, fmt.Errorf("send control request: %w", err)
	}
	resp, err := ReadResponseFrame(conn)
	if err != nil {
		return Response{}, fmt.Errorf("read control response: %w", err)
	}
	return resp, nil
}

// GrantRequest files a new runtime host grant request on the daemon. The daemon
// assigns a GrantID, queues it, and returns the ID to the caller so it can poll
// or wait for approval. sessionID and cwd are non-secret, display-only identity
// for the session (see Request.SessionID / Request.CWD) so a human approving a
// grant later can tell sessions apart; neither carries authority.
func GrantRequest(sockPath string, sessionID, cwd, host string, ttlMs int64, reason string, timeout time.Duration) (string, error) {
	resp, err := roundTrip(sockPath, Request{
		Type:      ReqGrantRequest,
		SessionID: sessionID,
		CWD:       cwd,
		Host:      host,
		TTLMs:     ttlMs,
		Reason:    reason,
	}, timeout)
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("grant request refused: %s", resp.Error)
	}
	return resp.GrantID, nil
}

// GrantList lists the pending grant requests the daemon currently holds, across
// all sessions. The result never contains a Token (see GrantInfo).
func GrantList(sockPath, ctlToken string, timeout time.Duration) ([]GrantInfo, error) {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantList, CtlToken: ctlToken}, timeout)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("grant list refused: %s", resp.Error)
	}
	return resp.Grants, nil
}

// ReviewSnapshot returns the bounded v1 menu-review projection. The request
// always carries an explicit version; missing and unsupported response
// versions are protocol errors rather than empty queues.
func ReviewSnapshot(sockPath, ctlToken string, timeout time.Duration) (ReviewSnapshotV1, error) {
	resp, err := roundTrip(sockPath, Request{
		Type:            ReqReviewSnapshot,
		CtlToken:        ctlToken,
		ProtocolVersion: ReviewProtocolVersion,
	}, timeout)
	if err != nil {
		return ReviewSnapshotV1{}, err
	}
	if !resp.OK {
		return ReviewSnapshotV1{}, fmt.Errorf("review snapshot refused: %s", resp.Error)
	}
	if resp.ReviewSnapshot == nil || resp.ReviewSnapshot.ProtocolVersion == 0 {
		return ReviewSnapshotV1{}, fmt.Errorf("review snapshot response missing protocol_version")
	}
	if resp.ReviewSnapshot.ProtocolVersion != ReviewProtocolVersion {
		return ReviewSnapshotV1{}, fmt.Errorf("unsupported review protocol version %d", resp.ReviewSnapshot.ProtocolVersion)
	}
	if err := validateReviewSnapshotV1(*resp.ReviewSnapshot); err != nil {
		return ReviewSnapshotV1{}, fmt.Errorf("invalid review snapshot: %w", err)
	}
	return *resp.ReviewSnapshot, nil
}

// DashboardSnapshot returns the bounded v1 overview projection.
func DashboardSnapshot(sockPath, ctlToken string, timeout time.Duration) (DashboardSnapshotV1, error) {
	resp, err := roundTrip(sockPath, Request{Type: ReqDashboardSnapshot, CtlToken: ctlToken, ProtocolVersion: DashboardProtocolVersion}, timeout)
	if err != nil {
		return DashboardSnapshotV1{}, err
	}
	if !resp.OK {
		return DashboardSnapshotV1{}, fmt.Errorf("dashboard snapshot refused: %s", resp.Error)
	}
	if resp.DashboardSnapshot == nil || resp.DashboardSnapshot.ProtocolVersion != DashboardProtocolVersion {
		return DashboardSnapshotV1{}, fmt.Errorf("unsupported or missing dashboard protocol version")
	}
	if err := validateDashboardSnapshotV1(*resp.DashboardSnapshot); err != nil {
		return DashboardSnapshotV1{}, fmt.Errorf("invalid dashboard snapshot: %w", err)
	}
	return *resp.DashboardSnapshot, nil
}

// DiscoverMCPTools requests an explicit, authenticated tools/list pass.
func DiscoverMCPTools(sockPath, ctlToken string, timeout time.Duration) (MCPToolsDiscoveryV1, error) {
	resp, err := roundTripSlow(sockPath, Request{
		Type:            ReqMCPToolsDiscover,
		CtlToken:        ctlToken,
		ProtocolVersion: MCPDiscoveryProtocolVersion,
	}, timeout, timeout)
	if err != nil {
		return MCPToolsDiscoveryV1{}, err
	}
	if !resp.OK {
		return MCPToolsDiscoveryV1{}, fmt.Errorf("MCP tool discovery refused: %s", resp.Error)
	}
	if resp.MCPToolsDiscovery == nil || resp.MCPToolsDiscovery.ProtocolVersion != MCPDiscoveryProtocolVersion {
		return MCPToolsDiscoveryV1{}, fmt.Errorf("unsupported or missing MCP discovery protocol version")
	}
	if err := validateMCPToolsDiscoveryV1(*resp.MCPToolsDiscovery); err != nil {
		return MCPToolsDiscoveryV1{}, fmt.Errorf("invalid MCP tool discovery: %w", err)
	}
	return *resp.MCPToolsDiscovery, nil
}

func validateMCPToolsDiscoveryV1(discovery MCPToolsDiscoveryV1) error {
	if discovery.ProtocolVersion != MCPDiscoveryProtocolVersion {
		return fmt.Errorf("unsupported MCP discovery protocol version")
	}
	if discovery.Servers == nil || len(discovery.Servers) > 64 {
		return fmt.Errorf("MCP discovery exceeds server limit")
	}
	for _, server := range discovery.Servers {
		if server.Server == "" || len(server.Server) > MaxDashboardLabelBytes || server.Tools == nil || len(server.Tools) > 128 {
			return fmt.Errorf("invalid MCP discovery server")
		}
		switch server.Status {
		case MCPDiscoveryConnected, MCPDiscoveryAuthRequired, MCPDiscoveryUnreachable, MCPDiscoveryTimeout:
		default:
			return fmt.Errorf("invalid MCP discovery status")
		}
		for _, tool := range server.Tools {
			if tool == "" || len(tool) > MaxDashboardLabelBytes {
				return fmt.Errorf("invalid MCP discovery tool")
			}
		}
	}
	return nil
}

func validateDashboardSnapshotV1(snapshot DashboardSnapshotV1) error {
	if snapshot.RecentSessions == nil || snapshot.Activity == nil || snapshot.Tokens == nil || snapshot.TokenAgents == nil || snapshot.TokenCoverage == nil {
		return fmt.Errorf("dashboard arrays are required")
	}
	if len(snapshot.RecentSessions) > MaxDashboardSessions || len(snapshot.Activity) > MaxDashboardDays || len(snapshot.Tokens) > MaxDashboardDays || len(snapshot.TokenAgents) > 8 || len(snapshot.MCPTools) > 64 || len(snapshot.MCPDiscovery) > 64 {
		return fmt.Errorf("dashboard projection exceeds item limits")
	}
	for _, agent := range snapshot.TokenAgents {
		if agent.Agent == "" || len(agent.Agent) > MaxDashboardLabelBytes || agent.InputTokens < 0 || agent.OutputTokens < 0 || agent.CacheTokens < 0 {
			return fmt.Errorf("invalid dashboard token agent")
		}
	}
	if snapshot.ActiveSessions < 0 || snapshot.TotalCalls < 0 || snapshot.TotalSessions < 0 {
		return fmt.Errorf("dashboard counts cannot be negative")
	}
	if snapshot.TokenStatus != DashboardTokensLoading && snapshot.TokenStatus != DashboardTokensReady {
		return fmt.Errorf("invalid dashboard token status")
	}
	for _, session := range snapshot.RecentSessions {
		if session.SessionID == "" || len(session.SessionID) > MaxDashboardSessionIDBytes || len(session.Agent) > MaxDashboardLabelBytes || len(session.Project) > MaxDashboardLabelBytes || session.AuditedCalls < 0 {
			return fmt.Errorf("invalid dashboard session")
		}
	}
	for _, day := range snapshot.Activity {
		if len(day.Day) != len("2006-01-02") || day.Count < 0 {
			return fmt.Errorf("invalid dashboard activity point")
		}
	}
	for _, day := range snapshot.Tokens {
		if len(day.Day) != len("2006-01-02") || day.InputTokens < 0 || day.OutputTokens < 0 || day.CacheTokens < 0 {
			return fmt.Errorf("invalid dashboard token point")
		}
	}
	for _, server := range snapshot.MCPTools {
		if server.Server == "" || len(server.Server) > MaxDashboardLabelBytes || server.Tools == nil || len(server.Tools) > 128 {
			return fmt.Errorf("invalid dashboard MCP tools")
		}
		for _, tool := range server.Tools {
			if tool == "" || len(tool) > MaxDashboardLabelBytes {
				return fmt.Errorf("invalid dashboard MCP tool")
			}
		}
	}
	for _, server := range snapshot.MCPDiscovery {
		if server.Server == "" || len(server.Server) > MaxDashboardLabelBytes {
			return fmt.Errorf("invalid dashboard MCP discovery server")
		}
		switch server.Status {
		case MCPDiscoveryConnected, MCPDiscoveryAuthRequired, MCPDiscoveryUnreachable, MCPDiscoveryTimeout:
		default:
			return fmt.Errorf("invalid dashboard MCP discovery status")
		}
	}
	return nil
}

func validateReviewSnapshotV1(snapshot ReviewSnapshotV1) error {
	if snapshot.Reviews == nil {
		return fmt.Errorf("reviews is required")
	}
	if len(snapshot.Reviews) > MaxReviewSnapshotItems {
		return fmt.Errorf("reviews exceeds item limit")
	}
	if snapshot.TotalPending < len(snapshot.Reviews) {
		return fmt.Errorf("total_pending is smaller than reviews")
	}
	if snapshot.Truncated != (snapshot.TotalPending > len(snapshot.Reviews)) {
		return fmt.Errorf("truncated does not match total_pending")
	}
	for i, review := range snapshot.Reviews {
		if err := validateReviewInfoV1(review); err != nil {
			return fmt.Errorf("review %d: %w", i, err)
		}
	}
	return nil
}

func validateReviewInfoV1(review ReviewInfo) error {
	if review.ReviewID == "" {
		return fmt.Errorf("review_id is required")
	}
	if review.Kind != ReviewKindProjectHost {
		return fmt.Errorf("unsupported kind %q", review.Kind)
	}
	if review.ApprovalScope != ReviewScopeFutureProjectSessions {
		return fmt.Errorf("unsupported approval_scope %q", review.ApprovalScope)
	}
	if len(review.Host) > MaxReviewHostBytes {
		return fmt.Errorf("host exceeds byte limit")
	}
	if len(review.ProjectPath) > MaxReviewProjectPathBytes {
		return fmt.Errorf("project_path exceeds byte limit")
	}
	if len(review.Reason) > MaxReviewReasonBytes {
		return fmt.Errorf("reason exceeds byte limit")
	}

	switch review.ContextState {
	case ReviewContextStateVerified:
		if review.Host == "" || review.ProjectPath == "" || !review.CanApprove || !review.CanDeny {
			return fmt.Errorf("verified context is not actionable")
		}
	case ReviewContextStateUnbound:
		if review.Host == "" || review.ProjectPath != "" || review.CanApprove || !review.CanDeny {
			return fmt.Errorf("unbound context has invalid authority")
		}
	case ReviewContextStateUnrepresentable:
		if review.Host != "" && review.ProjectPath != "" {
			return fmt.Errorf("unrepresentable context contains complete authority")
		}
		if review.CanApprove || !review.CanDeny {
			return fmt.Errorf("unrepresentable context is actionable")
		}
	default:
		return fmt.Errorf("unsupported context_state %q", review.ContextState)
	}
	return nil
}

// GrantApprove claims the pending grant request identified by grantID and
// applies it to its owning session's allowlist. The daemon resolves
// SessionID/CWD from its own in-memory grant map by GrantID.
func GrantApprove(sockPath, ctlToken, grantID string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantApprove, CtlToken: ctlToken, GrantID: grantID}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("grant approve refused: %s", resp.Error)
	}
	return nil
}

// GrantDeny discards the pending grant request identified by grantID without
// applying it. Same GrantID-only shape as GrantApprove.
func GrantDeny(sockPath, ctlToken, grantID string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{Type: ReqGrantDeny, CtlToken: ctlToken, GrantID: grantID}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("grant deny refused: %s", resp.Error)
	}
	return nil
}

// UpdateAudit records one terminal manual-update outcome through the daemon's
// authenticated control socket. The daemon owns persistence, so CLI callers
// never open the audit database for a write.
func UpdateAudit(sockPath, ctlToken string, status UpdateAuditStatus, version, goos string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{
		Type:          ReqUpdateAudit,
		CtlToken:      ctlToken,
		UpdateStatus:  status,
		UpdateVersion: version,
		UpdateOS:      goos,
	}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return &RefusedError{Op: ReqUpdateAudit, Reason: resp.Error}
	}
	return nil
}

// RegisterSessionLaunch records daemon-authoritative launch metadata before
// the shield starts the agent. The authenticated control token is the authority.
func RegisterSessionLaunch(sockPath, ctlToken string, pid int, root, pathValue string, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{
		Type: ReqSessionLaunchRegister, CtlToken: ctlToken,
		LaunchPID: pid, LaunchRoot: root, LaunchPath: pathValue,
	}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return &RefusedError{Op: ReqSessionLaunchRegister, Reason: resp.Error}
	}
	return nil
}

func UnregisterSessionLaunch(sockPath, ctlToken string, pid int, timeout time.Duration) error {
	resp, err := roundTrip(sockPath, Request{
		Type: ReqSessionLaunchUnregister, CtlToken: ctlToken, LaunchPID: pid,
	}, timeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return &RefusedError{Op: ReqSessionLaunchUnregister, Reason: resp.Error}
	}
	return nil
}

// RefusedError reports that the round trip COMPLETED and the daemon answered
// ok=false. It is distinct from a transport error on purpose: "the daemon
// rejected your policy" and "no daemon answered" demand opposite responses from
// the caller (surface the reason vs. fall back to another delivery path), and
// collapsing both into one error is how a rejected policy gets silently retried
// as a success.
type RefusedError struct {
	Op     RequestType
	Reason string
}

func (e *RefusedError) Error() string {
	return string(e.Op) + " refused: " + e.Reason
}

// DaemonReloadReplyTimeout bounds how long DaemonReload waits for the daemon to
// finish reloading, as opposed to how long it waits to connect. Sized for a full
// Rego recompile on a cold, contended box, since the alternative -- timing out
// mid-compile -- makes a rejected policy look like an absent daemon.
const DaemonReloadReplyTimeout = 10 * time.Second

// DaemonReload asks the daemon on sockPath (the privileged control socket) to
// reload policy.yaml and recompile the Rego bundle. dialTimeout bounds only the
// connect; the reply is given DaemonReloadReplyTimeout, because serving this verb
// means compiling.
//
// A *RefusedError carries the compile error verbatim when the new rules are
// rejected -- the daemon keeps the old bundle in that case, so the caller must
// surface it rather than assume the edit took effect. Any other error means the
// daemon could not be reached.
//
// sockPath must be the privileged control socket, never the agent-facing
// daemon.sock (ADR 0066).
func DaemonReload(sockPath, ctlToken string, dialTimeout time.Duration) error {
	resp, err := roundTripSlow(sockPath, Request{Type: ReqDaemonReload, CtlToken: ctlToken}, dialTimeout, DaemonReloadReplyTimeout)
	if err != nil {
		return err
	}
	if !resp.OK {
		return &RefusedError{Op: ReqDaemonReload, Reason: resp.Error}
	}
	return nil
}

// IsAvailable probes the socket at sockPath with a short dial timeout and
// returns true if the socket is connectable, false otherwise. A false result
// means no daemon is serving that socket (caller decides start-fresh vs.
// fail-closed).
func IsAvailable(sockPath string) bool {
	conn, err := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
