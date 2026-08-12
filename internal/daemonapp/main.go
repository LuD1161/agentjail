// Package daemonapp is the agentjail policy evaluation daemon. It listens on a
// Unix socket, accepts newline-delimited JSON requests, evaluates each request
// against the OPA policy engine, and writes back a JSON response. The daemon
// is designed to run as a persistent background process (launchd on macOS)
// so OPA warm-start cost (~50 ms) is paid once; per-decision latency target
// is p95 < 5 ms.
//
// Protocol: one JSON object per line, request and response each terminated by '\n'.
//
// Request:
//
//	{"id":"req-123","hook_event":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s1","cwd":"/tmp"}
//
// Response:
//
//	{"id":"req-123","action":"allow","reason":"default allow","rule_id":"default"}
//
// Signals:
//   - SIGTERM / SIGINT: drain in-flight requests, close socket, exit 0.
//   - SIGHUP: reload policy.yaml AND Rego modules, rebuild engine atomically
//     under RWMutex; in-flight Eval calls complete against the old engine.
//     On reload failure, old config is kept — daemon never goes open.
//
// Architecture note: pattern copied from Firecracker's JSON-over-socket
// control plane — tiny, no framework, no external deps beyond stdlib.
package daemonapp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	policy "github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/agentpolicy"
	"github.com/LuD1161/agentjail/internal/approvalexec"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/custompolicy"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/hookwatch"
	"github.com/LuD1161/agentjail/internal/hostproxy"
	"github.com/LuD1161/agentjail/internal/logrotate"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/policyeval"
	"github.com/LuD1161/agentjail/internal/procutil"
	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/store"
	"github.com/LuD1161/agentjail/internal/telemetry"
	"github.com/LuD1161/agentjail/internal/wire"
)

// Request is an alias for policyeval.Request used in daemon tests.
type Request = policyeval.Request

// Response is an alias for policyeval.Response used in daemon tests.
type Response = policyeval.Response

// server holds all daemon state. Policy evaluation is delegated to the
// evaluator; the server owns connection handling, telemetry, persistence,
// and session tracking.
type server struct {
	// evaluator owns the OPA engine, LRU cache, per-project engines,
	// repo-root cache, and AWS profile cache.
	evaluator          policyeval.Evaluator
	approvals          *approvalexec.Manager
	hostProxyApprovals *hostproxy.Manager
	hostProxyExecutor  hostproxy.Executor

	// wg tracks in-flight connections so graceful shutdown can drain them.
	wg sync.WaitGroup

	// telemetry is nil-safe: a nil recorder records nothing.
	telemetry *telemetry.Recorder

	// eventStore persists decisions/audit/sessions to SQLite (ADR 0018).
	// nil-safe: a nil store means the daemon continues without persistence
	// (fail-open on logging, never on policy). decCh is a bounded buffer
	// drained by a goroutine so a DB write never wedges a decision.
	eventStore store.EventStore
	decCh      chan store.DecisionRecord
	decWg      sync.WaitGroup

	// decDropped counts decisions the writer could not persist. Incremented
	// on the hot path (atomic, no IO); flushed to a decisions.dropped audit
	// event by drainDecisions so under-recording is visible (ADR 0072).
	decDropped atomic.Int64

	// monitoring mirrors PolicyConfig.Enforcement == monitor. Read on the hot
	// path and rewritten by reload(), so it is atomic rather than living behind
	// the config pointer. See ADR 0091-monitor-mode-tools.
	monitoring atomic.Bool

	// activeSessions tracks which session IDs have open connections.
	activeSessions *activeTracker

	// grantSrv handles runtime host grant requests. Nil-safe.
	grantSrv *grantServer

	// connSem bounds the number of concurrent agent-socket connections
	// (P9): an agent that holds write access to daemon.sock could otherwise
	// open unbounded connections and exhaust daemon resources, pushing
	// per-request latency past the hook's fail-open deadline and forcing
	// every hook invocation in the fleet to fail open. nil-safe: a nil
	// semaphore means no cap is enforced (used in tests that construct a
	// bare server{}).
	connSem chan struct{}

	// rulesDir and policyPath mirror the --rules/--policy flags. reloadPolicy
	// reads them to know what to reload; both are set once at construction
	// and never mutated. rulesDir == "" means the inline defaultInlinePolicy
	// is in use (dev/test), matching the flag's own zero-value semantics.
	rulesDir   string
	policyPath string

	// reloadMu serializes reloadPolicy so at most one Rego recompile -- the
	// daemon's most expensive operation -- is ever in flight (ADR 0066).
	reloadMu sync.Mutex

	// idleTimeout bounds how long handleConn blocks on a single read from an
	// agent-socket connection (P9). Set once at construction and never mutated,
	// so concurrent handleConn goroutines read it race-free. A zero value falls
	// back to defaultAgentConnIdleTimeout (bare server{} built directly in
	// tests); production and the test helpers set it explicitly.
	idleTimeout time.Duration
}

// maxAgentConns bounds concurrent connections to the agent-reachable
// daemon.sock (P9). Generously sized for legitimate concurrent hook
// invocations (parallel tool calls, multiple sessions) while still bounding
// worst-case goroutine/scanner-buffer memory from a misbehaving or hostile
// peer.
const maxAgentConns = 256

// defaultAgentConnIdleTimeout bounds how long the daemon will block on a single
// read from an agent-socket connection (P9). Mirrors the control socket's
// 5-second deadline (see grantServer.handleCtlConn). The deadline is reset
// after each request is fully processed, so a connection that is actively
// making requests is never punished — only one that opens a connection and
// then goes idle or trickles bytes.
//
// It is the fallback for server.idleTimeout; tests set a per-server idleTimeout
// (never a shared global) to exercise the timeout without a multi-second sleep.
const defaultAgentConnIdleTimeout = 5 * time.Second

// recordTelemetry feeds one decision to the telemetry recorder (nil-safe).
// toolName and agentID are enum values from the daemon Request struct; they are
// safe to forward to telemetry (not user-controlled argv).
func (s *server) recordTelemetry(action, ruleID, toolName, agentID string, elapsed time.Duration) {
	if s.telemetry != nil {
		s.telemetry.RecordDecisionFull(action, ruleID, toolName, agentID, elapsed)
	}
}

// recordPolicyConfig snapshots the policy configuration into telemetry (nil-safe).
func (s *server) recordPolicyConfig(cfg *agentconfig.PolicyConfig, rulesDir string) {
	if s.telemetry != nil {
		s.telemetry.RecordPolicyConfig(countCustomRuleFiles(rulesDir), cfg.DisabledRules)
	}
}

// droppedDecisionFlushInterval bounds how often the writer turns dropped
// decisions into an audit event — often enough to bound the loss window,
// rarely enough that a saturated store is not hammered further (ADR 0072).
const droppedDecisionFlushInterval = 30 * time.Second

// enqueueDecision enqueues a decision record for async SQLite persistence
// (ADR 0018). Fail-open: if the store is nil or the buffer is full, the
// record is dropped with a Warn log — the policy decision was already
// returned to the hook and is NOT affected. The buffer is bounded so a slow
// DB cannot cause unbounded memory growth.
func (s *server) enqueueDecision(d store.DecisionRecord) {
	if s.eventStore == nil || s.decCh == nil {
		return
	}
	select {
	case s.decCh <- d:
	default:
		s.decDropped.Add(1)
		slog.Warn("store buffer full; dropping decision record (fail-open on logging)", "session_id", d.SessionID, "action", d.Action)
	}
}

// flushDroppedDecisions emits a decisions.dropped audit event for any
// decisions lost since the last flush, so a silent under-recording window
// leaves a durable trace (ADR 0072). Best-effort and off the hot path: the
// count is restored on failure so the next flush retries it.
func (s *server) flushDroppedDecisions(ctx context.Context) {
	n := s.decDropped.Swap(0)
	if n == 0 {
		return
	}
	if err := s.eventStore.Emit(ctx, audit.Event{
		EventType: audit.DecisionsDropped,
		Detail:    map[string]string{"count": strconv.FormatInt(n, 10)},
	}); err != nil {
		s.decDropped.Add(n)
		slog.Warn("audit emit failed for dropped decisions", "count", n, "err", err)
	}
}

// retentionSweep runs one retention pass: store cleanup (retention window + WAL
// checkpoint, ADR 0071) and the captured-body sweep (ADR 0092 D2). Both
// failures are non-fatal. Shared by the startup pass and retentionLoop so they
// cannot diverge. See ADR 0101-periodic-retention.
func (s *server) retentionSweep(ctx context.Context, dur time.Duration) {
	if s.eventStore != nil {
		if cerr := s.eventStore.Cleanup(ctx, dur); cerr != nil {
			slog.Warn("store retention cleanup failed (non-fatal)", "err", cerr)
		}
	}
	if n, berr := mitm.SweepBodies(mitm.DefaultBodyDir(), dur, time.Now()); berr != nil {
		slog.Warn("body retention sweep failed (non-fatal)", "err", berr, "removed", n)
	} else if n > 0 {
		slog.Info("body retention sweep", "removed", n, "retention", dur)
	}
}

// retentionLoop re-runs run on a ticker until ctx is cancelled. interval<=0
// disables it (startup-only). See ADR 0101-periodic-retention (AGE-225).
func retentionLoop(ctx context.Context, interval time.Duration, run func()) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			run()
		case <-ctx.Done():
			return
		}
	}
}

// drainDecisions consumes the decision channel and writes to the store. It
// runs until ctx is cancelled, then drains any remaining records and exits
// so graceful shutdown flushes pending writes.
func (s *server) drainDecisions(ctx context.Context) {
	defer s.decWg.Done()
	tick := time.NewTicker(droppedDecisionFlushInterval)
	defer tick.Stop()
	for {
		select {
		case d := <-s.decCh:
			// Detached: ctx cancellation must end the loop, not abort a write
			// already dequeued. select picks randomly among ready cases, so a
			// cancelled ctx here loses records the shutdown drain would keep.
			if err := s.eventStore.RecordDecision(context.Background(), d); err != nil {
				s.decDropped.Add(1)
				slog.Warn("store write decision failed (fail-open)", "err", err, "session_id", d.SessionID)
			}
		case <-tick.C:
			s.flushDroppedDecisions(ctx)
		case <-ctx.Done():
			// Flush remaining records before exiting.
			for {
				select {
				case d := <-s.decCh:
					if err := s.eventStore.RecordDecision(context.Background(), d); err != nil {
						s.decDropped.Add(1)
						slog.Warn("store write decision failed during drain", "err", err)
					}
				default:
					// Record the shutdown's own losses too, on a live context.
					s.flushDroppedDecisions(context.Background())
					return
				}
			}
		}
	}
}

// countCustomRuleFiles returns how many *.rego files in rulesDir are custom rules
// (stem not in coreFileStems/libraryFileStems). Returns 0 if the dir is empty or
// unreadable. Used only for the telemetry policy_config snapshot.
func countCustomRuleFiles(rulesDir string) int {
	if rulesDir == "" {
		return 0
	}
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
			continue
		}
		stem := strings.TrimSuffix(name, ".rego")
		if !coreFileStems[stem] && !libraryFileStems[stem] {
			n++
		}
	}
	return n
}

// reloadPolicy reloads policy.yaml and the Rego rule bundle in place,
// rebuilding the OPA engine atomically under the evaluator's lock. It is the
// single implementation shared by the SIGHUP signal handler and the
// grantctl.ReqDaemonReload control message (see grantServer.handleCtlConn) so
// both delivery paths behave identically.
//
// Reloads are serialized by reloadMu. A Rego recompile is the most expensive
// thing the daemon does, and every socket delivery path is one goroutine per
// connection, so without this N concurrent callers would mean N concurrent
// compiles -- CPU amplification against a hook budget that defaults to
// fail-open (ADR 0066). SIGHUP is already serialized by the signal loop; this
// makes "at most one compile in flight" a property of the daemon rather than an
// accident of the delivery path. It does not deduplicate: each caller still gets
// a real reload and an honest compile verdict, just not concurrently.
//
// Fail-safe / never-fail-open contract: reloadPolicy returns a non-nil error
// on ANY failure -- loading Rego modules, loading policy.yaml, or compiling
// the new bundle -- and does NOT mutate daemon state before that point. In
// particular, s.evaluator.Reload itself keeps serving the old engine when the
// new bundle fails to compile (see policyeval.Evaluator.Reload). The caller
// (signal handler or control dispatch) is responsible for logging/reporting
// the error; the old policy stays in effect either way.
func (s *server) reloadPolicy(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	var mods [][2]string
	if s.rulesDir != "" {
		m, err := loadModules(s.rulesDir)
		if err != nil {
			return fmt.Errorf("reload: load modules: %w", err)
		}
		mods = m
	} else {
		mods = [][2]string{{"default.rego", defaultInlinePolicy}}
	}

	newCfg, err := loadConfig(s.policyPath)
	if err != nil {
		return fmt.Errorf("reload: load policy config: %w", err)
	}

	if err := s.evaluator.Reload(ctx, mods, newCfg); err != nil {
		return fmt.Errorf("reload: compile: %w", err)
	}

	// Set only after the engine swap succeeds: a failed reload keeps serving the
	// old engine, so the old enforcement mode must stay with it.
	s.setMonitoring(newCfg.Monitoring())

	slog.Info("policy reloaded",
		"rules_dir", s.rulesDir,
		"mcp_allowed", newCfg.MCP.Allowed,
		"mcp_blocked_count", len(newCfg.MCP.Blocked),
		"enforcement", newCfg.Enforcement,
	)

	// Emit policy.reloaded audit event (best-effort).
	if s.eventStore != nil {
		_ = s.eventStore.Emit(ctx, audit.Event{
			EventType: audit.PolicyReloaded,
			Actor:     "daemon",
		})
	}
	s.recordPolicyConfig(newCfg, s.rulesDir)

	// Re-write the hook-fallback sidecar (ADR 0050) so a config change to
	// daemon_unreachable (or a locked-rule recompile) takes effect for the
	// hook without a daemon restart. Best-effort -- same rationale as the
	// startup write in main().
	if err := writeHookFallback(newCfg); err != nil {
		slog.Warn("reload: write hook-fallback sidecar failed (non-fatal)", "err", err)
		if s.eventStore != nil {
			_ = s.eventStore.Emit(ctx, audit.Event{
				EventType: audit.HookFallbackWriteFailed,
				Actor:     "daemon",
				Detail:    map[string]string{"err": err.Error()},
			})
		}
	}

	return nil
}

// handleConn serves one client connection. Each connection runs in its own
// goroutine. The function reads newline-delimited JSON requests until the
// connection closes or ctx is cancelled, calling s.eval for each and writing
// the response back.
func (s *server) handleConn(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	if s.connSem != nil {
		defer func() { <-s.connSem }()
	}

	scanner := bufio.NewScanner(conn)
	// 1 MB line buffer — large enough for realistic tool_input payloads.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	enc := json.NewEncoder(conn)

	// idleTimeout is immutable after construction (see server.idleTimeout), so
	// reading it here off the shared server is race-free across goroutines.
	idleTimeout := s.idleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultAgentConnIdleTimeout
	}

	for {
		// Reset the idle read deadline before each read (P9). A connection
		// that opens and then sends nothing (or trickles bytes slowly) is
		// cut off instead of holding a goroutine + 1 MB scanner buffer
		// indefinitely; a connection making steady requests is unaffected
		// since the deadline is pushed out again after each one completes.
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		if !scanner.Scan() {
			break
		}
		if ctx.Err() != nil {
			return
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		{
			var probe struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(line, &probe) == nil && probe.Type == hostproxy.RequestType {
				s.handleHostProxyExec(ctx, conn, enc, line)
				continue
			}
		}

		// Route grant_request to the grant server.
		{
			var probe struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(line, &probe) == nil && probe.Type == approvalexec.RedeemRequestType {
				s.handleApprovalRedeem(ctx, conn, enc, line)
				continue
			}
		}

		// Route grant_request to the grant server.
		if s.grantSrv != nil {
			var probe struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(line, &probe) == nil && probe.Type == string(grantctl.ReqGrantRequest) {
				var greq grantctl.Request
				if err := json.Unmarshal(line, &greq); err != nil {
					_ = enc.Encode(grantctl.Response{OK: false, Error: "malformed grant request"})
					continue
				}
				resp := s.grantSrv.handleGrantRequest(conn, greq)
				_ = enc.Encode(resp)
				continue
			}
		}

		// Route control-plane messages. ControlOpPing ONLY: it is
		// side-effect-free and must live here, because this is the socket the
		// single-instance guard probes for a squatter (singleton.go).
		//
		// ControlOpReload used to be served here too, on the reasoning that
		// re-reading on-disk rules is not a privileged mutation. That was
		// wrong (ADR 0066). This socket is reachable by the sandboxed agent BY
		// DESIGN -- shield_agentpaths.go grants a single-file write on
		// daemon.sock precisely so the hook can connect() -- and the peer-UID
		// check below cannot exclude it, because the agent runs as the same
		// UID as the daemon. SO_PEERCRED proves "same Unix user", not "outside
		// the sandbox"; it is identity, not authorization. Reload is cheap to
		// ask for and expensive to serve (a full Rego recompile), so on this
		// socket it was a DoS lever against a ~30ms hook budget that defaults
		// to fail-open -- i.e. a policy bypass. It now lives on the
		// sandbox-denied daemon-ctl.sock as grantctl.ReqDaemonReload.
		//
		// The peer-UID check stays as defence-in-depth against a
		// different-UID peer, which is all it can honestly do.
		{
			var probe struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(line, &probe) == nil && probe.Type == wire.ControlType {
				peerUID, uidErr := extractPeerUID(conn)
				if !peerUIDAllowed(peerUID, os.Getuid(), uidErr) {
					slog.Warn("control socket: rejecting connection", "peer_uid", peerUID, "daemon_uid", os.Getuid(), "err", uidErr)
					_ = enc.Encode(wire.ControlResponse{OK: false, Error: "unauthorized"})
					continue
				}

				var creq wire.ControlRequest
				if err := json.Unmarshal(line, &creq); err != nil {
					_ = enc.Encode(wire.ControlResponse{OK: false, Error: "malformed control request"})
					continue
				}
				switch creq.Op {
				case wire.ControlOpReload:
					// Refused here on purpose (ADR 0066) — see the block
					// comment above. This socket is reachable by the sandboxed
					// agent by design, and the peer-UID check cannot exclude a
					// same-UID peer, so serving a Rego recompile here is a
					// fail-open DoS lever. The CLI uses
					// grantctl.ReqDaemonReload on the sandbox-denied control
					// socket instead.
					slog.Warn("control reload refused on the agent socket — use the daemon control socket", "peer_uid", peerUID)
					_ = enc.Encode(wire.ControlResponse{OK: false, Error: "reload is not served on the agent socket; use the daemon control socket"})
				case wire.ControlOpPing:
					// Side-effect-free liveness probe for the single-instance
					// guard (see singleton.go). Reply OK and do nothing else.
					_ = enc.Encode(wire.ControlResponse{OK: true, Version: buildinfo.Version})
				default:
					_ = enc.Encode(wire.ControlResponse{OK: false, Error: "unknown control op: " + creq.Op})
				}
				continue
			}
		}

		var req policyeval.Request
		if err := json.Unmarshal(line, &req); err != nil {
			// Write a synthetic error response so the caller doesn't hang.
			_ = enc.Encode(policyeval.Response{
				ID:     "",
				Action: "ask",
				Reason: "malformed request: " + err.Error(),
			})
			slog.Warn("malformed request", "err", err)
			continue
		}

		// A user-space client can claim to be Codex in its JSON payload. The
		// native approval bridge therefore binds its challenge to the kernel-
		// observed peer's actual Codex ancestor, never the caller-reported PID.
		// See ADR 0118-codex-approval-broker.
		verifiedCodexPID := 0
		if req.Agent == "codex" && req.HookEvent == "PreToolUse" {
			if peerUID, uidErr := extractPeerUID(conn); uidErr == nil && peerUID == os.Getuid() {
				if peerPID, pidErr := extractPeerPID(conn); pidErr == nil {
					verifiedCodexPID, _ = procutil.FindAncestorPID(peerPID, func(pid int) bool {
						return procutil.PIDHasComm(pid, "codex")
					})
				}
			}
			if verifiedCodexPID > 0 {
				req.AgentPID = verifiedCodexPID
			}
		}

		// PostToolUse outcome report (ADR 0112): the hook observed the sandbox's
		// own EPERM signature after the tool ran and is telling us who actually
		// enforced the call. This is not a policy decision — route it to the
		// existing record instead of running Eval / enqueuing a new row.
		if req.HookEvent == "PostToolUse" || req.Outcome != nil {
			if s.eventStore != nil && req.Outcome != nil && req.Outcome.SandboxDenied && req.ToolUseID != "" {
				if err := s.eventStore.UpdateOutcome(ctx, req.ToolUseID, "blocked", "sandbox"); err != nil {
					slog.Debug("update outcome", "req_id", req.ID, "tool_use_id", req.ToolUseID, "err", err)
				}
			}
			_ = enc.Encode(policyeval.Response{ID: req.ID, Action: "allow"})
			continue
		}

		if req.Agent == "codex" && req.HookEvent == "PreToolUse" && s.approvals != nil {
			s.approvals.BeginToolCall(approvalexec.SessionID(req.SessionID))
			if command, _ := req.ToolInput["command"].(string); command != "" {
				if _, broker := approvalexec.ParseBrokerCommand(command); broker {
					_ = enc.Encode(policyeval.Response{
						ID: req.ID, Action: "deny", PolicyAction: "deny",
						EffectiveAction: "deny", Adapter: "codex",
						Reason: "direct approval broker invocation is not allowed",
					})
					continue
				}
			}
		}

		if req.Agent == "codex" && req.HookEvent == "PermissionRequest" && s.approvals != nil {
			if command, _ := req.ToolInput["command"].(string); command != "" {
				if invocation, ok := approvalexec.ParseBrokerCommand(command); ok {
					s.handleApprovalPrompt(ctx, conn, enc, req, invocation)
					continue
				}
			}
		}

		if req.SessionID != "" && s.activeSessions != nil && req.AgentPID > 0 {
			if verifiedCodexPID <= 0 || !s.activeSessions.bindVerified(req.SessionID, verifiedCodexPID, policyeval.CanonicalizeCWD(req.CWD)) {
				s.activeSessions.update(req.SessionID, req.AgentPID, req.CWD)
			}
		}

		start := time.Now()
		resp, err := s.evaluator.Eval(ctx, req)
		elapsed := time.Since(start)

		if err == nil {
			// Monitor mode downgrades here, before telemetry and persistence, so
			// every downstream consumer records what actually happened rather
			// than what policy wanted. See ADR 0091-monitor-mode-tools.
			resp = applyMonitorMode(resp, s.monitoring.Load())
			policyAction := resp.Action
			if resp.WouldAction != "" {
				policyAction = resp.WouldAction
			}
			translation := agentpolicy.Normalize(agentpolicy.Request{
				Agent:          req.Agent,
				HookEvent:      req.HookEvent,
				ToolName:       req.ToolName,
				RuleID:         resp.RuleID,
				PermissionMode: req.PermissionMode,
				PolicyAction:   agentpolicy.Action(policyAction),
				EnforcedAction: agentpolicy.Action(resp.Action),
				Capabilities:   req.Capabilities,
			})
			resp.PolicyAction = string(translation.PolicyAction)
			resp.EffectiveAction = string(translation.EffectiveAction)
			resp.Adapter = translation.Adapter
			resp.TranslationReason = translation.TranslationReason
			resp.DeferToNativePermission = translation.DeferToNativePermission
			resp.CodexApprovalBridge = translation.CodexApprovalBridge
			bridgeEligible := translation.CodexApprovalBridge
			approvalOperation := codexApprovalOperationFor(req.Capabilities)
			var preparedHostProxyTarget hostproxy.Target
			if resp.RuleID == "command_policy/confirm-host-proxy" {
				var prepErr error
				if preparedHostProxyTarget, prepErr = s.prepareHostProxy(req); prepErr != nil {
					resp.Action = "deny"
					resp.PolicyAction = "deny"
					resp.EffectiveAction = "deny"
					resp.CodexApprovalBridge = false
					bridgeEligible = false
					resp.RuleID = "host_proxy/preflight-deny"
					resp.Reason = prepErr.Error()
					resp.TranslationReason = "host proxy preflight failed closed"
					s.emitHostProxyEvent(ctx, audit.HostProxyDenied, req.SessionID, "preflight")
				} else {
					approvalOperation = approvalexec.HostProxyOperation
				}
			}
			if bridgeEligible && s.approvals != nil && verifiedCodexPID > 0 {
				command, _ := req.ToolInput["command"].(string)
				meta, mintErr := s.approvals.Mint(approvalexec.MintRequest{
					SessionID: approvalexec.SessionID(req.SessionID),
					TurnID:    approvalexec.TurnID(req.TurnID),
					ToolUseID: approvalexec.ToolUseID(req.ToolUseID),
					Operation: approvalOperation, Command: approvalexec.Command(command), CWD: req.CWD,
					AgentPID: req.AgentPID, RuleID: resp.RuleID, Now: time.Now(),
				})
				if mintErr != nil {
					resp.CodexApprovalBridge = false
					resp.EffectiveAction = "deny"
					resp.TranslationReason = "Codex approval challenge mint failed; fail closed"
					slog.Warn("codex approval challenge mint failed", "session_id", req.SessionID, "err", mintErr)
					if approvalOperation == approvalexec.HostProxyOperation {
						s.emitHostProxyEvent(ctx, audit.HostProxyDenied, req.SessionID, "challenge_mint")
					}
				} else {
					resp.ApprovalChallenge = string(meta.ChallengeID)
					resp.ApprovalOperation = string(meta.Operation)
					resp.ApprovalDisplay = approvalDisplayCommand(req.ToolInput)
					slog.Info("codex approval challenge minted", "session_id", req.SessionID, "rule_id", resp.RuleID)
					s.emitApprovalAudit(ctx, audit.CodexApprovalMinted, meta)
					if approvalOperation == approvalexec.HostProxyOperation {
						if s.eventStore != nil {
							_ = s.eventStore.Emit(ctx, audit.Event{
								EventType: audit.HostProxyRequested, Actor: "daemon", SessionID: req.SessionID,
								RefID:  hostProxyTargetRef(preparedHostProxyTarget),
								Detail: map[string]string{"reason": "approval_required", "cwd_ref": hostProxyPathRef(req.CWD)},
							})
						}
					}
				}
			} else if bridgeEligible {
				resp.CodexApprovalBridge = false
				resp.EffectiveAction = "deny"
				resp.TranslationReason = "Codex approval broker identity unavailable; fail closed"
				if approvalOperation == approvalexec.HostProxyOperation {
					s.emitHostProxyEvent(ctx, audit.HostProxyDenied, req.SessionID, "broker_identity")
				}
			}
			s.recordTelemetry(resp.Action, resp.RuleID, req.ToolName, req.Agent, elapsed)
		}

		// Extract a short identifying summary from tool_input — the command
		// string for Bash, the file_path for file tools, MCP server name for
		// MCP calls. Truncated to keep the log line bounded. This is what the
		// `agentjail logs -v` formatter shows on the same row as the verdict.
		summary := policyeval.SummarizeToolInput(req.ToolName, req.ToolInput)

		// Full redacted input for the log line, same redactor + 4096 cap the
		// store persists (ADR 0019). The UI's live SSE feed is parsed from
		// this log; with only the 200-char summary, the monitor's detail
		// pane showed live events cut mid-command.
		redactedInput := store.RedactToolInput(req.ToolInput)

		// Write the response to the client BEFORE logging. This ensures that
		// log rotation (which holds a mutex and may do file I/O) does not add
		// latency to the hook response. The client is unblocked first; the log
		// write follows. If the client has already disconnected we still log
		// the eval result for forensics (the log is useful even when the hook
		// fell open).
		encErr := enc.Encode(resp)
		if encErr != nil {
			if isClientGone(encErr) {
				// The caller (e.g. agentjail-hook) closed the connection before we
				// finished writing — expected whenever eval exceeds the hook's
				// request-specific deadline. The hook has already fallen open;
				// this is a benign race, not a daemon fault, so keep it out of the
				// Info-level log that `agentjail logs` surfaces.
				slog.Debug("response not delivered: client disconnected", "req_id", req.ID, "err", encErr)
			} else {
				slog.Warn("write response", "req_id", req.ID, "err", encErr)
			}
			// Fall through to log the eval result even when the client is gone.
		}

		// NOTE on `elapsed_us` (see docs/adr/0002-latency-as-engineering-metric.md):
		// This measures cache lookup + (on miss) OPA Rego eval + cache set —
		// internal to s.eval. It is NOT the user-perceived latency. End-to-end
		// wall time = elapsed_us + ~10 ms plumbing (hook fork/exec, socket I/O,
		// JSON marshal). When citing performance externally, use the smoke test's
		// end-to-end wall time, not this field. The field is kept for forensics;
		// the user-facing `agentjail logs` rich view hides it.
		if err != nil {
			slog.Warn("eval error", "req_id", req.ID, "tool", req.ToolName, "session_id", req.SessionID, "agent", req.Agent, "cwd", req.CWD, "summary", summary, "err", err, "elapsed_us", elapsed.Microseconds())
		} else {
			slog.Info("eval", "req_id", req.ID, "tool", req.ToolName, "session_id", req.SessionID, "agent", req.Agent, "cwd", req.CWD, "summary", summary, "tool_input_redacted", redactedInput, "action", resp.Action, "would_action", resp.WouldAction, "policy_action", resp.PolicyAction, "effective_action", resp.EffectiveAction, "adapter", resp.Adapter, "translation_reason", resp.TranslationReason, "rule_id", resp.RuleID, "reason", resp.Reason, "impact", resp.Impact, "elapsed_us", elapsed.Microseconds())
			// Persist the decision to SQLite (async, fail-open). The full
			// tool_input is redacted at the store boundary (ADR 0019).
			s.enqueueDecision(store.DecisionRecord{
				Ts:                time.Now(),
				SessionID:         req.SessionID,
				Agent:             req.Agent,
				ToolName:          req.ToolName,
				Summary:           summary,
				Action:            resp.Action,
				WouldAction:       resp.WouldAction,
				PolicyAction:      resp.PolicyAction,
				EffectiveAction:   resp.EffectiveAction,
				Adapter:           resp.Adapter,
				TranslationReason: resp.TranslationReason,
				RuleID:            resp.RuleID,
				Reason:            resp.Reason,
				Impact:            resp.Impact,
				ElapsedUs:         elapsed.Microseconds(),
				CWD:               req.CWD,
				ToolInput:         req.ToolInput,
				// Seed the final outcome from the enforced policy verdict (ADR
				// 0112). A policy deny is already final; an allow is provisional
				// until PostToolUse reports whether the sandbox overrode it.
				ToolUseID:   req.ToolUseID,
				FinalAction: finalFromAction(resp.EffectiveAction),
				Enforcer:    "policy",
			})
		}

		if encErr != nil && !isClientGone(encErr) {
			return
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("scanner error", "err", err)
	}
}

const maxApprovalDisplayRunes = 2048

func approvalDisplayCommand(toolInput map[string]interface{}) string {
	redacted := store.RedactToolInput(toolInput)
	var input struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal([]byte(redacted), &input); err != nil || input.Command == "" {
		return "command unavailable"
	}

	var display strings.Builder
	for _, r := range input.Command {
		switch {
		case r == '\n' || r == '\r':
			display.WriteString(" ↵ ")
		case r == '\t':
			display.WriteByte(' ')
		case unicode.IsPrint(r):
			display.WriteRune(r)
		}
	}
	runes := []rune(strings.TrimSpace(display.String()))
	if len(runes) > maxApprovalDisplayRunes {
		return string(runes[:maxApprovalDisplayRunes]) + "…"
	}
	if len(runes) == 0 {
		return "git push (command unavailable)"
	}
	return string(runes)
}

func approvalRef(id approvalexec.ChallengeID) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:8])
}

func codexApprovalOperationFor(capabilities []string) approvalexec.Operation {
	legacy := false
	for _, capability := range capabilities {
		switch capability {
		case wire.CapabilityCodexShellApprovalV1:
			return approvalexec.ShellCommandOperation
		case wire.CapabilityCodexApprovalBridgeV1:
			legacy = true
		}
	}
	if legacy {
		return approvalexec.GitPushOperation
	}
	return ""
}

func (s *server) emitApprovalAudit(ctx context.Context, eventType string, meta approvalexec.Metadata) error {
	if s.eventStore == nil {
		return errors.New("durable audit store unavailable")
	}
	return s.eventStore.Emit(ctx, audit.Event{
		EventType: eventType,
		Actor:     "daemon",
		SessionID: string(meta.SessionID),
		RefID:     approvalRef(meta.ChallengeID),
		Entity:    meta.RuleID,
		Detail: map[string]string{
			"operation":   string(meta.Operation),
			"tool_use_id": string(meta.ToolUseID),
		},
	})
}

func (s *server) handleApprovalPrompt(
	ctx context.Context,
	conn net.Conn,
	enc *json.Encoder,
	req policyeval.Request,
	invocation approvalexec.BrokerInvocation,
) {
	meta, err := s.approvals.Inspect(invocation.ChallengeID, time.Now())
	if err == nil {
		peerUID, uidErr := extractPeerUID(conn)
		peerPID, pidErr := extractPeerPID(conn)
		_, descends := procutil.FindAncestorPID(peerPID, func(pid int) bool {
			return pid == meta.AgentPID
		})
		if uidErr != nil || pidErr != nil || peerUID != os.Getuid() || !descends {
			err = approvalexec.ErrBinding
		}
	}
	var boundary procutil.StartMarker
	if err == nil {
		boundary, err = procutil.NextStartBoundary()
	}
	if err == nil {
		_, err = s.approvals.ObservePrompt(approvalexec.ObserveRequest{
			ChallengeID: invocation.ChallengeID,
			Operation:   invocation.Operation,
			SessionID:   approvalexec.SessionID(req.SessionID),
			TurnID:      approvalexec.TurnID(req.TurnID),
			CWD:         req.CWD,
			FreshAfter:  uint64(boundary),
			Now:         time.Now(),
		})
	}
	if err != nil {
		slog.Warn("codex approval prompt rejected", "challenge_ref", approvalRef(invocation.ChallengeID), "err", err)
		_ = enc.Encode(policyeval.Response{
			ID: req.ID, Action: "deny", PolicyAction: "deny",
			EffectiveAction: "deny", Adapter: "codex",
			Reason: "invalid or expired AgentJail approval challenge",
		})
		return
	}
	meta, _ = s.approvals.Inspect(invocation.ChallengeID, time.Now())
	slog.Info("codex approval prompt observed", "challenge_ref", approvalRef(invocation.ChallengeID), "session_id", req.SessionID)
	_ = s.emitApprovalAudit(ctx, audit.CodexPromptObserved, meta)
	_ = enc.Encode(policyeval.Response{
		ID: req.ID, Action: "ask", PolicyAction: "ask",
		EffectiveAction: "ask", Adapter: "codex",
		DeferToNativePermission: true,
		Reason:                  "AgentJail requires native Codex approval",
	})
}

func (s *server) handleApprovalRedeem(
	ctx context.Context,
	conn net.Conn,
	enc *json.Encoder,
	line []byte,
) {
	var req approvalexec.WireRedeemRequest
	if err := json.Unmarshal(line, &req); err != nil || req.ChallengeID == "" {
		_ = enc.Encode(approvalexec.WireRedeemResponse{Error: "malformed approval redemption"})
		return
	}
	meta, err := s.approvals.Inspect(req.ChallengeID, time.Now())
	var verifiedSession approvalexec.SessionID
	peerFresh := false
	peerPID := 0
	if err == nil {
		peerUID, uidErr := extractPeerUID(conn)
		var pidErr error
		peerPID, pidErr = extractPeerPID(conn)
		if uidErr == nil && pidErr == nil && peerUID == os.Getuid() && s.activeSessions != nil {
			sessionID, _, active := s.activeSessions.findSessionByPID(peerPID)
			if active && sessionID == string(meta.SessionID) {
				verifiedSession = approvalexec.SessionID(sessionID)
				peerFresh = procutil.DescendantChainStartedAtOrAfter(
					peerPID, meta.AgentPID, procutil.StartMarker(meta.FreshAfter),
				)
			}
		}
	}
	var redeemed approvalexec.Redemption
	if err == nil {
		// Redeem owns the burn. Even an invalid peer reaches this one-use state
		// transition with empty verification fields. See ADR 0118-codex-approval-broker.
		redeemed, err = s.approvals.Redeem(approvalexec.RedeemRequest{
			ChallengeID: req.ChallengeID, Operation: req.Operation, VerifiedSession: verifiedSession,
			PeerChainFresh: peerFresh,
			CurrentEpoch:   s.approvals.CurrentEpoch(meta.SessionID),
			Now:            time.Now(),
		})
	}
	if err == nil {
		if auditErr := s.emitApprovalAudit(ctx, audit.CodexApprovalRedeemed, meta); auditErr != nil {
			err = fmt.Errorf("record approval redemption: %w", auditErr)
		}
	}
	if err == nil {
		if outcomeErr := s.eventStore.UpdateOutcome(ctx, string(redeemed.ToolUseID), "allowed", "policy"); outcomeErr != nil {
			err = fmt.Errorf("record approval outcome: %w", outcomeErr)
		}
	}
	var proxyAuth hostproxy.Authorization
	if err == nil && redeemed.Operation == approvalexec.HostProxyOperation {
		proxyAuth, err = s.issueHostProxyAuthorization(redeemed, meta, peerPID)
	}
	if err != nil {
		slog.Warn("codex approval redemption rejected", "challenge_ref", approvalRef(req.ChallengeID), "err", err)
		if s.eventStore != nil {
			_ = s.eventStore.Emit(ctx, audit.Event{
				EventType: audit.CodexApprovalRejected,
				Actor:     "daemon", RefID: approvalRef(req.ChallengeID),
			})
		}
		if meta.Operation == approvalexec.HostProxyOperation {
			s.emitHostProxyEvent(ctx, audit.HostProxyDenied, string(meta.SessionID), "approval_redemption")
		}
		_ = enc.Encode(approvalexec.WireRedeemResponse{Error: "approval unavailable or no longer valid"})
		return
	}
	slog.Info("codex approval redeemed", "challenge_ref", approvalRef(req.ChallengeID), "session_id", redeemed.SessionID)
	if redeemed.Operation == approvalexec.HostProxyOperation {
		_ = enc.Encode(approvalexec.WireRedeemResponse{
			OK: true, CWD: redeemed.CWD, ToolUseID: redeemed.ToolUseID,
			HostProxyProof: string(proxyAuth.Proof), HostProxyExecutable: proxyAuth.Target.Executable,
			HostProxyArgv: proxyAuth.Target.Argv,
		})
		return
	}
	_ = enc.Encode(approvalexec.WireRedeemResponse{
		OK: true, Command: redeemed.Command, CWD: redeemed.CWD,
		ToolUseID: redeemed.ToolUseID,
	})
}

func (s *server) prepareHostProxy(req policyeval.Request) (hostproxy.Target, error) {
	if s.activeSessions == nil {
		return hostproxy.Target{}, errors.New("host proxy session metadata unavailable")
	}
	state, ok := s.activeSessions.metadata(req.SessionID)
	if !ok {
		return hostproxy.Target{}, errors.New("host proxy requires an authenticated shield launch")
	}
	cwd := policyeval.CanonicalizeCWD(req.CWD)
	if !hostproxy.WithinRoot(state.Root, cwd) {
		return hostproxy.Target{}, errors.New("host proxy working directory is outside the registered session root")
	}
	command, _ := req.ToolInput["command"].(string)
	argv, err := hostproxy.ParseCommand(command)
	if err != nil {
		return hostproxy.Target{}, err
	}
	target, err := hostproxy.Resolve(state.Path, cwd, argv)
	if err != nil {
		return hostproxy.Target{}, err
	}
	decision := hostproxy.Evaluate(target)
	if decision.Action != hostproxy.ActionAsk {
		return hostproxy.Target{}, errors.New(decision.Reason)
	}
	return target, nil
}

func (s *server) issueHostProxyAuthorization(redeemed approvalexec.Redemption, meta approvalexec.Metadata, peerPID int) (hostproxy.Authorization, error) {
	if s.hostProxyApprovals == nil || s.activeSessions == nil {
		return hostproxy.Authorization{}, errors.New("host proxy authorization unavailable")
	}
	state, ok := s.activeSessions.metadata(string(redeemed.SessionID))
	if !ok {
		return hostproxy.Authorization{}, errors.New("host proxy session metadata unavailable")
	}
	argv, err := hostproxy.ParseCommand(string(redeemed.Command))
	if err != nil {
		return hostproxy.Authorization{}, err
	}
	cwd := policyeval.CanonicalizeCWD(redeemed.CWD)
	if !hostproxy.WithinRoot(state.Root, cwd) {
		return hostproxy.Authorization{}, errors.New("host proxy working directory is outside the registered session root")
	}
	target, err := hostproxy.Resolve(state.Path, cwd, argv)
	if err != nil {
		return hostproxy.Authorization{}, err
	}
	if decision := hostproxy.Evaluate(target); decision.Action != hostproxy.ActionAsk {
		return hostproxy.Authorization{}, errors.New(decision.Reason)
	}
	return s.hostProxyApprovals.Issue(hostproxy.Authorization{
		SessionID: hostproxy.SessionID(redeemed.SessionID), Target: target,
		CWD: cwd, Root: state.Root, Path: state.Path, BrokerPID: peerPID,
		FreshAfter: meta.FreshAfter,
	}, time.Now())
}

func (s *server) handleHostProxyExec(ctx context.Context, conn net.Conn, enc *json.Encoder, line []byte) {
	deny := func(reason string) {
		s.emitHostProxyEvent(ctx, audit.HostProxyDenied, "", reason)
		_ = enc.Encode(hostproxy.WireResponse{Error: "host proxy authorization unavailable or invalid"})
	}
	if s.hostProxyApprovals == nil || s.hostProxyExecutor == nil || s.activeSessions == nil {
		deny("unavailable")
		return
	}
	var wireReq hostproxy.WireRequest
	if err := json.Unmarshal(line, &wireReq); err != nil || wireReq.Request.Proof == "" {
		deny("malformed")
		return
	}
	peerUID, uidErr := extractPeerUID(conn)
	peerPID, pidErr := extractPeerPID(conn)
	if uidErr != nil || pidErr != nil || peerUID != os.Getuid() {
		deny("peer_identity")
		return
	}
	auth, err := s.hostProxyApprovals.Inspect(wireReq.Request.Proof, time.Now())
	if err != nil {
		deny("proof")
		return
	}
	if len(line) > hostproxy.MaxRequestBytes {
		_, _ = s.hostProxyApprovals.Redeem(hostproxy.RedeemRequest{Proof: wireReq.Request.Proof, CurrentTime: time.Now()})
		deny("request_too_large")
		return
	}
	sessionID, _, active := s.activeSessions.findSessionByPID(peerPID)
	state, metadataOK := s.activeSessions.metadata(sessionID)
	verifiedCWD := policyeval.CanonicalizeCWD(wireReq.Request.CWD)
	peerFresh := false
	if active && metadataOK {
		peerFresh = procutil.DescendantChainStartedAtOrAfter(peerPID, state.PID, procutil.StartMarker(auth.FreshAfter))
	}
	auth, err = s.hostProxyApprovals.Redeem(hostproxy.RedeemRequest{
		Proof: wireReq.Request.Proof, SessionID: hostproxy.SessionID(sessionID), Target: wireReq.Request.Target,
		CWD: verifiedCWD, PeerPID: peerPID, PeerChainFresh: peerFresh, CurrentTime: time.Now(),
	})
	if err != nil {
		deny("redeem")
		return
	}
	if !hostproxy.WithinRoot(auth.Root, auth.CWD) {
		deny("cwd_outside_root")
		return
	}
	resolved, err := hostproxy.Resolve(auth.Path, auth.CWD, auth.Target.Argv)
	if err != nil || resolved.Executable != auth.Target.Executable || hostproxy.Evaluate(resolved).Action != hostproxy.ActionAsk {
		deny("revalidation")
		return
	}
	if s.eventStore == nil {
		deny("audit_unavailable")
		return
	}
	ref := hostProxyTargetRef(resolved)
	if err := s.eventStore.Emit(ctx, audit.Event{
		EventType: audit.HostProxyAuthorizationRedeemed, Actor: "daemon", SessionID: sessionID, RefID: ref,
	}); err != nil {
		deny("audit_failed")
		return
	}
	result := s.hostProxyExecutor.Execute(ctx, resolved, auth.CWD, hostproxy.DefaultTimeout, hostproxy.DefaultOutputLimit, func(int) {
		slog.Info("host proxy process started", "session_id", sessionID, "target_ref", ref)
		_ = s.eventStore.Emit(ctx, audit.Event{EventType: audit.HostProxyStarted, Actor: "daemon", SessionID: sessionID, RefID: ref})
	})
	slog.Info("host proxy process completed", "session_id", sessionID, "target_ref", ref, "exit_code", result.ExitCode, "reason", result.Reason)
	_ = s.eventStore.Emit(ctx, audit.Event{
		EventType: audit.HostProxyCompleted, Actor: "daemon", SessionID: sessionID, RefID: ref,
		Detail: map[string]string{"exit_code": strconv.Itoa(result.ExitCode), "reason": result.Reason,
			"timed_out": strconv.FormatBool(result.TimedOut), "truncated": strconv.FormatBool(result.Truncated),
			"duration_ns": strconv.FormatInt(result.Duration.Nanoseconds(), 10), "cwd_ref": hostProxyPathRef(auth.CWD)},
	})
	_ = enc.Encode(hostproxy.WireResponse{OK: true, Result: result})
}

func hostProxyTargetRef(target hostproxy.Target) string {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Executable))
	for _, arg := range target.Argv {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(arg))
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func hostProxyPathRef(path string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:8])
}

func (s *server) emitHostProxyEvent(ctx context.Context, eventType, sessionID, reason string) {
	if s.eventStore == nil {
		return
	}
	detail := map[string]string{}
	if reason != "" {
		detail["reason"] = reason
	}
	_ = s.eventStore.Emit(ctx, audit.Event{EventType: eventType, Actor: "daemon", SessionID: sessionID, Detail: detail})
}

// acceptConn admits conn onto an agent-socket worker goroutine, subject to
// the bounded-concurrency cap (P9): if s.connSem is at capacity, conn is
// closed immediately instead of blocking the accept loop (which would delay
// every other agent) or spawning unboundedly (which would let one
// hostile/misbehaving peer exhaust daemon memory/goroutines and starve
// latency for everyone, pushing hooks past their fail-open deadline). A nil
// s.connSem (e.g. a bare server{} built directly in tests) means no cap is
// enforced.
func (s *server) acceptConn(ctx context.Context, conn net.Conn) {
	if s.connSem == nil {
		s.wg.Add(1)
		go s.handleConn(ctx, conn)
		return
	}
	select {
	case s.connSem <- struct{}{}:
		s.wg.Add(1)
		go s.handleConn(ctx, conn)
	default:
		slog.Warn("daemon.sock: max concurrent connections reached; rejecting connection", "max", maxAgentConns)
		_ = conn.Close()
	}
}

// isClientGone reports whether err indicates the peer closed the connection
// before the daemon could write its response (broken pipe, connection reset, or
// an already-closed socket). Under the hook's fail-open deadline this is an
// expected race rather than a daemon error, so the caller logs it at Debug.
func isClientGone(err error) bool {
	return errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, net.ErrClosed)
}

// setMonitoring records the enforcement mode and, when it actually changes,
// emits an audit event. Monitor mode means nothing is enforced; the decisions
// table alone cannot explain a run of allows, so the window must be
// reconstructable from the audit log. Called on startup and after every
// successful reload. See ADR 0091-monitor-mode-tools.
func (s *server) setMonitoring(monitoring bool) {
	if s.monitoring.Swap(monitoring) == monitoring {
		return // unchanged -- a reload that did not touch the mode stays quiet
	}
	mode := string(agentconfig.EnforcementEnforce)
	if monitoring {
		mode = string(agentconfig.EnforcementMonitor)
		slog.Warn("enforcement mode: MONITOR — policy verdicts are recorded, nothing is blocked")
	} else {
		slog.Info("enforcement mode: enforce")
	}
	if s.eventStore != nil {
		_ = s.eventStore.Emit(context.Background(), audit.Event{
			EventType: audit.EnforcementModeChanged,
			Actor:     "daemon",
			Detail:    map[string]string{"mode": mode},
		})
	}
}

// actionAllow is the permissive verdict. The action vocabulary is a bare string
// at every layer (policy.Decision, policyeval.Response, store.DecisionRecord)
// with no enum to check it -- see AGE-242's landmine note. Monitor mode
// therefore adds no new action value; it downgrades to this one and records the
// original in WouldAction.
const actionAllow = "allow"

// applyMonitorMode downgrades an enforcing verdict to allow and parks the real
// verdict in WouldAction, so the decision row and the hook can both say what
// policy wanted without claiming it happened. Enforce mode, an allow, or an
// empty action returns resp untouched.
//
// Deliberately not inside policyeval.Eval: its decision cache is keyed on input
// only, so flipping the mode there would poison cached entries across a reload.
// See ADR 0091-monitor-mode-tools.
func applyMonitorMode(resp policyeval.Response, monitoring bool) policyeval.Response {
	if !monitoring || resp.Action == "" || resp.Action == actionAllow {
		return resp
	}
	resp.WouldAction = resp.Action
	resp.Action = actionAllow
	return resp
}

// finalFromAction maps an enforced policy action to the FinalAction stored on
// the decision record (ADR 0112). PostToolUse may later flip this to
// "blocked"/"sandbox" if the sandbox denied a policy-allowed call.
func finalFromAction(action string) string {
	switch action {
	case "deny":
		return "blocked"
	case actionAllow:
		return "allowed"
	case "ask":
		return "ask"
	default:
		return action
	}
}

// loadConfig loads ~/.agentjail/policy.yaml, merges it over Default(), and
// injects the resolved temp roots.  Returns the merged config.  If the file
// does not exist, Default() is returned with temp roots injected.
func loadConfig(policyPath string) (*agentconfig.PolicyConfig, error) {
	cfg, err := agentconfig.LoadOrDefault(policyPath)
	if err != nil {
		return nil, err
	}
	// Always inject temp roots so Rego never needs env access.
	cfg.File.TempRoots = policyeval.BuildTempRoots()
	return cfg, nil
}

// coreFileNames is the set of rego file stems that are always-on core rules
// (shipped with the binary, managed by agentjail install, never custom).
// Custom rules are any *.rego in rulesDir whose stem is NOT in this set and
// NOT in the library set.  We use file-stem matching (the same convention as
// installCoreRules in the CLI) rather than package inspection.
//
// NOTE: this list must stay in sync with coreRuleNames() in
// cmd/agentjail/library_embed.go.  If a new core file is added there, add the
// stem here too so the daemon correctly classifies it as non-custom and doesn't
// subject it to staged quarantine.
var coreFileStems = map[string]bool{
	"aws_posture":    true,
	"command_policy": true,
	"file_policy":    true,
	"internal_tools": true,
	"mcp_policy":     true,
	"web_policy":     true,
	"no_daemon_kill": true,
	"resolver":       true,
}

// libraryFileStems is the set of rego file stems that are opt-in library rules.
// Any file in rulesDir with one of these stems is treated as a library rule
// (not custom) and loaded unconditionally as part of the baseline.
//
// NOTE: must match libraryRuleNames() in cmd/agentjail/library_embed.go.
var libraryFileStems = map[string]bool{
	"no_app_binary_write": true,
	"no_aws_destructive":  true,
	"no_destructive_git":  true,
	"no_history_read":     true,
	"no_launchctl":        true,
	"no_shell_eval":       true,
	"no_shell_init_write": true,
}

// loadModules reads all *.rego files from rulesDir (non-recursive, top-level
// only) and returns them as a slice of (filename, source) pairs suitable for
// passing to NewHookOPAEngineWithData.
//
// Staged quarantine (ADR 0014 §5): the function compiles the core+library
// baseline first, then adds custom rule files ONE AT A TIME in sorted
// (deterministic) filename order.  A custom file that breaks the accumulated
// bundle is logged at WARN and skipped — it never prevents the baseline from
// loading.  The daemon therefore NEVER fails startup and NEVER goes open because
// of a bad custom rule.
//
// A file is "custom" if its stem is not in coreFileStems or libraryFileStems.
func loadModules(rulesDir string) ([][2]string, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %s: %w", rulesDir, err)
	}

	type regoFile struct {
		name string // filename (with .rego)
		src  string
	}

	var baselineFiles []regoFile
	var customFiles []regoFile

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".rego") {
			continue
		}
		// Skip OPA test files — only for `opa test`.
		if strings.HasSuffix(name, "_test.rego") {
			continue
		}
		full := filepath.Join(rulesDir, name)
		b, rerr := os.ReadFile(full)
		if rerr != nil {
			return nil, fmt.Errorf("read %s: %w", full, rerr)
		}
		stem := strings.TrimSuffix(name, ".rego")
		rf := regoFile{name: full, src: string(b)}
		if coreFileStems[stem] || libraryFileStems[stem] {
			baselineFiles = append(baselineFiles, rf)
		} else {
			customFiles = append(customFiles, rf)
		}
	}

	// Assemble the baseline module list.
	baseline := make([][2]string, 0, len(baselineFiles))
	for _, f := range baselineFiles {
		baseline = append(baseline, [2]string{f.name, f.src})
	}

	// If there are no custom files, return the baseline unchanged (happy path —
	// identical behaviour to before this change).
	if len(customFiles) == 0 {
		return baseline, nil
	}

	// Sort custom files for deterministic quarantine order.
	sort.Slice(customFiles, func(i, j int) bool {
		return customFiles[i].name < customFiles[j].name
	})

	// Staged accumulation: try to add each custom file to the growing bundle.
	// We probe by compiling; the ctx is background (compile is fast).
	ctx := context.Background()
	accumulated := make([][2]string, len(baseline))
	copy(accumulated, baseline)

	for _, cf := range customFiles {
		if err := custompolicy.ValidateModule(cf.name, cf.src); err != nil {
			slog.Warn("skipping custom rule: authoring contract violation", "file", cf.name, "err", err)
			continue
		}
		candidate := append(accumulated, [2]string{cf.name, cf.src}) //nolint:gocritic
		_, compileErr := policy.NewHookOPAEngine(ctx, candidate)
		if compileErr != nil {
			// Bad custom file — log WARN and skip; do not update accumulated.
			slog.Warn("skipping custom rule: bundle compile error",
				"file", cf.name,
				"err", compileErr,
			)
			continue
		}
		// File is good — keep it in the accumulation.
		accumulated = candidate
	}

	return accumulated, nil
}

// defaultSocketPath returns ~/.agentjail/daemon.sock.
func defaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-daemon.sock"
	}
	return filepath.Join(home, ".agentjail", "daemon.sock")
}

// defaultPolicyPath returns ~/.agentjail/policy.yaml.
func defaultPolicyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-policy.yaml"
	}
	return filepath.Join(home, ".agentjail", "policy.yaml")
}

// defaultLogPath returns ~/.agentjail/daemon.log.
func defaultLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-daemon.log"
	}
	return filepath.Join(home, ".agentjail", "daemon.log")
}

// removeFailOpenSentinel deletes the fail-open warning sentinel
// (~/.agentjail/fail-open-warned) so agentjail-hook's "warn once" gate
// re-arms after a successful daemon startup (U2). Uses the same path
// construction as the hook (wire.FailOpenWarnedSentinelPath) so the two
// sides can never drift apart. Best-effort: a missing file (the common
// case — no prior fail-open) is not an error and is not logged; any other
// removal failure is logged at Warn since it means the next daemon outage
// will silently fail to re-warn the user.
func removeFailOpenSentinel() {
	path := wire.FailOpenWarnedSentinelPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		slog.Warn("remove fail-open sentinel", "path", path, "err", err)
	}
}

// defaultDBPath returns ~/.agentjail/agentjail.db (the SQLite store, ADR 0018).
func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail.db"
	}
	return filepath.Join(home, ".agentjail", "agentjail.db")
}

// Run executes the agentjail-daemon entrypoint with the given args (i.e.
// os.Args[1:]) and returns a process exit code.
func Run(args []string) int {
	fs := flag.NewFlagSet("agentjail-daemon", flag.ContinueOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "path to Unix domain socket")
	policyPath := fs.String("policy", defaultPolicyPath(), "path to policy.yaml (data overlay for OPA)")
	rulesDir := fs.String("rules", "", "path to Rego rules directory (default: uses inline default policy)")
	logPath := fs.String("log", defaultLogPath(), "path to structured log file (rotated internally)")
	dbPath := fs.String("db", defaultDBPath(), "path to SQLite event store (~/.agentjail/agentjail.db)")
	retentionDur := fs.Duration("retention", 30*24*time.Hour, "max age to retain decisions/audit events in the store (e.g. 720h)")
	retentionInterval := fs.Duration("retention-interval", 6*time.Hour, "how often to re-run retention cleanup + body sweep on a long-lived daemon (0 = startup only). See ADR 0101-periodic-retention")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Open the rotating log writer before setting up slog so all startup
	// messages land in the file. 10 MB per file, 5 rotated backups.
	logWriter, err := logrotate.New(*logPath, 10*1024*1024, 5)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-daemon: open log %s: %v\n", *logPath, err)
		return 1
	}
	defer logWriter.Close()

	// Structured JSON logging to the rotating file. slog default level = Info.
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("agentjail-daemon starting",
		"version", buildinfo.Version,
		"socket", *socketPath,
		"policy", *policyPath,
		"rules_dir", *rulesDir,
	)

	// Ensure the socket directory exists with 0700 so other users cannot
	// enumerate or connect to the daemon socket.
	socketDir := filepath.Dir(*socketPath)
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		slog.Error("create socket dir", "dir", socketDir, "err", err)
		return 1
	}

	// Single-instance guard: hold an exclusive flock on daemon.lock (beside the
	// socket) before touching the socket, so a second daemon — a different
	// install channel, a manual run, or an upgrade transition — stands down
	// instead of hijacking daemon.sock. Kept for the process lifetime; the OS
	// releases it on exit/crash. Stale-socket removal is deferred to
	// bindAgentSocket, which probes before unlinking. See singleton.go / ADR 0060.
	lockPath := filepath.Join(socketDir, instanceLockName)
	instanceLock, acquired, lockErr := acquireInstanceLock(lockPath, instanceLockRetries, instanceLockInterval)
	if lockErr != nil {
		slog.Error("acquire instance lock", "path", lockPath, "err", lockErr)
		return 1
	}
	if !acquired {
		slog.Info("another agentjail-daemon is already running; standing down", "lock", lockPath)
		return 0
	}
	defer func() { _ = instanceLock.Close() }()

	// Load initial policy config — merge policy.yaml over Default(), inject temp roots.
	cfg, err := loadConfig(*policyPath)
	if err != nil {
		slog.Error("load policy config", "path", *policyPath, "err", err)
		return 1
	}
	if warns := agentconfig.Validate(cfg); len(warns) > 0 {
		for _, w := range warns {
			slog.Warn("policy config warning", "warning", w)
		}
	}
	slog.Info("policy config loaded",
		"mcp_allowed", cfg.MCP.Allowed,
		"mcp_blocked_count", len(cfg.MCP.Blocked),
		"temp_roots", cfg.File.TempRoots,
	)

	// Load initial Rego modules.
	var initModules [][2]string
	if *rulesDir != "" {
		mods, err := loadModules(*rulesDir)
		if err != nil {
			slog.Error("load rego modules", "rules_dir", *rulesDir, "err", err)
			return 1
		}
		initModules = mods
		slog.Info("loaded rego modules", "count", len(mods), "rules_dir", *rulesDir)
	} else {
		// No --rules flag: use the inline default policy so the daemon can
		// start and evaluate requests in dev/test. In production, --rules
		// points to the agentpolicy/policies/ directory.
		slog.Info("no --rules dir specified; using inline default policy (deny rm -rf, allow everything else)")
		initModules = [][2]string{
			{"default.rego", defaultInlinePolicy},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build the initial engine with config data injected.
	// Rego reads data.agentjail.config.mcp.allowed etc, so wrap under "config".
	initOPAData := map[string]interface{}{
		"config": cfg.ToOPAData(),
	}
	eng, err := policy.NewHookOPAEngineWithData(ctx, initModules, initOPAData)
	if err != nil {
		slog.Error("compile rego", "err", err)
		return 1
	}

	srv := &server{
		evaluator:          policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), initModules, cfg),
		approvals:          approvalexec.NewManager(nil, 0, 0),
		hostProxyApprovals: hostproxy.NewManager(nil, 0),
		hostProxyExecutor:  hostproxy.NewExecutor(),
		activeSessions:     newActiveTracker(filepath.Dir(*policyPath)),
		connSem:            make(chan struct{}, maxAgentConns),
		rulesDir:           *rulesDir,
		policyPath:         *policyPath,
		idleTimeout:        defaultAgentConnIdleTimeout,
	}

	// Open the SQLite event store (ADR 0018). Failure is non-fatal: the daemon
	// continues without persistence (fail-open on logging). On first run, if
	// daemon.log exists and the store is empty, import the historical JSON-lines
	// decisions (best-effort). Then run retention cleanup + start the async
	// drain goroutine.
	if st, serr := store.Open(*dbPath); serr == nil {
		srv.eventStore = st
		srv.decCh = make(chan store.DecisionRecord, 1024)
		migrateDaemonLog(ctx, st, *logPath)
		srv.decWg.Add(1)
		go srv.drainDecisions(ctx)
		slog.Info("sqlite event store opened", "db", *dbPath, "retention", *retentionDur)
	} else {
		slog.Warn("sqlite event store open failed; continuing without persistence (fail-open on logging)", "db", *dbPath, "err", serr)
	}

	// Enforce retention now, then on a ticker: Cleanup runs exactly once at
	// startup otherwise, so a long-lived daemon (Restart=always, ADR 0070) would
	// stop enforcing its window after the first second. See ADR 0101-periodic-retention (AGE-225).
	srv.retentionSweep(ctx, *retentionDur)
	go retentionLoop(ctx, *retentionInterval, func() { srv.retentionSweep(ctx, *retentionDur) })

	// After the store is wired, so the mode-changed audit event has somewhere to
	// land. The zero value is false (enforce), so a monitor-mode config emits the
	// event on startup and an enforce-mode one stays silent.
	srv.setMonitoring(cfg.Monitoring())

	// Wire telemetry recorder: nil-safe, failure-tolerant — if init fails, the
	// daemon continues without telemetry. The same ctx is cancelled on
	// SIGTERM/SIGINT, which triggers Recorder.Run's final flush on shutdown.
	if tp, perr := telemetry.DefaultPaths(); perr == nil {
		if rec, rerr := telemetry.New(tp, os.Getenv, buildinfo.Version, runtime.GOOS, runtime.GOARCH, telemetry.DefaultClient()); rerr == nil {
			srv.telemetry = rec
			go rec.Run(ctx) // ctx is cancelled on SIGTERM/SIGINT → triggers final flush
			srv.recordPolicyConfig(cfg, *rulesDir)
		} else {
			slog.Warn("telemetry init failed; continuing without telemetry", "err", rerr)
		}
	}

	// Start background update checker (respects AGENTJAIL_NO_UPDATE_CHECK).
	if os.Getenv("AGENTJAIL_NO_UPDATE_CHECK") == "" {
		// InstallDir: the directory containing the running binary.
		// os.Executable() returns e.g. ~/.agentjail/bin/agentjail-daemon.
		autoUpdate := os.Getenv("AGENTJAIL_AUTO_UPDATE") != "false"

		installDir := ""
		if exePath, exeErr := os.Executable(); exeErr == nil {
			installDir = filepath.Dir(exePath)
		}

		// servicePath is passed to RestartDaemon on rollback. On macOS it is
		// the launchd plist path; on Linux it is the systemd user unit name.
		var servicePath string
		if runtime.GOOS == "darwin" {
			homeDir, _ := os.UserHomeDir()
			servicePath = filepath.Join(homeDir, "Library", "LaunchAgents", "com.agentjail.daemon.plist")
		} else if runtime.GOOS == "linux" {
			servicePath = "agentjail-daemon.service"
		}

		checker := &selfupdate.Checker{}
		uc := &UpdateChecker{
			Version:     buildinfo.Version,
			BasePath:    filepath.Dir(*socketPath), // ~/.agentjail
			Fetcher:     checker,
			Notifier:    &osNotifier{},
			ExeResolver: selfupdate.ResolveExecutablePath,
			JitterFunc: func(max time.Duration) time.Duration {
				return time.Duration(int64(os.Getpid()) % int64(max))
			},
			AutoUpdate: autoUpdate,
			InstallDir: installDir,
			PlistPath:  servicePath,
			GOOS:       runtime.GOOS,
			GOARCH:     runtime.GOARCH,
		}
		go uc.Run(ctx)
	}

	// Start hook-config watchdog: polls agent settings files every 5 s and
	// re-injects the agentjail-hook entry if it is removed (ADR 0026).
	var hwEmitter audit.Emitter = audit.NopEmitter{}
	if srv.eventStore != nil {
		hwEmitter = srv.eventStore
	}
	hookWatchdog := hookwatch.New(logger, hwEmitter)
	go hookWatchdog.Run(ctx)

	// Start grant control server on daemon-ctl.sock (see ADR 0047).
	{
		ctlSockPath := grantctl.ControlSocketPath()
		durableAudit := srv.eventStore != nil
		var grantEmitter audit.Emitter = audit.NopEmitter{}
		if srv.eventStore != nil {
			grantEmitter = srv.eventStore
		}
		// Mint before binding. On failure the control socket is not served at
		// all, which is the fail-closed outcome: no approvals, no reload (ADR 0069).
		gs, gerr := startGrantServer(ctlSockPath, grantEmitter, durableAudit, srv.activeSessions, srv.reloadPolicy)
		if gerr != nil {
			slog.Warn("grant control server failed to start (grants unavailable)", "err", gerr)
		} else {
			srv.grantSrv = gs
			go srv.grantSrv.serveCtl(ctx)
			go srv.grantSrv.startReaper(ctx, 60*time.Second)
			slog.Info("grant control server listening", "socket", ctlSockPath)
		}
	}

	// Start listening before installing signal handlers so the socket is
	// ready as soon as we log "listening".
	ln, bound, bindErr := bindAgentSocket(*socketPath)
	if bindErr != nil {
		slog.Error("bind agent socket", "socket", *socketPath, "err", bindErr)
		return 1
	}
	if !bound {
		slog.Info("another agentjail-daemon already owns the socket; standing down", "socket", *socketPath)
		return 0
	}
	// Restrict socket permissions to the current user — no group or world
	// access. 0600 = read+write for owner only.
	if err := os.Chmod(*socketPath, 0o600); err != nil {
		slog.Warn("chmod socket", "err", err)
	}

	slog.Info("listening", "socket", *socketPath)

	// Remove the fail-open warning sentinel (U2). agentjail-hook writes
	// ~/.agentjail/fail-open-warned the first time it fails open (daemon
	// unreachable) and stays silent on subsequent fail-opens until this file
	// is gone — that re-arming is the daemon's job, not the hook's (the hook
	// has no way to know the daemon is healthy again). Without this, the
	// warning would fire at most once ever, for the lifetime of the
	// ~/.agentjail directory. Best-effort: os.IsNotExist is the expected,
	// common case (no prior fail-open) and is not logged.
	removeFailOpenSentinel()

	// Emit daemon.started audit event (best-effort).
	if srv.eventStore != nil {
		_ = srv.eventStore.Emit(ctx, audit.Event{
			EventType: audit.DaemonStarted,
			Actor:     "daemon",
		})
	}

	// Write the hook-fallback sidecar (ADR 0050) now that the daemon has
	// successfully started listening. Best-effort: a failure is logged (and
	// audited if the store is available) but never blocks startup — the
	// hook treats a missing/unparseable sidecar as "allow" (today's
	// behavior), so this can never make things worse than not having the
	// feature at all.
	if err := writeHookFallback(cfg); err != nil {
		slog.Warn("write hook-fallback sidecar failed (non-fatal)", "err", err)
		if srv.eventStore != nil {
			_ = srv.eventStore.Emit(ctx, audit.Event{
				EventType: audit.HookFallbackWriteFailed,
				Actor:     "daemon",
				Detail:    map[string]string{"err": err.Error()},
			})
		}
	}

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// Accept loop in a separate goroutine so signals can be processed on
	// the main goroutine without blocking.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// When ctx is cancelled we close ln; Accept returns an error.
				if ctx.Err() != nil {
					return
				}
				slog.Warn("accept", "err", err)
				continue
			}
			srv.acceptConn(ctx, conn)
		}
	}()

	// SIGHUP-driven reloads are coalesced (ADR 0075): a full Rego recompile is
	// the daemon's most expensive operation, and SIGHUP is the one reload
	// trigger that cannot be authenticated — Landlock does not mediate signals,
	// so a same-UID process reaches it regardless of the sandbox.
	coalescer := newReloadCoalescer(minReloadInterval, time.Now)
	var coalesceC <-chan time.Time

	reload := func(why string) {
		slog.Info(why + " — reloading policy")
		if err := srv.reloadPolicy(ctx); err != nil {
			slog.Error("reload failed — keeping old policy", "err", err)
		}
	}

	// Block waiting for signals.
	for {
		var sig os.Signal
		select {
		case <-coalesceC:
			// A deferred reload came due: one recompile covering however many
			// SIGHUPs arrived during the cooldown.
			coalesceC = nil
			coalescer.deferredFired()
			reload("coalesced SIGHUP")
			continue
		case s, ok := <-sigCh:
			if !ok {
				return 0
			}
			sig = s
		}

		switch sig {
		case syscall.SIGHUP:
			runNow, wait := coalescer.request()
			switch {
			case runNow:
				reload("SIGHUP received")
			case wait > 0:
				slog.Info("SIGHUP received — reload deferred to bound recompile rate", "in", wait)
				coalesceC = time.After(wait)
			default:
				slog.Info("SIGHUP received — collapsed into the pending reload")
			}

		case syscall.SIGTERM, syscall.SIGINT:
			slog.Info("shutdown signal received", "signal", sig)
			// Emit daemon.stopped audit event (best-effort, before cancel).
			if srv.eventStore != nil {
				_ = srv.eventStore.Emit(context.Background(), audit.Event{
					EventType: audit.DaemonStopped,
					Actor:     "daemon",
				})
			}
			// Stop accepting new connections.
			cancel()
			_ = ln.Close()
			// Drain in-flight connections with a 5-second deadline.
			done := make(chan struct{})
			go func() {
				srv.wg.Wait()
				close(done)
			}()
			select {
			case <-done:
				slog.Info("all connections drained; exiting")
			case <-time.After(5 * time.Second):
				slog.Warn("drain timeout; forcing exit")
			}
			// Flush the async SQLite writer so pending decisions are persisted
			// before exit. drainDecisions exits after draining the channel on
			// ctx cancellation; wait for it (bounded).
			flushDone := make(chan struct{})
			go func() {
				srv.decWg.Wait()
				close(flushDone)
			}()
			select {
			case <-flushDone:
			case <-time.After(3 * time.Second):
				slog.Warn("store drain timeout; forcing exit")
			}
			if srv.eventStore != nil {
				_ = srv.eventStore.Close()
			}
			if srv.grantSrv != nil {
				srv.grantSrv.close()
			}
			// Remove the socket file so a fresh start won't see a stale one.
			_ = os.Remove(*socketPath)
			srv.activeSessions.cleanup()
			return 0
		}
	}
}

// migrateDaemonLog imports historical decisions from an existing daemon.log
// (slog JSON-lines, msg=="eval") into the SQLite store on first run, iff the
// store is empty. Best-effort: unparseable lines are skipped, failures are
// logged, and startup is never blocked. Migrated records have no tool_input
// (the slog line only carries a summary).
func migrateDaemonLog(ctx context.Context, st store.EventStore, logPath string) {
	n, err := st.DecisionCount(ctx)
	if err != nil || n > 0 {
		return
	}
	f, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	imported := 0
	for sc.Scan() {
		var line struct {
			Time      time.Time `json:"time"`
			Msg       string    `json:"msg"`
			Tool      string    `json:"tool"`
			SessionID string    `json:"session_id"`
			Agent     string    `json:"agent"`
			CWD       string    `json:"cwd"`
			Summary   string    `json:"summary"`
			Action    string    `json:"action"`
			RuleID    string    `json:"rule_id"`
			Reason    string    `json:"reason"`
			Impact    string    `json:"impact"`
			ElapsedUs int64     `json:"elapsed_us"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			continue
		}
		if line.Msg != "eval" || line.Action == "" {
			continue
		}
		sid := line.SessionID
		if sid == "" {
			sid = "migrated"
		}
		if err := st.RecordDecision(ctx, store.DecisionRecord{
			Ts:        line.Time,
			SessionID: sid,
			Agent:     line.Agent,
			ToolName:  line.Tool,
			Summary:   line.Summary,
			Action:    line.Action,
			RuleID:    line.RuleID,
			Reason:    line.Reason,
			Impact:    line.Impact,
			ElapsedUs: line.ElapsedUs,
			CWD:       line.CWD,
		}); err != nil {
			slog.Warn("daemon.log migration: insert failed (continuing)", "err", err)
			continue
		}
		imported++
	}
	if imported > 0 {
		slog.Info("migrated daemon.log decisions into sqlite", "count", imported)
	}
}

// defaultInlinePolicy is a minimal Rego policy used when --rules is not
// specified. It denies rm -rf commands and allows everything else.
// Production deployments pass --rules pointing to agentpolicy/policies/.
//
// Package name is "agentjail" — the namespace queried by NewHookOPAEngine
// (data.agentjail.decision).
const defaultInlinePolicy = `
package agentjail

import future.keywords.if

default decision = {"action": "allow", "reason": "default allow", "rule_id": "default"}

decision = {"action": "deny", "reason": "rm -rf is blocked by default policy", "rule_id": "command_policy/rm_rf"} if {
    input.tool_name == "Bash"
    contains(input.tool_input.command, "rm -rf")
}
`
