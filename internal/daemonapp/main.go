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
	"strings"
	"sync"
	"syscall"
	"time"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	policy "github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/hookwatch"
	"github.com/LuD1161/agentjail/internal/logrotate"
	"github.com/LuD1161/agentjail/internal/policyeval"
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
	// repo-root cache, AWS profile cache, and ask-promotion tracking.
	evaluator policyeval.Evaluator

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
		slog.Warn("store buffer full; dropping decision record (fail-open on logging)", "session_id", d.SessionID, "action", d.Action)
	}
}

// drainDecisions consumes the decision channel and writes to the store. It
// runs until ctx is cancelled, then drains any remaining records and exits
// so graceful shutdown flushes pending writes.
func (s *server) drainDecisions(ctx context.Context) {
	defer s.decWg.Done()
	for {
		select {
		case d := <-s.decCh:
			if err := s.eventStore.RecordDecision(ctx, d); err != nil {
				slog.Warn("store write decision failed (fail-open)", "err", err, "session_id", d.SessionID)
			}
		case <-ctx.Done():
			// Flush remaining records before exiting.
			for {
				select {
				case d := <-s.decCh:
					if err := s.eventStore.RecordDecision(context.Background(), d); err != nil {
						slog.Warn("store write decision failed during drain", "err", err)
					}
				default:
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

	slog.Info("policy reloaded",
		"rules_dir", s.rulesDir,
		"mcp_allowed", newCfg.MCP.Allowed,
		"mcp_blocked_count", len(newCfg.MCP.Blocked),
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
					_ = enc.Encode(wire.ControlResponse{OK: true})
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

		if req.SessionID != "" && s.activeSessions != nil && req.AgentPID > 0 {
			s.activeSessions.update(req.SessionID, req.AgentPID, req.CWD)
		}

		start := time.Now()
		resp, err := s.evaluator.Eval(ctx, req)
		elapsed := time.Since(start)

		if err == nil {
			s.recordTelemetry(resp.Action, resp.RuleID, req.ToolName, req.Agent, elapsed)
		}

		// Extract a short identifying summary from tool_input — the command
		// string for Bash, the file_path for file tools, MCP server name for
		// MCP calls. Truncated to keep the log line bounded. This is what the
		// `agentjail logs -v` formatter shows on the same row as the verdict.
		summary := policyeval.SummarizeToolInput(req.ToolName, req.ToolInput)

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
				// fail-open deadline (~45 ms). The hook has already fallen open;
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
			slog.Info("eval", "req_id", req.ID, "tool", req.ToolName, "session_id", req.SessionID, "agent", req.Agent, "cwd", req.CWD, "summary", summary, "action", resp.Action, "rule_id", resp.RuleID, "reason", resp.Reason, "impact", resp.Impact, "elapsed_us", elapsed.Microseconds())
			// Persist the decision to SQLite (async, fail-open). The full
			// tool_input is redacted at the store boundary (ADR 0019).
			s.enqueueDecision(store.DecisionRecord{
				Ts:        time.Now(),
				SessionID: req.SessionID,
				Agent:     req.Agent,
				ToolName:  req.ToolName,
				Summary:   summary,
				Action:    resp.Action,
				RuleID:    resp.RuleID,
				Reason:    resp.Reason,
				Impact:    resp.Impact,
				ElapsedUs: elapsed.Microseconds(),
				CWD:       req.CWD,
				ToolInput: req.ToolInput,
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
		evaluator:      policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), initModules, cfg),
		activeSessions: newActiveTracker(filepath.Dir(*policyPath)),
		connSem:        make(chan struct{}, maxAgentConns),
		rulesDir:       *rulesDir,
		policyPath:     *policyPath,
		idleTimeout:    defaultAgentConnIdleTimeout,
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
		if cerr := st.Cleanup(ctx, *retentionDur); cerr != nil {
			slog.Warn("store retention cleanup failed (non-fatal)", "err", cerr)
		}
		srv.decWg.Add(1)
		go srv.drainDecisions(ctx)
		slog.Info("sqlite event store opened", "db", *dbPath, "retention", *retentionDur)
	} else {
		slog.Warn("sqlite event store open failed; continuing without persistence (fail-open on logging)", "db", *dbPath, "err", serr)
	}

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

	// Block waiting for signals.
	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			slog.Info("SIGHUP received — reloading policy")
			if err := srv.reloadPolicy(ctx); err != nil {
				slog.Error("reload failed — keeping old policy", "err", err)
				continue
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
	return 0
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
