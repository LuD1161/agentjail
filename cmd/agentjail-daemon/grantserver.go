// grantserver.go implements the daemon's grant control server (AGE-116, ADR
// 0047). It replaces the netproxy-hosted grant control plane
// (cmd/agentjail-netproxy/control.go) with a daemon-hosted equivalent: the
// same request/list/approve/deny lifecycle, backed by grantctl.Registry,
// but serving a SEPARATE privileged socket (~/.agentjail/run/daemon-ctl.sock)
// rather than the agent-reachable daemon.sock.
//
// Two sockets, two trust levels:
//   - daemon.sock (agent-reachable): carries policy eval requests AND now
//     grant_request submissions (an agent may file a request for itself).
//   - daemon-ctl.sock (privileged/host-resident only): carries grant_list,
//     grant_approve, grant_deny -- the human-only decision verbs. The
//     sandboxed agent cannot reach this socket (see grantctl.ControlSocketPath).
//
// Approval is transactional and fail-closed: ClaimGrant marks the pending
// entry unclaimed-elsewhere, PolicyChangeRequested is emitted BEFORE the
// policy.yaml overlay is written (ADR 0044 fail-closed audit), and only on
// full success is the claim committed. Any failure along the way rolls the
// claim back so the request remains pending and retryable.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/hostgrant"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
)

// grantCtlLockName is the flock'd lockfile that serializes singleton
// ownership of the grant control socket, mirroring netproxy's
// controlLockName convention.
const grantCtlLockName = "daemon-ctl.lock"

// errGrantUnbound is the sentinel returned when an approval is attempted on
// a grant that was never bound to a session's CWD (no PID match was found at
// request time). Persisting requires a target directory; without a bound
// CWD there is nowhere to write the overlay, so approval is refused.
var errGrantUnbound = errors.New("grant is unbound - no session PID matched; cannot persist")

// grantServer serves the daemon's privileged grant control socket
// (daemon-ctl.sock): grant_list, grant_approve, grant_deny. It also exposes
// handleGrantRequest, called inline from the daemon's agent-reachable
// handleConn when a grant_request message arrives on daemon.sock.
type grantServer struct {
	ctlLn    *net.UnixListener
	lock     *os.File
	sockPath string
	registry *grantctl.Registry
	emitter  audit.Emitter
	// durableAudit is true only when emitter is backed by a real, writable
	// store (never audit.NopEmitter). grant_approve is refused (fail closed)
	// when this is false -- a live policy change must never be applied
	// without a durable audit record (ADR 0044 / 0047).
	durableAudit   bool
	activeSessions *activeTracker
}

// acquireGrantCtlSocket makes the daemon the singleton owner of the grant
// control socket. It creates the socket dir (0700), takes a non-blocking
// flock on a lockfile (so two racing daemon starts serialize), clears a
// stale socket left by a crashed predecessor, binds, and chmods 0600.
// Mirrors acquireControlSocket in cmd/agentjail-netproxy/control.go.
func acquireGrantCtlSocket(sockPath string) (*net.UnixListener, *os.File, error) {
	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create grant control socket dir %s: %w", dir, err)
	}

	lockPath := filepath.Join(dir, grantCtlLockName)
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open grant control lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, nil, fmt.Errorf("another daemon holds the grant control lock: %w", err)
	}

	// We hold the lock. If a socket file exists, only remove it after
	// confirming nothing live is serving it.
	if _, statErr := os.Stat(sockPath); statErr == nil {
		if c, derr := net.DialTimeout("unix", sockPath, 100*time.Millisecond); derr == nil {
			c.Close()
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			lock.Close()
			return nil, nil, fmt.Errorf("grant control socket %s already served by a live daemon", sockPath)
		}
		_ = os.Remove(sockPath) // stale
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		return nil, nil, fmt.Errorf("bind grant control socket %s: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		slog.Warn("chmod grant control socket", "path", sockPath, "err", err)
	}
	return ln, lock, nil
}

// newGrantServer acquires the grant control socket and returns a ready
// server. durableAudit must be true only when emitter is backed by a real,
// writable store -- see grantServer.durableAudit.
func newGrantServer(sockPath string, registry *grantctl.Registry, emitter audit.Emitter, durableAudit bool, activeSessions *activeTracker) (*grantServer, error) {
	ln, lock, err := acquireGrantCtlSocket(sockPath)
	if err != nil {
		return nil, err
	}
	return &grantServer{
		ctlLn:          ln,
		lock:           lock,
		sockPath:       sockPath,
		registry:       registry,
		emitter:        emitter,
		durableAudit:   durableAudit,
		activeSessions: activeSessions,
	}, nil
}

// close stops serving, removes the socket, and releases the lock.
func (gs *grantServer) close() {
	if gs.ctlLn != nil {
		gs.ctlLn.Close()
	}
	_ = os.Remove(gs.sockPath)
	if gs.lock != nil {
		syscall.Flock(int(gs.lock.Fd()), syscall.LOCK_UN)
		gs.lock.Close()
	}
}

// serveCtl accepts grant control connections until ctx is cancelled.
func (gs *grantServer) serveCtl(ctx context.Context) {
	go func() {
		<-ctx.Done()
		gs.ctlLn.Close()
	}()
	for {
		conn, err := gs.ctlLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Warn("grant control accept error", "err", err)
				continue
			}
		}
		go gs.handleCtlConn(conn)
	}
}

// handleCtlConn reads one control request off the privileged grant control
// socket and writes one response. Dispatches grant_list, grant_approve, and
// grant_deny; anything else is rejected.
func (gs *grantServer) handleCtlConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req grantctl.Request
	if err := json.NewDecoder(io.LimitReader(conn, grantctl.MaxControlMsgBytes)).Decode(&req); err != nil {
		gs.reply(conn, grantctl.Response{OK: false, Error: "malformed grant control request"})
		return
	}

	switch req.Type {
	case grantctl.ReqGrantList:
		gs.reply(conn, grantctl.Response{OK: true, Grants: gs.registry.ListPending()})

	case grantctl.ReqGrantApprove:
		if req.GrantID == "" {
			gs.reply(conn, grantctl.Response{OK: false, Error: "grant_approve requires grant_id"})
			return
		}
		if err := gs.approve(req.GrantID); err != nil {
			gs.reply(conn, grantctl.Response{OK: false, Error: err.Error()})
			return
		}
		slog.Info("grant approved", "grant_id", req.GrantID)
		gs.reply(conn, grantctl.Response{OK: true, GrantID: req.GrantID})

	case grantctl.ReqGrantDeny:
		if req.GrantID == "" {
			gs.reply(conn, grantctl.Response{OK: false, Error: "grant_deny requires grant_id"})
			return
		}
		if err := gs.registry.DenyGrant(req.GrantID); err != nil {
			gs.reply(conn, grantctl.Response{OK: false, Error: err.Error()})
			return
		}
		slog.Info("grant denied", "grant_id", req.GrantID)
		_ = gs.emitter.Emit(context.Background(), audit.Event{
			EventType: audit.DaemonGrantDenied,
			Actor:     "daemon",
			RefID:     req.GrantID,
		})
		gs.reply(conn, grantctl.Response{OK: true, GrantID: req.GrantID})

	default:
		gs.reply(conn, grantctl.Response{OK: false, Error: fmt.Sprintf("unsupported grant control request %q", req.Type)})
	}
}

// approve runs the transactional approval flow for grantID:
//  1. refuse outright if audit is not durable (fail-closed, ADR 0044/0047)
//  2. look up the grant and require a bound CWD (errGrantUnbound otherwise)
//  3. claim the grant (making it invisible to ListPending/FindGrant)
//  4. emit PolicyChangeRequested (fail-closed) before touching disk
//  5. persist the host into the bound CWD's policy.yaml overlay
//  6. emit PolicyChanged (best-effort)
//  7. commit the claim
//
// Any failure after the claim rolls it back so the grant remains pending and
// retryable -- no partial state is left behind.
func (gs *grantServer) approve(grantID string) error {
	if !gs.durableAudit {
		return fmt.Errorf("audit unavailable, refusing to approve grant (fail closed)")
	}

	// FindGrant's GrantInfo is display-only (no BoundCWD); it just confirms
	// the grant still exists and is unclaimed before we attempt to claim it.
	// The authoritative BoundCWD check happens below, once ClaimGrant hands
	// back the full ClaimedGrant snapshot.
	if _, ok := gs.registry.FindGrant(grantID); !ok {
		return grantctl.ErrGrantNotFound
	}

	claimed, commit, rollback, err := gs.registry.ClaimGrant(grantID)
	if err != nil {
		return err
	}

	if claimed.BoundCWD == "" {
		rollback()
		return errGrantUnbound
	}

	if aerr := gs.emitter.Emit(context.Background(), audit.Event{
		EventType: audit.PolicyChangeRequested,
		Actor:     "daemon",
		RefID:     grantID,
		Detail:    map[string]string{"host": claimed.Host, "cwd": claimed.BoundCWD},
	}); aerr != nil {
		rollback()
		return fmt.Errorf("audit unavailable, grant not applied: %w", aerr)
	}

	overlayPath, perr := persistGrantHost(claimed.BoundCWD, claimed.Host)
	if perr != nil {
		rollback()
		return fmt.Errorf("persist grant: %w", perr)
	}

	// Best-effort: the overlay write already succeeded; a failure to record
	// PolicyChanged does not roll back the already-applied change.
	_ = gs.emitter.Emit(context.Background(), audit.Event{
		EventType: audit.PolicyChanged,
		Actor:     "daemon",
		RefID:     grantID,
		Detail:    map[string]string{"host": claimed.Host, "overlay": overlayPath},
	})

	commit()
	return nil
}

// handleGrantRequest is called inline from the daemon's agent-reachable
// handleConn when a grant_request message arrives on daemon.sock. It
// validates the request, resolves the requesting session via the peer PID
// (best-effort -- an unresolved session simply leaves the grant unbound
// until a human happens to approve it from the same directory), files the
// request in the registry, and audits it (best-effort).
func (gs *grantServer) handleGrantRequest(conn net.Conn, req grantctl.Request) grantctl.Response {
	if req.Host == "" {
		return grantctl.Response{OK: false, Error: "grant_request requires host"}
	}
	if req.SessionID == "" {
		return grantctl.Response{OK: false, Error: "grant_request requires session_id"}
	}

	validHost, err := hostgrant.Validate(req.Host)
	if err != nil {
		return grantctl.Response{OK: false, Error: err.Error()}
	}

	ttlMs := req.TTLMs
	if ttlMs <= 0 || ttlMs > grantctl.MaxGrantTTLMs {
		ttlMs = grantctl.MaxGrantTTLMs
	}
	reason := req.Reason
	if len(reason) > grantctl.MaxReasonLen {
		reason = reason[:grantctl.MaxReasonLen]
	}

	gi, gerr := gs.registry.RequestGrant(req.SessionID, req.CWD, validHost, ttlMs, reason, time.Now())
	if gerr != nil {
		return grantctl.Response{OK: false, Error: gerr.Error()}
	}

	// Best-effort PID-based binding: if we can resolve the requesting
	// session from the peer PID, record the daemon-observed CWD so a human
	// approval can persist into the right directory even if the agent's
	// self-reported CWD (req.CWD) is stale or absent.
	if peerPID, perr := extractPeerPID(conn); perr == nil && gs.activeSessions != nil {
		if _, cwd, found := gs.activeSessions.findSessionByPID(peerPID); found {
			gs.registry.SetBoundCWD(gi.GrantID, cwd)
		}
	}

	_ = gs.emitter.Emit(context.Background(), audit.Event{
		EventType: audit.DaemonGrantRequested,
		Actor:     "daemon",
		SessionID: req.SessionID,
		RefID:     gi.GrantID,
		Detail:    map[string]string{"host": validHost},
	})

	return grantctl.Response{OK: true, GrantID: gi.GrantID}
}

// startReaper runs a periodic reap of expired pending grants until ctx is
// cancelled. Reaping is best-effort; a claimed (in-flight approval) grant is
// never reaped (see grantctl.Registry.Reap).
func (gs *grantServer) startReaper(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res := gs.registry.Reap(time.Now())
			if len(res.Reaped) > 0 {
				slog.Info("reaped expired pending grants", "count", len(res.Reaped))
			}
		}
	}
}

func (gs *grantServer) reply(conn net.Conn, resp grantctl.Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		slog.Warn("grant control reply write failed", "err", err)
	}
}

// persistGrantHost merges host into <dir>/.agentjail/policy.yaml's
// network.allowed_hosts (creating the overlay if it does not exist yet),
// writes it atomically (config.Save: temp file + rename), then re-trusts the
// overlay by its new content hash so future sessions inherit the grant
// without a manual 'agentjail trust'. It returns the overlay path on
// success.
//
// This is a daemon-side copy of cmd/agentjail/cmd_grants.go's
// persistGrantHost (same behavior, different caller: the daemon's grant
// control server rather than the CLI's `agentjail grant approve --persist`).
func persistGrantHost(dir, host string) (string, error) {
	overlayDir := filepath.Join(dir, projectpolicy.ProjectDirName)
	overlayPath := filepath.Join(overlayDir, projectpolicy.ProjectPolicyFile)

	var cfg *config.PolicyConfig
	if _, err := os.Stat(overlayPath); err == nil {
		loaded, err := config.Load(overlayPath)
		if err != nil {
			return "", fmt.Errorf("load %s: %w", overlayPath, err)
		}
		cfg = loaded
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(overlayDir, 0o755); err != nil {
			return "", fmt.Errorf("create %s: %w", overlayDir, err)
		}
		cfg = &config.PolicyConfig{}
	} else {
		return "", fmt.Errorf("stat %s: %w", overlayPath, err)
	}

	already := false
	for _, h := range cfg.Network.AllowedHosts {
		if strings.EqualFold(h, host) {
			already = true
			break
		}
	}
	if !already {
		cfg.Network.AllowedHosts = append(cfg.Network.AllowedHosts, host)
	}

	if err := config.Save(cfg, overlayPath); err != nil {
		return "", fmt.Errorf("write %s: %w", overlayPath, err)
	}

	// Recompute the hash from what actually landed on disk (not the
	// in-memory struct) so the trust entry matches byte-for-byte.
	written, err := os.ReadFile(overlayPath)
	if err != nil {
		return "", fmt.Errorf("re-read %s after save: %w", overlayPath, err)
	}
	newHash := projectpolicy.HashContent(written)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	trustPath := projectpolicy.TrustStorePath(filepath.Join(homeDir, projectpolicy.ProjectDirName))
	ts, err := projectpolicy.LoadTrustStore(trustPath)
	if err != nil {
		return "", fmt.Errorf("load trust store: %w", err)
	}
	ts.Trust(&projectpolicy.Overlay{Path: overlayPath, ContentHash: newHash})
	if err := ts.Save(); err != nil {
		return "", fmt.Errorf("save trust store (overlay was written but is now UNTRUSTED until you run 'agentjail trust %s'): %w", dir, err)
	}

	return overlayPath, nil
}
