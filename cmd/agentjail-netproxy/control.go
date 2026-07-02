package main

// control.go implements the session-aware control plane for agentjail-netproxy.
//
// One netproxy serves every shielded session on the single TCP port
// (127.0.0.1:9100). Each session registers a per-session allowlist over a Unix
// control socket (proxyctl.ControlSocketPath) that the sandboxed agent cannot
// reach. The data plane (handleConn) then keys the effective allowlist by the
// session Token carried as the Proxy-Authorization credential -- there is NO
// global fallback, so an unknown/missing token is denied.
//
// Ownership: the control socket IS the singleton token. netproxy acquires it
// under an flock'd lockfile and refuses to start if a live proxy already serves
// it. A launching shield decides reuse-vs-fail-closed via a Fingerprint request
// (see the shield side); netproxy here just serves fingerprint + register and
// never kills anyone.
//
// Security: never log the Token or the proxy URL. Registration is a LEASE with
// a hard absolute TTL (proxyctl.MaxLeaseTTLMs), reaped regardless of traffic so
// an agent-spawned background process cannot keep a token alive.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/proxyctl"
)

// version is the netproxy binary version reported in the control Fingerprint.
// Overridable at build time via -ldflags "-X main.version=...". The Fingerprint
// tolerates binary drift; only proxyctl.ProtocolVersion governs compatibility.
var version = "dev"

// controlLockName is the flock'd lockfile that serializes singleton ownership
// of the control socket, alongside proxyctl's controlSocketName.
const controlLockName = "netproxy-ctl.lock"

// session is one registered shielded session's enforcement state. al is the
// prebuilt (normalized) allowlist for this session's hosts, so the data plane
// reuses the same tested host-matching as the former global allowlist.
type session struct {
	al          *allowlist
	leaseExpiry time.Time
}

// sessionRegistry holds the per-Token session policies. It is the only source
// of truth the data plane consults; a token that is absent or past its lease is
// denied (fail closed, no global fallback).
type sessionRegistry struct {
	mu       sync.RWMutex
	sessions map[proxyctl.Token]*session
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{sessions: make(map[proxyctl.Token]*session)}
}

// maxLease is the hard ceiling on any registration lease.
var maxLease = time.Duration(proxyctl.MaxLeaseTTLMs) * time.Millisecond

// register leases tok -> policy until now+ttl. A non-positive or over-cap ttl is
// clamped to maxLease. Re-registering the same token replaces its policy and
// extends the lease (a fresh launch re-registers; there is no stale global
// state to inherit).
func (r *sessionRegistry) register(tok proxyctl.Token, pol proxyctl.SessionPolicy, ttl time.Duration, now time.Time) {
	if ttl <= 0 || ttl > maxLease {
		ttl = maxLease
	}
	al := &allowlist{}
	al.load(pol.AllowedHosts)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[tok] = &session{al: al, leaseExpiry: now.Add(ttl)}
}

// lookup returns the token's allowlist if it is registered and its lease has not
// expired. A missing or expired token returns (nil, false) -> deny (fail
// closed, no global fallback).
func (r *sessionRegistry) lookup(tok proxyctl.Token, now time.Time) (*allowlist, bool) {
	if tok == "" {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[tok]
	if !ok || now.After(s.leaseExpiry) {
		return nil, false
	}
	return s.al, true
}

// reap deletes every session whose lease has expired and returns the tokens
// reaped (so the caller can audit expiry). The Token values are returned only
// for counting/audit; callers must not log them.
func (r *sessionRegistry) reap(now time.Time) []proxyctl.Token {
	r.mu.Lock()
	defer r.mu.Unlock()
	var expired []proxyctl.Token
	for t, s := range r.sessions {
		if now.After(s.leaseExpiry) {
			expired = append(expired, t)
			delete(r.sessions, t)
		}
	}
	return expired
}

// count returns the number of live registrations (for tests/observability).
func (r *sessionRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// controlServer serves the control socket: fingerprint + register (grant is
// Phase 3). It holds the flock'd lockfile for singleton ownership.
type controlServer struct {
	ln       *net.UnixListener
	lock     *os.File
	sockPath string
	registry *sessionRegistry
	emitter  audit.Emitter
	logger   *slog.Logger
	binVer   string
}

// acquireControlSocket makes netproxy the singleton owner of the control socket.
// It creates the socket dir (0700), takes a non-blocking flock on a lockfile
// (so two racing netproxy starts serialize), clears a stale socket left by a
// crashed predecessor (only after confirming nothing live answers it), binds,
// and chmods 0600. It returns an error if a live proxy already owns the socket
// or the lock is held -- netproxy then refuses to start (the shield is expected
// to have fingerprinted and reused instead of spawning us).
func acquireControlSocket(sockPath string, logger *slog.Logger) (*net.UnixListener, *os.File, error) {
	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create control socket dir %s: %w", dir, err)
	}

	lockPath := filepath.Join(dir, controlLockName)
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open control lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, nil, fmt.Errorf("another netproxy holds the control lock: %w", err)
	}

	// We hold the lock. If a socket file exists, only remove it after confirming
	// nothing live is serving it (defense against clobbering a real owner in the
	// unlikely event the lock and socket disagree).
	if _, statErr := os.Stat(sockPath); statErr == nil {
		if c, derr := net.DialTimeout("unix", sockPath, 100*time.Millisecond); derr == nil {
			c.Close()
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			lock.Close()
			return nil, nil, fmt.Errorf("control socket %s already served by a live proxy", sockPath)
		}
		_ = os.Remove(sockPath) // stale
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		return nil, nil, fmt.Errorf("bind control socket %s: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		logger.Warn("chmod control socket", "path", sockPath, "err", err)
	}
	return ln, lock, nil
}

// newControlServer acquires the control socket and returns a ready server.
func newControlServer(sockPath string, registry *sessionRegistry, emitter audit.Emitter, binVer string, logger *slog.Logger) (*controlServer, error) {
	ln, lock, err := acquireControlSocket(sockPath, logger)
	if err != nil {
		return nil, err
	}
	return &controlServer{
		ln:       ln,
		lock:     lock,
		sockPath: sockPath,
		registry: registry,
		emitter:  emitter,
		logger:   logger,
		binVer:   binVer,
	}, nil
}

// close stops serving, removes the socket, and releases the lock.
func (cs *controlServer) close() {
	if cs.ln != nil {
		cs.ln.Close()
	}
	_ = os.Remove(cs.sockPath)
	if cs.lock != nil {
		syscall.Flock(int(cs.lock.Fd()), syscall.LOCK_UN)
		cs.lock.Close()
	}
}

// serve accepts control connections until ctx is cancelled.
func (cs *controlServer) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		cs.ln.Close()
	}()
	for {
		conn, err := cs.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				cs.logger.Warn("control accept error", "err", err)
				continue
			}
		}
		go cs.handle(conn)
	}
}

// handle reads one control request and writes one response. Never logs the token.
func (cs *controlServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req proxyctl.Request
	if err := json.NewDecoder(io.LimitReader(conn, proxyctl.MaxControlMsgBytes)).Decode(&req); err != nil {
		cs.reply(conn, proxyctl.Response{OK: false, Error: "malformed control request"})
		return
	}

	switch req.Type {
	case proxyctl.ReqFingerprint:
		cs.reply(conn, proxyctl.Response{
			OK: true,
			Fingerprint: &proxyctl.Fingerprint{
				BinaryVersion:   cs.binVer,
				ProtocolVersion: proxyctl.CurrentProtocolVersion,
			},
		})

	case proxyctl.ReqRegister:
		if req.Token == "" || req.Policy == nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "register requires token and policy"})
			return
		}
		cs.registry.register(req.Token, *req.Policy, time.Duration(req.LeaseTTLMs)*time.Millisecond, time.Now())
		// State change -> Info + audit (best-effort). Token is NEVER included.
		cs.logger.Info("session registered", "allowed_hosts_count", len(req.Policy.AllowedHosts), "live_sessions", cs.registry.count())
		_ = cs.emitter.Emit(context.Background(), audit.Event{
			EventType: audit.NetproxySessionRegistered,
			Actor:     "netproxy",
			Detail:    map[string]string{"allowed_hosts_count": fmt.Sprintf("%d", len(req.Policy.AllowedHosts))},
		})
		cs.reply(conn, proxyctl.Response{OK: true})

	default:
		// ReqGrant and anything else are not served in Phase 1.
		cs.reply(conn, proxyctl.Response{OK: false, Error: fmt.Sprintf("unsupported control request %q", req.Type)})
	}
}

func (cs *controlServer) reply(conn net.Conn, resp proxyctl.Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		cs.logger.Warn("control reply write failed", "err", err)
	}
}
