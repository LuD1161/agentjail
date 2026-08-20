package netproxyapp

// control.go implements the session-aware control plane for agentjail-netproxy.
//
// One netproxy serves every shielded session on the single TCP port
// (127.0.0.1:9100). Each session registers a per-session allowlist over a Unix
// control socket (proxyctl.ControlSocketPath), authenticated by the ctlauth
// token rather than by the socket path (ADR 0068). The data plane (handleConn)
// then keys the effective allowlist by the
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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/proxyctl"
)

// controlLockName is the flock'd lockfile that serializes singleton ownership
// of the control socket, alongside proxyctl's controlSocketName.
const controlLockName = "netproxy-ctl.lock"

// pendingGrant is one filed-but-undecided runtime host grant request.
// It is created by the data-plane sentinel (see handleGrantSentinel in
// main.go) and resolved by a human via grant_approve/grant_deny over the
// control socket. Expires bounds how long an undecided request stays live
// before the reaper prunes it as stale -- distinct from TTLMs, which is the
// duration the eventual GRANT would last once approved.
type pendingGrant struct {
	GrantID string
	Host    string
	TTLMs   int64
	Reason  string
	Created time.Time
	Expires time.Time
}

// grantedHost is one approved runtime host grant, additive to the
// session's static allowlist until Expiry.
type grantedHost struct {
	Host    string
	GrantID string
	Expiry  time.Time
}

// pendingGrantTTL bounds how long an undecided grant request stays in the
// pending set before the reaper treats it as stale and discards it. This is
// independent of the grant's own requested TTL.
const pendingGrantTTL = time.Hour

// session is one registered shielded session's enforcement state. al is the
// prebuilt (normalized) allowlist for this session's hosts, so the data plane
// reuses the same tested host-matching as the former global allowlist.
// sessionID and cwd are non-secret, display-only identity (see
// proxyctl.Request.SessionID / Cwd); pending/granted hold this session's
// runtime host grants. All fields other than al's own internal lock
// are protected by the owning sessionRegistry's mutex.
type session struct {
	al                    *allowlist
	leaseExpiry           time.Time
	sessionID             string
	cwd                   string
	pending               map[string]*pendingGrant // keyed by GrantID
	granted               []grantedHost
	connectors            map[string]proxyctl.ConnectorRoute
	connectorCapabilities map[string]map[string]proxyctl.ConnectorRoute
}

// allowed reports whether host is permitted under this session: the static
// allowlist or a non-expired runtime grant. Callers must hold the owning
// registry's lock (read or write) -- granted is not independently guarded.
func (s *session) allowed(host string, now time.Time) bool {
	if s.al.allowed(host) {
		return true
	}
	h := normalizeHost(host)
	for _, g := range s.granted {
		if !now.Before(g.Expiry) {
			continue
		}
		if matchHost(normalizeHost(g.Host), h) {
			return true
		}
	}
	return false
}

// sessionRegistry holds the per-Token session policies. It is the only source
// of truth the data plane consults; a token that is absent or past its lease is
// denied (fail closed, no global fallback). grantIndex maps a pending
// GrantID -> owning Token so grant_approve/grant_deny can resolve the owning
// session from the GrantID alone, without the caller ever supplying a Token
// or session identity (see proxyctl.Request.GrantID doc).
type sessionRegistry struct {
	mu         sync.RWMutex
	sessions   map[proxyctl.Token]*session
	grantIndex map[string]proxyctl.Token
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions:   make(map[proxyctl.Token]*session),
		grantIndex: make(map[string]proxyctl.Token),
	}
}

// maxLease is the hard ceiling on any registration lease.
var maxLease = time.Duration(proxyctl.MaxLeaseTTLMs) * time.Millisecond

// Errors returned by the runtime host grant operations. Callers map
// these to control-plane Response.Error strings; the data-plane sentinel maps
// the cap errors to 429 and everything else to 400.
var (
	errUnknownSession    = errors.New("unknown or expired session")
	errPendingCapSession = errors.New("too many pending grant requests for this session")
	errPendingCapGlobal  = errors.New("too many pending grant requests across all sessions")
	errGrantNotFound     = errors.New("grant not found or already decided")
	errSessionDead       = errors.New("owning session lease is no longer live")
)

// register leases tok -> policy until now+ttl. A non-positive or over-cap ttl is
// clamped to maxLease. sessionID and cwd are non-secret, display-only identity
// (see proxyctl.Request.SessionID / Cwd). Re-registering the same token
// replaces its policy, identity, and lease, and clears any pending/granted
// runtime host grants (a fresh launch re-registers; there is no stale state to
// inherit).
func (r *sessionRegistry) register(tok proxyctl.Token, sessionID, cwd string, pol proxyctl.SessionPolicy, ttl time.Duration, now time.Time) {
	if ttl <= 0 || ttl > maxLease {
		ttl = maxLease
	}
	al := &allowlist{}
	al.load(pol.AllowedHosts)
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.sessions[tok]; ok {
		for gid := range old.pending {
			delete(r.grantIndex, gid)
		}
	}
	r.sessions[tok] = &session{
		al:                    al,
		leaseExpiry:           now.Add(ttl),
		sessionID:             sessionID,
		cwd:                   cwd,
		pending:               make(map[string]*pendingGrant),
		connectors:            make(map[string]proxyctl.ConnectorRoute),
		connectorCapabilities: make(map[string]map[string]proxyctl.ConnectorRoute),
	}
}

func (r *sessionRegistry) installConnector(route proxyctl.ConnectorRoute, now time.Time) error {
	if route.SessionID == "" || route.ConnectorID == "" || route.Host == "" || route.Port == 0 {
		return errUnknownSession
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var matched *session
	for _, s := range r.sessions {
		if s.sessionID == route.SessionID && now.Before(s.leaseExpiry) {
			if matched != nil {
				return errUnknownSession
			}
			matched = s
		}
	}
	if matched == nil {
		return errUnknownSession
	}
	matched.connectors[route.ConnectorID] = route
	return nil
}

func (r *sessionRegistry) registerConnectorCapability(token proxyctl.Token, capability string, route proxyctl.ConnectorRoute, now time.Time) error {
	if token == "" || capability == "" || route.ConnectorID == "" || route.Host == "" || route.Port == 0 {
		return errUnknownSession
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[token]
	if !ok || now.After(s.leaseExpiry) || route.SessionID != s.sessionID {
		return errUnknownSession
	}
	if s.connectorCapabilities[capability] == nil {
		s.connectorCapabilities[capability] = make(map[string]proxyctl.ConnectorRoute)
	}
	s.connectorCapabilities[capability][route.ConnectorID] = route
	return nil
}

func (r *sessionRegistry) useConnectorCapability(capability, connectorID string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if now.After(s.leaseExpiry) {
			continue
		}
		if routes := s.connectorCapabilities[capability]; routes != nil {
			route, ok := routes[connectorID]
			if !ok {
				return errUnknownSession
			}
			s.connectors[connectorID] = route
			return nil
		}
	}
	return errUnknownSession
}

func (r *sessionRegistry) removeConnectorCapability(capability, connectorID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if routes := s.connectorCapabilities[capability]; routes != nil {
			if _, ok := routes[connectorID]; !ok {
				return errUnknownSession
			}
			delete(s.connectors, connectorID)
			return nil
		}
	}
	return errUnknownSession
}

func (r *sessionRegistry) removeConnector(route proxyctl.ConnectorRoute) error {
	if route.SessionID == "" || route.ConnectorID == "" {
		return errUnknownSession
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.sessionID == route.SessionID {
			delete(s.connectors, route.ConnectorID)
			return nil
		}
	}
	return errUnknownSession
}

func (r *sessionRegistry) connector(tok proxyctl.Token, id string, now time.Time) (proxyctl.ConnectorRoute, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[tok]
	if !ok || !now.Before(s.leaseExpiry) {
		return proxyctl.ConnectorRoute{}, false
	}
	route, ok := s.connectors[id]
	return route, ok
}

// lookup returns the token's session if it is registered and its lease has not
// expired. A missing or expired token returns (nil, false) -> deny (fail
// closed, no global fallback). The returned *session must only be read; its
// pending/granted fields are mutated under the registry's lock elsewhere.
func (r *sessionRegistry) lookup(tok proxyctl.Token, now time.Time) (*session, bool) {
	if tok == "" {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[tok]
	if !ok || !now.Before(s.leaseExpiry) {
		return nil, false
	}
	return s, true
}

// sessionValid reports whether tok is registered and its lease has not
// expired, without exposing the session itself. Used by the data plane's
// initial auth gate (see handleConn in main.go).
func (r *sessionRegistry) sessionValid(tok proxyctl.Token, now time.Time) bool {
	if tok == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[tok]
	return ok && now.Before(s.leaseExpiry)
}

// allowedHost reports whether host is permitted for tok's session: the static
// allowlist or a non-expired runtime grant. An unknown/expired token is
// denied. This is the sole data-plane authorization check for CONNECT.
func (r *sessionRegistry) allowedHost(tok proxyctl.Token, host string, now time.Time) bool {
	if tok == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[tok]
	if !ok || !now.Before(s.leaseExpiry) {
		return false
	}
	return s.allowed(host, now)
}

// requestGrant records (or, for a same-session+host duplicate, coalesces into)
// a pending runtime host grant request for tok's session. It enforces the
// per-session (proxyctl.MaxPendingPerSession) and global
// (proxyctl.MaxPendingGlobal) pending caps. host/ttlMs/reason are assumed
// already validated and bounded by the caller (hostgrant.Validate,
// proxyctl.MaxGrantTTLMs, proxyctl.MaxReasonLen).
func (r *sessionRegistry) requestGrant(tok proxyctl.Token, host string, ttlMs int64, reason string, now time.Time) (pendingGrant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sessions[tok]
	if !ok || !now.Before(s.leaseExpiry) {
		return pendingGrant{}, errUnknownSession
	}

	// Duplicate coalescing: same session + host updates the existing pending
	// entry (fresh TTL/reason/expiry) instead of adding a new one.
	for _, pg := range s.pending {
		if pg.Host == host {
			pg.TTLMs = ttlMs
			pg.Reason = reason
			pg.Expires = now.Add(pendingGrantTTL)
			return *pg, nil
		}
	}

	if len(s.pending) >= proxyctl.MaxPendingPerSession {
		return pendingGrant{}, errPendingCapSession
	}
	total := 0
	for _, sess := range r.sessions {
		total += len(sess.pending)
	}
	if total >= proxyctl.MaxPendingGlobal {
		return pendingGrant{}, errPendingCapGlobal
	}

	gid, err := newGrantID()
	if err != nil {
		return pendingGrant{}, err
	}
	pg := &pendingGrant{
		GrantID: gid,
		Host:    host,
		TTLMs:   ttlMs,
		Reason:  reason,
		Created: now,
		Expires: now.Add(pendingGrantTTL),
	}
	s.pending[gid] = pg
	r.grantIndex[gid] = tok
	return *pg, nil
}

// listPending returns every pending grant request across all sessions, for
// `agentjail grants`. Never carries a Token (see proxyctl.GrantInfo).
func (r *sessionRegistry) listPending() []proxyctl.GrantInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []proxyctl.GrantInfo
	for _, s := range r.sessions {
		for _, pg := range s.pending {
			out = append(out, proxyctl.GrantInfo{
				GrantID: pg.GrantID,
				Host:    pg.Host,
				TTLMs:   pg.TTLMs,
				Cwd:     s.cwd,
				Reason:  pg.Reason,
			})
		}
	}
	return out
}

// approveGrant atomically claims the pending request identified by grantID:
// it removes the entry from the pending set (and the grant index) BEFORE
// calling emitAudit, so a concurrent second approve/deny for the same
// grantID always loses the race and sees errGrantNotFound. It verifies the
// owning session's lease is still live (else errSessionDead, and the claimed
// entry is discarded rather than restored -- the session is gone regardless).
// emitAudit is called BEFORE the grant is applied; if it returns an error the
// grant is NOT applied (fail-closed audit, see ADR 0044) and that error is
// returned to the caller. Only on a nil emitAudit result does the host get
// appended to the session's granted set.
func (r *sessionRegistry) approveGrant(grantID string, now time.Time, emitAudit func(host string) error) (host string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	tok, ok := r.grantIndex[grantID]
	if !ok {
		return "", errGrantNotFound
	}
	delete(r.grantIndex, grantID)

	s, ok := r.sessions[tok]
	if !ok {
		return "", errSessionDead
	}
	pg, ok := s.pending[grantID]
	if !ok {
		return "", errGrantNotFound
	}
	delete(s.pending, grantID)

	if !now.Before(s.leaseExpiry) {
		return "", errSessionDead
	}

	if emitAudit != nil {
		if aerr := emitAudit(pg.Host); aerr != nil {
			return "", fmt.Errorf("audit unavailable, grant not applied: %w", aerr)
		}
	}

	s.granted = append(s.granted, grantedHost{
		Host:    pg.Host,
		GrantID: pg.GrantID,
		Expiry:  now.Add(time.Duration(pg.TTLMs) * time.Millisecond),
	})
	return pg.Host, nil
}

// denyGrant discards the pending request identified by grantID without
// applying it. Same atomic-claim shape as approveGrant.
func (r *sessionRegistry) denyGrant(grantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tok, ok := r.grantIndex[grantID]
	if !ok {
		return errGrantNotFound
	}
	delete(r.grantIndex, grantID)
	if s, ok := r.sessions[tok]; ok {
		delete(s.pending, grantID)
	}
	return nil
}

// newGrantID mints a fresh, non-secret GrantID. It is a display/reference
// handle only -- it carries no authority (unlike Token) so it is safe to
// print, log, and put in an audit RefID.
func newGrantID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mint grant id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// reapResult is what one reap() sweep pruned, for the caller to audit.
type reapResult struct {
	// ExpiredSessions is the Token of every session lease reaped. Token
	// values are returned only for counting/audit; callers must not log them.
	ExpiredSessions []proxyctl.Token
	// ExpiredGrants is every granted host whose TTL lapsed.
	ExpiredGrants []grantedHost
}

// reap deletes every session whose lease has expired and, for sessions that
// remain live, prunes expired granted hosts and stale (past pendingGrantTTL)
// pending requests. It returns what it pruned so the caller can audit each
// expiry (session expiry best-effort; grant expiry best-effort per ADR 0044 --
// only grant_approved is fail-closed).
func (r *sessionRegistry) reap(now time.Time) reapResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	var res reapResult
	for t, s := range r.sessions {
		if !now.Before(s.leaseExpiry) {
			res.ExpiredSessions = append(res.ExpiredSessions, t)
			for gid := range s.pending {
				delete(r.grantIndex, gid)
			}
			delete(r.sessions, t)
			continue
		}

		kept := s.granted[:0]
		for _, g := range s.granted {
			if !now.Before(g.Expiry) {
				res.ExpiredGrants = append(res.ExpiredGrants, g)
				continue
			}
			kept = append(kept, g)
		}
		s.granted = kept

		for gid, pg := range s.pending {
			if !now.Before(pg.Expires) {
				delete(s.pending, gid)
				delete(r.grantIndex, gid)
			}
		}
	}
	return res
}

// count returns the number of live registrations (for tests/observability).
func (r *sessionRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// controlServer serves the control socket: fingerprint, register, and the
// Phase 3 runtime host grant verbs (grant_list/grant_approve/grant_deny). It
// holds the flock'd lockfile for singleton ownership.
type controlServer struct {
	ln       *net.UnixListener
	lock     *os.File
	sockPath string
	registry *sessionRegistry
	emitter  audit.Emitter
	// durableAudit is true only when emitter is backed by a real, writable
	// store (never audit.NopEmitter). grant_approve is refused (fail closed)
	// when this is false -- a live grant must never be applied without a
	// durable audit record (ADR 0044, Codex r3 #1). grant_requested and
	// grant_expired remain best-effort regardless.
	durableAudit bool
	logger       *slog.Logger
	binVer       string
	// ctlToken authenticates callers as processes outside the sandbox. Every
	// verb but fingerprint requires it (ADR 0068).
	ctlToken string
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
// durableAudit must be true only when emitter is backed by a real, writable
// store -- see controlServer.durableAudit.
//
// ctlToken is injected rather than read here so the caller owns the fail-closed
// decision (see run) and tests do not touch the real ~/.agentjail. An empty
// ctlToken is refused: ctlauth.Valid would reject every caller, which would
// present as an unregisterable proxy rather than as the misconfiguration it is.
func newControlServer(sockPath, ctlToken string, registry *sessionRegistry, emitter audit.Emitter, durableAudit bool, binVer string, logger *slog.Logger) (*controlServer, error) {
	if ctlToken == "" {
		return nil, errors.New("refusing to serve the control plane without a control token")
	}
	ln, lock, err := acquireControlSocket(sockPath, logger)
	if err != nil {
		return nil, err
	}
	return &controlServer{
		ln:           ln,
		lock:         lock,
		sockPath:     sockPath,
		registry:     registry,
		emitter:      emitter,
		durableAudit: durableAudit,
		logger:       logger,
		binVer:       binVer,
		ctlToken:     ctlToken,
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

	// Authenticate before dispatch, so a verb added later is gated by default
	// rather than by remembering to gate it (ADR 0068).
	if req.Type != proxyctl.ReqFingerprint && req.Type != proxyctl.ReqConnectorCapabilityUse && req.Type != proxyctl.ReqConnectorCapabilityRemove && !ctlauth.Valid(req.CtlToken, cs.ctlToken) {
		cs.logger.Warn("control request rejected: invalid control token", "type", req.Type)
		cs.reply(conn, proxyctl.Response{OK: false, Error: "unauthorized"})
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
		cs.registry.register(req.Token, req.SessionID, req.Cwd, *req.Policy, time.Duration(req.LeaseTTLMs)*time.Millisecond, time.Now())
		// State change -> Info + audit (best-effort). Token is NEVER included.
		cs.logger.Info("session registered", "allowed_hosts_count", len(req.Policy.AllowedHosts), "live_sessions", cs.registry.count())
		_ = cs.emitter.Emit(context.Background(), audit.Event{
			EventType: audit.NetproxySessionRegistered,
			Actor:     "netproxy",
			Detail:    map[string]string{"allowed_hosts_count": fmt.Sprintf("%d", len(req.Policy.AllowedHosts))},
		})
		cs.reply(conn, proxyctl.Response{OK: true})

	case proxyctl.ReqGrantList:
		// Never carries a Token -- see proxyctl.GrantInfo.
		cs.reply(conn, proxyctl.Response{OK: true, Grants: cs.registry.listPending()})

	case proxyctl.ReqGrantApprove:
		if req.GrantID == "" {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "grant_approve requires grant_id"})
			return
		}
		// Fail-closed audit gate (ADR 0044, Codex r3 #1): a live grant must
		// never be applied without a durable audit record. Refuse outright,
		// before ever touching the pending set, so the request remains
		// pending and can be retried once audit is available again.
		if !cs.durableAudit {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "audit unavailable, refusing to approve grant (fail closed)"})
			return
		}
		grantID := req.GrantID
		host, err := cs.registry.approveGrant(grantID, time.Now(), func(h string) error {
			return cs.emitter.Emit(context.Background(), audit.Event{
				EventType: audit.NetproxyGrantApproved,
				Actor:     "netproxy",
				RefID:     grantID,
				Detail:    map[string]string{"host": h},
			})
		})
		if err != nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: err.Error()})
			return
		}
		cs.logger.Info("grant approved", "grant_id", grantID, "host", host)
		cs.reply(conn, proxyctl.Response{OK: true})

	case proxyctl.ReqGrantDeny:
		if req.GrantID == "" {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "grant_deny requires grant_id"})
			return
		}
		if err := cs.registry.denyGrant(req.GrantID); err != nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: err.Error()})
			return
		}
		cs.logger.Info("grant denied", "grant_id", req.GrantID)
		_ = cs.emitter.Emit(context.Background(), audit.Event{
			EventType: audit.NetproxyGrantDenied,
			Actor:     "netproxy",
			RefID:     req.GrantID,
		})
		cs.reply(conn, proxyctl.Response{OK: true})

	case proxyctl.ReqConnectorInstall:
		if req.Connector == nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "connector_install requires connector"})
			return
		}
		if err := cs.registry.installConnector(*req.Connector, time.Now()); err != nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: err.Error()})
			return
		}
		cs.reply(conn, proxyctl.Response{OK: true})

	case proxyctl.ReqConnectorRemove:
		if req.Connector == nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "connector_remove requires connector"})
			return
		}
		if err := cs.registry.removeConnector(*req.Connector); err != nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: err.Error()})
			return
		}
		cs.reply(conn, proxyctl.Response{OK: true})
	case proxyctl.ReqConnectorCapabilityRegister:
		if req.Connector == nil || req.ConnectorCapability == "" {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "connector capability registration requires connector and capability"})
			return
		}
		if err := cs.registry.registerConnectorCapability(req.Token, req.ConnectorCapability, *req.Connector, time.Now()); err != nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: err.Error()})
			return
		}
		cs.reply(conn, proxyctl.Response{OK: true})
	case proxyctl.ReqConnectorCapabilityUse:
		if req.Connector == nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "connector capability use requires connector"})
			return
		}
		if err := cs.registry.useConnectorCapability(req.ConnectorCapability, req.Connector.ConnectorID, time.Now()); err != nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: err.Error()})
			return
		}
		cs.reply(conn, proxyctl.Response{OK: true})
	case proxyctl.ReqConnectorCapabilityRemove:
		if req.Connector == nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: "connector capability removal requires connector"})
			return
		}
		if err := cs.registry.removeConnectorCapability(req.ConnectorCapability, req.Connector.ConnectorID); err != nil {
			cs.reply(conn, proxyctl.Response{OK: false, Error: err.Error()})
			return
		}
		cs.reply(conn, proxyctl.Response{OK: true})

	default:
		// ReqGrant (additive widen without approval flow) is not served.
		cs.reply(conn, proxyctl.Response{OK: false, Error: fmt.Sprintf("unsupported control request %q", req.Type)})
	}
}

func (cs *controlServer) reply(conn net.Conn, resp proxyctl.Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		cs.logger.Warn("control reply write failed", "err", err)
	}
}
