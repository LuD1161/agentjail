package grantctl

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// PendingGrantTTL bounds how long an undecided grant request sits in the
// pending queue before the reaper prunes it. This is independent of the
// grant's own requested TTLMs (which governs the *applied* grant's lifetime
// once approved); PendingGrantTTL only bounds how long a human has to
// approve/deny before the request itself goes stale.
const PendingGrantTTL = time.Hour

// Sentinel errors returned by Registry methods. Callers (the control-socket
// server) map these to Response.Error strings.
var (
	// ErrGrantNotFound is returned when a GrantID does not match any pending
	// (unclaimed) grant.
	ErrGrantNotFound = errors.New("grant not found")
	// ErrGrantAlreadyClaimed is returned by ClaimGrant when the grant is
	// currently held by an in-flight claim (another approver, or a claim
	// that has not yet been committed or rolled back).
	ErrGrantAlreadyClaimed = errors.New("grant already claimed")
	// ErrPerSessionCapExceeded is returned by RequestGrant when the
	// requesting session already has MaxPendingPerSession outstanding
	// requests.
	ErrPerSessionCapExceeded = errors.New("per-session pending grant cap exceeded")
	// ErrGlobalCapExceeded is returned by RequestGrant when the daemon
	// already holds MaxPendingGlobal outstanding requests across all
	// sessions.
	ErrGlobalCapExceeded = errors.New("global pending grant cap exceeded")
)

// pendingGrant is the registry's internal record for one outstanding grant
// request. It carries strictly more state than GrantInfo (the display type):
// BoundCWD, Created/Expires, and claimed, none of which are exposed to
// `agentjail grants list`.
type pendingGrant struct {
	GrantID   string
	Host      string
	TTLMs     int64
	Reason    string
	SessionID string
	CWD       string
	// BoundCWD is set by SetBoundCWD once the daemon resolves the
	// requesting session's live working directory via PID lookup. Empty
	// until then.
	BoundCWD string
	Created  time.Time
	Expires  time.Time
	// claimed is true while a ClaimGrant transaction is in flight (between
	// ClaimGrant returning and the caller invoking commitFn or rollbackFn).
	// A claimed grant is invisible to ListPending and FindGrant, and cannot
	// be claimed again until rolled back.
	claimed bool
}

// info projects a pendingGrant down to the display-only GrantInfo type.
func (pg *pendingGrant) info() GrantInfo {
	return GrantInfo{
		GrantID:   pg.GrantID,
		Host:      pg.Host,
		TTLMs:     pg.TTLMs,
		SessionID: pg.SessionID,
		CWD:       pg.CWD,
		Reason:    pg.Reason,
	}
}

// claimed projects a pendingGrant down to the ClaimedGrant snapshot type
// returned by ClaimGrant.
func (pg *pendingGrant) toClaimedGrant() ClaimedGrant {
	return ClaimedGrant{
		GrantID:   pg.GrantID,
		Host:      pg.Host,
		TTLMs:     pg.TTLMs,
		SessionID: pg.SessionID,
		CWD:       pg.CWD,
		Reason:    pg.Reason,
		BoundCWD:  pg.BoundCWD,
	}
}

// ReapResult summarizes one Reap() pass over the pending queue.
type ReapResult struct {
	// Reaped lists the GrantIDs pruned for exceeding PendingGrantTTL.
	Reaped []string
}

// Registry is the daemon's in-memory store of pending grant requests. It is
// the sole owner of grant state: the control-socket server (grantctl server,
// not part of this package) never mutates grant state directly, it only
// calls Registry methods. All methods are safe for concurrent use.
//
// Registry holds no persistence; a daemon restart drops all pending grants
// (matching the existing netproxy sessionRegistry behavior this replaces).
type Registry struct {
	mu sync.RWMutex
	// grants indexes every pending (including currently-claimed) grant by
	// GrantID.
	grants map[string]*pendingGrant
	// bySessionHost enables the duplicate-request coalesce check in
	// RequestGrant: (sessionID, host) -> GrantID.
	bySessionHost map[sessionHostKey]string
}

// sessionHostKey is the composite key used to detect a duplicate in-flight
// grant request for the same session and host.
type sessionHostKey struct {
	sessionID string
	host      string
}

// NewRegistry constructs an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		grants:        make(map[string]*pendingGrant),
		bySessionHost: make(map[sessionHostKey]string),
	}
}

// countPendingForSession returns the number of non-claimed grants currently
// filed by sessionID. Caller must hold at least r.mu (read or write lock).
func (r *Registry) countPendingForSession(sessionID string) int {
	n := 0
	for _, pg := range r.grants {
		if pg.claimed {
			continue
		}
		if pg.SessionID == sessionID {
			n++
		}
	}
	return n
}

// countPendingGlobal returns the number of non-claimed grants across all
// sessions. Caller must hold at least r.mu (read or write lock).
func (r *Registry) countPendingGlobal() int {
	n := 0
	for _, pg := range r.grants {
		if !pg.claimed {
			n++
		}
	}
	return n
}

// RequestGrant files a new pending grant request for sessionID at host, or
// coalesces into an existing pending request for the same (sessionID, host)
// pair (updating its TTL, reason, and expiry rather than creating a
// duplicate). It enforces MaxPendingPerSession and MaxPendingGlobal before
// creating a brand new entry (coalescing into an existing entry never
// increases the pending count, so the caps do not apply to it).
func (r *Registry) RequestGrant(sessionID, cwd, host string, ttlMs int64, reason string, now time.Time) (GrantInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := sessionHostKey{sessionID: sessionID, host: host}
	if existingID, ok := r.bySessionHost[key]; ok {
		if pg, ok := r.grants[existingID]; ok && !pg.claimed {
			pg.TTLMs = ttlMs
			pg.Reason = reason
			pg.CWD = cwd
			pg.Expires = now.Add(PendingGrantTTL)
			return pg.info(), nil
		}
		// Stale index entry (grant claimed/removed without cleanup); fall
		// through and treat as a fresh request.
		delete(r.bySessionHost, key)
	}

	if r.countPendingForSession(sessionID) >= MaxPendingPerSession {
		return GrantInfo{}, ErrPerSessionCapExceeded
	}
	if r.countPendingGlobal() >= MaxPendingGlobal {
		return GrantInfo{}, ErrGlobalCapExceeded
	}

	id, err := newGrantID()
	if err != nil {
		return GrantInfo{}, err
	}

	pg := &pendingGrant{
		GrantID:   id,
		Host:      host,
		TTLMs:     ttlMs,
		Reason:    reason,
		SessionID: sessionID,
		CWD:       cwd,
		Created:   now,
		Expires:   now.Add(PendingGrantTTL),
	}
	r.grants[id] = pg
	r.bySessionHost[key] = id
	return pg.info(), nil
}

// ListPending returns the display-only view of every currently pending
// (unclaimed) grant request. The order is unspecified.
func (r *Registry) ListPending() []GrantInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]GrantInfo, 0, len(r.grants))
	for _, pg := range r.grants {
		if pg.claimed {
			continue
		}
		out = append(out, pg.info())
	}
	return out
}

// ReviewSnapshot returns the deterministic v1 projection of unclaimed,
// unexpired grants at now. The supplied time is used for both expiry and the
// response timestamp. See ADR 0133-macos-menu-review.
func (r *Registry) ReviewSnapshot(now time.Time) ReviewSnapshotV1 {
	type projectedReview struct {
		created time.Time
		info    ReviewInfo
	}

	r.mu.RLock()
	projected := make([]projectedReview, 0, len(r.grants))
	for _, pg := range r.grants {
		if pg.claimed || !pg.Expires.After(now) {
			continue
		}
		projected = append(projected, projectedReview{
			created: pg.Created,
			info:    pg.reviewInfo(),
		})
	}
	r.mu.RUnlock()

	sort.Slice(projected, func(i, j int) bool {
		if !projected[i].created.Equal(projected[j].created) {
			return projected[i].created.After(projected[j].created)
		}
		return projected[i].info.ReviewID < projected[j].info.ReviewID
	})

	total := len(projected)
	if len(projected) > MaxReviewSnapshotItems {
		projected = projected[:MaxReviewSnapshotItems]
	}
	reviews := make([]ReviewInfo, len(projected))
	for i := range projected {
		reviews[i] = projected[i].info
	}

	return ReviewSnapshotV1{
		ProtocolVersion:   ReviewProtocolVersion,
		GeneratedAtUnixMs: UnixMilliseconds(now.UnixMilli()),
		TotalPending:      total,
		Truncated:         total > len(reviews),
		Reviews:           reviews,
	}
}

// reviewInfo projects one pending grant without using the self-reported CWD.
func (pg *pendingGrant) reviewInfo() ReviewInfo {
	host, hostOK := completeReviewAuthority(pg.Host, MaxReviewHostBytes)
	projectPath := ""
	projectOK := false
	if pg.BoundCWD != "" {
		projectPath, projectOK = completeReviewAuthority(pg.BoundCWD, MaxReviewProjectPathBytes)
	}

	state := ReviewContextStateVerified
	canApprove := true
	switch {
	case !hostOK || (pg.BoundCWD != "" && !projectOK):
		state = ReviewContextStateUnrepresentable
		canApprove = false
	case pg.BoundCWD == "":
		state = ReviewContextStateUnbound
		canApprove = false
	}

	reason, reasonTruncated := truncateReviewReason(pg.Reason)
	return ReviewInfo{
		ReviewID:        ReviewID(pg.GrantID),
		Kind:            ReviewKindProjectHost,
		Host:            host,
		ProjectPath:     projectPath,
		Reason:          reason,
		ReasonTruncated: reasonTruncated,
		ContextState:    state,
		CreatedAtUnixMs: UnixMilliseconds(pg.Created.UnixMilli()),
		ExpiresAtUnixMs: UnixMilliseconds(pg.Expires.UnixMilli()),
		ApprovalScope:   ReviewScopeFutureProjectSessions,
		CanApprove:      canApprove,
		CanDeny:         true,
	}
}

func completeReviewAuthority(value string, limit int) (string, bool) {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return "", false
	}
	return value, true
}

func truncateReviewReason(value string) (string, bool) {
	truncated := false
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "\uFFFD")
		truncated = true
	}
	if len(value) <= MaxReviewReasonBytes {
		return value, truncated
	}

	cut := MaxReviewReasonBytes
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut], true
}

// SetBoundCWD records the daemon-observed working directory for grantID,
// resolved via PID lookup after the request was filed. It is a no-op if
// grantID does not exist (e.g., it expired or was denied between the
// request and the PID lookup completing).
func (r *Registry) SetBoundCWD(grantID, cwd string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if pg, ok := r.grants[grantID]; ok {
		pg.BoundCWD = cwd
	}
}

// FindGrant looks up a still-pending (unclaimed) grant by ID without
// claiming it. It returns (GrantInfo{}, false) if the grant does not exist
// or is currently claimed.
func (r *Registry) FindGrant(grantID string) (GrantInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pg, ok := r.grants[grantID]
	if !ok || pg.claimed {
		return GrantInfo{}, false
	}
	return pg.info(), true
}

// ClaimGrant atomically transitions the pending grant identified by grantID
// into the "claimed" state and returns a snapshot plus a commit/rollback
// pair. The caller (the control-socket server, after it has applied the
// grant to the sandbox and emitted the fail-closed audit event) must call
// exactly one of the two returned functions:
//
//   - commitFn: permanently deletes the grant from the registry. Call this
//     once the grant has been successfully applied AND the audit event has
//     been recorded.
//   - rollbackFn: restores the grant to the pending queue (claimed=false),
//     making it visible again in ListPending/FindGrant and reclaimable. Call
//     this if applying the grant or emitting its audit event failed, so the
//     fail-closed contract (see the credential broker rule) is upheld:
//     no changes take effect without a corresponding audit record.
//
// While a grant is claimed, no other caller can claim it (ErrGrantAlreadyClaimed)
// and it is invisible to ListPending/FindGrant. Both returned functions are
// idempotent-safe to call once; calling ClaimGrant again for the same ID
// before commit/rollback returns ErrGrantAlreadyClaimed.
func (r *Registry) ClaimGrant(grantID string) (ClaimedGrant, func(), func(), error) {
	r.mu.Lock()

	pg, ok := r.grants[grantID]
	if !ok {
		r.mu.Unlock()
		return ClaimedGrant{}, nil, nil, ErrGrantNotFound
	}
	if pg.claimed {
		r.mu.Unlock()
		return ClaimedGrant{}, nil, nil, ErrGrantAlreadyClaimed
	}
	pg.claimed = true
	snapshot := pg.toClaimedGrant()
	r.mu.Unlock()

	commitFn := func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.grants, grantID)
		key := sessionHostKey{sessionID: pg.SessionID, host: pg.Host}
		if r.bySessionHost[key] == grantID {
			delete(r.bySessionHost, key)
		}
	}
	rollbackFn := func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if cur, ok := r.grants[grantID]; ok {
			cur.claimed = false
		}
	}

	return snapshot, commitFn, rollbackFn, nil
}

// DenyGrant discards the pending grant identified by grantID without
// applying it. It returns ErrGrantNotFound if grantID does not match any
// pending grant. Denying a claimed grant is not supported by this method
// (the claim holder must roll back first); this mirrors the netproxy
// sessionRegistry.denyGrant which operates only on unclaimed entries.
func (r *Registry) DenyGrant(grantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pg, ok := r.grants[grantID]
	if !ok {
		return ErrGrantNotFound
	}
	delete(r.grants, grantID)
	key := sessionHostKey{sessionID: pg.SessionID, host: pg.Host}
	if r.bySessionHost[key] == grantID {
		delete(r.bySessionHost, key)
	}
	return nil
}

// Reap prunes every pending (unclaimed) grant whose Expires has passed as of
// now. Claimed grants are never reaped (the claim holder is responsible for
// commit/rollback). It returns the GrantIDs pruned.
func (r *Registry) Reap(now time.Time) ReapResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result ReapResult
	for id, pg := range r.grants {
		if pg.claimed {
			continue
		}
		if now.Before(pg.Expires) {
			continue
		}
		delete(r.grants, id)
		key := sessionHostKey{sessionID: pg.SessionID, host: pg.Host}
		if r.bySessionHost[key] == id {
			delete(r.bySessionHost, key)
		}
		result.Reaped = append(result.Reaped, id)
	}
	return result
}

// newGrantID mints a fresh, non-secret GrantID: 16 random bytes, hex
// encoded. It is a display/reference handle only, not a capability token, so
// it is safe to print, log, and put in an audit RefID. Mirrors
// agentjail-netproxy's newGrantID (cmd/agentjail-netproxy/control.go).
func newGrantID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mint grant id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
