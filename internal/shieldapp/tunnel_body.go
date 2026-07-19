package shieldapp

// Body-transcript recording is OS-agnostic: keyring.Open() already dispatches
// to the right backend per OS (darwin keychain, Linux Secret Service/file-KEK
// ladder, an ErrNoKeychain stub elsewhere). Keeping this logic in one tag-free
// file, rather than duplicated per platform, is the shared-contract pattern in
// ADR 0034-platform-backend-shared-contract: only the KEK source is per-OS,
// and that source already lives in internal/keyring.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/keyring"
	"github.com/LuD1161/agentjail/internal/mitm"
)

// openBodyKeys is the KEK seam. Tests substitute a wrapper.
// See ADR 0095-chunked-body-envelope.
var openBodyKeys = func() (mitm.KeyWrapper, string, error) {
	kr, err := keyring.Open()
	if err != nil {
		return nil, "", err
	}
	return kr, kr.Backend(), nil
}

// keyState is why the session has no KEK. A LOCKED keychain and an ABSENT one
// need opposite advice, so they are never collapsed. See AGE-254.
type keyState string

// The degraded states ARE the audit reason vocabulary: one source of truth.
const (
	keysAvailable keyState = ""
	keysLocked    keyState = audit.TunnelKeysLocked
	keysAbsent    keyState = audit.TunnelKeysAbsent
	keysError     keyState = audit.TunnelKeysError
)

// classifyKeyErr must test ErrKeychainLocked FIRST: it wraps ErrNoKeychain, so
// the reverse order silently gives every locked host the absent advice.
// See AGE-254.
func classifyKeyErr(err error) keyState {
	switch {
	case err == nil:
		return keysAvailable
	case errors.Is(err, keyring.ErrKeychainLocked):
		return keysLocked
	case errors.Is(err, keyring.ErrNoKeychain):
		return keysAbsent
	default:
		return keysError
	}
}

// cause states what is actually true of this host's keychain, and advice says
// what the user can do about it - different per state. See AGE-254.
func (s keyState) cause() string {
	switch s {
	case keysLocked:
		return "An OS keychain IS present here, but it is LOCKED, so no key could be sealed"
	case keysAbsent:
		return "There is NO OS keychain on this host, so no key could be sealed"
	default:
		return "The OS keychain could not be opened, so no key could be sealed"
	}
}

func (s keyState) advice() string {
	switch s {
	case keysLocked:
		return "To encrypt future sessions: unlock the login keyring, or enable PAM auto-unlock at login"
	case keysAbsent:
		return "Nothing to unlock: no keychain exists here. Run a Secret Service keyring, or accept plaintext capture"
	default:
		return "Check the keychain service, then relaunch to encrypt future sessions"
	}
}

// bodyRecording is the recording posture ACHIEVED for one session, not the one
// requested, so the launch notice cannot overclaim.
// See ADR 0092-persist-request-bodies (D5).
type bodyRecording struct {
	store     *mitm.BodyStore
	encrypted bool
	backend   string   // KEK backend; "" when bodies are in the clear
	keys      keyState // why bodies are in the clear; keysAvailable when encrypted
}

// notice is the launch banner's recording clause. No sweep runs yet, so the
// window is stated as the target it is. See ADR 0092-persist-request-bodies (D2, D5).
func (r bodyRecording) notice() string {
	switch {
	case r.store == nil:
		return "bodies NOT recorded (capture unavailable; interception and policy unaffected)"
	case r.encrypted:
		return fmt.Sprintf("RECORDING request/response bodies, encrypted at rest under the %s keychain "+
			"(retention target 90 days or 1 GB; no sweep runs yet, so bodies persist until removed)", r.backend)
	default:
		return fmt.Sprintf("RECORDING request/response bodies UNENCRYPTED (%s; %s; retention target 90 days "+
			"or 1 GB, but no sweep runs yet, so bodies persist until removed)",
			r.keys.cause(), r.keys.advice())
	}
}

// newBodyRecording builds the session's body store. It never fails the tunnel:
// policy evaluates from the in-memory body, not the recorder.
// See ADR 0092-persist-request-bodies (D1, D5).
func newBodyRecording(ctx context.Context, sessionID string, logger *slog.Logger, emitter audit.Emitter) bodyRecording {
	keys, backend, keyErr := openBodyKeys()

	store, err := mitm.NewBodyStore(mitm.DefaultBodyDir(), sessionID, keys)
	if err != nil {
		logger.Warn("tunnel body recording UNAVAILABLE; interception stays ON and HTTP(S) policy still evaluates - this session's bodies are simply not kept",
			"dir", mitm.DefaultBodyDir(), "err", err)
		return bodyRecording{}
	}
	if keyErr != nil {
		state := classifyKeyErr(keyErr)
		reportUnencryptedBodies(ctx, sessionID, state, keyErr, logger, emitter)
		return bodyRecording{store: store, keys: state}
	}
	return bodyRecording{store: store, encrypted: true, backend: backend}
}

// reportUnencryptedBodies makes the degraded posture loud on stderr and durable
// in agentjail.db: network.db cannot hold its own failure.
// See ADR 0092-persist-request-bodies (D5), AGE-254.
func reportUnencryptedBodies(ctx context.Context, sessionID string, state keyState, keyErr error, logger *slog.Logger, emitter audit.Emitter) {
	fmt.Fprintf(os.Stderr,
		"agentjail-shield: WARNING - recording this agent's HTTPS bodies IN THE CLEAR\n"+
			"  %s (%v).\n"+
			"  Captured request/response bodies - including any secrets this agent sends -\n"+
			"  are written UNENCRYPTED to %s\n"+
			"  %s.\n"+
			"  Recording continues by design: policy enforcement must not depend on the recorder.\n",
		state.cause(), keyErr, mitm.DefaultBodyDir(), state.advice())
	logger.Warn("tunnel body recording is UNENCRYPTED - "+state.cause(),
		"dir", mitm.DefaultBodyDir(), "session", sessionID, "reason", string(state), "err", keyErr)

	if emitter == nil {
		return
	}
	// Fixed strings only: never the raw error, never key material, never body
	// bytes. ADR 0032.
	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.TunnelBodiesUnencrypted,
		Entity:    mitm.BodyDirName,
		SessionID: sessionID,
		Detail: map[string]string{
			"kek_backend": "none",
			"reason":      string(state),
			"posture":     "recording continues in the clear",
		},
	})
}
