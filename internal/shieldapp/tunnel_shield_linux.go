//go:build linux

package shieldapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/keyring"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/netns"
	"github.com/LuD1161/agentjail/internal/tunnel"
)

// openBodyKeys is the KEK seam. Linux has no keychain backend yet, so it
// reports ErrNoKeychain today; tests substitute a wrapper.
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
// what the user can do about it -- different per state. See AGE-254.
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
		logger.Warn("tunnel body recording UNAVAILABLE; interception stays ON and HTTP(S) policy still evaluates — this session's bodies are simply not kept",
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
		"agentjail-shield: WARNING — recording this agent's HTTPS bodies IN THE CLEAR\n"+
			"  %s (%v).\n"+
			"  Captured request/response bodies — including any secrets this agent sends —\n"+
			"  are written UNENCRYPTED to %s\n"+
			"  %s.\n"+
			"  Recording continues by design: policy enforcement must not depend on the recorder.\n",
		state.cause(), keyErr, mitm.DefaultBodyDir(), state.advice())
	logger.Warn("tunnel body recording is UNENCRYPTED — "+state.cause(),
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

// tunnelSession bundles one shield's live transparent-tunnel objects so the
// exec path can run the agent inside the namespace and cleanup can tear it all
// down in the right order.
type tunnelSession struct {
	ns        *netns.Namespace
	gw        *tunnel.Gateway
	tun       *os.File
	dns       *dnsvip.Server
	store     *mitm.RequestStore // non-nil when TLS interception is enabled
	caCleanup func()             // removes the temp CA cert dir; nil if no MITM
	caEnv     map[string]string  // CA trust env for the agent; nil if no MITM
	// mitmActive is the posture ACHIEVED, not the one requested. ADR 0077 (D6).
	mitmActive bool
	cancel     context.CancelFunc
}

// startTunnel sets up the unprivileged-userns transparent tunnel (ADR 0079,
// AGE-148): an isolated user+network namespace whose only route is a TUN
// device, with the agent's traffic pumped into a userspace forwarder. No host
// CAP_NET_ADMIN, no privileged daemon, no install password — the privileged
// network operation happens only inside namespaces this process created and
// owns.
//
// It is strictly fail-open: ANY failure returns (nil, false) and the caller
// falls back to netproxy. A broken or unavailable tunnel must never choke the
// agent's network (a hard constraint of this feature).
//
// NOTE (remaining integration gap): the forwarder intercepts TCP to any
// destination, but DNS-VIP resolution over the TUN (UDP) is not yet wired, so
// name resolution inside the namespace does not work end-to-end. --tunnel is
// therefore opt-in and experimental until the DNS-VIP/UDP slice lands. The
// registry is still passed to the gateway so per-VIP policy can attach once DNS
// is wired. See docs/reviews/2026-07-08-network-visibility-review.md (W1).
// mitmEnabled selects the posture: false relays TLS opaquely, true terminates
// it via a per-session namespace-scoped CA. ADR 0077.
// usernsRestrictedByAppArmor reports whether Ubuntu's AppArmor userns
// restriction is the active block (kernel.apparmor_restrict_unprivileged_userns=1),
// distinguishing it from other tunnel-setup errors so only that case fails loud
// with the scoped-profile remediation. See ADR 0104-shield-apparmor-userns.
func usernsRestrictedByAppArmor() bool {
	b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func startTunnel(ctx context.Context, mitmEnabled bool, emitter audit.Emitter) (*tunnelSession, bool) {
	logger := slog.Default()

	// Create the owned user+net+mount namespaces and the in-namespace TUN,
	// receiving the open TUN fd back over SCM_RIGHTS.
	ns, tun, err := netns.CreateWithTUN(netns.TUNIfName, netns.TUNAddrCIDR)
	if err != nil {
		// The one failure that does NOT fall open: userns blocked by Ubuntu's
		// AppArmor restriction. A tunnel that silently becomes netproxy is the
		// AGE-212 failure shape applied to network capture, so --tunnel fails
		// loud with the single remediation. See ADR 0104-shield-apparmor-userns.
		if errors.Is(err, netns.ErrUnsupported) && usernsRestrictedByAppArmor() {
			fmt.Fprintf(os.Stderr,
				"agentjail-shield ERROR: --tunnel requires an unprivileged user namespace,\n"+
					"  which this host restricts (kernel.apparmor_restrict_unprivileged_userns=1).\n"+
					"  agentjail can enable it for its OWN binary only, without weakening the\n"+
					"  setting for anything else on your machine:\n\n"+
					"    run: agentjail install --with-apparmor\n\n"+
					"  Refusing to launch: the tunnel is either real or off — it will not\n"+
					"  silently degrade to netproxy. (%v)\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr,
			"agentjail-shield: transparent tunnel unavailable (%v)\n"+
				"  Falling back to netproxy mode.\n", err)
		return nil, false
	}

	registry := dnsvip.NewRegistry()
	tunnelCtx, cancel := context.WithCancel(ctx)

	// Forward gateway: a userspace gVisor stack that accepts a SYN to any
	// destination the agent dials (the S-F1 transparent-forwarder fix).
	//
	// PacksDir wires the L7 policy matcher into the MITM handler (via
	// gw.Matcher() below): with it set, decrypted HTTPS is evaluated against the
	// Nuclei-style templates in the dir and denied operations get a 403. Without
	// it the matcher is nil and the MITM is observe/log-only. Sourced from
	// AGENTJAIL_NETPACKS_DIR, falling back to ~/.agentjail/netpacks when that dir
	// exists, so enforcement is opt-in per install and empty by default.
	gw, err := tunnel.NewForwardGateway(tunnel.Config{MTU: netns.TUNMTU, PacksDir: resolveNetpacksDir()}, registry, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield: could not create tunnel gateway (%v)\n"+
				"  Falling back to netproxy mode.\n", err)
		cancel()
		_ = tun.Close()
		_ = ns.Close()
		return nil, false
	}

	// Pump raw IP packets between the netns TUN fd and the forwarder.
	if err := gw.AttachTUN(tunnelCtx, tun); err != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield: could not attach TUN to gateway (%v)\n"+
				"  Falling back to netproxy mode.\n", err)
		cancel()
		_ = gw.Close()
		_ = tun.Close()
		_ = ns.Close()
		return nil, false
	}

	// TLS interception (AGE-149) is ON by default here and declinable via
	// --no-mitm / network.tunnel_mitm: false, which relay TLS opaquely and
	// forfeit HTTP(S) policy. ADR 0077 (D1, D2).
	sess := &tunnelSession{ns: ns, gw: gw, tun: tun, cancel: cancel}
	// CA injection replaces the namespace trust store, so it is the LAST
	// fallible step before SetMITM. ADR 0077 (D6).
	if !mitmEnabled {
		// No CA minted, no SetMITM: the gateway relays TLS byte-for-byte.
		logger.Info("tunnel TLS interception OFF (transparent-only) — HTTP(S) policy templates will NOT match; visibility is destination IP, SNI and byte counts only")
	} else if store, serr := mitm.NewRequestStore(mitm.DefaultDBPath()); serr != nil {
		logger.Warn("tunnel TLS interception UNAVAILABLE (network.db open failed); relaying HTTPS opaque — HTTP(S) policy templates will NOT match", "err", serr)
	} else if caDir, caCert, caKey, caCleanup, err := setupTunnelCA(ns); err != nil {
		_ = store.Close() // not on sess yet; cleanup() would not reach it
		logger.Warn("tunnel TLS interception UNAVAILABLE (CA setup failed); relaying HTTPS opaque — HTTP(S) policy templates will NOT match", "err", err)
	} else {
		// Fail-open: an id-less session logs ungrouped rows, which must not cost
		// the agent its network. See ADR 0092-persist-request-bodies (D1).
		sessionID, sidErr := mitm.NewSessionID()
		if sidErr != nil {
			logger.Warn("tunnel session id unavailable; request logs will not be grouped per session", "err", sidErr)
		}
		sess.store = store
		sess.caCleanup = caCleanup
		// Node/Python ignore the namespace trust store. ADR 0034, AGE-113.
		sess.caEnv = TunnelCAEnv(TunnelCACertPath(caDir), TunnelCABundlePath(caDir))
		h := mitm.NewMITMHandler(caCert, caKey, logger, func(rl *mitm.RequestLog) {
			if lerr := store.Log(rl); lerr != nil {
				logger.Debug("network.db log failed", "err", lerr)
			}
		})
		h.SessionID = sessionID
		// This shield process owns the session; the UI reads its liveness back
		// to decide "active". See ADR 0100-network-active-pid.
		h.OwnerPID = os.Getpid()
		h.Matcher = gw.Matcher() // nil => observe/log only (no PacksDir configured)
		h.Audit = emitter        // session-level notices, e.g. the ALPN downgrade (AGE-222)
		rec := newBodyRecording(ctx, sessionID, logger, emitter)
		h.Bodies = rec.store // nil => decrypt without keeping a transcript
		gw.SetMITM(h)
		sess.mitmActive = true
		logger.Info("tunnel TLS interception ON — agentjail is decrypting this agent's HTTPS via a per-session CA scoped to its namespace; "+rec.notice(),
			"db", mitm.DefaultDBPath(), "bodies", mitm.DefaultBodyDir(), "session", sessionID)
	}

	go func() {
		if err := gw.ListenAndServe(tunnelCtx); err != nil && tunnelCtx.Err() == nil {
			logger.Error("tunnel gateway error", "err", err)
		}
	}()

	return sess, true
}

// cleanup tears the tunnel down. Order matters: stop the gateway/pump first (it
// holds the TUN fd), then close the fd, then SIGKILL the namespace holder so the
// kernel reclaims the namespaces. Safe on a nil receiver.
func (s *tunnelSession) cleanup() {
	if s == nil {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.gw != nil {
		_ = s.gw.Close() // also stops the fd pump (Gateway.pump)
	}
	if s.dns != nil {
		_ = s.dns.Close()
	}
	if s.tun != nil {
		_ = s.tun.Close()
	}
	if s.store != nil {
		_ = s.store.Close()
	}
	if s.caCleanup != nil {
		s.caCleanup() // remove the temp CA cert dir (key was never on disk)
	}
	if s.ns != nil {
		_ = s.ns.Close() // SIGKILL the holder -> namespaces torn down
	}
}
