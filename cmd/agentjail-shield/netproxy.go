// Package main is agentjail-shield. This file contains platform-independent
// helpers for locating, launching, and registering a session with
// agentjail-netproxy.
//
// One netproxy serves every shielded session on 127.0.0.1:9100. Rather than a
// blind "is something on :9100?" TCP probe (which could reuse a stale proxy
// carrying another session's allowlist), the shield speaks the control protocol
// (internal/proxyctl): it fingerprints the running proxy, reuses it only if the
// protocol version is compatible, and registers THIS session's allowlist under
// an unguessable token. The token is injected as the agent's proxy credential
// so netproxy keys the right per-session allowlist.

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
	"github.com/LuD1161/agentjail/internal/proxyctl"
)

// sessionPolicyFromConfig builds the per-session allowlist the shield registers
// with netproxy: the fully-resolved EffectiveAllowedHosts (essentials ++
// MCP-derived ++ editable). A nil config falls back to the non-removable
// essentials so a session is never registered wide-open or empty.
func sessionPolicyFromConfig(cfg *config.PolicyConfig) proxyctl.SessionPolicy {
	if cfg == nil {
		return proxyctl.SessionPolicy{AllowedHosts: config.EssentialAllowedHosts()}
	}
	return proxyctl.SessionPolicy{AllowedHosts: cfg.EffectiveAllowedHosts()}
}

// resolveSessionPolicy builds the session allowlist, applying a per-folder
// `./.agentjail/policy.yaml` overlay ONLY when the agent's working directory is
// trusted (direnv-style). Untrusted or malformed overlays are ignored
// (global-only) and audited. The overlay merge is additive-only, so a trusted
// project can only WIDEN egress, never weaken a global restriction. Called
// pre-sandbox in the shield, so the trust store (~/.agentjail/trusted.yaml,
// agent-unwritable) is read out-of-band.
func resolveSessionPolicy(ctx context.Context, cfg *config.PolicyConfig, emitter audit.Emitter) proxyctl.SessionPolicy {
	cwd, err := os.Getwd()
	if err != nil {
		return sessionPolicyFromConfig(cfg)
	}
	home, _ := os.UserHomeDir()
	trustPath := projectpolicy.TrustStorePath(filepath.Join(home, projectpolicy.ProjectDirName))

	res, rerr := projectpolicy.Resolve(cfg, cwd, home, trustPath)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: project overlay resolve error (ignored): %v\n", rerr)
	}
	switch res.Status {
	case projectpolicy.StatusApplied:
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: applied trusted project overlay %s\n", res.OverlayPath)
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.ProjectOverlayApplied,
			Actor:     "shield",
			Detail:    map[string]string{"overlay": res.OverlayPath},
		})
	case projectpolicy.StatusUntrusted:
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: ignoring UNTRUSTED project overlay %s -- run 'agentjail trust' to apply it\n", res.OverlayPath)
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.ProjectOverlayIgnoredUntrusted,
			Actor:     "shield",
			Detail:    map[string]string{"overlay": res.OverlayPath},
		})
	case projectpolicy.StatusInvalid:
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: ignoring malformed project overlay %s\n", res.OverlayPath)
	}
	return sessionPolicyFromConfig(res.Config)
}

// netproxyDefaultAddr is the address the netproxy listens on when started by
// the shield.  It must match the address the agent connects to via
// HTTPS_PROXY.  Shared between macOS (Seatbelt) and Linux (Landlock).
const netproxyDefaultAddr = "127.0.0.1:9100"

const (
	// fingerprintTimeout bounds the control-socket handshake with an existing
	// proxy.
	fingerprintTimeout = 200 * time.Millisecond
	// registerTimeout bounds a session registration round trip.
	registerTimeout = 500 * time.Millisecond
	// tcpProbeTimeout bounds the "is :9100 occupied?" check when no control
	// socket is present.
	tcpProbeTimeout = 50 * time.Millisecond
	// sessionLeaseTTL is the lease requested per session. netproxy clamps it to
	// proxyctl.MaxLeaseTTLMs (24h). A session running longer than the cap would
	// need re-registration; that is an accepted edge (see ADR).
	sessionLeaseTTL = 24 * time.Hour
)

// proxyStartTimeout is how long we wait for a freshly started netproxy to expose
// a fingerprint-able control socket. Generous vs. the old 200ms TCP bind wait --
// first-run process start can be slow. It is a var so tests can shrink it.
var proxyStartTimeout = 3 * time.Second

// findNetproxyBinary locates the agentjail-netproxy binary.
//
// Search order (first hit wins):
//  1. $AGENTJAIL_NETPROXY env var
//  2. ~/.agentjail/bin/agentjail-netproxy
//  3. Sibling of the shield binary itself (filepath.Dir(os.Args[0]))
func findNetproxyBinary() (string, error) {
	if envPath := os.Getenv("AGENTJAIL_NETPROXY"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath, nil
		}
		return "", fmt.Errorf("$AGENTJAIL_NETPROXY=%s does not exist", envPath)
	}

	home, _ := os.UserHomeDir()
	if home != "" {
		candidate := filepath.Join(home, ".agentjail", "bin", "agentjail-netproxy")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	if len(os.Args) > 0 && os.Args[0] != "" {
		candidate := filepath.Join(filepath.Dir(os.Args[0]), "agentjail-netproxy")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("agentjail-netproxy binary not found; " +
		"set $AGENTJAIL_NETPROXY, install to ~/.agentjail/bin/, " +
		"or place alongside agentjail-shield")
}

// ensureSessionProxy guarantees a compatible netproxy is running, registers
// this session's resolved allowlist under a fresh unguessable token, and
// returns the token to inject into the agent's proxy credential. The returned
// *exec.Cmd is non-nil only if WE started the proxy (the caller must reap it on
// exit); it is nil when we reused an already-running proxy.
//
// sessionID and cwd are non-secret, display-only identity (see
// proxyctl.Request.SessionID / Cwd) so a human approving a runtime host grant
// later (`agentjail grants`) can tell concurrent sessions apart. Neither
// carries authority -- Token remains the sole data-plane bearer. Callers mint
// a fresh opaque sessionID per launch (e.g. "shield-<pid>") since the shield
// runs before any hook fires and has no Claude Code session id available in
// its own environment.
//
// Fail-closed semantics (never silently weaken enforcement, never blind-kill
// another session's proxy):
//   - A running proxy with an INCOMPATIBLE control protocol -> error (refuse to
//     launch); the user ends other sessions or restarts the proxy.
//   - No control socket but :9100 occupied by an unverifiable listener -> error
//     (refuse; do not kill by port).
func ensureSessionProxy(netproxyPath, proxyAddr, sessionID, cwd string, policy proxyctl.SessionPolicy) (*exec.Cmd, proxyctl.Token, error) {
	tok, err := proxyctl.NewToken()
	if err != nil {
		return nil, "", fmt.Errorf("mint session token: %w", err)
	}
	ctlPath := proxyctl.ControlSocketPath()

	// 1. A proxy is already serving the control socket?
	if fp, err := proxyctl.QueryFingerprint(ctlPath, fingerprintTimeout); err == nil {
		if !fp.Compatible(proxyctl.CurrentProtocolVersion) {
			return nil, "", fmt.Errorf(
				"a running agentjail-netproxy speaks control protocol v%d but this shield speaks v%d; "+
					"end other shielded sessions or restart the proxy (fail closed)",
				fp.ProtocolVersion, proxyctl.CurrentProtocolVersion)
		}
		if err := proxyctl.Register(ctlPath, tok, sessionID, cwd, policy, sessionLeaseTTL, registerTimeout); err != nil {
			return nil, "", fmt.Errorf("register session with running proxy: %w", err)
		}
		return nil, tok, nil // reuse; not ours to reap
	}

	// 2. No control socket. If something else is on :9100 we cannot verify it,
	// so we refuse rather than route this session's traffic through an unknown
	// listener or kill it by port.
	if c, derr := net.DialTimeout("tcp", proxyAddr, tcpProbeTimeout); derr == nil {
		c.Close()
		return nil, "", fmt.Errorf(
			"%s is occupied but exposes no agentjail control socket (%s); refusing to use it (fail closed)",
			proxyAddr, ctlPath)
	}

	// 3. Start a fresh netproxy, wait for its control socket, register.
	cmd, err := spawnNetproxy(netproxyPath, proxyAddr)
	if err != nil {
		return nil, "", err
	}
	if err := waitForControlSocket(ctlPath, proxyStartTimeout); err != nil {
		_ = cmd.Process.Kill()
		return nil, "", fmt.Errorf("netproxy did not expose its control socket: %w", err)
	}
	if err := proxyctl.Register(ctlPath, tok, sessionID, cwd, policy, sessionLeaseTTL, registerTimeout); err != nil {
		_ = cmd.Process.Kill()
		return nil, "", fmt.Errorf("register session with new proxy: %w", err)
	}
	return cmd, tok, nil
}

// spawnNetproxy starts agentjail-netproxy as a child process. It logs per-CONNECT
// decisions (allow/deny) and upstream dial errors at info level to
// ~/.agentjail/netproxy.log so the proxy is observable -- the shield execs into
// the agent, so an in-memory stderr buffer would be lost the moment the session
// starts. netproxy runs outside the sandbox, so it can write the log file.
func spawnNetproxy(netproxyPath, proxyAddr string) (*exec.Cmd, error) {
	cmd := exec.Command(netproxyPath,
		"--addr="+proxyAddr,
		"--log-level=info",
	)
	cmd.Stderr = netproxyLogWriter()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start netproxy: %w", err)
	}
	return cmd, nil
}

// netproxyLogWriter returns an appending file at ~/.agentjail/netproxy.log for
// the netproxy's stderr, or the discard-buffer fallback if the file cannot be
// opened.
func netproxyLogWriter() io.Writer {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return &proxyStderrWriter{}
	}
	logPath := filepath.Join(home, ".agentjail", "netproxy.log")
	f, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if ferr != nil {
		return &proxyStderrWriter{}
	}
	return f
}

// waitForControlSocket polls until the netproxy's control socket answers a
// fingerprint or the timeout elapses.
func waitForControlSocket(ctlPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := proxyctl.QueryFingerprint(ctlPath, 100*time.Millisecond); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("control socket %s not ready within %s", ctlPath, timeout)
}

// proxyStderrWriter buffers writes until forward is set, then writes to os.Stderr.
type proxyStderrWriter struct {
	buf     strings.Builder
	forward bool
}

func (w *proxyStderrWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

// proxyEnvVars returns the HTTPS_PROXY, HTTP_PROXY, and ALL_PROXY environment
// variables pointing at proxyAddr, carrying the session token as the Basic-auth
// username so netproxy keys this session's allowlist. The token is base64url
// (no ':' '@' '/'), so it is safe in the URL userinfo without escaping.
func proxyEnvVars(proxyAddr string, tok proxyctl.Token) []string {
	proxyURL := fmt.Sprintf("http://%s:@%s", tok, proxyAddr)
	return []string{
		"HTTPS_PROXY=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"ALL_PROXY=" + proxyURL,
	}
}

// sshOverrideInjected reports whether env (the return of
// sandbox.AgentGitSSHEnv) contains the agentjail marker, i.e. whether the
// shield actually injected the agent-backed GIT_SSH_COMMAND override (as
// opposed to preserving a user value or injecting nothing). Shared by both
// OS exec paths so the INFO line logic never drifts between them.
func sshOverrideInjected(env []string) bool {
	for _, kv := range env {
		if kv == "AGENTJAIL_SSH_OVERRIDE=1" {
			return true
		}
	}
	return false
}

// cleanupNetproxy terminates and reaps the netproxy child process to prevent
// zombies.  Safe to call with a nil cmd (i.e. when we reused an existing proxy).
func cleanupNetproxy(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = cmd.Wait()
}
