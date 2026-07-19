//go:build darwin

package shieldapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/tunnel"
)

// tunnelAppDefaultPath is where `AgentjailTunnel install` puts the host app
// bundle (see macos/AgentjailTunnel and macos/README.md). Overridable via the
// AGENTJAIL_TUNNEL_APP env var for local dev / CI, where the app may not be
// installed to /Applications.
const tunnelAppDefaultPath = "/Applications/AgentjailTunnel.app/Contents/MacOS/AgentjailTunnel"

// tunnelSessionSockPath is the unix socket the AgentjailExtension sysext
// listens on for the register/unregister session protocol (see
// macos/AgentjailExtension/Provider.swift's sessionSockPath and
// macos/AgentjailTunnel/main.swift's sessionIPC). Both sides agree on this
// literal path - it is unrelated to proxyctl's control socket, which is the
// agentjail-secrets/netproxy control plane used elsewhere in this package.
const tunnelSessionSockPath = "/tmp/agentjail.sock"

// Frozen wg-conf contract addresses (see startTunnelDarwin doc comment).
const (
	tunnelServerAddr = "10.78.0.1/16" // gateway's address inside the tunnel
	tunnelAgentAddr  = "10.78.0.2/32" // agent's address, written into wg-conf
	tunnelDNSAddr    = "10.78.0.1"    // DNS server address, written into wg-conf
)

// resolveTunnelAppPath resolves the AgentjailTunnel.app helper binary:
// AGENTJAIL_TUNNEL_APP overrides for local dev/CI; otherwise the standard
// /Applications install path.
func resolveTunnelAppPath() string {
	if p := os.Getenv("AGENTJAIL_TUNNEL_APP"); p != "" {
		return p
	}
	return tunnelAppDefaultPath
}

// generateSessionID returns a shield session identifier of the form
// "shield-<unix_timestamp>-<8 hex chars>", used to tag every intercepted
// request (see mitm.RequestLog.SessionID) with the shield session that
// produced it.
func generateSessionID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("shield-%d-%s", time.Now().Unix(), hex.EncodeToString(b))
}

// startTunnelDarwin drives the sanctioned macOS path for --tunnel: the
// NETransparentProxyProvider system extension via the AgentjailTunnel.app
// host app, replacing the utun/tunneld dial used by the Linux transparent
// tunnel (tunnel_shield_linux.go's startTunnel).
//
// Because the extension's PPID filter matches a flow's PROCESS ANCESTORS
// (not the flow process itself - see macos/AgentjailExtension/Provider.swift
// ancestorMatches/sessionRegister), the shield must NOT syscall.Exec into the
// agent here: it stays alive as the agent's PARENT process, registers its own
// PID with the extension's session socket before the agent ever starts, and
// spawns (not execs) the agent as a child. Every flow the agent (or anything
// it forks) opens then has the shield's registered PID somewhere in its PPID
// chain, so the extension's ancestor walk matches it. syscall.Exec would
// replace the shield's own process image with the agent's, discarding the
// registered PID's identity and leaving the agent's flows unmatched.
//
// Because the shield does not exec, its cleanup (unregister, cancel the
// in-process gateway, `<app> stop`) runs as ordinary code after the agent
// exits - there is no daemon-side PID watcher standing in for it the way
// agentjail-tunneld does for the Linux path.
//
// Order of operations. This is fail-OPEN for the tunnel as a whole (any
// setup failure below "GATEWAY" invokes fallback, which runs the ordinary
// sbpl+netproxy launch - matching the Linux transparent tunnel's documented
// fail-open contract in tunnel_shield_linux.go) and separately fail-open for
// MITM specifically (a CA/store failure disables interception but keeps the
// tunnel, relaying TLS opaquely, matching ADR 0077's transparent-only
// fallback):
//
//  1. SYSEXT   - resolve + `install` the AgentjailTunnel.app (idempotent).
//  2. GATEWAY  - generate WireGuard keys, start an in-process tunnel.Gateway
//     (WireGuard-over-UDP netstack, NOT the promiscuous forward stack used by
//     Linux's --tunnel path) + a dnsvip.Server wired to the gateway's own
//     netstack-bound DNS packet conn (DNSPacketConn), and read back the
//     gateway's actual UDP port.
//  3. MITM     - (unless mitmEnabled is false) generate an in-memory tunnel
//     CA, open network.db, and wire a mitm.MITMHandler into the gateway via
//     SetMITM. The CA private key is NEVER written to disk (S-C1); only
//     root.crt (+ the derived bundle.crt) touch the filesystem.
//  4. WG-CONF  - write the frozen wg-conf contract (agent keys + the
//     gateway's 127.0.0.1:<port> endpoint) to a 0600 temp file, hand it to
//     `<app> start`, then remove the temp file (it holds the agent's
//     private key).
//  5. REGISTER - connect tunnelSessionSockPath and register this process's
//     own PID, before the agent is spawned.
//  6. SEATBELT + SPAWN - build the broad-allow tunnel sbpl profile
//     (generateSBProfileTunnel) and run the agent as a CHILD via
//     sandbox-exec (exec.Command, not syscall.Exec).
//  7. CLEANUP  - (ordinary code, since we never exec'd): unregister, cancel
//     the gateway, `<app> stop`, revoke secret grants; propagate the child's
//     exit code.
//
// This function never returns to its caller on success or on a fatal setup
// error: it terminates the process via os.Exit with the wrapped agent's exit
// code, or via the fallback closure's own os.Exit/syscall.Exec. It DOES
// return (without exiting) when a fail-open setup step fails BEFORE the agent
// is spawned, having already invoked fallback - fallback itself never
// returns, so this is dead code reachable only if that contract is violated;
// the explicit return keeps that violation a compile error away from a
// fallthrough double-launch rather than a silent one.
func startTunnelDarwin(ctx context.Context, cfg *config.PolicyConfig, agentPath string, agentArgs []string, packsDir string, mitmEnabled bool, emitter audit.Emitter, fallback func()) {
	logger := slog.Default()
	sessionID := generateSessionID()
	logger.Info("tunnel session started", "session_id", sessionID)

	fail := func(format string, args ...any) {
		logger.Warn("tunnel unavailable, falling back to non-tunnel shield launch", "reason", fmt.Sprintf(format, args...))
		fallback()
	}

	// --- 1. SYSEXT: ensure the AgentjailTunnel host app + system extension
	// are active. `install` is idempotent - safe to call on every launch.
	appPath := resolveTunnelAppPath()
	if _, statErr := os.Stat(appPath); statErr != nil {
		emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStarted, sessionID, appPath, false, "app_not_found")
		fail("AgentjailTunnel app not found at %s (set AGENTJAIL_TUNNEL_APP, or build/install it - see macos/README.md): %v", appPath, statErr)
		return
	}
	if out, err := exec.Command(appPath, "install").CombinedOutput(); err != nil {
		emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStarted, sessionID, appPath, false, "install_failed")
		fail("%s install failed: %v: %s", appPath, err, string(out))
		return
	}

	// --- 2. GATEWAY (in-process): server + agent WireGuard keypairs, then
	// bring up the gateway and DNS-VIP server bound to its netstack.
	serverPriv, serverPub, err := tunnel.GenerateKeyPair()
	if err != nil {
		fail("generating server keypair: %v", err)
		return
	}
	agentPriv, agentPub, err := tunnel.GenerateKeyPair()
	if err != nil {
		fail("generating agent keypair: %v", err)
		return
	}

	registry := dnsvip.NewRegistry()
	gwCfg := tunnel.Config{
		PrivateKey:    serverPriv,
		ListenPort:    0, // OS-assigned; read back via gateway.ListenPort()
		PeerPublicKey: agentPub,
		TunnelAddr:    tunnelServerAddr,
		PacksDir:      packsDir,
	}
	gateway, err := tunnel.NewGateway(gwCfg, registry, logger)
	if err != nil {
		fail("creating tunnel gateway: %v", err)
		return
	}

	gwCtx, gwCancel := context.WithCancel(ctx)
	// DNSPacketConn is bound to the gateway's OWN tunnel address (10.78.0.1:53
	// inside the netstack), not to a VIP: the agent's stub resolver sends DNS
	// queries to tunnelDNSAddr (written into the wg-conf below), and
	// dnsvip.Registry.Allocate mints a VIP as the ANSWER to that query - the
	// query itself never targets a VIP address. So binding the stack's own
	// addr:53 (as DNSPacketConn does) is sufficient here; the promiscuous
	// serverNetstack (internal/tunnel/servernetstack.go) exists for a
	// different shape of interception (Linux's NewForwardGateway, which
	// intercepts SYNs to arbitrary VIP destinations pumped in from a real
	// TUN fd) and is not needed on this WireGuard-over-UDP path. See AGE-149
	// Phase 0 verifier notes in docs/build/age-149-mac-mitm/TODO.md.
	dnsServer := dnsvip.NewServer(fmt.Sprintf("%s:53", tunnelDNSAddr), registry)
	dnsServer.PacketConn(gateway.DNSPacketConn())

	var caCleanup func()
	var caEnvVars map[string]string
	// mitmActive is the posture ACHIEVED, not the one requested (ADR 0077 D6);
	// it feeds the tunnel.extension_started audit detail so a fail-open MITM
	// step never gets reported as "mitm: true". See AGE-149 T1.5.
	var mitmActive bool
	cleanupGateway := func() {
		gwCancel()
		_ = gateway.Close()
		_ = dnsServer.Close()
		if caCleanup != nil {
			caCleanup()
		}
	}

	go func() {
		if err := gateway.ListenAndServe(gwCtx); err != nil && gwCtx.Err() == nil {
			logger.Error("tunnel gateway error", "err", err)
		}
	}()
	go func() {
		if err := dnsServer.ListenAndServe(gwCtx); err != nil && gwCtx.Err() == nil {
			logger.Error("DNS-VIP server error", "err", err)
		}
	}()

	port := gateway.ListenPort()
	if port == 0 {
		cleanupGateway()
		fail("could not determine gateway UDP listen port")
		return
	}

	// --- 3. MITM: in-memory CA + network.db + mitm.MITMHandler wired into
	// the gateway. Fail-open for this step only (ADR 0077): any failure here
	// disables interception but keeps the tunnel running, relaying TLS
	// opaquely - it does NOT invoke fallback.
	if !mitmEnabled {
		logger.Info("tunnel TLS interception OFF (transparent-only) - HTTP(S) policy templates will NOT match; visibility is destination IP, SNI and byte counts only")
	} else if caDir, mkErr := os.MkdirTemp("", "agentjail-tunnel-ca-*"); mkErr != nil {
		logger.Warn("tunnel TLS interception UNAVAILABLE (temp CA dir failed); relaying HTTPS opaque", "err", mkErr)
	} else if caCert, caKey, certPEM, genErr := mitm.GenerateCAInMemory(); genErr != nil {
		os.RemoveAll(caDir)
		logger.Warn("tunnel TLS interception UNAVAILABLE (CA generation failed); relaying HTTPS opaque", "err", genErr)
	} else if writeErr := os.WriteFile(filepath.Join(caDir, TunnelCACertName), certPEM, 0o644); writeErr != nil {
		os.RemoveAll(caDir)
		logger.Warn("tunnel TLS interception UNAVAILABLE (writing CA cert failed); relaying HTTPS opaque", "err", writeErr)
	} else if envVars, _, envErr := setupTunnelCADarwin(caDir); envErr != nil {
		os.RemoveAll(caDir)
		logger.Warn("tunnel TLS interception UNAVAILABLE (CA env setup failed); relaying HTTPS opaque", "err", envErr)
	} else if store, storeErr := mitm.NewRequestStore(mitm.DefaultDBPath()); storeErr != nil {
		os.RemoveAll(caDir)
		logger.Warn("tunnel TLS interception UNAVAILABLE (network.db open failed); relaying HTTPS opaque", "err", storeErr)
	} else {
		caEnvVars = envVars
		caCleanup = func() { os.RemoveAll(caDir); _ = store.Close() }
		h := mitm.NewMITMHandler(caCert, caKey, logger, func(rl *mitm.RequestLog) {
			if lerr := store.Log(rl); lerr != nil {
				logger.Debug("network.db log failed", "err", lerr)
			}
		})
		h.SessionID = sessionID
		h.OwnerPID = os.Getpid()
		h.Matcher = gateway.Matcher() // nil => observe/log only (no PacksDir configured)
		h.Audit = emitter
		// Bodies: same encrypted BodyStore + keychain-KEK path as Linux
		// (newBodyRecording, tunnel_body.go) - darwin's keyring backend
		// (internal/keyring/store_darwin.go) is the per-OS KEK source, the
		// rest of the contract is shared. Fail-open: a missing/locked
		// keychain degrades to unencrypted-with-a-loud-warning, never drops
		// interception. See AGE-149 T1.6, ADR 0092-persist-request-bodies.
		rec := newBodyRecording(ctx, sessionID, logger, emitter)
		h.Bodies = rec.store
		mitmActive = true
		gateway.SetMITM(h)
		logger.Info("tunnel TLS interception ON - agentjail is decrypting this agent's HTTPS via a per-session in-memory CA; "+rec.notice(),
			"db", mitm.DefaultDBPath(), "bodies", mitm.DefaultBodyDir(), "session", sessionID)
	}

	// --- 4. WG-CONF: the frozen contract. Written to a 0600 temp file
	// (it holds the agent's private key), handed to the app, then removed.
	conf := fmt.Sprintf(
		"[Interface]\nPrivateKey = %s\nAddress    = %s\nDNS        = %s\n[Peer]\nPublicKey  = %s\nEndpoint   = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n",
		agentPriv, tunnelAgentAddr, tunnelDNSAddr, serverPub, port,
	)
	confFile, err := os.CreateTemp("", "agentjail-wg-*.conf")
	if err != nil {
		cleanupGateway()
		fail("creating wg-conf temp file: %v", err)
		return
	}
	confPath := confFile.Name()
	if chmodErr := confFile.Chmod(0o600); chmodErr != nil {
		confFile.Close()
		os.Remove(confPath)
		cleanupGateway()
		fail("chmod wg-conf temp file: %v", chmodErr)
		return
	}
	if _, writeErr := confFile.WriteString(conf); writeErr != nil {
		confFile.Close()
		os.Remove(confPath)
		cleanupGateway()
		fail("writing wg-conf temp file: %v", writeErr)
		return
	}
	confFile.Close()

	startOut, startErr := exec.Command(appPath, "start", confPath).CombinedOutput()
	os.Remove(confPath) // secret material; remove regardless of start outcome
	if startErr != nil {
		cleanupGateway()
		emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStarted, sessionID, appPath, mitmActive, "app_start_failed")
		fail("%s start failed: %v: %s", appPath, startErr, string(startOut))
		return
	}

	// --- WAIT FOR PROVIDER: `<app> start` returns before the OS actually
	// launches the provider (which binds tunnelSessionSockPath in startProxy).
	// Poll until the session socket accepts connections.
	regDeadline := time.Now().Add(15 * time.Second)
	for {
		c, dialErr := net.DialTimeout("unix", tunnelSessionSockPath, time.Second)
		if dialErr == nil {
			c.Close()
			break
		}
		if time.Now().After(regDeadline) {
			cleanupGateway()
			_, _ = exec.Command(appPath, "stop").CombinedOutput()
			emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStarted, sessionID, appPath, mitmActive, "session_socket_timeout")
			fail("sysext session socket %s not ready in 15s: %v", tunnelSessionSockPath, dialErr)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}

	logger.Info("NETransparentProxyProvider tunnel active", "port", port)
	emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStarted, sessionID, appPath, mitmActive, "")

	// --- 6. SEATBELT + SPAWN CHILD (no syscall.Exec - see doc comment).
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		home = "/Users/unknown"
	}
	profile := generateSBProfileTunnel(cfg, home)

	env := buildBaseEnv(os.Environ(), cfg)
	env = AppendShieldedEnv(env, Sandboxed)
	env = append(env, "AGENTJAIL_TUNNEL=1")

	// Not yet sandboxed here (sbpl applies at exec.Command below), so the
	// token is readable at this point - unlike Linux (ADR 0067).
	ctlToken, _ := ctlauth.Load()
	grantEnvVars, activeGrants := requestSecretGrants(cfg, ctlToken)
	env = append(env, grantEnvVars...)

	for k, v := range caEnvVars {
		env = append(env, k+"="+v)
	}

	argv := append([]string{"-p", profile, agentPath}, agentArgs...)
	child := exec.Command(sandboxExecPath, argv...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = env

	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.ShieldActivated,
		Detail:    map[string]string{"mode": "tunnel"},
		Actor:     "shield",
	})

	// Register the SHIELD's PID before spawning the child. The extension's
	// ancestorMatches starts at the flow process's PARENT (not the process
	// itself), so registering the shield PID means:
	//   - child (curl/claude) flows: ancestorMatches walks parent chain and
	//     hits the shield PID -> tunneled.
	//   - shield's own flows (gateway's net.Dial): ancestorMatches starts at
	//     the shield's parent (terminal/shell), which is NOT registered ->
	//     not tunneled. No loop.
	if regErr := tunnelSessionIPC(fmt.Sprintf("register %d\n", os.Getpid())); regErr != nil {
		logger.Warn("failed to register shield PID with extension", "pid", os.Getpid(), "err", regErr)
		emitTunnelExtensionEvent(ctx, emitter, audit.TunnelSessionRegistered, sessionID, appPath, mitmActive, "register_ipc_failed")
	} else {
		emitTunnelExtensionEvent(ctx, emitter, audit.TunnelSessionRegistered, sessionID, appPath, mitmActive, "")
	}

	exitCode := 0
	runErr := child.Start()
	if runErr == nil {
		runErr = child.Wait()
	}
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			logger.Error("spawning agent under sandbox-exec failed", "err", runErr)
			exitCode = 1
		}
	}

	// --- 7. CLEANUP: ordinary code, not a defer - this function's job is to
	// be main.go's terminal step, so running cleanup inline (rather than via
	// defer) keeps the sequencing explicit. Runs because we never
	// syscall.Exec'd. Best-effort: none of these should mask the agent's own
	// exit code.
	_ = tunnelSessionIPC(fmt.Sprintf("unregister %d\n", os.Getpid()))
	emitTunnelExtensionEvent(ctx, emitter, audit.TunnelSessionUnregistered, sessionID, appPath, mitmActive, "")
	cleanupGateway()
	_, _ = exec.Command(appPath, "stop").CombinedOutput()
	emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStopped, sessionID, appPath, mitmActive, "")
	revokeSecretGrants(activeGrants, ctlToken)

	os.Exit(exitCode)
}

// emitTunnelExtensionEvent audits one step of the darwin tunnel's lifecycle
// (extension start/stop, session register/unregister). Detail carries fixed
// keys only - mode, mitm posture, and the app path - plus failureReason when
// the step failed; never a key path or token. See AGE-149 T1.5.
func emitTunnelExtensionEvent(ctx context.Context, emitter audit.Emitter, eventType, sessionID, appPath string, mitmActive bool, failureReason string) {
	if emitter == nil {
		return
	}
	detail := map[string]string{
		"mode":     "tunnel",
		"mitm":     strconv.FormatBool(mitmActive),
		"app_path": appPath,
	}
	if failureReason != "" {
		detail["failure_reason"] = failureReason
	}
	_ = emitter.Emit(ctx, audit.Event{
		EventType: eventType,
		SessionID: sessionID,
		Detail:    detail,
		Actor:     "shield",
	})
}

// tunnelSessionIPC dials the extension's session socket at
// tunnelSessionSockPath and writes msg (newline-terminated), then reads its
// small ack. Mirrors the Swift sessionIPC helper in
// macos/AgentjailTunnel/main.swift and the wire protocol documented in
// macos/AgentjailExtension/Provider.swift (serviceSessionClient): "register
// <pid>\n" / "unregister <pid>\n" -> "ok\n". The ack is read but not
// strictly validated here (best-effort, matching the Swift client) - a
// connect/write failure is the fail-closed signal; a malformed ack from an
// otherwise-reachable extension is not worth aborting the whole launch over.
func tunnelSessionIPC(msg string) error {
	conn, err := net.DialTimeout("unix", tunnelSessionSockPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, 8)
	_, _ = conn.Read(buf) // best-effort ack, see doc comment
	return nil
}
