//go:build darwin

package shieldapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/captureproxy"
	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/sandbox"
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

// v6 datapath addresses, derived from dnsvip (the single source of truth for
// the tunnel's reserved addresses) with the prefix lengths mirroring the v4
// server/agent split: server gets the /64 the agent's /128 lives inside.
// AGE-262.
var (
	tunnelServerAddr6 = dnsvip.GatewayV6().String() + "/64"
	tunnelAgentAddr6  = dnsvip.AgentV6().String() + "/128"
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
// "shield<unix_timestamp><8 hex chars>", used to tag every intercepted request
// (see mitm.RequestLog.SessionID). It MUST stay alphanumeric (no dashes): the id
// is the per-session bodystore group key and mitm.NewBodyStore rejects any
// non-alnum component, which silently disabled body persistence. See ADR
// 0092-persist-request-bodies (D1), AGE-259.
func generateSessionID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("shield%d%s", time.Now().Unix(), hex.EncodeToString(b))
}

// tunnelCADir returns a fresh temp dir to hold the tunnel MITM CA for the
// life of this session.
func tunnelCADir() (dir string, err error) {
	return os.MkdirTemp("", "agentjail-tunnel-ca-*")
}

// loadOrGenTunnelCA returns an in-memory per-session CA whose key never
// touches disk (S-C1).
func loadOrGenTunnelCA() (*x509.Certificate, crypto.PrivateKey, []byte, error) {
	return mitm.GenerateCAInMemory()
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
func startTunnelDarwin(ctx context.Context, cfg *config.PolicyConfig, agentPath string, agentArgs []string, packsDir string, mitmEnabled bool, ipv6Enabled bool, sshAuthSock sandbox.SSHAuthSock, credentialTools credentialSelections, emitter audit.Emitter, fallback func()) {
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
	// v6 provisioning is flag-gated (AGE-262 Phase 1): only attempt it when the
	// resolved on/off decision (resolveTunnelIPv6 in main.go — CLI flag > env
	// > config > default off) says so, and only trust it once NewGateway
	// actually succeeds with the v6 address provisioned. A v6 failure falls
	// back to v4-only below — it never fails the launch.
	ipv6Requested := ipv6Enabled
	ipv6Provisioned := false
	if ipv6Requested {
		gwCfg.TunnelAddr6 = tunnelServerAddr6
	}
	gateway, err := tunnel.NewGateway(gwCfg, registry, logger)
	if err != nil && ipv6Requested {
		logger.Warn("tunnel IPv6 provisioning failed; falling back to v4-only", "err", err)
		gwCfg.TunnelAddr6 = ""
		gateway, err = tunnel.NewGateway(gwCfg, registry, logger)
	} else if err == nil && ipv6Requested {
		ipv6Provisioned = true
	}
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
	// providerGatewayCloseFn / sharedStoreCleanup are assigned once the
	// capture gateway is known to be wanted (below); declared here, ahead of
	// cleanupGateway, so the closure captures them by reference. See A0.
	var providerGatewayCloseFn func() error
	var sharedStoreCleanup func()
	// Order matters: cancel the context first (stops the ListenAndServe
	// goroutines below), then close the gateway/DNS server, then the
	// provider capture gateway, then MITM's own CA/store cleanup, then the
	// shared RequestStore last (nothing after this point still needs it).
	// Delegated to runCleanupSteps so the ordering is unit-testable without
	// a live gateway; see tunnel_shield_darwin_test.go. AGE-149 T1.7, A0.
	cleanupGateway := func() {
		runCleanupSteps(
			gwCancel,
			func() { _ = gateway.Close() },
			func() { _ = dnsServer.Close() },
			func() {
				if providerGatewayCloseFn != nil {
					_ = providerGatewayCloseFn()
				}
			},
			caCleanup,
			sharedStoreCleanup,
		)
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

	// --- Shared capture prerequisite (A0): open the RequestStore + body
	// recorder ONCE, before MITM decides its own posture, so the base-URL
	// gateway (LLM /v1/messages capture, ADR 0109) never depends on MITM CA
	// setup succeeding. MITM below reuses this SAME store when enabled; when
	// MITM is off or its own CA setup fails, the gateway still runs off it.
	gwProv, gwWanted := providerGatewayWanted(cfg, agentPath)
	var sharedStore *mitm.RequestStore
	var sharedRec bodyRecording
	if gwWanted {
		st, storeErr := mitm.NewRequestStore(mitm.DefaultDBPath())
		if storeErr != nil {
			cleanupGateway()
			emitGatewayStartFailed(ctx, emitter, sessionID, gwProv, "store")
			fail("capture gateway store open failed for %s: %v", gwProv.Name, storeErr)
			return
		}
		sharedStore = st
		sharedStoreCleanup = func() { _ = st.Close() }
		sharedRec = newBodyRecording(ctx, sessionID, logger, emitter)
	}

	// One ref for both writers (MITM handler + provider gateway): the shield
	// resolves its claude descendant's session id once and every row after
	// carries it; watchClaudeSession also backfills the rows before.
	claudeRef := &mitm.ClaudeSessionRef{}

	// --- 3. MITM: in-memory CA + network.db + mitm.MITMHandler wired into
	// the gateway. Fail-open for this step only (ADR 0077): any failure here
	// disables interception but keeps the tunnel running, relaying TLS
	// opaquely - it does NOT invoke fallback.
	if !mitmEnabled {
		logger.Info("tunnel TLS interception OFF (transparent-only) - HTTP(S) policy templates will NOT match; visibility is destination IP, SNI and byte counts only")
	} else if caDir, mkErr := tunnelCADir(); mkErr != nil {
		logger.Warn("tunnel TLS interception UNAVAILABLE (temp CA dir failed); relaying HTTPS opaque", "err", mkErr)
	} else if caCert, caKey, certPEM, genErr := loadOrGenTunnelCA(); genErr != nil {
		os.RemoveAll(caDir)
		logger.Warn("tunnel TLS interception UNAVAILABLE (CA generation failed); relaying HTTPS opaque", "err", genErr)
	} else if writeErr := os.WriteFile(filepath.Join(caDir, TunnelCACertName), certPEM, 0o644); writeErr != nil {
		os.RemoveAll(caDir)
		logger.Warn("tunnel TLS interception UNAVAILABLE (writing CA cert failed); relaying HTTPS opaque", "err", writeErr)
	} else if envVars, _, envErr := setupTunnelCADarwin(caDir); envErr != nil {
		os.RemoveAll(caDir)
		logger.Warn("tunnel TLS interception UNAVAILABLE (CA env setup failed); relaying HTTPS opaque", "err", envErr)
	} else if store, storeOwned, storeErr := acquireMITMStore(sharedStore); storeErr != nil {
		os.RemoveAll(caDir)
		logger.Warn("tunnel TLS interception UNAVAILABLE (network.db open failed); relaying HTTPS opaque", "err", storeErr)
	} else {
		caEnvVars = envVars
		if storeOwned {
			caCleanup = func() {
				os.RemoveAll(caDir)
				_ = store.Close()
			}
		} else {
			// store is the shared RequestStore (A0), owned by
			// sharedStoreCleanup and closed last by cleanupGateway -- MITM's
			// own cleanup here only removes its CA temp dir.
			caCleanup = func() { os.RemoveAll(caDir) }
		}
		h := mitm.NewMITMHandler(caCert, caKey, logger, func(rl *mitm.RequestLog) {
			if lerr := store.Log(rl); lerr != nil {
				logger.Debug("network.db log failed", "err", lerr)
			}
		})
		h.SessionID = sessionID
		h.OwnerPID = os.Getpid()
		h.Agent, h.Cwd = sessionMeta(agentPath)
		h.ClaudeSession = claudeRef
		if !gwWanted {
			// Gateway-less MITM owns the store; with a gateway the shared
			// store's watcher starts after the gateway block below.
			watchClaudeSession(ctx, store, sessionID, claudeRef)
		}
		h.Matcher = gateway.Matcher() // nil => observe/log only (no PacksDir configured)
		h.Audit = emitter
		// Bodies: same encrypted BodyStore + keychain-KEK path as Linux
		// (newBodyRecording, tunnel_body.go) - darwin's keyring backend
		// (internal/keyring/store_darwin.go) is the per-OS KEK source, the
		// rest of the contract is shared. Fail-open: a missing/locked
		// keychain degrades to unencrypted-with-a-loud-warning, never drops
		// interception. See AGE-149 T1.6, ADR 0092-persist-request-bodies.
		var rec bodyRecording
		if storeOwned {
			rec = newBodyRecording(ctx, sessionID, logger, emitter)
		} else {
			// Reuse the shared recorder (A0) instead of minting a second one
			// under the same sessionID: mitm.NewBodyStore rejects a duplicate
			// per-session group key.
			rec = sharedRec
		}
		h.Bodies = rec.store
		mitmActive = true
		gateway.SetMITM(h)
		notice := rec.notice()
		logger.Info("tunnel TLS interception ON - agentjail is decrypting this agent's HTTPS via a per-session in-memory CA; "+notice,
			"db", mitm.DefaultDBPath(), "bodies", mitm.DefaultBodyDir(), "session", sessionID)
	}

	// --- Provider capture gateway (A0/A1): independent of MITM's outcome
	// above -- runs whenever a provider is detected + gateway enabled,
	// whether MITM is on, off, or degraded. See ADR 0109-baseurl-capture-gateway.
	if gwWanted {
		envVars, closeFn, started, gerr := startProviderGateway(ctx, cfg, agentPath, sharedStore, sharedRec.store, sessionID, claudeRef, logger, emitter)
		if gerr != nil {
			cleanupGateway()
			fail("%v", gerr)
			return
		}
		watchClaudeSession(ctx, sharedStore, sessionID, claudeRef)
		if started {
			providerGatewayCloseFn = closeFn
			if caEnvVars == nil {
				caEnvVars = map[string]string{}
			}
			for k, v := range envVars {
				caEnvVars[k] = v
			}
		}
	}

	// --- 4. WG-CONF: the frozen contract. Written to a 0600 temp file
	// (it holds the agent's private key), handed to the app, then removed.
	//
	// v4-only (flag unset or v6 provisioning failed) emits the EXACT
	// pre-AGE-262 conf — no behavior change. The v6 arm is a single,
	// comma-separated Address line: cbridge owns one Address key and splits
	// on commas, so a second "Address =" line would overwrite v4 and break
	// startup. Never emit two Address lines. AGE-262 Phase 1.
	var conf string
	if ipv6Provisioned {
		conf = fmt.Sprintf(
			"[Interface]\nPrivateKey = %s\nAddress    = %s, %s\nDNS        = %s\n[Peer]\nPublicKey  = %s\nEndpoint   = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0, ::/0\n",
			agentPriv, tunnelAgentAddr, tunnelAgentAddr6, tunnelDNSAddr, serverPub, port,
		)
	} else {
		conf = fmt.Sprintf(
			"[Interface]\nPrivateKey = %s\nAddress    = %s\nDNS        = %s\n[Peer]\nPublicKey  = %s\nEndpoint   = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n",
			agentPriv, tunnelAgentAddr, tunnelDNSAddr, serverPub, port,
		)
	}
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
	// Poll until the session socket accepts connections, or time out - a
	// stuck/stale socket must degrade to a bounded error, never a hang.
	// 30s, not 15s: when a provider from a prior session is still resident, the
	// NE stack reloads it (stop -> wait .disconnected -> start) to pick up this
	// run's fresh WG keys+port, and the session socket is unbound for the whole
	// reload window (~10s) plus `app start` latency. 15s raced that and fell
	// back spuriously. See ADR 0106-tunnel-socket-wait.
	if sockErr := waitForSessionSocket(tunnelSessionSockPath, 30*time.Second, 300*time.Millisecond); sockErr != nil {
		cleanupGateway()
		_, _ = exec.Command(appPath, "stop").CombinedOutput()
		emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStarted, sessionID, appPath, mitmActive, "session_socket_timeout")
		fail("sysext session socket %s not ready in 30s: %v", tunnelSessionSockPath, sockErr)
		return
	}

	logger.Info("NETransparentProxyProvider tunnel active", "port", port)
	emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStarted, sessionID, appPath, mitmActive, "")

	// --- 6. SEATBELT + SPAWN CHILD (no syscall.Exec - see doc comment).
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		home = "/Users/unknown"
	}
	profileCapabilities, credentialErr := resolveDarwinProfileCapabilities(agentPath, credentialTools, sshAuthSock)
	if credentialErr != nil {
		cleanupGateway()
		_, _ = exec.Command(appPath, "stop").CombinedOutput()
		fmt.Fprintf(os.Stderr, "agentjail-shield: credential MCP profile setup failed: %v\n", credentialErr)
		os.Exit(1)
	}
	profile := generateSBProfileTunnelWithCapabilities(cfg, home, profileCapabilities)

	env := buildBaseEnv(os.Environ(), cfg, sshAuthSock)
	env = AppendShieldedEnv(env, Sandboxed)
	env = append(env, "AGENTJAIL_TUNNEL=1")

	// Not yet sandboxed here (sbpl applies at exec.Command below), so the
	// token is readable at this point - unlike Linux (ADR 0067).
	ctlToken, _ := ctlauth.Load()
	grantEnvVars, activeGrants := requestSecretGrants(cfg, ctlToken)
	env = append(env, grantEnvVars...)
	credentialSession, credentialErr := prepareCredentialSession(credentialTools, ctlToken, agentPath)
	if credentialErr != nil {
		cleanupGateway()
		_, _ = exec.Command(appPath, "stop").CombinedOutput()
		fmt.Fprintf(os.Stderr, "agentjail-shield: credentialed tool bootstrap failed: %v\n", credentialErr)
		os.Exit(1)
	}
	agentArgs, credentialErr = credentialSession.configureAgent(agentPath, agentArgs)
	if credentialErr != nil {
		credentialSession.cleanup(ctlToken)
		cleanupGateway()
		_, _ = exec.Command(appPath, "stop").CombinedOutput()
		fmt.Fprintf(os.Stderr, "agentjail-shield: credential MCP configuration failed: %v\n", credentialErr)
		os.Exit(1)
	}
	env = credentialSession.applyEnv(env)
	for _, tool := range credentialTools {
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: %s ready for %s broker credentials\n", tool.Tool, tool.deliveryMode())
		logger.Info("credentialed tool ready", "tool", tool.Tool, "credential_name", tool.Name, "binary", tool.BinaryPath, "delivery", tool.deliveryMode())
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.CredentialToolReady,
			Entity:    tool.auditEntity(),
			Detail:    map[string]string{"tool": string(tool.Tool), "binary": tool.BinaryPath, "delivery": tool.deliveryMode()},
			Actor:     "shield",
		})
	}

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

	// The child is spawned (not exec'd - see doc comment), so it shares this
	// process's terminal/process group and receives SIGINT/SIGTERM directly.
	// Without arming a handler, Go's default action would kill THIS process
	// on the same signal, skipping CLEANUP below (unregister, gateway close,
	// `<app> stop`, grant revocation) entirely. Mirrors shield_linux.go's
	// os/exec (non-tunnel) signal handling. See AGE-149 T1.7.
	stopSignalDrain := armSignalDrain(syscall.SIGINT, syscall.SIGTERM)

	exitCode := startAndWaitChild(child, logger)

	// --- 7. CLEANUP: ordinary code, not a defer - this function's job is to
	// be main.go's terminal step, so running cleanup inline (rather than via
	// defer) keeps the sequencing explicit. Runs because we never
	// syscall.Exec'd. Best-effort: none of these should mask the agent's own
	// exit code.
	stopSignalDrain()
	_ = tunnelSessionIPC(fmt.Sprintf("unregister %d\n", os.Getpid()))
	emitTunnelExtensionEvent(ctx, emitter, audit.TunnelSessionUnregistered, sessionID, appPath, mitmActive, "")
	cleanupGateway()
	_, _ = exec.Command(appPath, "stop").CombinedOutput()
	emitTunnelExtensionEvent(ctx, emitter, audit.TunnelExtensionStopped, sessionID, appPath, mitmActive, "")
	revokeSecretGrants(activeGrants, ctlToken)
	credentialSession.cleanup(ctlToken)

	os.Exit(exitCode)
}

// acquireMITMStore returns the shared RequestStore (A0) when the capture
// gateway already opened one, else opens a fresh RequestStore that MITM owns
// outright. owned reports which -- callers must only Close what they opened;
// the shared store is closed once, last, by sharedStoreCleanup.
func acquireMITMStore(shared *mitm.RequestStore) (store *mitm.RequestStore, owned bool, err error) {
	if shared != nil {
		return shared, false, nil
	}
	st, err := mitm.NewRequestStore(mitm.DefaultDBPath())
	return st, true, err
}

// runCleanupSteps runs each step in order, skipping nils. Extracted so the
// shutdown sequence's ORDER (cancel, then close, then close, then the CA temp
// dir) is unit-testable without a live gateway. See AGE-149 T1.7.
func runCleanupSteps(steps ...func()) {
	for _, step := range steps {
		if step != nil {
			step()
		}
	}
}

// waitForSessionSocket polls path until a unix listener answers, or returns
// the last dial error once timeout elapses. A stuck or stale sysext socket
// must degrade to a bounded error, never a hang. See AGE-149 T1.7.
func waitForSessionSocket(path string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		c, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			c.Close()
			return nil
		}
		lastErr = dialErr
		if time.Now().After(deadline) {
			return lastErr
		}
		time.Sleep(interval)
	}
}

// armSignalDrain intercepts sigs so Go's default (process-killing) action
// never fires here: the spawned child (see startTunnelDarwin's doc comment on
// why it is spawned, not exec'd) shares this process's terminal/process group
// and receives the same signal directly, so this process only needs to
// survive long enough to run CLEANUP after child.Wait() returns. The returned
// stop func must be called before the process exits normally (not deferred
// past os.Exit, which skips defers). Mirrors shield_linux.go's os/exec signal
// handling for the non-tunnel path. See AGE-149 T1.7.
func armSignalDrain(sigs ...os.Signal) (stop func()) {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, sigs...)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-sigCh:
				// Drain - the child already received it from the TTY.
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(done)
	}
}

// captureGatewayEnabled: tri-state opt-out, default on. See ADR 0109-baseurl-capture-gateway.
func captureGatewayEnabled(cfg *config.PolicyConfig) bool {
	if cfg != nil && cfg.Network.CaptureGateway != nil {
		return *cfg.Network.CaptureGateway
	}
	return true
}

// emitGatewayProviderRouted audits that a provider agent's LLM API traffic was
// routed through the local capture gateway. Detail never carries the gateway's
// baseURL/nonce - only the provider name and its upstream host. See ADR
// 0109-baseurl-capture-gateway.
func emitGatewayProviderRouted(ctx context.Context, emitter audit.Emitter, sessionID string, prov captureproxy.Provider) {
	if emitter == nil {
		return
	}
	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.GatewayProviderRouted,
		SessionID: sessionID,
		Detail: map[string]string{
			"agent":         prov.Name,
			"provider_host": prov.UpstreamHost,
		},
		Actor: "shield",
	})
}

// emitGatewayStartFailed audits a capture-gateway setup failure. reason is a
// short fixed string, never the raw error (which may embed the target URL) -
// see ADR 0109-baseurl-capture-gateway.
func emitGatewayStartFailed(ctx context.Context, emitter audit.Emitter, sessionID string, prov captureproxy.Provider, reason string) {
	if emitter == nil {
		return
	}
	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.GatewayStartFailed,
		SessionID: sessionID,
		Detail: map[string]string{
			"agent":         prov.Name,
			"provider_host": prov.UpstreamHost,
			"reason":        reason,
		},
		Actor: "shield",
	})
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
