# AGE-149 - Restore end-to-end MITM on macOS via the agentjail CLI

Build tracker for the NE-transparent-proxy restore, distributable/notarized scope.
Approved plan: [PLAN.md](./PLAN.md) (Codex-approved after 3 rounds).

## Claim protocol (prevents two models picking the same task)

- **In-flight lock = Linear + the orchestrator's session task list.** Before an executor
  starts a task, the orchestrator sets the Linear ticket to In Progress and adds a comment
  `claimed by <BUILD_SID> / executor <agent-id>`. Reading Linear shows what is taken.
- **This tracker is committed only at task completion** (state -> done + commit sha). Do
  NOT commit claim churn - in-flight state lives in Linear, not git history.
- **BUILD_SID for this effort:** `macmitm-8b72ecfc`.
- Executors run in isolated worktrees; the orchestrator (Opus) is the single serializer
  that moves a task todo -> claimed and verifies done.

## Atomic tasks

State: todo | claimed | in-review | done. Manual = needs human/credentials/hardware.

### Phase 0 - tunnel package prerequisites (OS-agnostic; do first)
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| T0.1 | Port promiscuous serverNetstack into internal/tunnel | package builds; unit test exercises promiscuous accept | done | macmitm-8b72ecfc | c88fb26b |
| T0.2 | Zero-listen-port support + Gateway.ListenPort() | config.go accepts ListenPort==0; ListenPort() returns bound port after start; test | done | macmitm-8b72ecfc | 0919d94c,d4ddecea |
| T0.3 | Gateway.DNSPacketConn() bound to netstack | returns usable PacketConn dnsvip.Server serves on; test | done | macmitm-8b72ecfc | d4ddecea |
| T0.4 | Phase 0 build/vet/test green | GOOS=darwin go build+vet ./internal/tunnel/...; go test ./internal/tunnel/... | done | macmitm-8b72ecfc | verified by orchestrator |

**Phase 0 verifier notes (carry into Phase 1):**
- serverNetstack was added as a STANDALONE unwired primitive; it is NOT spliced into
  NewGateway (feat/nv still uses netstack.CreateNetTUN). Phase 1 T1.1 must decide whether
  the darwin NE-loopback path needs the promiscuous stack wired in.
- DNSPacketConn() is implemented via tnet.ListenUDP (binds the stack's OWN addr:53), not
  via the promiscuous serverNetstack. RISK: the rescue DNS-VIP path served DNS for VIP
  destinations; if darwin needs to answer DNS sent to a VIP (not the stack's own addr),
  this may be insufficient and the promiscuous stack must be wired. Phase 1 must verify
  DNS-VIP resolution actually works on the darwin path.
- Pre-existing flaky test (NOT ours): TestChaosPortCollision (fixed port 51845, racy
  double-bind expectation). Ignore for this build; do not "fix" as part of AGE-149.

### Phase 1 - darwin MITM orchestration (internal/shieldapp)
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| T1.1 | Port runTunnelDarwin -> internal/shieldapp/tunnel_shield_darwin.go | //go:build darwin; app install/start/stop exec; in-process NewGateway + dnsvip; builds | todo | - | - |
| T1.2 | runShield (darwin) reads tunnelMode + mitmMode | flag no longer a no-op; calls darwin startTunnel | todo | - | - |
| T1.3 | Wire setupTunnelCADarwin + extend TunnelCAEnv (CURL/GIT) + in-memory CA | env has SSL_CERT_FILE/NODE_EXTRA_CA_CERTS/REQUESTS/CURL/GIT; root.key absent on disk; no key path in env or sbpl (grep empty) | todo | - | - |
| T1.4 | Signature adaptation: ctlauth.Load, AppendShieldedEnv, resolveMITM, audit/open-before-sandbox, grant cleanup | compiles against current signatures; grants revoked at exit | todo | - | - |
| T1.5 | Audit events: extension start/stop + session register | additive constants in internal/audit; details mode/mitm/app_path/failure_reason; no secrets/keys in details | todo | - | - |
| T1.6 | mitm store + dnsvip write network.db on darwin | a request produces a RequestLog row + body file | todo | - | - |
| T1.7 | Failure-path tests | child-spawn fail, SIGINT/SIGTERM, ext-start fail, stale /tmp/agentjail.sock all clean up | todo | - | - |

### Phase 2 - Swift extension + host app
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| T2.1 | Resolve main.swift conflict; keep NETransparentProxyProvider, delete dead L3 TunnelExtension | no conflict markers in macos/; one extension target; swiftc builds host app | todo | - | - |
| T2.2 | Port VIP+RFC1918 capture filter fix | Provider.swift no longer excludes 10.78/16 DNS-VIP range | todo | - | - |
| T2.3 | Port DNS/principal-class/PID-registration e2e fixes | dnsvip read loop; Info.plist principal class literal; child-pid register; port-53 rewrite | todo | - | - |
| T2.4 | Port VIP allocation offset fix | allocator starts at offset 3 (skip gateway+agent) | todo | - | - |
| T2.5 | Port DNS black-hole + resource-leak fixes | system-daemon bypass list; WG-readiness fail-closed; fd/thread/timer leaks fixed | todo | - | - |

### Phase 3 - build + sign + notarize
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| T3.1 | Restore scripts/build-macos-app.sh + Makefile tunnel-lib | one cmd builds libagentjail_tunnel.a + extension + host app + locally-signed .app (NOTARIZE=0) | todo | - | - |
| T3.2 | Sign extension+app (Developer ID + entitlements + profile) | codesign -d --entitlements :- ok; systemextensionsctl list; bundle IDs match profile | todo (Manual) | - | - |
| T3.3 | Notarize + staple | xcrun notarytool log clean; spctl -a -vvv accepts | todo (Manual) | - | - |

### Phase 4 - package + verify
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| T4.1 | Signed+notarized DMG + CLI app discovery | DMG mounts; CLI finds app at default path / AGENTJAIL_TUNNEL_APP | todo | - | - |
| T4.2 | Verify e2e on build Mac | install+approve; agentjail-shield --tunnel -- claude; network.db rows; no DNS black hole | todo (Manual) | - | - |
| T4.3 | Verify clean-Mac notarized install | non-build Mac: Gatekeeper ok, ext approves, Claude session captured | todo (Manual) | - | - |
| T4.4 | Darwin smoke script (mirror tunnel-e2e A8/A11/A12) | rerunnable script PASSes on set-up Mac | todo | - | - |

### Docs / ADR (decision records land WITH their code commit; prose pass last)
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| TD.1 | ADR: NE-app is the macOS CLI tunnel vehicle | committed with Phase 1; make adr-check green | todo | - | - |
| TD.2 | ADR: reverse ADR 0005 for the notarized .app | committed with Phase 3 | todo | - | - |
| TD.3 | macOS CA-boundary note (URLSession/CFNetwork) | in the NE-vehicle ADR or a comment pointer | todo | - | - |
| TD.4 | Final prose pass: rewrite macos/README.md, delete stale NEPacketTunnelProvider/TunnelExtension refs | README matches reality; user guide polished | todo (last) | - | - |
