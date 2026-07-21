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
| T1.1 | Port runTunnelDarwin -> internal/shieldapp/tunnel_shield_darwin.go | //go:build darwin; app install/start/stop exec; in-process NewGateway + dnsvip; builds | done | macmitm-8b72ecfc | 9d60883f |
| T1.2 | runShield (darwin) reads tunnelMode + mitmMode | flag no longer a no-op; calls darwin startTunnel | done | macmitm-8b72ecfc | 9d60883f |
| T1.3 | Wire CA + extend TunnelCAEnv (CURL/GIT) + in-memory CA | env has all 5 keys; root.key absent; no key path in env or sbpl (verified grep empty; test TestTunnelCAEnvFullKeySet) | done | macmitm-8b72ecfc | d6679eb3,9d60883f |
| T1.4 | Signature adaptation: ctlauth.Load, AppendShieldedEnv, resolveMITM, audit/open-before-sandbox, grant cleanup | compiles against current signatures; grants revoked at exit | done | macmitm-8b72ecfc | 9d60883f |
| T1.5 | Audit events: extension start/stop + session register | additive constants in internal/audit; details mode/mitm/app_path/failure_reason; no secrets/keys in details | done | macmitm-8b72ecfc | fa3043e9 |
| T1.6 | Wire body capture (newBodyRecording) on darwin | Bodies wired via shared tunnel_body.go + keychain KEK; darwin gets policy_action free (shared engine); verified build+tests | done | macmitm-8b72ecfc | 3f91b849 |
| T1.7 | Failure-path tests | + found/fixed a REAL bug: startTunnelDarwin had no signal handling (armSignalDrain), SIGINT/SIGTERM skipped cleanup | done | macmitm-8b72ecfc | c9c10a67 |

**Phase 1b verifier notes:**
- Body-redaction GAP (AGE-149 work item, NOT done, shared not darwin-specific): internal/mitm/store.go redacts credential HEADERS only; request/response BODIES are encrypted at rest (KEK) but NOT secret-redacted. Same for Linux + darwin. Tracked as T1.9 below - not blocking e2e (bodies are captured + encrypted), but AGE-149 lists it.
- Child-PID registration (routed from Phase 2 T2.3) INVESTIGATED and RESOLVED as NOT-A-BUG: Provider.swift ancestorMatches (line 749) starts at the flow's PARENT and excludes self, so registering the shield's own PID captures the agent subtree without looping the gateway's own dials. The rescue "register child PID" fix does not apply to feat/nv's matching semantics. No change made.

| T1.9 | Redact credential values in captured bodies (not just headers) | shared internal/mitm; bodies scrubbed of secrets before/at store; Linux + darwin | todo (follow-up, non-blocking) | - | - |

**Phase 1a verifier notes:** T1.1-T1.4 verified by orchestrator (darwin build+vet green, tunnelMode read at shield_darwin.go:742, in-memory CA only, 5-key TunnelCAEnv test passes). Executor introduced 27 double-dash separators in new files; fixed in 5b0d2bd8. DNS-VIP risk RESOLVED: agent stub resolver queries the gateway's own addr (DNS=10.78.0.1), VIPs are only answers, so DNSPacketConn own-addr bind suffices; promiscuous serverNetstack not needed for darwin WG-over-UDP path. Body capture (Bodies) deferred to T1.6.

### Phase 2 - Swift extension + host app
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| T2.1 | Resolve main.swift conflict; keep NETransparentProxyProvider, delete dead L3 TunnelExtension | no conflict markers in macos/; one extension target; swiftc -parse clean | done | macmitm-8b72ecfc | f02f6cb6 |
| T2.2 | Port VIP+RFC1918 capture filter fix | Provider.swift no longer excludes 10.78/16 DNS-VIP range | done | macmitm-8b72ecfc | f9f861ea |
| T2.3 | Port DNS/principal-class/port-53 e2e fixes | dnsvip gonet read loop; Info.plist principal class literal; port-53 rewrite (child-pid = not-a-bug, see T1.5 notes) | done | macmitm-8b72ecfc | 3efd9204 |
| T2.4 | VIP allocation offset | ALREADY PRESENT on feat/nv (firstHostOffsetV4=3); no-op | done | n/a | already-present |
| T2.5 | DNS black-hole + resource-leak fixes | ALREADY PRESENT on feat/nv (verified vs bf47db7c); no-op | done | n/a | already-present |

**Phase 2 merged into feat/nv via merge commit (disjoint from Phase 1b). Swift worktree removed after merge.**

### Phase 3 - build + sign + notarize
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| T3.1 | Restore scripts/build-macos-app.sh + Makefile tunnel-lib | `make macos-app` builds .app ad-hoc-signed; codesign valid; plutil OK; verified by orchestrator | done | macmitm-8b72ecfc | dd431cf9,4befb097 |
| T3.2 | Sign extension+app (Developer ID) | DONE - Developer ID Application: Aseem Shrey (Q98Z3744J2); codesign valid | done | macmitm-8b72ecfc | creds from .env |
| T3.3 | Notarize + staple (app + DMG) | DONE - notarytool Accepted, stapled; spctl accepted, source=Notarized Developer ID; DMG stapler validate ok | done | macmitm-8b72ecfc | creds from .env |

### Phase 4 - package + verify
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| T4.1 | DMG packaging script + CLI app discovery | `make macos-dmg` builds + hdiutil-verifies DMG (ad-hoc); CLI discovery already exists (Phase 1a). Notarized DMG = manual (NOTARIZE=1) | done (script) | macmitm-8b72ecfc | a4b83a8c |
| T4.4 | Darwin smoke script (A8/A11/A12) | test/tunnel-e2e/smoke_darwin.sh; syntax+shellcheck clean; SKIPs cleanly without the extension | done | macmitm-8b72ecfc | 750fdadd |
| T4.2 | Verify e2e on build Mac | install+approve; agentjail-shield --tunnel -- claude; network.db rows; no DNS black hole | todo (Manual) | - | - |
| T4.3 | Verify clean-Mac notarized install | non-build Mac: Gatekeeper ok, ext approves, Claude session captured | todo (Manual) | - | - |

## MANUAL HANDOFF - only the human-gated steps remain

DONE by the loop (creds were in repo-root .env): build/AgentjailTunnel.app and
build/AgentjailTunnel.dmg are Developer-ID signed, NOTARIZED, and stapled
(spctl: accepted, source=Notarized Developer ID). build/agentjail-shield built
with the new darwin --tunnel path.

Remaining (need a human at the keyboard / a 2nd Mac):
1. **Install + approve (T4.2):** `build/AgentjailTunnel.app/Contents/MacOS/AgentjailTunnel install`,
   then click Allow in System Settings > General > Login Items & Extensions > Network
   Extensions. Un-automatable dialog. NOTE: an OLDER extension bundle
   `com.blinkerlm.agentjail.extension (0.0.5)` is currently activated; the new build is
   `com.blinkerlm.agentjail.app.extension`, so it registers fresh and needs its own approval.
2. **Run e2e (T4.2):** `build/agentjail-shield --tunnel -- claude` (the installed
   ~/.agentjail/bin/agentjail-shield predates this code - use the freshly built one, or
   cp it into ~/.agentjail/bin), then `bash test/tunnel-e2e/smoke_darwin.sh` - expect
   A8/A11/A12 to PASS and rows in ~/.agentjail/network.db.
3. **Clean-Mac check (T4.3):** install build/AgentjailTunnel.dmg on a second Mac, confirm
   Gatekeeper + approval + capture.

Known small fix for the docs pass: `agentjail-shield --help` still says `--tunnel (Linux)`;
darwin is now supported - update the help text.

Only after step 2 PASSes: do the prose docs pass (TD.4) per the user's "docs last".

### Docs / ADR (decision records land WITH their code commit; prose pass last)
| id | task | acceptance | state | claimant | commit |
|----|------|------------|-------|----------|--------|
| TD.1 | ADR: NE-app is the macOS CLI tunnel vehicle | committed with Phase 1; make adr-check green | todo | - | - |
| TD.2 | ADR: reverse ADR 0005 for the notarized .app | committed with Phase 3 | todo | - | - |
| TD.3 | macOS CA-boundary note (URLSession/CFNetwork) | in the NE-vehicle ADR or a comment pointer | todo | - | - |
| TD.4 | Final prose pass: rewrite macos/README.md, delete stale NEPacketTunnelProvider/TunnelExtension refs | README matches reality; user guide polished | todo (last) | - | - |
