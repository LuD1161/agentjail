# Plan: Restore end-to-end MITM on macOS via the agentjail CLI (distributable/notarized)

## Goal
Get MITM working end-to-end on macOS, delivered through `agentjail-shield --tunnel`,
as a distributable (Developer ID signed + notarized) `.app` + system extension.
"Working" = Claude Code runs under the tunnel, its HTTPS traffic to api.anthropic.com
et al is TLS-terminated, logged to `~/.agentjail/network.db` with method/url/status +
captured bodies, DNS is not black-holed, and a non-build Mac can install and run it.

## Key finding (why this is a restore, not a greenfield build)
The working macOS MITM path already existed and was seen running:
- Vehicle: `agentjail-shield --tunnel` -> `runTunnelDarwin` shells out to a signed
  `AgentjailTunnel.app` whose `NETransparentProxyProvider` system extension forwards
  flows over WireGuard-on-loopback (Swift `Provider.swift` -> cgo `wg_netstack_*` in
  `internal/tunnel/cbridge/cbridge.go`) into an in-process Go `tunnel.NewGateway`.
- That gateway runs the SAME shared Go MITM engine as Linux (`internal/tunnel/handler.go`,
  `internal/mitm/*`): TLS terminate, HTTP parse, policy, body capture to network.db.
- CA is injected into the agent env on macOS via `setupTunnelCADarwin` (SSL_CERT_FILE,
  NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO).
- This lives on tag `dns-blackhole-fix` (bf47db7c) / branch `rescue/burp-ui-2026-07-05`.

It REGRESSED on `feat/network-visibility`: that branch refactored the shield from
`cmd/agentjail-shield/` into `internal/shieldapp/` and did NOT bring the darwin tunnel
orchestration (`runTunnelDarwin`) across. On feat/nv today: `runShield(...tunnelMode...)`
ignores tunnelMode on darwin; `setupTunnelCADarwin` has zero callers; the pure-Go utun
gateway is dead code; and `macos/AgentjailTunnel/main.swift` has live merge-conflict
markers (lines 1/156/475). This is ticket AGE-149.

Branch divergence: feat/nv has 476 commits rescue lacks; rescue has 61 feat/nv lacks.
The completion commits will NOT cherry-pick cleanly (feat/nv rewrote the touched files),
so they must be ported by hand and re-verified.

## Known boundary (call out, do not try to fix in this plan)
`setupTunnelCADarwin`'s own doc notes macOS native frameworks (URLSession/CFNetwork)
ignore env-var CA trust and need system-keychain trust instead. Claude Code is Node
(honors NODE_EXTRA_CA_CERTS), and curl/git honor the env vars, so the target use case
works. Native-Apple-framework clients are out of scope; record in the ADR.

## Decisions already made
- Vehicle: restore the NE transparent-proxy path (NOT the utun/sudo path).
- Scope: distributable / notarized (folds AGE-67 signing + AGE-78 packaging into done).

## Repo constraints (AGENTS.md)
- Domain-driven, interface-first, type-safe. No `any`/`interface{}` except at
  serialization boundaries decoded immediately into typed structs.
- Platform code: interface/shared-contract in a tag-free `.go`, per-OS impl in
  `_linux.go`/`_darwin.go` with `//go:build`. The shared contract is ONE source of
  truth; Linux and darwin must not drift (ADR 0034). setupTunnelCADarwin and its Linux
  sibling TunnelCAEnv should share the contract, not re-list env keys independently.
- Store access only through internal/store singletons (sqlc); network.db is
  internal/mitm's own store, typed scans.
- Audit events for any state change / user-visible action.
- Small atomic commits, conventional, `git commit -s`, push after each. Never bypass
  hooks. Docs/ADR in the same commit as the behavior change.
- No em dashes, no ` -- ` prose separators; use ` - `.

## Phases

### Phase 0 - Tunnel package prerequisites (feat/nv lacks these; do FIRST)
0a. Port/adapt the promiscuous `serverNetstack` (rescue `servernetstack.go`) into feat/nv
    `internal/tunnel`, replacing the reliance on `netstack.CreateNetTUN` for the
    NE/loopback path. AC: package builds; unit test exercises promiscuous accept.
0b. Add zero-listen-port support to `internal/tunnel/config.go` (today it rejects
    ListenPort==0) and expose `Gateway.ListenPort()` returning the OS-assigned port.
    AC: config accepts 0; `ListenPort()` returns a non-zero bound port after start; test.
0c. Expose `Gateway.DNSPacketConn()` bound to the netstack. AC: returns a usable
    PacketConn the dnsvip.Server can serve on; test.
0d. These are shared (non-darwin) tunnel APIs used by both the future darwin path and any
    NE loopback path - keep them OS-agnostic; no `//go:build` on the contract.

### Phase 1 - Restore darwin MITM orchestration into internal/shieldapp (AGE-149)
1. Port `runTunnelDarwin` from rescue `cmd/agentjail-shield/tunnel_shield_darwin.go`
   into `internal/shieldapp/tunnel_shield_darwin.go` (//go:build darwin), adapted to the
   refactored package. Preserve: app path resolution (tunnelAppDefaultPath /
   AGENTJAIL_TUNNEL_APP), exec of app install/start/stop, in-process tunnel.NewGateway +
   dnsvip.Server bound to gateway.DNSPacketConn(), MITM enable unless --no-mitm.
2. Make `runShield` on darwin read `tunnelMode` (currently ignored) and call the darwin
   startTunnel; thread `mitmMode`/`--no-mitm` too.
3. Wire `setupTunnelCADarwin` into the agent exec env, mirroring shield_linux.go:378-387.
   Share the env-key contract with Linux (no drift). Extend TunnelCAEnv to also set
   CURL_CA_BUNDLE + GIT_SSL_CAINFO (per R4). Use in-memory GenerateCAInMemory + SetMITM;
   write only root.crt + bundle.crt (per R2). AC gate: after darwin CA setup, `root.key`
   does NOT exist on disk, and neither the agent env nor the sandbox profile references any
   private-key path (grep the emitted env + generated sbpl for `root.key`/key paths = empty).
4. Confirm internal/mitm store + internal/dnsvip (both platform-agnostic) attach on
   darwin and write network.db.

### Phase 2 - Swift extension + host app
5. Resolve `macos/AgentjailTunnel/main.swift` conflict: keep NETransparentProxyProvider
   (e090c3f side), delete dead L3 `macos/TunnelExtension/PacketTunnelProvider.swift`.
6. Port 4 completion fixes from rescue (by hand, not cherry-pick):
   a. VIP+RFC1918 capture filter (Provider.swift excluded all RFC1918, killing the
      10.78/16 DNS-VIP range).
   b. DNS/principal-class/PID-registration e2e fixes: gVisor gonet.UDPConn read loop in
      dnsvip/server.go; Info.plist principal class literal; port-53 rewrite to DNS-VIP;
      register CHILD pid after Start() to avoid gateway self-loop; session-socket retry.
   c. VIP allocation offset (start at offset 3 to skip gateway + agent addresses).
   d. DNS black-hole + resource-leak fixes in Provider.swift (system-daemon bypass list,
      WG-readiness gate = fail closed, fd/thread/timer leak fixes).

### Phase 3 - Build + sign + notarize
7. Restore `scripts/build-macos-app.sh` + Makefile `tunnel-lib` target (README references
   `make tunnel-lib`, which does not exist). Builds libagentjail_tunnel.a (c-archive,
   CGO_ENABLED=1 -buildmode=c-archive), extension (swiftc, needs -lbsm), host app,
   assembles AgentjailTunnel.app.
8. Sign extension then app with Developer ID Application + system-extension /
   networkextension entitlements + provisioning profile; notarize + staple (NOTARIZE=1).

### Phase 4 - Package + verify
9. Packaging/distribution: ship as a signed + notarized DMG containing
   AgentjailTunnel.app (decided, per R6 - not a pkg installer). Wire how the CLI locates
   it (tunnelAppDefaultPath /Applications/AgentjailTunnel.app vs AGENTJAIL_TUNNEL_APP).
   Gatekeeper: browser/DMG delivery sets com.apple.quarantine, so the .app MUST be
   notarized to install cleanly.
10. Verify e2e on the build Mac: install + approve extension, `agentjail-shield --tunnel
    -- claude`, assert network.db capture + no DNS black hole.
11. Verify on a clean (non-build) Mac: notarized .app installs via the normal flow,
    extension approves, MITM captures a Claude session. This is the distributable gate.
12. Add a darwin smoke script mirroring test/tunnel-e2e/scenarios.sh A8 (node fetch 200),
    A11 (network.db rows), A12 (claude under tunnel).

### Docs/ADR - split timing (per R5, one source of truth)
- Decision-record ADRs + code-comment pointers land IN THE SAME COMMIT as their behavior
  change (AGENTS.md rule): the NE-vehicle ADR, the ADR reversing ADR 0005's "unsigned is
  fine" for the notarized .app, and the macOS CA-boundary note. Not deferred.
### Phase 5 - Prose docs pass (only after Phase 4 build is green)
13. Rewrite macos/README.md for the internal/shieldapp layout + restored build flow, and
    DELETE the stale NEPacketTunnelProvider / TunnelExtension references (per R6). Polish
    the user guide. Refresh AGE-149/172/67/78. This is the final prose pass the user asked
    to run last; the ADRs above already landed with their commits.

## Revisions after Codex round 1 (all 7 findings addressed)
R1. Tunnel package API gap (Codex #1): feat/nv `internal/tunnel` does NOT have the
    rescue capabilities this path needs - `config.go` rejects ListenPort==0,
    `gateway.go` uses `netstack.CreateNetTUN` not the rescue promiscuous
    `serverNetstack` with a netstack-bound DNS conn, and there is no `ListenPort()` /
    `DNSPacketConn()`. NEW Phase 0 task: port/adapt `servernetstack.go`, add
    zero-listen-port support, `ListenPort()`, and `DNSPacketConn()` to feat/nv's tunnel
    package, WITH unit tests, BEFORE any darwin wiring. This is a prerequisite, not part
    of the darwin file.
R2. In-memory CA only (Codex #2): do NOT restore rescue's on-disk `mitm.LoadOrCreateCA`
    (writes root.key). Follow the current Linux model: `GenerateCAInMemory` + `SetMITM`,
    write ONLY root.crt + bundle.crt to disk, NEVER root.key. Darwin must match Linux
    here (shared contract, no drift).
R3. Signature-adaptation checklist (Codex #3): rescue `runTunnelDarwin` will not compile
    against current signatures. The port task must adapt to: `ctlauth.Load` control token
    (requestSecretGrants now needs it), `AppendShieldedEnv`, `resolveMITM`, the current
    audit / open-before-sandbox ordering, and active-grant cleanup. Each is an explicit
    sub-task acceptance item.
R4. Trust-env scope (Codex #4): current `TunnelCAEnv` sets only SSL_CERT_FILE,
    REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS. Decision: EXTEND the shared `TunnelCAEnv`
    contract to also set CURL_CA_BUNDLE + GIT_SSL_CAINFO (Linux + darwin both, no drift)
    and add a table test asserting the full key set. curl/git stay in the acceptance
    claim because we are adding the coverage, not assuming it.
R5. Docs/ADR timing (Codex #5 vs the user's "docs last"): reconcile by SPLITTING doc
    types. (a) ADRs + code-comment pointers that AGENTS.md requires land IN THE SAME
    COMMIT as the behavior change - specifically: the NE-vehicle ADR, the ADR reversing
    ADR 0005's "unsigned is fine" for the notarized .app, and the macOS CA-boundary note.
    (b) The comprehensive user-facing README / macos/README.md rewrite + user guide polish
    is the FINAL pass after the build is green. This honors both the repo rule and the
    user's "docs last" for the prose pass. FLAG: this is the one place the user's literal
    "docs only after done" is narrowed to "prose docs after done; decision records with
    their commit".
R6. Concrete build/sign acceptance gates (Codex #6): every build/sign/notarize task gets
    machine-checkable gates - `plutil -lint` on Info.plists, `codesign -d --entitlements :-`,
    `systemextensionsctl list`, `spctl -a -vvv`, `xcrun notarytool log`, and a check that
    bundle IDs match the provisioning profile. DECIDE NOW: ship as a signed+notarized DMG
    containing AgentjailTunnel.app (not a pkg installer) - simplest quarantine-clean path.
    Also: current macos/README.md still documents the dead NEPacketTunnelProvider /
    TunnelExtension - the docs task must delete that, not just add.
R7. Audit + failure-path coverage (Codex #7): extension start/stop and tunnel-session
    register are user-visible security state changes - emit audit events (or reuse) with
    details mode=tunnel, mitm=true|false, app_path, failure_reason. Add explicit tests for
    cleanup on: child-spawn failure, signal interruption (SIGINT/SIGTERM), extension start
    failure, and stale /tmp/agentjail.sock.

## Coordination and claim protocol (prevents two models picking the same item)
Cross-model safety cannot rely on the harness TaskList (session-local). Source of truth
is shared + durable:
- Claim identifier for this build effort: BUILD_SID (e.g. macmitm-8b72ecfc). Every claim
  carries it.
- Linear is the cross-model lock. Before work on a ticket: set state In Progress and add a
  comment "claimed by <BUILD_SID> / executor <agent-id> at <ts>". On verified completion:
  set Done and comment. A second session reading Linear sees the claim and skips it.
- LOCK = Linear + the harness TaskList (ephemeral, in-flight). Per R5-followup: do NOT
  commit a claim transition to source - that leaves transient state in history and causes
  merge conflicts. In-flight "claimed"/"in-review" state lives only in Linear (In Progress +
  session-id comment) and the session TaskList owner field.
- Permanent tracker file `docs/build/age-149-mac-mitm/TODO.md` is committed only at
  MEANINGFUL COMPLETION - a task moving to done, appending its commit sha - not on claim.
  It is an intentionally permanent build record, updated with conventional signed commits.
- Executors run in isolated git worktrees (one per task) so parallel file writes never
  collide; Opus merges/rebases verified work onto the branch serially.
- Opus is the single serializing orchestrator this session: it is the only writer that
  moves a task todo->claimed (in Linear + TaskList), guaranteeing no double-claim within
  the session; the Linear claim comment guarantees it across sessions.
- Invariant: the Linear board is updated at EVERY state transition, in the same step as the
  transition - never batched at the end. The committed tracker updates at completion only.

## Execution model
- Explode each phase into many small atomic tasks, each with observable acceptance
  criteria (command exits 0 with output X; test T passes; file F has symbol S).
- Dispatch each task to a Sonnet 4.6 executor sub-agent (in its own worktree). Opus
  verifies each against its acceptance criteria (compile/build/test/diff), adjudicates
  PASS/FAIL, re-dispatches on FAIL. Claim protocol above runs on every task transition.
- After every round, run the available end-to-end checks and ask "is it ready to use?".
  Loop until the code is completely built and verified up to the manual gates.
- Manual gates the loop cannot clear (flagged, not automated): notarization credentials
  (task 8), system-extension approval dialog + clean-Mac hardware (tasks 10-11).
- Prose docs (Phase 5) only after the build works; decision-record ADRs land with their
  code commits per R5.

## Verification anchors
- `GOOS=darwin go build ./... && GOOS=darwin go vet ./...` green, then host `go test`
  (run with sandbox disabled per repo).
- `go test ./internal/mitm/... ./internal/dnsvip/... ./internal/tunnel/...` green.
- scripts/build-macos-app.sh (NOTARIZE=0) produces a locally-signed .app.
- Manual: extension approves, Claude session shows rows in network.db, no DNS black hole.

## Open questions for the reviewer
- Is porting-by-hand + re-verify the right call vs an octopus-merge / subtree graft of the
  rescue macOS files onto feat/nv? Given the 476/61 divergence and feat/nv's newer
  body-capture/encryption stack, is there a cleaner reconciliation?
- Sequencing risk: should the Swift/build phase (2-3) precede the Go wiring (1) so we can
  actually run the extension while wiring, or is Go-first correct?
- Anything in the security model (fail-closed on WG-not-ready, CA key handling, quarantine
  / Gatekeeper, extension entitlements) that this plan under-weights?
