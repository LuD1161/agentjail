# Changelog

`main` is the live branch. Significant ships only — see `git log` for the full picture. Format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and dates are ISO-8601.

## Unreleased

### Added

- **Observe-only MCP inventory for macOS**: the unified app reads global Claude
  Code, Codex, and Cursor MCP configuration through versioned adapters and shows
  redacted targets, configuration issues, and duplicate names without writing
  config, launching servers, contacting endpoints, or changing policy.

## v1.6.0 - 2026-08-16

![v1.6.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v1.6.0-summary.svg)

## TL;DR

- **Store credentials under arbitrary IDs** with optional labels and tags,
  then deliver explicit environment variables or private session files without
  teaching AgentJail what vendor or tool consumes them.
- **Run eligible host commands from shielded Codex sessions on macOS** through
  the same native allow-once host-proxy contract already used on Linux.
- **Prove macOS tunnel enforcement instead of accepting SKIPs** with an approved
  Tart golden image, strict policy matrix, structured scenario results, and a
  real Codex release gate.
- **Keep the distribution boundary explicit**: the CLI release does not install
  or activate the macOS Network Extension.

### Added

- **Generic credential records**: `agentjail credential set ID` imports named
  environment variables, mode-0600 file bindings, or one stdin value. Optional
  labels and tags are discovery metadata, while the exact ID remains the only
  selection key.
- **Agent credential discovery**: shielded coding agents receive a session-only
  MCP surface that lists non-secret IDs, labels, and tags and requests one exact
  credential. Eager launches use `agentjail run --credential ID -- <command>`.
- **macOS host proxy**: `agentjail proxy -- <argv...>` shares the Linux policy,
  evidence, audit, timeout, output, and failure contracts while using Darwin
  process-group primitives behind the platform interface.
- **Fail-closed tunnel assertions**: `--require-tunnel` and
  `AGENTJAIL_REQUIRE_TUNNEL=1` refuse fallback when a test or release claim
  requires the transparent tunnel.

### Changed

- **Credential identity is provider-neutral**: IDs such as
  `aws-read-only-cred-prod`, `cluster-dev`, or `slack-channel-read-token` are
  opaque names. AgentJail no longer requires a tool, provider, account, or
  context field and never infers permissions from a name or tag.
- **Credential delivery shares one audited domain path**: eager launch and
  agent-requested delivery use the same exact-selection, authorization,
  durable-audit, issuance, expiry, revocation, and cleanup contract.
- **macOS testbeds use one approved golden**: all Tart workflows clone
  `golden-macos-mitm`; non-tunnel scenarios leave its inactive extension alone,
  while tunnel assertions require it to be activated and enabled.
- **Distribution stays CLI-only**: release tarballs contain `agentjail` and
  `agentjail-hook`. They do not package, install, activate, or approve the
  separately built macOS Network Extension application.

### Fixed

- **Darwin tunnel session selection**: live registered PIDs survive permission
  errors from `kill(pid, 0)` and are reaped only when the process no longer
  exists, preventing valid sessions from silently bypassing the gateway.
- **Darwin temporary staging**: tunneled sessions use the same validated
  per-user temporary-directory renderer as ordinary macOS shield sessions, so
  image paste and other agent staging no longer fail under the tunnel.
- **Codex test teardown and daemon readiness**: release scenarios drain probe
  process groups, isolate subprocess state, wait for launchd readiness, and use
  typed health evidence instead of one-shot terminal text.
- **Credential residue cleanup**: scenario credentials are removed and verified
  absent, fixture values are scanned across raw AgentJail storage, and the
  release evidence manifest fails when required artifacts or prompts are absent.

### Security

- **No credential values in argv**: imports read from trusted environment
  variables, stdin, or files. Bindings that could replace PATH, dynamic loaders,
  proxy or TLS controls, shell startup, module paths, or SSH-agent state are
  rejected before storage.
- **Host execution remains exact and one-use**: the daemon binds native approval
  to the authenticated session, executable, argv, cwd, project root, PATH,
  broker PID, and fresh process ancestry. Shells, interpreters, missing proofs,
  replay, timeout, and rejection fail closed.
- **No all-SKIP tunnel passes**: the macOS release gate requires an activated
  extension, at least one executed tunnel scenario, strict allow/deny/bypass
  policy evidence, and zero required SKIPs.

## v1.5.0 - 2026-08-06

![v1.5.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v1.5.0-summary.svg)

## TL;DR

- **Route ordinary PATH-shim launches through the transparent tunnel** so opted-in Claude Code, Codex, and Cursor sessions get network visibility by default.
- **Start the macOS local UI with shielded sessions** and surface its loopback link in the persistent status line.
- **Keep routine startup to one to three useful lines** while retaining private per-session JSON diagnostics and an explicit `--verbose` troubleshooting mode.
- **Preserve SSH and credential boundaries** while fixing Linux Landlock grants for legitimate regular files under `~/.config`.

### Added

- **Private shield session logs**: each launch records structured diagnostics in
  `~/.agentjail/logs/`, keeps the newest 10 files, and accepts
  `agentjail run --verbose -- <agent>` to mirror them to stderr.
- **macOS UI auto-start**: shielded sessions start the loopback UI on demand and
  expose a clickable `📊 UI` link in the persistent status line when reachable.

### Changed

- **Tunneled PATH-shim launches**: the opt-in wrappers now enter
  `agentjail run --tunnel -- <agent>`, preserving child arguments and launch
  policy while enabling transparent network visibility by default.
- **Compact startup**: routine launch details move out of the interactive
  terminal. Sandbox readiness, required consent, enforcement failures, and the
  broad SSH-signing warning remain visible.
- **Concise SSH bootstrap**: the selected identity, session-only OpenSSH scope,
  and passphrase privacy statement share one consent prompt. Launch-time Codex
  hook reassertion no longer repeats install-only trust guidance.

### Fixed

- **Linux config-file grants**: regular files directly under `~/.config` receive
  file-scoped Landlock rights instead of invalid directory-only rights, removing
  noisy `EINVAL` skips and restoring intended read access.
- **Shared local UI address**: UI launch and status-line rendering use one typed
  loopback address contract instead of duplicating the endpoint.

### Security

- **Private diagnostic storage**: shield log directories are forced to mode
  `0700` and log files to `0600`; retention and log-open outcomes are audited
  without recording file paths.
- **Important warnings stay interactive**: quiet mode does not suppress
  malformed-policy failures, sandbox downgrades, SSH delegation scope, or other
  actionable security notices.

## v1.4.1 - 2026-08-06

![v1.4.1 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v1.4.1-summary.svg)

## TL;DR

- **Calculate current Claude and Codex API-equivalent costs accurately** with cache-write TTLs, GPT-5.6 long-context tiers, fork-aware usage, and source-dated fallback pricing.
- **Recover historical usage from real local transcripts** even when JSONL records exceed 1 MiB, then recalculate eligible sessions with the latest bundled rates.
- **Read spending and activity faster** through a structured terminal dashboard, semantic color controls, complete command help, and explicit cached-token breakdowns.
- **Use Git over SSH more consistently** through policy-controlled session agents
  with cleaner remote-aware identity selection while preserving the existing
  private-key boundary.

### Added

- **Global color control**: human-readable commands use the shared terminal
  palette by default and accept `agentjail --no-color <command>` as a
  process-wide color override while preserving Unicode structure.
- **Terminal cost dashboard**: `agentjail cost` renders project and model
  spending, impact bars, session totals, cache efficiency, and detailed token
  categories while retaining JSON output for automation.
- **Policy-controlled Git SSH**: the standard policy can bootstrap a
  session-only native OpenSSH agent through the same agent-neutral launch path
  for Claude Code, Codex, and Cursor.

### Changed

- **Colorized activity reports**: `stats`, `cost`, and `sessions list` now use
  the shared semantic palette for totals, outcomes, spend, metadata, and impact
  bars; each also accepts a command-local `--no-color` flag.
- **Cleaner SSH identity selection**: session bootstrap follows Git push remote
  precedence and effective OpenSSH `IdentityFile` ordering, selects one matching
  identity by default, and asks only when multiple matches remain.
- **Complete command help**: legacy subcommands now expose their local flags in
  `--help` alongside inherited global options.

### Fixed

- **Current-model cost estimates**: price GPT-5.6 Sol/Terra and Claude Opus
  4.8/5 from officially verified rates, and include cache pricing for Claude
  Opus 4.6 instead of reporting active sessions as `$0.00`.
- **Real transcript ingestion**: recover after oversized Claude and Codex JSONL
  records, retain valid later records, and surface bounded warnings instead of
  dropping the rest of a session.
- **Cached and supplemental usage pricing**: separate uncached input,
  cache-read, cache-write, and output charges; preserve Claude cache-write TTLs;
  apply GPT-5.6 long-context rates per request; and exclude copied Codex fork
  history from the child session.
- **Pricing boundaries**: attribute model changes to the request that produced
  each usage delta, keep synthetic zero-usage records out of human dashboards,
  and warn when incomplete history prevents a safe estimate.

### Security

- **Validated SSH delegation**: accept only a clean, owned, live Unix agent
  socket, strip ambient delegation variables, and audit the capability without
  recording socket paths or key material.
- **Existing private-key isolation preserved**: SSH-agent delegation enables
  signing without granting the sandbox access to private-key files. This
  release improves selection and bootstrap consistency without changing that
  existing boundary; the strict policy still disables automatic Git SSH.

## v1.4.0 - 2026-07-31

![v1.4.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v1.4.0-summary.svg)

## TL;DR

- **Analyze local Claude Code, Codex, and OpenCode costs** by project and model with bundled Gryph pricing, token efficiency, and budget alerts.
- **Explore the same cost report in the local SPA** with session totals and input/output token breakdowns.
- **Activate Linux updates transactionally** by restarting and attesting the new daemon, then restoring the exact prior installation if activation fails.
- **Diagnose protection state faster** with a polished terminal report and explicit CLI/daemon version-skew repair.

### Added

- **Local cost analytics**: `agentjail cost` summarizes Claude Code, Codex, and OpenCode
  spend by project and model, with JSON output, token efficiency, and optional
  daily/per-project budget alerts backed by bundled Gryph pricing (ADR
  0120-bundled-model-pricing).
- **Cost dashboard contract**: the local UI can consume the same typed report,
  including unique session totals and per-model input/output token counts.
- **Local Cost dashboard**: the SPA presents project, model, session, token,
  spend, efficiency, and budget data without sending transcripts off-device.

### Changed

- **Doctor terminal report**: `agentjail doctor` now renders a concise,
  structured health summary while preserving typed output for automation.

### Fixed

- **Transactional manual updates**: Linux now activates swapped binaries by
  restarting the supervised daemon; activation failure restores the exact
  prior binary and role-path state, then restarts the restored daemon.
- **Headless systemd recovery**: daemon restart derives a missing user-bus
  environment only after validating the runtime directory and bus socket are
  owned by the current user and have safe types and permissions.
- **Daemon version attestation**: `agentjail doctor` compares the installed CLI
  with the running daemon and repairs stale or pre-version-reporting processes.

### Security

- **Human-only daemon recovery**: CLI and direct systemd restart paths are
  permanently policy-locked, mirrored by degraded offline enforcement, and
  the CLI requires control-token access plus typed confirmation on `/dev/tty`.
- **Attested update activation**: manual updates now require a versioned daemon
  ping before commit, audit terminal outcomes over the authenticated control
  socket, and restore the prior generation on restart or attestation failure.
- **Bounded local analytics**: transcript readers cap periods, files, records,
  and JSONL line size; sanitize terminal metadata; and open OpenCode SQLite with
  an enforced read-only URI plus `query_only`.

## v1.3.0 - 2026-07-31

![v1.3.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v1.3.0-summary.svg)

## TL;DR

- **Route every effective Codex `PreToolUse` Bash `ask` through native approval**, including user-authored custom-policy asks, with a one-use `shell-command` broker.
- **Keep non-Bash Codex asks fail closed** while preserving their canonical policy decision for records and diagnostics.
- **Classify Git remote updates from parsed executable arguments**, including `git -C`, rather than matching words in raw shell text.
- **Preserve a human approval boundary in bypass mode** while Codex remains at `danger-full-access` and unrelated approval categories stay rejected.

### Added

- **Codex Bash native approval transport** (ADR 0119-command-approval-transport): every effective Codex `PreToolUse` Bash `ask` opens Codex's native prompt through an exact, ownership-safe managed execpolicy rule. This includes core, library, AWS-posture, resolver-default, project, and user-authored custom-policy asks; Codex 0.146 is verified.
- **Typed `shell-command` broker**: the fixed broker command carries only the operation and opaque one-use challenge, while AgentJail displays the bounded, redacted effective shell command immediately before Codex's native prompt.
- **Parsed Git remote-update intents**: policy evaluates typed executable Git-push intent, including documented global options, push options, and branch-aware force forms.

### Changed

- **Codex bypass-flag handling**: the opt-in PATH shim recognizes `--dangerously-bypass-approvals-and-sandbox` and `--yolo` as leading Codex options, keeps Codex at `danger-full-access`, and leaves only execpolicy-rule prompts interactive. Sandbox, MCP, `request_permissions`, and skill-script approval categories remain auto-rejected.
- **Approval transport now follows the effective Bash `ask` action**, rather than a built-in rule allowlist; non-Bash asks retain the fail-closed Codex adapter behavior.
- **Git-push policy matching** now follows the executed invocation rather than raw phrase matching, preventing inert argument text from being treated as a remote update.

### Fixed

- **Cold bridge decisions** retain the broker rewrite under the bridge-specific daemon deadline instead of falling back to the original command during a healthy but slower approval decision.
- **Approval prompt context** now shows the redacted effective shell command immediately before the native Codex prompt.

### Security

- **Approval redemption is fail closed**: declining the prompt, `approval_policy=never`, `--ignore-rules`, a missing managed rule, replay, expiry, daemon restart, version skew, or unverifiable process ancestry cannot execute the original command.
- **Broker authorization is bound and one-use**: a redemption requires the typed operation, active Codex session, unchanged tool-call epoch, same-UID peer, and fresh descendant process chain; an operation mismatch burns the challenge. Challenge references are non-reversible and original command text is not added to broker logs or audit detail.

## v1.2.0 - 2026-07-29

![v1.2.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v1.2.0-summary.svg)

#### TL;DR

- **Summarize AgentJail activity** with final outcomes, policy deny rules, per-agent counts, latency percentiles, and recording coverage from the local SQLite store.
- **Scope and automate reports** with `agentjail stats --since`, `--top`, and typed JSON output.
- **Restore consented PATH shims during every update** so existing opt-ins gain the complete Claude Code, Codex, and Cursor wrapper set.

### Added

- **`agentjail stats`**: a read-only activity summary over the singleton `store.ReadOnlyStore`, with all-time or duration-scoped reports, ranked policy deny rules, per-agent and audit-event breakdowns, latency percentiles, and coverage-gap warnings.
- **Machine-readable stats**: `--json` emits the typed aggregate contract, `--since` accepts durations such as `24h` and `7d`, and `--top` controls ranked table depth.

### Changed

- **Final-outcome totals**: allowed, asked, and blocked counts follow the observed final action, including OS-sandbox blocks, while the deny-rule table remains tied to canonical policy denies.
- **Missing agent identity** is normalized to the explicit `unknown` sentinel at the store boundary so attribution gaps remain queryable.
- **Shared PATH-shim contract**: install, doctor, uninstall, manual update, and daemon auto-update use one target list, renderer, consent probe, and restoration path.

### Fixed

- **Manual `agentjail update` restores PATH shims** after swapping binaries and reconciling role symlinks, but only when a prior wrapper or shell-profile consent marker exists.
- **Daemon auto-update restores PATH shims** under the same opt-in contract, fixing upgrades that kept an older Claude-only wrapper and failed to add the v1.1 Codex and Cursor wrappers.

## v1.1.0 - 2026-07-27

![v1.1.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v1.1.0-summary.svg)

#### TL;DR

- **Display live AgentJail protection state when Codex sessions start and stop**, including startup, resume, clear, and compact boundaries.
- **Distinguish full protection, shield-only operation, and unshielded sessions** by probing both enforcement layers before attesting.
- **Launch Codex and Cursor through the same default OS sandbox as Claude Code**, with PATH shims, hook installation, status reporting, and uninstall support for all three agents.
- **Preserve policy meaning across agent protocols** by recording the canonical policy action separately from the effective action rendered to Claude, Codex, or Cursor.
- **Harden custom Rego rules** so extensions can add candidates but cannot override the resolver, suppress locked rules, or mutate policy evaluation.
- **Fix daemon recovery and uninstall targeting** so restart uses the installed supervisor and uninstall probes only the daemon belonging to the requested home.

### Added

- **Codex lifecycle attestation** (ADR 0113-cursor-status-line): matcher-free `SessionStart` and `Stop` hooks display `sandbox + policy active`, `sandbox active, policy daemon offline`, or `OS sandbox inactive` through Codex's supported `systemMessage` channel.
- **Codex and Cursor PATH shims**: detected installations now receive the same automatic shield activation as Claude Code; macOS grants the agent-specific runtime paths from the shared sandbox contract.
- **Complete Codex hook integration**: registers `PreToolUse`, `PermissionRequest`, and `PostToolUse`, normalizes their wire shapes, and preserves Codex-native approvals when Codex independently opens a permission request.
- **Complete Cursor hook integration**: handles shell, MCP, and file-read hook events with typed normalization and binary allow/deny rendering.
- **Cursor status line** (ADR 0113-cursor-status-line): installs an AgentJail protection badge while preserving and restoring a user's existing status command byte-for-byte.
- **Agent decision adapters** (ADR 0115-agent-decision-adapters): decision records, logs, and UI state expose `policy_action`, `effective_action`, adapter provenance, and translation reason.
- **Cross-agent clean-VM conformance scenario** covering installed Claude Code, Codex, and Cursor hook behavior.
- **Bounded decision snapshots**: `agentjail logs --latest N` selects the newest matching SQLite decisions and prints them chronologically, including JSON output.

### Changed

- **Codex asks fail closed at `PreToolUse`** (ADR 0117-codex-ask-boundary): because Codex hooks cannot create an approval prompt, AgentJail records canonical `ask` and renders an explicit effective `deny`; an ask can never silently continue.
- **Policy inputs normalize at the adapter boundary** so file paths, shell commands, MCP calls, session identity, and tool-call correlation have one canonical shape across supported agents.
- **Daemon restart uses the installed supervisor** instead of treating `restart` as daemon process arguments and accidentally starting an unconfigured resolver-default daemon.

### Fixed

- **Uninstall target-home isolation**: daemon liveness checks now probe the socket under the requested home, rather than the process user's daemon, preventing false aborts that leave hooks and shell RC entries installed.
- **Fail-open recovery reporting**: `doctor` recognizes a later recorded decision as proof that policy evaluation resumed instead of leaving a permanent outage warning.
- **Development deployment**: refreshes all multicall role symlinks and the hook binary consistently.
- **Complete non-follow logs**: `agentjail logs --no-follow` now traverses every matching SQLite page instead of stopping after the oldest 1,000 decisions.
- **Truthful sandbox outcomes**: successful tool output that merely discusses `EPERM` or sandbox denials is no longer recorded as an OS-enforced block; Claude failures now use `PostToolUseFailure`, while Codex attribution requires structured failure evidence.
- **Inert commit-message paths**: static, non-expanding `git commit -m` text no longer triggers the Bash sensitive-path rule, while expansions, other arguments, and chained commands remain protected.

### Security

- **Custom rule surface validation** (ADR 0116-custom-rule-surface): OPA AST validation accepts only partial `candidate` entries and rejects resolver/helper declarations, both at `policy add` and daemon load; invalid manually installed rules are quarantined without weakening the baseline.
- **Canonical/effective action separation** prevents protocol limitations from being misreported as policy decisions and keeps final sandbox attribution independent.

## v1.0.0 - 2026-07-21

#### TL;DR

- **Capture your agent's LLM traffic on macOS with no system extension.** A base-URL capture gateway points the agent's own provider override (`ANTHROPIC_BASE_URL`) at a local proxy, so a plain `agentjail-shield -- claude` records the full `POST /v1/messages` request+response (bodies encrypted at rest) and forwards to the real API over TLS. This works where a transparent MITM can't — current Claude Code runs on Bun and its inference client rejects every custom CA — and needs no privileged extension, so the CLI captures the traffic that matters out of the box (AGE-259, ADR 0109).
- **macOS transparent tunnel** for everything else: a NETransparentProxy system extension funnels the agent's traffic through the same gVisor + MITM engine as Linux, now with an opt-in IPv6 datapath so IPv6 egress is intercepted+captured instead of leaking (AGE-262).
- **HTTP/2 and gRPC through the tunnel** (Linux): the transparent-tunnel MITM now negotiates ALPN and serves `h2` for real, so gRPC and h2-only clients work — not just HTTP/1.1. gRPC status/trailers are preserved and client-streaming RPCs no longer stall.
- **The tunnel now works with a real agent on the *installed* build**: a live Claude Code session is decrypted and captured end-to-end (validated by a golden-VM gate). Three defects that only the shipped symlinked binary + a real agent could hit are fixed (ADR 0103).
- **Network visibility UI**: a Network tab with per-session request timelines, column filters, and a body viewer, driven by an on-disk capture store.

### Added

- **Base-URL capture gateway for LLM providers** (AGE-259, ADR 0109): current Claude Code runs on Bun and its inference client ignores every CA trust store, so a transparent MITM cannot decrypt `POST /v1/messages` (and in fact breaks it). Instead the shield points the agent's own `ANTHROPIC_BASE_URL` at a per-session loopback proxy — nonce-gated, egress-guarded, a user-set base URL is preserved — that records the full request/response (bodies encrypted at rest) and forwards to the real provider over TLS. Runs in **both plain and `--tunnel` modes, independent of the system extension**; fail-closed for a detected provider with an explicit `--no-provider-gateway` / `network.capture_gateway: false` opt-out. The darwin non-tunnel path became spawn-and-wait (from `syscall.Exec`) so the in-process gateway survives, preserving exit-code and signal parity.
- **IPv6 datapath for the macOS tunnel** (AGE-262, opt-in): IPv6 egress was grabbed by the extension but had no v6 datapath, so it reset (`SSL_ERROR_SYSCALL`) and evaded capture while IPv4 worked. The gateway now provisions a v6 address (`fd79::`, outside the DNS-VIP pool) end to end; enable with `--tunnel-ipv6` / `network.tunnel_ipv6` (default off until the installed app is attested dual-stack).
- **Network flag precedence + `doctor` sourcing** (ADR 0110): one canonical order for every network knob — CLI flag > env var > `policy.yaml` > default — and `agentjail doctor` now prints each knob's effective value AND where it came from (cli/env/config/default). `--netproxy` is documented as deprecated.
- **HTTP/2 in the tunnel MITM** (ADR 0102): advertises `h2, http/1.1`, serves h2 via `http2.Server.ServeConn` with an `http2.Transport` upstream, full parity with the HTTP/1.1 path (body capture, policy/deny, recording). gRPC unary works with `grpc-status` through trailers; hop-by-hop headers are stripped on both legs. Proven end-to-end over the real TUN.
- Streaming/bidi h2 request bodies are forwarded without pre-draining, so a long-lived stream never deadlocks; host/path/method policy still applies (body-content scan is bounded-body only — ADR 0102).
- **Encrypted body capture** with keychain/file KEK tiers so `doctor` never overstates protection (ADR 0095/0097).
- **`agentjail ui --trusted-host`**: reach the local UI behind a same-host reverse proxy without disabling the anti-rebinding guard (ADR 0099).
- **`agentjail-daemon --retention-interval`**: retention + WAL checkpoint re-run periodically, not just at startup (ADR 0101).
- Network session "active" state reflects the owning shield PID's liveness, matching `agentjail sessions list --active` (ADR 0100).

### Fixed

- **Streaming responses stalled on the macOS tunnel** (ADR 0108): the gVisor `serverNetstack` pump dropped outbound packets when its queue was full, silently losing TCP segments on a lossless carrier and hanging long SSE streams. It now applies backpressure (blocks, never drops).
- **Decrypted bodies were not persisted on the darwin tunnel** (AGE-259): the session id was `shield-<ts>-<hex>`, which `mitm.NewBodyStore` rejected (non-alnum), silently disabling body storage. The id is now alphanumeric, so request/response bodies actually land.
- Dev builds (`make dev-deploy`/`dev-install`) reported version `dev` — the `-ldflags` targeted a nonexistent `main.version` instead of `internal/buildinfo.Version` (AGE-247).
- Retention enforced its window only once at daemon startup, so a long-lived daemon's DB grew unbounded (AGE-225).
- h2 request trailers were dropped on streamed bodies (`.Clone()` froze an all-nil map before net/http2 filled it).
- **Tunnel silently fell back to netproxy on every installed deployment** (ADR 0103): the TUN-holder / `nsenter` re-exec used `os.Executable()`, which resolves the installed `agentjail-shield` symlink to `agentjail` and misdispatched to the CLI, so the TUN helper never ran. It worked only from the standalone dev binary, hiding the bug. Now dispatched by `argv[0]`.
- **Tunnel holder died mid-session** (ADR 0103): `Pdeathsig` fires on the cloning *thread*'s exit, which Go could retire, SIGKILLing the holder so a follow-on `nsenter` failed. Replaced with socket-based liveness (the holder exits when the shield closes the handoff socket).
- **Agent could not resolve DNS inside the tunnel on systemd-resolved hosts** (ADR 0103): the `127.0.0.53` stub is unreachable in the netns, so the agent saw `ENOTIMP`. The holder now bind-mounts a resolver pointing at the in-tunnel gateway.

### Docs

- Document the unprivileged-userns requirement: Ubuntu 23.10+ gates it behind AppArmor; the tunnel fails open to netproxy when it is unavailable, and `agentjail doctor` prints the one-time command to enable the full tunnel.

## v0.9.0 - 2026-07-16

#### TL;DR

- **Monitor mode** (ADR 0091): the daemon evaluates every tool call and enforces nothing, recording the verdict that would have fired. `agentjail monitor` shows what a rule set would allow, deny, or ask about, so you can try it against your real workflow before turning it on.
- **Attestation now verifies the daemon end to end**: the status line pings the policy daemon rather than assuming it, shows UNSECURED when not shielded, and defaults to a degraded posture instead of silent-allow when the daemon is unreachable - so a green badge is a verified claim.
- **Control-plane token auth** (ADR 0067/0068/0069): every privileged control-socket verb now requires a token the shield withholds from the sandboxed agent, closing a path where the guarded agent could reach the guard's own control plane.

### Added

- **Monitor mode** (ADR 0091): a new enforcement mode where the daemon evaluates every call and enforces nothing, recording the would-have-fired verdict. `agentjail monitor` surfaces it.
- **Control-plane token authentication** across the daemon, netproxy, and secrets broker (ADR 0067/0068/0069); the shield withholds the token from the sandboxed agent.
- **`agentjail doctor --fix`** (ADR 0086): doctor repairs what it diagnoses (dangling PATH shim, stale supervisor, missing role symlinks), not just reports it.
- **Status line always attests** (ADR 0064/0085): UNSECURED when not shielded, and it attests the policy daemon by pinging it, not just the shield.
- The store redacts secrets by value, not only by key name (ADR 0084).
- Rego input is type-checked against the HookInput schema; `policy add` fails closed on an unknown `input.*` reference (ADR 0080).
- Dropped decisions are visible in the audit log (ADR 0072).

### Changed

- **Degraded is the default posture** when the daemon is unreachable, not silent allow (ADR 0074).
- **Uninstall is total** (ADR 0063/0065): stops the daemon before unhooking, verifies it stopped, aborts rather than tearing down half-way, and restores any chained status line.
- `AGENTJAIL_SHIELDED=1` now means actually sandboxed, not merely that the shield ran (ADR 0087).
- Policy reload moved off the agent-reachable socket onto the privileged control socket (ADR 0066).
- Daemon durability: WAL checkpoint instead of VACUUM-on-start, SIGHUP reloads coalesced and rate-bounded (ADR 0075), and buffered decisions survive shutdown.

### Fixed

- The status badge no longer reads "secured" while the daemon is down and enforcing nothing (the signature was shield activations climbing while recorded decisions stayed flat); a wedged daemon is no longer badged as secured.
- The fail-open notice now surfaces where the user can see it (systemMessage); Codex users are warned during a daemon-down window too.
- Shield: canonicalizes aliased paths in the control-socket guard, works from a git worktree, never launches silently unrecorded, and emits macOS control-socket denies last with SSH_AUTH_SOCK preserved.
- Install repairs the deployed supervisor, not just the template; the Linux daemon restarts after the auto-updater's clean exit (ADR 0070).
- Dropped two Landlock grants measured as connect() no-ops.

### Security

- Control-plane token auth closes a privilege-escalation path: a sandboxed agent could previously reach the daemon, netproxy, and secrets control sockets. Every verb but the fingerprint challenge now requires a token the shield withholds from the agent.
- Secrets redacted by value, not just key name (ADR 0084), so a secret pasted into an unexpected field is still masked in the audit log.
- Honest attestation (ADR 0074/0087): the guard reports UNSECURED or degraded instead of a green badge when enforcement is not actually running.

## v0.8.2 - 2026-07-14

#### TL;DR

- Exactly one `agentjail-daemon` can own the policy socket now, regardless of how it was installed (Homebrew vs curl) or started (service vs manual) — a second daemon stands down instead of hijacking `daemon.sock` and orphaning the incumbent.
- Closes an enforcement-integrity hazard where two daemons could double-bind the socket, splitting hooks across them with a fail-open window during the handoff.

### Fixed

- **Daemon single-instance guard** (ADR 0060, `internal/daemonapp/`) — the
  agent-facing policy socket (`daemon.sock`) was bound with a blind `os.Remove`
  + `net.Listen` and no single-instance lock, so a second daemon — a different
  install channel, a manual run, or an upgrade transition — could unlink the
  incumbent's socket and double-bind, leaving two daemons alive with hooks split
  across them. The daemon now takes an exclusive `flock` on `daemon.lock` (beside
  the socket) before binding, with a bounded ~1s retry to absorb a
  supervised-restart handoff, and replaces the blind unlink with `stat →
  ControlOpPing probe → remove-only-if-stale → ListenUnix`. A healthy incumbent →
  the newcomer stands down cleanly (`exit 0`, so systemd's `StartLimit` never
  pins the unit failed and launchd's `KeepAlive` self-heals); a foreign/wedged
  process squatting on the socket → `exit 1` (never unlink a socket something
  holds). A new side-effect-free `wire.ControlOpPing` op backs the probe so a
  bare `connect()` can't be mistaken for a live daemon. Reuses the flock +
  probe-before-remove pattern already used by the grant control socket and the
  netproxy. No service-definition or user-facing CLI changes.

## v0.8.1 - 2026-07-14

#### TL;DR

- Fixed the macOS release gate (`make e2e-release`) flaking with a misleading "VM never got an IP": the real cause was the macOS concurrent-VM cap, which the tooling now surfaces instead of hiding.
- The gate now runs exactly one testbed VM at a time and stops it on exit, so a run never leaves an orphaned VM holding a slot.

### Fixed

- **macOS testbed release gate** (`test/testbed/`, Tart driver) - no shipped
  binary change; release-tooling only.
  - `tart run` errors (notably "The number of VMs exceeds the system limit",
    the macOS Virtualization.framework concurrent-VM cap) are now surfaced and
    the gate fails fast with the real reason, instead of swallowing the error
    and blaming a DHCP-lease timeout after 120s.
  - The gate waits for SSH to become reachable before provisioning (sshd comes
    up a few seconds after the VM's IP), fixing an intermittent provision-time
    SSH timeout.
  - The gate enforces a single testbed VM: it stops other running testbed VMs
    up front to guarantee a free slot, and stops its own VM on exit
    (success, failure, or interrupt) so a run never orphans a VM.

## v0.8.0 - 2026-07-14

![v0.8.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v0.8.0-summary.svg)

#### TL;DR

- agentjail now ships **2 binaries instead of 6** - the daemon, shield, netproxy, and secrets roles are folded into one multicall `agentjail` binary dispatched by its invocation name, so there is half as much to build, sign, notarize, and self-update.
- The four role names are now **symlinks to `agentjail`**, reconciled on every install/update - a role binary can no longer drift out of sync with the build it should track.
- Caught a release-blocking bug pre-tag: the CI version ldflag stopped reaching the version symbol after the refactor, which would have shipped every tagged release reporting `dev`.
- The latency-critical hook stays its **own lean binary** (~5 ms, no OPA/SQLite tax) - consolidation never touches the hot path.

### Changed

- **Multicall `agentjail` binary** (ADR 0059) - the daemon, shield, netproxy,
  and secrets roles are no longer separate executables. They are folded into a
  single `agentjail` binary that dispatches on its invocation name
  (`filepath.Base(os.Args[0])`), with a hidden `agentjail <role>` subcommand
  form as a fallback. Role logic moved into importable `internal/{daemonapp,
  shieldapp,netproxyapp,secretsapp}` packages. The result: **2 shipped binaries**
  (`agentjail` + `agentjail-hook`) instead of 6, so half as much to build, sign,
  notarize, and atomically self-update.
- **`agentjail-hook` deliberately stays separate** - it runs on every tool call
  against a single-digit-millisecond budget, and folding the daemon's OPA/SQLite
  `init()` into it would tax the hot path (~+6 ms). Verified it still links no
  OPA/store/SQLite and starts in ~5 ms.
- **Role binaries are now symlinks to `agentjail`** - `agentjail-daemon`,
  `agentjail-shield`, `agentjail-netproxy`, and `agentjail-secrets` are relative
  symlinks reconciled by `EnsureRoleSymlinks` on install, update, uninstall, and
  in `install.sh` / the Homebrew formula. Existing launchd plists, systemd units,
  PATH shims, and hook-config paths keep working unchanged. Drift is closed by
  construction: a role name always resolves to the current `agentjail` build.
- **Unified version injection** behind `internal/buildinfo.Version` - one symbol
  every binary and reporter reads, injected by a single fully-qualified ldflag.
- **Self-update payload trimmed** to the two real binaries; role symlinks are
  reconciled after each swap instead of being downloaded separately.

### Fixed

- **Release-blocking version ldflag** - after the role packages became imports
  rather than `main`, the CI release build's `-X main.version=` ldflag silently
  no-oped, so every tagged release would have reported version `dev`. The build
  now injects `internal/buildinfo.Version`. Caught and fixed before tagging.
- **Codex / Cursor hook config serialization** - `agentjail` no longer writes a
  degenerate empty codex hook group or a null Cursor event entry when
  reconciling an agent's hook config, both of which could produce malformed
  `hooks.json` that a coding agent would warn on.

## v0.7.0 - 2026-07-14

#### TL;DR

- New clean-VM testbed engine: a real end-user VM per worktree, a `make e2e-release` release gate, and a 15-scenario CLI suite recorded to asciinema, green on Linux and macOS.
- The credential broker now auto-starts on demand — `agentjail secret set` and shield grants no longer need a manual `agentjail-secrets serve`.
- Fixed a Linux shield read-leak: launching from `$HOME` no longer exposed `~/.ssh`/`~/.aws`/`~/.gnupg`.

### Added

- **Clean-VM testbed engine** (`test/testbed/`, ADR 0053) — persistent, isolated
  VMs (Lima/QEMU on Linux, Tart on macOS) that behave like a real end-user
  machine: full kernel (Landlock/Seatbelt), a service manager, no host mounts,
  no Go toolchain. agentjail is installed the true user way — a release-layout
  tarball fed to the shipped `install.sh`. `make e2e-release` is the release
  gate: reset to a clean golden, provision, run the `e2e-smoke` scenario, exit
  non-zero on any failure.
- **Recorded CLI scenario suite** — 15 scenarios captured with asciinema (tiny
  `.cast` JSON, not video), each with a structured pass/fail result. Recordings
  are auto-sanitized of host-identifying data before they are written.
- **On-demand secrets broker auto-start** (ADR 0058) — the broker is a
  loaded-but-not-running launchd/systemd definition that clients bring up on
  first use (`EnsureSecretsBroker`), with an idle self-exit that never tears
  down live grants. Closes DEFECT-2: `agentjail secret set` / shield grants no
  longer require a manual `agentjail-secrets serve`. Ships as the sixth binary.

### Fixed

- **Linux shield `$HOME` read-leak** — the shield grants the working directory
  read-write; when launched with `cwd == $HOME` that grant swallowed the whole
  home tree, overriding the allowlist that withholds `~/.ssh`, `~/.aws`,
  `~/.gnupg`. Launching from `$HOME` now grants only the non-hidden home
  children as a workspace and denies every dotfile/dotdir by default (that's
  where credentials live), matching the macOS shield. A normal project cwd is
  unaffected.
- **`--help` on flag-passthrough commands** — subcommands using
  `DisableFlagParsing` now intercept `--help` and print usage instead of
  forwarding it to the wrapped tool.

## v0.6.2 - 2026-07-09

#### TL;DR

- Restore a green CI pipeline - the e2e, smoke, and race-enabled unit tests pass again on macOS and Linux (they had been red since v0.6.0 due to test-harness assumptions the v0.6.0 hardening invalidated).
- Fix a data race in the daemon's agent-connection idle-timeout handling that the race detector flagged.

### Fixed

- **Daemon idle-timeout data race** - the agent-connection idle timeout moved
  from a mutable package global to an immutable per-server field
  (`server.idleTimeout`), set once at construction. The old global was written
  by a test while a `handleConn` goroutine read it concurrently, which
  `go test -race` flagged. Production behavior is unchanged (still a 5s idle
  deadline).
- **CI test harnesses green again** - the e2e/smoke harnesses now isolate HOME
  so the hook honors their test socket (v0.6.0 restricted `AGENTJAIL_SOCKET` to
  paths under `~/.agentjail`), and the sensitive-path fixtures (e2e `~/.ssh`
  deny, shield known-hosts read-only) run against non-temp paths so the
  policy/shield temp-write carve-outs no longer mask them. Test-only changes;
  no shipped behavior is affected.

## v0.6.1 - 2026-07-09

#### TL;DR

- Surface the enforcing build's version in the shielded status line instead of a bare commit hash - it reads `v0.6.1` on a release and `v0.6.0+5` between releases.

### Changed

- **Status line shows the version** - `agentjail statusline` now renders the
  build version parsed from `git describe`: an exact release tag (`v0.6.1`),
  `+N` commits past the last tag (`v0.6.0+5`), and a trailing `*` for a dirty
  tree. It falls back to the short commit hash when no version was embedded.
  Dev builds (`scripts/dev-deploy.sh`, `make dist`) now embed the describe
  string so the `+N` suffix shows up between releases; the release build
  already stamps the exact tag.

## v0.6.0 - 2026-07-08

![v0.6.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v0.6.0-summary.svg)

#### TL;DR

- Hardened the credential broker and daemon control plane - master key is now unreadable by the agent, grants auto-expire, and the daemon verifies peer UID/CWD instead of trusting self-reported claims.
- Brought the macOS shield to parity with Linux for ssh-agent auth, including a fix for the pinned-IdentityFile blind spot that silently broke `git` over SSH under the sandbox.
- Added first-class Linux install via a systemd `--user` service and a clean-VM testbed with a `make e2e-release` gate.
- Inverted the over-broad `.env` write-deny to a secret-form deny-list so cloning repos that commit `.env.example`/`.env.docker` templates no longer fails.

### Added

- **ssh-agent auth under the shield** - `SSH_AUTH_SOCK` passthrough, agent-socket
  connect allowed on the macOS seatbelt, and per-user temp + AF_UNIX local sockets
- **ssh-agent readiness tooling** - typed prober, a `doctor` warning when keys are
  on disk but not loaded, and a one-shot hook advisory on the allow path
- **Pinned-IdentityFile fix** (ADR 0056) - the shield injects an agent-backed
  `GIT_SSH_COMMAND` with `IdentitiesOnly=no` so a pinned on-disk key no longer
  breaks `git` over SSH under the sandbox
- **Daemon control-plane socket** (ADR 0052) - policy reload over the control
  socket with SIGHUP fallback
- **`daemon_unreachable` policy knob** (ADR 0050) with a hook-fallback sidecar the
  hook acts on
- **Linux install support** (ADR 0051) via a systemd `--user` daemon service
- **Clean-VM testbed + `make e2e-release` gate** (ADR 0053) - installs through the
  real `install.sh` and asserts enforcement on a clean box
- **Remediation hints** on `file_policy` and `command_policy` denies, and the exact
  MCP server name in the unknown-server deny hint

### Changed

- **`.env` write-deny inverted to a secret-form deny-list** (ADR 0057) - only
  secret-bearing forms are denied; templates like `.env.example` and `.env.docker`
  are allowed
- **Shell parsing** now unwraps interpreter and process wrappers
  (python/node/perl/ruby/php), newlines, and command substitutions
- **The shield re-asserts the agentjail hook** right before exec

### Fixed

- **`install.sh`** no longer aborts the outer script under `set -eu`
- **Daemon agent-socket** connections are bounded with an idle read deadline
- **README MCP inventory** references now point at the real `mcp scan`/`mcp where`
  commands

### Security

- **Secrets-broker master key** is protected from agent reads (policy + shield)
- **Postgres passwords** no longer leak via `psql` argv; grants auto-expire and
  requested TTL is capped
- **Daemon peer identity** - verify peer UID and CWD instead of trusting
  self-reported claims
- **`AGENTJAIL_SOCKET`** is honored only when it resolves under `~/.agentjail`;
  the fail-open sentinel re-arms on startup
- **Credential-dir grants** - block MCP-command credential-dir grants and deny
  `.config` credential subdirs
- **Cloud-metadata (IMDS) egress** guarded in port-only mode
- **Per-project policy overlay** is trust-gated before it is applied; store
  redaction extended to more credential shapes

## v0.5.1 - 2026-07-06

### Added

- **Read-only access to SSH and AWS config** in the sandbox - agents can now
  resolve SSH host aliases (via ssh-agent, no private key access) and read
  AWS region/profile settings; both backends (macOS sbpl + Linux Landlock)
  consume the shared `PerFileGrants()` contract

### Fixed

- **Landlock ctl_connect test** downgraded from assertion to log - Landlock
  cannot prevent AF_UNIX connect() (FS-only LSM); grant-socket isolation
  on Linux requires Tier 2+

## v0.5.0 - 2026-07-06

![v0.5.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v0.5.0-summary.svg)

#### TL;DR

- Daemon-hosted grant server - grants moved from netproxy to daemon with PID-based session binding, removing the `--netproxy` dependency for grant operations.
- Policy simplification - removed overly broad `no-hook-self-disable` rule that caused false positives with plugins; replaced with targeted `file_policy/hook_config` ask rule.
- Self-update and shield fixes - fail-open sentinel mechanism, launchctl daemon restart, SSH port 22 in sandbox fallback.

### Added

- **Daemon-hosted grant server** (ADR 0047) - grant control server on
  `daemon-ctl.sock` with PID-based session binding via SO_PEERCRED (Linux) /
  LOCAL_PEERPID (macOS); transactional claim-grant workflow with audit trail
- **`agentjail grants --log`** flag to display grant audit history from the
  daemon's SQLite store
- **`file_policy/hook_config`** ask rule protecting `~/.claude/settings*.json`
  from silent overwrites that could remove agentjail hooks
- **`make dev-install`** target to build, install, sync policy rules, restart
  daemon, and verify with SHA-256 checksums
- **Fail-open one-time warning** sentinel mechanism so users know
  when the hook is running in fail-open mode
- **SSH port 22** allowed in sandbox fallback ports

### Changed

- **Grant commands auto-detect backend** - `agentjail grants` queries daemon
  first, falls back to netproxy only when available; merged listing with SOURCE
  column
- **Peer PID extraction** via SO_PEERCRED/LOCAL_PEERPID for session binding
  without agent-supplied identity
- **Process walk helpers** extracted to shared `procutil` package

### Fixed

- **Removed `no-hook-self-disable`** rule that was blocking legitimate plugin
  operations (claude-mem worker diagnostics) due to overly broad Bash regex
  matching `>=` and `=>` as shell redirects
- **PATH shim regenerated on upgrade** so brew/curl installs pick up
  the current template
- **Daemon restart via launchctl kickstart** instead of stop+start
- **Landlock test updated** to use `daemon-ctl.sock` (was still referencing
  old `netproxy-ctl.sock` path)

### Security

- **`daemon-ctl.sock` denied on macOS** via sbpl network-outbound deny,
  mirroring the netproxy control socket isolation - agent cannot self-approve
  grants

## v0.4.0 - 2026-07-05

![v0.4.0 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v0.4.0-summary.svg)

#### TL;DR

- Session-aware network proxy (ADR 0042) - per-session allowlists over a control plane, replacing the global egress allowlist.
- Per-folder project policy overlays (ADR 0043) - direnv-style trust gate with `agentjail trust`/`untrust` CLI commands.
- Runtime host grants (ADR 0044) - `agentjail allow host` and `grants approve/deny` for interactive egress approval.
- Shared sandbox contract for darwin/linux parity, plus macOS code signing and notarization in the release pipeline.

### Added

- **Session-aware network proxy** - control-plane server with session registry,
  per-token data plane, and lease reaper; shield registers a per-session
  allowlist with netproxy over the control plane instead of a global allowlist
- **Per-folder project policy overlays** - direnv-style trust gate discovers
  per-folder overlays; `agentjail trust`/`untrust`/`trust list` CLI commands;
  shield applies the trusted overlay to the session allowlist additively
- **Runtime host grants** - `agentjail allow host` and
  `grants approve/deny (--persist)` CLI for interactive egress approval, backed
  by a shared runtime host-grant validator and session identity fields
- **macOS code signing and notarization** wired into the release pipeline
- **Dev-deploy script** to build and swap local binaries during development
- **Netproxy decision logging** to a file for observability, including target
  host on non-CONNECT rejects

### Changed

- **Domain-driven interface-first architecture (ADR 0035)** - extracted
  hookwatch, credential, sandbox, envaudit, and policyeval into internal
  packages; `policyctl` domain service replaces 12 copy-pasted audit ceremonies
- **Shared sandbox contract for darwin/linux parity** - hybrid
  `allowed_hosts` model with non-removable essential hosts and
  user-configurable extended hosts; `EffectiveAllowedHosts` enforces the split
- **Netproxy egress enforcement is now opt-in** via `--netproxy`; host
  resolution and upstream connectivity checks are bounded and parallelized
- **`agentjail run`/`claude` resolves the real binary** past the shim; status
  line now shows the build git hash and a "secured by agentjail" indicator

### Security

- **Policy denies agent-issued grant verbs** - `approve`/`deny`/`persist`/
  `trust` cannot be invoked by the agent itself, only by the human operator
- **Narrowed agent grant on `~/.agentjail`** to `daemon.sock` only; reads of
  the agentjail state dir are allowed while writes stay locked
- **macOS keychain access hardened for Claude Code** as part of darwin/linux
  sandbox parity, alongside Phase 3 grant-boundary regression guards

## v0.3.1 — 2026-06-28

![v0.3.1 summary](https://raw.githubusercontent.com/LuD1161/agentjail/main/assets/releases/v0.3.1-summary.svg)

#### TL;DR

- Close a tilde/`$HOME` credential bypass that let agents read `.ssh/id_rsa` and `.aws/credentials` unblocked.
- Fix CI flake caused by cold OPA engine exceeding the hook's 45ms deadline on first evaluation.
- Downgrade `eval_conflict` to non-fatal so edge-case Rego conflicts don't crash the daemon.

### Fixed

- **Tilde/`$HOME` credential bypass closed** — path matching now normalises `~`
  and `$HOME` before policy evaluation, closing a bypass that allowed agents to
  read credential files (`.ssh/id_rsa`, `.aws/credentials`) without triggering
  file_policy deny rules
- **`eval_conflict` downgraded** — non-fatal for edge-case Rego evaluation
  conflicts instead of crashing the daemon
- **E2E cold-start flake** — added OPA warmup probe after daemon startup to
  prevent spurious fail-open on the first deny assertion in CI
- **SIGHUP test timeout** — increased daemon startup timeout from 3s to 10s for
  loaded CI runners

### Security

- Path matching now normalises `~` and `$HOME` before policy evaluation, closing
  a bypass that allowed agents to read credential files without triggering deny
  rules.

## v0.3.0 — 2026-06-27

Sessions subsystem and Cobra CLI migration.

### TL;DR

- **Session tracking** — `agentjail sessions list` shows active and past agent sessions with PID-based detection.
- **Cobra CLI** — migrated to Cobra for automatic `--help`, shell completions, and subcommand groups.
- **Platform procwalk** — process tree walking split into `_darwin.go` / `_linux.go` with build tags.

### Added

- **`agentjail sessions list`** — new CLI command showing active and past agent
  sessions with PID-based active detection via process tree walking
- **Session names from Claude Code metadata** — sessions display human-readable
  names sourced from Claude Code session metadata instead of opaque IDs
- **Daemon session tracking** — active session detection wired into the daemon
  with CLI dispatch support
- **SQLite session store** — `internal/store` with schema, queries, and models
  for persistent session data
- **Cobra CLI framework** — migrated from hand-rolled subcommand dispatch to
  Cobra for automatic `--help` generation and shell completions

### Fixed

- **Platform-specific procwalk** — split `procwalk.go` into `_darwin.go`
  (sysctl) and `_linux.go` (`/proc`) with `//go:build` constraints for correct
  cross-platform compilation
- **Cobra wrapper** — testable active sessions loader with parity sync
- **Mock store** — added `ListSessionsFiltered` to mock store after rebase

### Changed

- **AGENTS.md** — added build-tag rule for platform-specific code

## v0.2.9 — 2026-06-26

MCP inventory and per-project policy resolution.

### TL;DR

- **MCP inventory** — `agentjail mcp inventory` scans configs, npm, pip, and Docker for a full MCP surface map.
- **Per-project policy** — policy resolution now cascades from global to per-project overrides.
- **Skill & tool policy** — per-skill allow/block/ask and per-tool policy CLI.

### Added

- **`agentjail mcp inventory`** — full MCP inventory from agent configs, npm
  packages, pip packages, and Docker containers with security audit per server
- **Per-project policy resolution** — policies cascade from global defaults to
  per-project overrides with a reverse MCP index
- **Project selector UI** — web UI project selector with per-project policy
  view and override management
- **Per-skill policy** — `agentjail skill allow/block/ask` for granular skill
  gating with `discovered_skills` table
- **Per-tool policy CLI** — `agentjail mcp tool allow/block/ask` with session
  log discovery and remote MCP connectors
- **Discovered tables** — `discovered_tools` and `discovered_skills` SQLite
  tables for tracking MCP tool and skill inventory

## v0.2.8 — 2026-06-23

MCP policy foundations and security hardening.

### TL;DR

- **Granular MCP policy** — per-tool `blocked_tools` and `ask_tools` controls.
- **Live tool discovery** — MCP protocol introspection with provenance metadata.
- **Security fixes** — XSS, CSRF, credential leak, DOM injection, goroutine safety.

### Added

- **Per-MCP-tool policy** — `blocked_tools` and `ask_tools` granular controls
  in `policy.yaml` for tool-level gating within MCP servers
- **Live MCP tool discovery** — introspects running MCP servers via the MCP
  protocol to enumerate available tools with provenance metadata
- **Policy management UI** — new tab in the web UI with an MCP tool matrix
  and inline config editor

### Fixed

- **XSS sanitization** — HTML output in the web UI is properly escaped
- **CSRF protection** — state-changing API endpoints validate origin
- **Credential leak prevention** — sensitive values are redacted in API
  responses and log output
- **DOM chip injection** — user-controlled values rendered as text nodes,
  not raw HTML
- **Goroutine safety** — concurrent map access in the policy engine protected
  with proper synchronization

## v0.2.7 — 2026-06-23

Replay gets colors, agent glyphs, and cleaner session labels.

### TL;DR

- **Replay gets color** - colored action badges, dim metadata, bold headers with proper alignment.
- **Agent glyphs** - replay reuses the same colored glyphs from `agentjail logs` (Claude ✳, Codex ◆, Cursor ▸).
- **Replay session prefix** - 8-char session prefix instead of truncated UUID with ellipsis.

### Added

- **Replay ANSI colors** - `agentjail replay` now shows colored action badges
  (green ALLOW, red DENY, yellow ASK), dim rule/reason metadata, bold headers
  with separator lines, and a `--no-color` flag for piped output
- **Agent glyphs in replay** - session list and replay rows show the same
  colored agent glyphs as `agentjail logs`, reusing `agentRegistry`

### Fixed

- **Replay session label** - `agentjail replay` now shows an 8-char session
  prefix instead of a truncated UUID with ellipsis
- **Duplicate badge** - removed duplicate GitHub downloads badge from README

### Changed

- **README** - updated for v0.2.6, added recent updates timeline

## v0.2.6 — 2026-06-23

Daemon auto-update - the daemon can now update itself without human
intervention.

### TL;DR

- **Daemon auto-update** - download, verify, swap binaries, and restart automatically.
- **Linux systemd support** - auto-update works on Linux via systemd in addition to macOS launchd.

### Added

- **Daemon auto-update** - the daemon can download the latest release, verify
  its SHA256 checksum, atomically swap binaries, and exit for launchd/systemd
  to restart it (ADR 0026)
- **Linux systemd support** - auto-update daemon restart works on Linux via
  systemd in addition to macOS launchd

### Fixed

- **ExtractTarball** - create destination directory if it does not exist

## v0.2.5 — 2026-06-23

Combined changelogs on update, UI polish, TUI local time fix, and telemetry
overhaul — PostHog now builds real user profiles, heartbeats actually arrive,
and the web UI gets session permalinks, scroll stability, and a wider sidebar.

### Added

- **Combined changelogs on update** — `agentjail update` now shows what shipped
  in every release you skipped, not just the latest; backed by a new Worker
  endpoint `/v1/changelog?from=vX.Y.Z`
- **Session URL permalinks** — selecting a session updates the URL with
  `?session=ID`; the session is restored on page load and browser back/forward
- **"← All Sessions" back button** — visible at the top of the sidebar when a
  session is selected; replaces the hidden bottom toggle

### Fixed

- **Person properties** — every telemetry event now sends `$set` (mutable:
  `agentjail_version`, `os`, `arch`) and `$set_once` (immutable:
  `install_method`, `first_installed_version`) so PostHog builds person profiles
  instead of showing anonymous hashes with no metadata
- **Heartbeat reliability** — CLI now waits for the heartbeat HTTP POST to
  complete before exiting; previously the goroutine was fire-and-forget and most
  heartbeats were silently lost
- **Install inflation** — install events now carry `is_fresh_install` to
  distinguish first-ever installs from binary/daemon refreshes (`curl | sh` on
  an already-installed machine)
- **Empty version on dev builds** — non-release builds now report
  `"dev-<sha7>"` instead of an empty string, via a `commit` ldflags variable
- **`session_start` reliability** — sent immediately at daemon startup instead
  of waiting for the 2-minute spool flush, so it's captured even if the daemon
  exits quickly
- **Worktree repo name** — git `--git-common-dir` resolves the real repo name
  inside worktrees instead of showing the worktree folder name
- **Timeline scroll stability** — scroll position is preserved during SSE
  updates; expanded event cards no longer jump to the top
- **Expanded event identity** — expanded cards track by `req_id|time` instead
  of array index, so new SSE events don't shift the card to a different row
- **Timeline grid layout** — Summary column is now the flexible column; Rule
  has a fixed width, eliminating the empty space on the right
- **Logs TUI local time** — `agentjail logs` now displays timestamps in local
  time instead of UTC

### Changed

- **Sidebar width** — default increased from 208px to 280px for better
  readability of session labels
- **Agent text removed from labels** — the agent icon is sufficient; agent name
  appears on hover tooltip only
- **Releases Worker cache TTL** — reduced from 5 minutes to 1 minute so new
  releases are visible immediately after publish
- **TELEMETRY.md** — documented person properties (`$set`/`$set_once`),
  `is_fresh_install`, version fallback, and updated delivery semantics

## v0.2.4 — 2026-06-23

Smarter session labels, live event ticker, and CWD column in the web UI.

### Added

- **Git-aware session labels** — sessions now display as `agent · branch ·
  repo` (e.g. "claude-code · main · agentjail") instead of opaque UUIDs; git
  branch and repo name are looked up once per session on first event
- **CWD column in timeline** — the event timeline table shows the working
  directory basename for each event
- **Live event ticker** — the header bar shows "last event: Xs ago" updated
  every second, so it is clear the SSE connection is alive

### Fixed

- **`agentjail ui` version label** — showed stale "NOT in v0.1.0-alpha
  release" text; now displays the actual binary version

## v0.2.3 — 2026-06-23

Changelog shown during install/update, so users see what shipped at a glance.

### Added

- **Install-time changelog** — `curl | sh` installer now displays a compact
  "What's new" section with unicode-formatted bullet points extracted from the
  GitHub release notes
- **Update-time changelog** — `agentjail update` shows the same "What's new"
  section after a successful self-update, using the release body from the
  `/v1/latest` API
- **Releases Worker changelog field** — `/v1/latest` API response includes
  the release body so both the installer and the update command can display it
  without an extra network call

### Changed

- **Update confirmation** — `agentjail update` now accepts Enter to proceed
  (previously required typing 'y'); the stricter confirmation remains for
  `policy disable` and `mcp allow/block`
- **CHANGELOG.md backfill** — added entries for v0.2.0, v0.2.1, and v0.2.2

## v0.2.2 — 2026-06-23

Reduced daemon memory usage and safer self-update behaviour.

### Added

- **Cross-process update lock** — a file-based lock prevents concurrent update
  attempts across multiple daemon instances or rapid restarts from racing each
  other during a self-update

### Fixed

- **SQLite memory footprint** — reduced per-connection cache and WAL settings so
  the daemon consumes significantly less resident memory under normal operation
- **daemon.log fallback** — when the SQLite store is unavailable, log queries
  fall back to `daemon.log` and emit a clear warning instead of silently
  returning empty results

## v0.2.1 — 2026-06-23

Web UI polish: live version display, session tracking, and layout fixes.

### Fixed

- **Dynamic version display** — the UI header now shows the running daemon
  version rather than a hardcoded placeholder
- **Cache-busting** — static assets include a version-derived query string so
  browsers pick up UI changes after a daemon upgrade without a manual cache clear
- **CWD display** — the current working directory is shown correctly in session
  context panels
- **Active session count** — the session list now reflects only currently active
  sessions rather than all historical sessions

## v0.2.0 — 2026-06-22

Layered self-protection, enriched Bash policy input, OS notifications for
pending updates, and a hook-config watchdog for self-healing.

### Added

- **Self-update package** — `internal/selfupdate` centralises version-check
  logic; the CLI and daemon both use it, and a background goroutine in the daemon
  fires OS-native notifications when a new release is available
- **OS notification package** — `internal/notify` delivers desktop alerts on
  macOS and Linux without a GUI dependency
- **Structured Bash input** — the daemon enriches every Bash `PreToolUse` event
  with `command_binaries` (a parsed list of the distinct executables in the
  command) via `internal/shellparse`, giving Rego policies fine-grained access to
  what will actually run
- **Layered self-protection** (ADR 0025) — policy evaluation now uses structured
  input to enforce agentjail's own protection rules in multiple independent
  layers, closing gaps that string-only matching left open
- **Shield hook-config protection** — `agentjail-shield` now blocks agent writes
  to hook-configuration directories, preventing an agent from removing its own
  guardrails through the filesystem
- **Hook-config watchdog** — the daemon monitors hook-config directories and
  automatically restores any entry that an agent removes, giving the installation
  self-healing capability
- **Shared 24-hour daemon ID** — telemetry heartbeats carry a stable 24-hour
  rotating daemon identifier and a `source` field so server-side analytics can
  distinguish CLI-initiated checks from daemon background checks

### Fixed

- **Heartbeat on every version check** — the daemon now emits a telemetry
  heartbeat on each scheduled version check, not only at startup

## v0.1.2 — 2026-06-20

SQLite decision store, AWS policy pack, shield hardening, web UI with
server-side filters, and E2E test infrastructure.

### Added

- **SQLite decision store** — WAL-mode event store at `~/.agentjail/agentjail.db`
  with redaction, retention cleanup, concurrent reader/writer support, and indexes
  on session_id, ts, action, tool_name, rule_id
- **ReadOnlyStore** — separate read-only connection type (`sqliteROStore`) for UI,
  logs, and replay; no write methods leak even via type assertion
- **AWS policy pack** — `no_aws_destructive.rego` library rule (deny destructive,
  ask mutating); per-account posture config (sandbox/prod/locked/custom);
  `policy-aws.yaml` sample template
- **Replay CLI** — `agentjail replay --session <id> --list --verbose --follow`
  with formatted output and column headers
- **Shield hardening** — env-stripping at launch (configurable blocklist),
  environment audit (root/ambient creds/IMDS detection), Landlock network rules
  with `runtime.LockOSThread()` preservation, `agentjail-netproxy` for per-host
  egress on Linux
- **Secrets broker** — `agentjail-secrets` binary (AES-256-GCM at rest, Unix
  socket RPC, AWS/PG/Redis backends); shield calls grant/revoke for scoped env
  var injection
- **Web UI** — `agentjail ui` local replay viewer with SQLite backend, server-side
  filters (action/tool/rule/limit query params), resizable panes and columns,
  agent logos (Claude/Cursor/Codex/OpenCode), collapsible audit section, branded
  header with GitHub star/issue links
- **Server-side filters** — `/api/state` and `/api/session` accept `?action=`,
  `?tool=`, `?rule=`, `?limit=` query params; counters remain global while events
  are filtered; `FilteredCount` and `TotalDecisions` in response
- **E2E test** — `make e2e` runs a 20-assertion new-user test script covering
  build, daemon, hook decisions, SQLite store, replay, UI API, filters, try, and
  SIGHUP reload; CI job on ubuntu-latest + macos-14

### Fixed

- AfterID keyset cursor for DESC pagination (`id < ?` not `id > ?`)
- Session filter uses substring match (INSTR) consistently across SQLite and
  daemon.log modes
- UI connection pooling — one shared SQLite handle instead of per-request open
- sqliteSnapshot over-fetch — SQL aggregate for counters, LIMIT for display
- DSN path URL-encoding for paths with `?`, `#`, `%`
- SSE "connecting..." stuck — flush `:ok` comment on connect
- Limit clamping (default 100, max 10000) on all queries
- SQLite fallthrough to daemon.log now logs a warning

### Security

- ADRs 0020-0024: environment audit, Landlock network, netproxy, secret server,
  env-stripping at launch

## v0.1.1 — 2026-06-15

Plugin MCP discovery, log rotation, and brew telemetry fix.

### Added

- MCP plugin discovery — `agentjail install` now auto-whitelists Claude Code
  plugin MCP servers from `~/.claude/plugins/`
- Built-in log rotation — daemon manages its own log (10 MB, 5 backups) instead
  of relying on launchd `StandardErrorPath`

### Fixed

- Brew install telemetry — formula now sets `AGENTJAIL_INSTALL_METHOD=brew`

## v0.1.0 — 2026-06-02

First public release. Hook-based policy guardrails evaluate every coding-agent
tool call locally — before it runs — across Claude Code, Codex, and Cursor. One
install discovers and wires every supported agent on the machine, backed by a
local OPA/Rego policy daemon, an OS-native sandbox, and a styled terminal UI.

### Added

- **Multi-agent support** — `internal/agents` registry with per-agent hook wiring;
  Claude Code path plus an `agentjail-hook --agent=cursor` adapter, with structured
  fail-open markers
- **Agent auto-discovery** — install detects and wires every supported agent on the
  machine, including inside the `curl | sh` one-liner; an interactive multi-select
  picker (over `/dev/tty`) chooses which agents to protect when several are present
- **`agentjail-hook`** — stdin/stdout bridge to the daemon; reads PreToolUse JSON,
  dials the per-session Unix socket (30 ms timeout), translates `allow/deny/ask` →
  exit code; fails-open when the daemon is absent
- **`agentjail-daemon`** — long-running OPA evaluator on a Unix socket; SIGHUP
  hot-reload; LRU cache with a static/dynamic split; p95 < 5 ms warm. Projects the
  loaded `policy.yaml` into OPA as `data.agentjail.config` (merged over defaults),
  canonicalizes request paths + `cwd`, and keeps the last-good policy on failure
- **`agentjail install` / `status` / `uninstall` / `version` / `help`** — install
  copies binaries, writes the launchd plist, and merges the PreToolUse hook entry
  idempotently; `~/.agentjail/bin` is added to PATH automatically
- **Policy packs** — `file_policy.rego` (sensitive-path denies: `~/.ssh`, `~/.aws`,
  `~/.gnupg`, `.env`, `*.pem`/`*.key`/`*.p12`, …; allow for the project CWD;
  default-ask for unknown), `command_policy.rego` (dangerous-shell guards:
  `curl|bash`, `sudo`, `rm -rf`, `git push --force`, `dd if=/dev/`, …), and
  `mcp_policy.rego` (server allowlist + per-tool gating)
- **`agentjail policy list/enable/disable`** plus a **user-tunable surface** —
  `agentjail policy add/remove` custom rules with an audit log of every change, and a
  locked self-protection set the agent can't disable
- **6 opt-in hardening library rules** (`agentjail policy enable <name>`):
  `no-shell-init-write`, `no-hook-self-disable`, `no-app-binary-write`,
  `no-launchctl`, `no-history-read`, `no-shell-eval`
- **`agentjail mcp allow/block/list`** + **trust-on-install** — discovers the MCP
  servers already configured in Claude (`~/.claude.json`), Codex
  (`~/.codex/config.toml`), and Cursor (`~/.cursor/mcp.json`) and seeds the allowlist
  so an existing setup keeps working instead of being denied on first run; each
  mutation hot-reloads the daemon
- **`agentjail-shield`** — OS-native sandbox wrapping the agent in `sandbox-exec`
  (macOS) or Landlock (Linux) for kernel-level file-access enforcement; fails-open
  when `sandbox-exec` is absent
- **`agentjail-netproxy`** — localhost HTTPS forward proxy enforcing
  `network.allowed_hosts` via CONNECT; wildcard matching; SIGHUP reload; stdlib only
- **`agentjail try`** — hands-on, live policy-evaluation walkthrough
- **`agentjail logs`** — color-coded real-time decision stream; follow mode; filters
  by action/tool/since; latency and impact display
- **Styled terminal UI** — `internal/ui` Lip Gloss layer across install, status,
  uninstall, version, help, and `agentjail logs`; palette matches the agentjail.io site
- **Resolver pattern** — `resolver.rego` defines the single complete `decision` rule
  and picks the most-restrictive `candidate` (deny > ask > allow); default-ask when no
  candidate fires, eliminating rule-conflict errors
- **`PolicyConfig`** — `~/.agentjail/policy.yaml` schema with `mcp`, `file`,
  `command`, and `network` sections; validated on startup; SIGHUP hot-reload
- **Samples + harness** — 5 example policies and 3 example configs (all
  dogfood-tested), and a hook → daemon → policy e2e smoke harness with latency in CI
- **Anonymous telemetry** — opt-out usage statistics (OS/arch, version, CLI command
  counts, aggregated decision/perf rollups with enum rule IDs) to guide what we
  improve. No paths, commands, repo names, or policy contents are ever sent; data is
  tied to a random ID. Off in CI; disable with `agentjail telemetry disable` or
  `AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS=false`. `agentjail telemetry view` shows
  exactly what's queued. Full data contract in `docs/TELEMETRY.md`

### Security

- **Always-on `no-daemon-kill` and `no-hook-self-disable` core rules** — an agent
  cannot kill the policy daemon or disable its own hook to escape enforcement
- **Credential-store read denies** — reads of `~/.npmrc`, `~/.pypirc`,
  `~/.git-credentials`, `~/.docker/config.json`, `~/.kube/config`,
  `~/.cargo/credentials`, and keychains are denied (home-anchored, so project-local
  copies stay allowed); mirrored into `agentjail-shield`
- **`confirm-publish` guard** — `npm`/`yarn`/`pnpm publish`, `gem push`,
  `poetry publish`, `docker push`, and `gh release create` prompt before running
- **Identity bound in the parent process** before the agent forks
  (`principal.id`/`agent`/`user`/`cwd_repo`/`enforce`), preventing child-process
  identity spoofing

### Known limitations (planned for v0.2.0)

- Credential broker not yet integrated — ADR 0004 sketches the design
- MCP reverse proxy is design-only — ADR 0003
- Linux network-egress control requires eBPF / Landlock's network ABI (Linux 6.7+)
- microVM isolation — libkrun + Firecracker integration are spike-complete but not
  yet wired into the `agentjail-shield` dispatch path

### License

Apache-2.0.
