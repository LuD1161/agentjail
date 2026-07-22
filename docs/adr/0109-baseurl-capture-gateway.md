# ADR 0109: base-URL capture gateway for LLM provider traffic

Status: Accepted

## Context

On macOS, the transparent tunnel MITM captures every `api.anthropic.com` request
from Claude Code EXCEPT the inference call `POST /v1/messages`, which fails with
`UNKNOWN_CERTIFICATE_VERIFICATION_ERROR` (AGE-259).

Root cause, proven on a Tart VM and the real host across npm+native runtimes and
versions 2.1.197/2.1.216: current Claude Code is a compiled **Bun** binary whose
**inference client (undici dispatcher) uses a bundled-only CA list** and ignores
every trust/verify lever - `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, login AND System
keychain, `CLAUDE_CODE_CERT_STORE`, `BUN_CA_BUNDLE`, `NODE_USE_SYSTEM_CA`, h1-only
ALPN, and even `NODE_TLS_REJECT_UNAUTHORIZED=0`. There is no Node-JS claude to
patch (the npm package spawns the same Mach-O), and BoringSSL is statically linked,
so neither trust delivery nor process injection is viable. Transparent MITM
therefore cannot capture `/v1/messages` on current Claude Code and, worse, BREAKS
inference. A per-host passthrough would un-break the agent but yields only SNI/byte
visibility, not the decrypted body.

## Decision

Do not fight the agent's TLS trust. Route the agent's LLM API traffic through a
local **capture gateway** using the provider's supported base-URL override
(`ANTHROPIC_BASE_URL` for Claude Code). The shield injects
`ANTHROPIC_BASE_URL=http://127.0.0.1:<port>/<nonce>` on the agent child; the agent
sends `/v1/messages` to the gateway in plaintext; the gateway records the full
request+response and forwards to the real upstream over TLS. Proven: full 334 KB
body + SSE stream captured with the native Bun binary, agent unaffected.

Design (Codex-approved, 3 rounds):

- **Provider registry** (`internal/gateway`), capability flags not a class enum
  (`base_url_env`, `config_file`, `tunnel_only`, `supports_oauth`,
  `supports_path_prefix`, `verified`). Phase 1 registers Claude Code (verified).
  Codex (`OPENAI_BASE_URL`) and Gemini (`GOOGLE_GEMINI_BASE_URL`) are inert
  data-only entries. Cursor is proprietary-backend -> tunnel-only, not registered.
- **Capability nonce.** Bind `127.0.0.1:0`; the injected base URL carries an
  unguessable nonce path prefix; requests without it are rejected. The nonce is a
  secret: never logged, persisted, audited, or surfaced in errors.
- **Interpose, don't clobber.** A user-set base URL is read, validated (scheme
  http/https, non-empty host, no credentials-in-URL, not our own loopback), stashed
  as `AGENTJAIL_ORIGINAL_<VAR>`, and used as the forward target with its path prefix
  preserved. Otherwise the provider default is used.
- **Egress guard.** The gateway's outbound is parent-owned, so it bypasses the
  child tunnel by construction (no host exclusion, no double-MITM). The resolved
  forward-target host must be the provider default or in the network allowlist,
  else it is refused - a user base URL cannot exfiltrate around policy.
- **Fail-closed.** For a detected, registered provider with the gateway enabled,
  failure to bind/start/open the store REFUSES launch and emits
  `gateway.start_failed`. Opt out with `network.capture_gateway: false` or
  `--no-provider-gateway`. No silent degradation.
- **Reuse, not reinvent.** Recording uses `internal/mitm` `RequestLog` +
  `RequestStore` + the shared encrypted body writer (ADR 0092). The gateway builds
  a `netpolicy.Operation` via the existing recognizers (`recognize_llm.go`) so the
  same protocol-aware YAML packs (AGE-81) apply; Phase 1 records only, netpolicy
  enforcement is a one-line insertion afterward.
- **Supersede the delegation experiment.** The uncommitted
  `NODE_TLS_REJECT_UNAUTHORIZED=0` "TLS delegation" is removed; it weakens TLS for
  no benefit (the Bun inference client ignores it too).

Phase 1 scope: the `--tunnel` (spawn) darwin path, Claude Code, record-only. The
non-tunnel `syscall.Exec` paths cannot host an in-process gateway and are
explicitly inert in Phase 1 (Phase 2 converts them to spawn-and-wait). Codex/Gemini
entries, netpolicy enforcement, and Linux parity are Phase 2+.

Phase 2 decouples the gateway from `--tunnel` entirely:

- **Two run modes, one contract.** The capture gateway runs whenever a
  registered provider agent is detected AND the gateway is enabled, in both
  plain (no `--tunnel`) and tunnel modes. It is independent of the MITM/tunnel
  - it does not require the macOS system extension. In plain mode it is the
  sole capture path for LLM provider traffic; the tunnel MITM, when present,
  captures other hosts and reuses the same `RequestStore`. This is what lets
  the CLI-only build capture `/v1/messages` before the desktop-app system
  extension ships.
- **Gateway decoupled from MITM.** Previously the gateway was nested inside
  the tunnel's MITM-setup success branch, so `--no-mitm` or a MITM CA-setup
  failure silently skipped gateway capture. Now the capture store
  (`RequestStore` + encrypted body recorder) is created once, when a provider
  is detected and the gateway is enabled, and the gateway runs off it
  regardless of MITM state.
- **Fail-closed uniformly.** For a detected provider with the gateway
  enabled, failure to start the gateway/store refuses launch (emits
  `gateway.start_failed`) in both plain and tunnel modes, matching the
  Phase 1 tunnel-only behavior. The only way to run uncaptured is the
  explicit opt-out `--no-provider-gateway` / `network.capture_gateway: false`.
- **Process model.** In plain mode, the darwin non-tunnel path (and the
  sandbox-exec-absent fail-open path) changes from `syscall.Exec` (process
  replacement) to spawn-and-wait, so the in-process gateway survives past
  launch; exit-code and signal parity with the old `syscall.Exec` behavior are
  preserved (ordinary exit -> child code; signal death -> 128+signal). The
  no-provider / gateway-disabled path is unchanged and still uses
  `syscall.Exec`.

## Consequences

- `/v1/messages` is fully captured (headers + body + streamed response) on current
  Claude Code, and inference is un-broken - both regressions from AGE-259 resolved
  without any dependency on Anthropic fixing the undici dispatcher.
- The OAuth token transits a loopback plaintext hop; it is gated by the nonce
  capability, never leaves the host in clear (re-TLS'd outbound), and is redacted
  everywhere per ADR 0032/0084.
- Two capture planes now exist: the base-URL gateway for redirectable LLM providers
  and the tunnel MITM for everything else (MCP, telemetry, Postgres/k8s/AWS). Both
  feed the same `internal/netpolicy` engine, so packs apply uniformly.
- New surface to maintain: a per-provider base-URL contract. Providers that route
  through a proprietary backend (Cursor) or need a config file rather than an env
  var (opencode, aider) are out of the Phase 1 env-var path.
- Capture no longer implies `--tunnel`: a plain-shield run (no system
  extension, no MITM) still captures registered-provider LLM traffic, closing
  the gap where CLI-only installs had zero visibility until the desktop app's
  tunnel shipped.
- The loopback plaintext hop, nonce gate, no-log/no-persist/no-surface
  handling, and ADR 0032/0084 redaction are unchanged in Phase 2 and now
  apply uniformly in both run modes. macOS Seatbelt already permits loopback
  traffic, so plain mode requires no sandbox-profile broadening - verified by
  test rather than by inspection alone.
- The non-tunnel darwin path's move from `syscall.Exec` to spawn-and-wait is a
  process-model change confined to the provider-detected-and-enabled case; it
  adds a wait/signal-relay layer to a path that previously replaced itself,
  so exit/signal-parity regressions are the main risk to watch for there.
