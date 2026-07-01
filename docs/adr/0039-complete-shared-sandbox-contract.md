# ADR 0039: Complete the shared sandbox contract -- darwin/linux parity

- **Status:** Accepted
- **Date:** 2026-07-01
- **Deciders:** agentjail-core
- **Related:** [ADR 0001](0001-os-sandbox-enforcement-layer.md) (OS sandbox
  enforcement layer), [ADR 0025](0025-layered-self-protection.md) (env
  stripping), [ADR 0034](0034-platform-backend-shared-contract.md) (platform
  backends share a canonical contract), [ADR 0035](0035-domain-driven-interface-first-typesafe.md)
  (domain-driven, interface-first, type-safe), [ADR 0037](0037-macos-keychain-access-shielded-agent.md)
  (macOS keychain access), [ADR 0038](0038-essential-vs-extended-allowed-hosts.md)
  (essential vs. extended allowed hosts)

## Context

ADR 0034 established that `agentjail-shield`'s macOS (`shield_darwin.go`) and
Linux (`shield_linux.go`) backends must consume a single, OS-agnostic
contract rather than each hardcoding its own copy of "what the agent needs."
An audit of the shield against that contract found four places where the two
backends had drifted, one of them a security regression:

1. **darwin env leak (security).** `shield_darwin.go`'s `runShield` and
   `execAgent` called `sandbox.StripEnv(os.Environ(), cfg)` directly.
   `StripEnv` is a *denylist* -- it only removes variable names matching
   `secrets.env_blocklist`. Every other host environment variable, including
   any ad-hoc, non-blocklisted secret a user had exported in their shell
   (`export MY_SECRET=...`), passed straight through into the sandboxed
   agent. Linux (`shield_linux.go`) called `sandbox.BuildCleanEnv` (an
   *allowlist*, the primary defence) FIRST, then `StripEnv` as a
   defence-in-depth second layer -- darwin never adopted that ordering.
2. **darwin OAuth TCP bind gap (functional).** darwin's sbpl profile allowed
   only `(local udp "*:*")` bind/inbound. MCP OAuth callback flows (and
   local IPC such as the claude-mem worker) need to bind a local TCP port to
   receive the OAuth redirect; darwin denied all such binds outright,
   forcing every new OAuth flow to run unshielded even though Linux already
   granted per-port TCP bind for resolved OAuth callback ports.
3. **darwin missing known_hosts carve-out (functional).** darwin's
   `~/.ssh` subpath deny (write AND read) covers the whole directory tree,
   including `known_hosts`, which the agent legitimately needs to read for
   SSH host-key verification. Linux already granted this file (albeit
   read-write, via `AgentPaths.HomeFilesRW`) -- darwin granted nothing.
4. **Duplicated pattern/port lists + faked non-parity.** The sensitive
   filename/extension regex list (`.env`, `id_rsa`, `.pem`, etc.) was a
   literal list embedded in `shield_darwin.go`
   (`sensitiveWriteRegexes`/`sensitiveReadRegexes`) with no Linux
   counterpart at all -- not because Linux was exempt, but because nothing
   ever asserted the two stayed in sync or documented why Linux differs.
   Similarly, `--no-netproxy` on Linux left Landlock's network access rights
   completely unhandled (silently "unrestricted"), while darwin's
   `--no-netproxy` restricted TCP to ports 80/443. Both the SANDBOX.md docs
   and `cmd/agentjail-shield/README.md` also contained a stale claim --
   "Linux: Landlock has no network ABI" -- left over from before ADR 0021
   added Landlock ABI v4+ network rules (that ADR fixed the comment in
   `shield_linux.go` but not the docs).

## Decision

**Complete the shared contract from ADR 0034 with the capabilities the audit
found missing, as domain-shaped typed Go (ADR 0035) -- not a bag of
strings -- in a new tag-free file, `cmd/agentjail-shield/shield_contract.go`.**

### The contract

```go
type AccessMode int                    // ReadOnly | ReadWrite
type PathGrant struct {                // PerFile => literal, else subpath
    Path string; Mode AccessMode; PerFile bool
}
type PatternDeny struct {              // filename/extension regex
    Regex string; Read, Write bool
}
type UnsupportedReason string          // named, precise non-parity reason
type CapabilityKey string              // e.g. "filename-pattern-deny"
type BackendCapability struct {        // per-backend claim
    Backend string
    Unsupported map[CapabilityKey]UnsupportedReason
}

func SensitiveFilePatterns() []PatternDeny   // moved from shield_darwin.go
func NoNetproxyFallbackPorts() []int         // {80, 443}
func PerFileGrants() []PathGrant             // known_hosts: ReadOnly, PerFile
func KnownHostsGrant() PathGrant
func resolveOAuthCallbackPorts(path string) []int  // relocated, shared
func resolveMCPServerPaths(path string) []string   // relocated, shared
```

`resolveOAuthCallbackPorts` and `resolveMCPServerPaths` were previously
Linux-only (`shield_linux.go`); they are moved (not duplicated) into the
tag-free contract file so darwin can use the same OAuth-port resolution for
FIX 2 below.

### FIX 1 -- darwin env: allowlist before denylist (security)

darwin now calls a shared `buildBaseEnv(hostEnv, cfg)` helper --
`sandbox.BuildCleanEnv` then `sandbox.StripEnv`, in that order -- at every
site that used to call `StripEnv` alone, matching Linux exactly. The
existing `EnvAllowlistBaseline` is unchanged: no bulk `__CF_*`/`XPC_*`/
`HOMEBREW_*`/`SSH_AUTH_SOCK` additions. `SSH_AUTH_SOCK` in particular is
credential-bearing (an ssh-agent socket grants signing capability) and stays
out of the baseline; a user who needs it opts in via
`secrets.env_passthrough`.

### FIX 2 -- darwin OAuth callback TCP bind (Approach A, shipped)

For each port `resolveOAuthCallbackPorts` resolves from
`~/.claude/.credentials.json`, the sbpl profile now emits both
`(allow network-bind (local tcp "*:<port>"))` and
`(allow network-inbound (local tcp "*:<port>"))`.

**`(local tcp "*:<port>")` binds ANY interface, not loopback-only** -- this
must never be described as loopback-scoped in code or docs. Approach B
(a loopback-scoped bind) was attempted with a real `sandbox-exec`
integration test
(`TestDarwinLoopbackScopedBindForm_NotEnforced`,
`TestDarwinLiteralIPBindForm_RejectedBySandboxExec`) using a tiny bind-probe
helper (`cmd/agentjail-shield/test/bindprobe`):

- `(local ip "127.0.0.1:*")` is rejected outright by sandbox-exec's parser
  ("host must be `*` or `localhost` in network address").
- `(local tcp "localhost:*")` parses, but was measured to allow a bind to
  BOTH `127.0.0.1:0` and `0.0.0.0:0` -- it is not loopback-scoped.

No sbpl form was found that restricts a bind/inbound rule to loopback only.
Per the plan's decision rule, Approach A ships; the gap is named
(`CapLoopbackScopedBind`) rather than faked as loopback-only.

Same practical limitation as Linux already had: a brand-new MCP connector's
FIRST OAuth flow may pick an ephemeral port not yet in
`.credentials.json`, so that first auth may need one unshielded run.

### FIX 3 -- darwin per-file read carve-out for `known_hosts`

`PerFileGrants()` contains one entry today: `.ssh/known_hosts`, `ReadOnly`,
`PerFile: true`. darwin emits `(allow file-read* (literal
"<home>/.ssh/known_hosts"))` for every `ReadOnly` `PerFile` grant, placed
AFTER the `~/.ssh` subpath deny (sbpl is last-match-wins, the same pattern
already used for the system trust-store carve-outs). No `file-write*`
carve-out is emitted: host-key VERIFICATION only reads `known_hosts`; ADDING
a new host key writes via temp-file+rename, which needs `~/.ssh` directory
write -- deliberately not granted. Verified with a real `sandbox-exec`
enforcement test against a fake `$HOME`
(`TestSandboxEnforcesKnownHostsReadOnly`): reading `known_hosts` succeeds,
reading `id_rsa` fails (EPERM), and creating a new file under `~/.ssh` fails.

`AgentPaths.HomeRO`/`Runtimes` are also referenced in the darwin profile
generator now, but only to guard against future drift -- they are no-ops
today because the darwin base policy is `(allow default)`. This is
documented in a code comment; it must not be read as "darwin enforces
HomeRO the way Linux's allowlist does."

### FIX 4 -- contract sourcing, honest non-parity, capability test

- `sensitiveWriteRegexes()`/`sensitiveReadRegexes()` in `shield_darwin.go`
  now filter `SensitiveFilePatterns()` by `Write`/`Read` instead of holding
  a duplicated literal list.
- `NoNetproxyFallbackPorts()` is the single source for the `--no-netproxy`
  fallback ports on both platforms.
- **Linux `--no-netproxy` is no longer silently unrestricted.** A new pure
  function, `buildLandlockNetPlan(abi, netproxyPort, oauthPorts)
  LandlockNetPlan`, decides Landlock's network rules as data, with zero
  `landlock_*` syscalls:
  - netproxy enabled (`netproxyPort > 0`) + ABI v4+: CONNECT restricted to
    the netproxy port only; BIND restricted to the resolved OAuth ports
    (unchanged behavior, now expressed as a plan).
  - `--no-netproxy` (`netproxyPort <= 0`) + ABI v4+: CONNECT restricted to
    `NoNetproxyFallbackPorts()` (80, 443); BIND is deliberately left
    *unhandled* (not merely empty) -- handling `NET_BIND_TCP` with an empty
    allowlist would deny every bind, including a dynamic OAuth callback
    port not yet known to Landlock. Leaving it unhandled means bind follows
    ordinary DAC permissions, same practical posture Linux had before this
    ADR for the connect side.
  - ABI < 4 (kernel < 6.7): nothing handled -- unchanged FS-only behavior.

  `applyLandlock` calls `buildLandlockNetPlan` before ruleset creation and
  applies the resulting `ConnectPorts`/`BindPorts`. `applyLandlock`'s call
  signature (`cfg *config.PolicyConfig, netproxyPort int`) is unchanged, so
  every existing caller and test keeps working.

- **`LandlockNetPlan.Unsupported` names, precisely, what Landlock cannot do
  on ANY kernel version:**
  - `CapFilenamePatternDeny`: `"landlock-has-no-filename-regex; enforced by
    hook layer (agentpolicy/policies/file_policy.rego)"`. Landlock has no
    basename/extension primitive; filename-based denial (`.env`, `id_rsa`,
    etc.) is enforced at the hook layer on Linux, not the kernel sandbox.
  - `CapLoopbackScopedBind`: `"landlock net rules ... are port-scoped only;
    there is no per-interface/address restriction"`. This mirrors darwin's
    Approach-A gap -- neither backend can scope a bind/inbound rule to
    loopback only.
- **Capability/parity test** (`shield_contract_test.go`,
  `shield_darwin_fixes_test.go`, `shield_linux_netplan_test.go`): darwin's
  generated profile is asserted to render every `SensitiveFilePatterns()`
  entry, every `ReadOnly` `PerFile` grant literal, and exactly
  `NoNetproxyFallbackPorts()`; `darwinCapabilities()` is asserted to name
  `CapLoopbackScopedBind` (and NOT `CapFilenamePatternDeny`, since darwin
  fully honors it). Linux's `buildLandlockNetPlan` is asserted to honor path
  grants and fallback CONNECT ports it can, and to always name both
  `Unsupported` reasons. No contract capability is silently dropped by
  either backend.

## Consequences

- **Security fix shipped:** an arbitrary, non-blocklisted secret exported in
  a user's shell no longer reaches the sandboxed agent on macOS
  (`TestBuildBaseEnv_NonBlocklistedSecretDoesNotSurvive`).
- **MCP OAuth / local IPC works under the darwin sandbox** without falling
  back to an unshielded run for already-known callback ports.
- **`known_hosts` is readable under the darwin sandbox**, closing a
  regression that silently broke SSH host-key verification for any
  sandboxed git/ssh operation.
- **Linux `--no-netproxy` is measurably tighter**, restricting egress to
  80/443 on ABI v4+ kernels instead of leaving Landlock's network rights
  completely unhandled.
- **Non-parity is honest, not faked.** Landlock cannot enforce filename
  regexes or loopback-scoped binds; darwin's Approach-A bind is not
  loopback-scoped either. Both gaps are named `UnsupportedReason` values,
  covered by tests that would fail if a future change silently regressed
  the claim (e.g. someone marking `CapLoopbackScopedBind` as honored without
  proof).
- **Docs corrected:** `docs/SANDBOX.md`,
  `cmd/agentjail-shield/README.md`, and `AGENTS.md` (via this ADR) drop the
  stale "Linux: Landlock has no network ABI" / "`--no-netproxy` =
  unrestricted" claims; both were wrong once ADR 0021 shipped Landlock ABI
  v4+ network rules, and doubly wrong now that `--no-netproxy` restricts to
  the fallback ports.
- **No new dependencies.** All four fixes are pure Go/stdlib plus the
  existing `golang.org/x/sys/unix` Landlock bindings.
