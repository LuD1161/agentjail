# Plan 010: DDD Domain Services — Full Codebase Extraction

## Problem

The daemon's `server` struct is a 1600-line God object with 6+ domain responsibilities. CLI commands duplicate domain logic (12 copy-pasted two-phase audit ceremonies, 20+ sites opening their own store connections). Shield and secrets server have domain logic embedded in `cmd/` with no `internal/` packages.

## Extraction Targets

### Current state: domain logic lives in `cmd/`

| Location | Domain logic | Lines | Issues |
|----------|-------------|-------|--------|
| `cmd/agentjail-daemon/main.go` | Policy eval/reload, session tracking, hook watch, lifecycle, store writes, telemetry, AWS resolution, path normalization | ~1600 | God object, untestable |
| `cmd/agentjail/mcp.go` | MCP allow/block (6 functions copy-pasting same audit ceremony) | ~1200 | 6x duplicated store.Open + two-phase audit |
| `cmd/agentjail/skill.go` | Skill allow/block/ask/clear (4 functions copy-pasting) | ~450 | 4x duplicated ceremony |
| `cmd/agentjail/policy.go` | Rule enable/disable + double store open | ~830 | Opens store TWICE per mutation |
| `cmd/agentjail/custom_rules.go` | Custom rule add/remove | ~400 | No audit at all |
| `cmd/agentjail/secret.go` | Secret set/remove | ~230 | No audit, calls config.Save |
| `cmd/agentjail/install.go` | Install/uninstall, daemon bootstrap, policy creation | ~1400 | config.Save with no audit |
| `cmd/agentjail/ui/server.go` | Policy enable/disable/config.Save (duplicates CLI) | ~1200 | Duplicates policy.go, no audit |
| `cmd/agentjail-shield/` | Sandbox profiles, env construction, audit checks | ~2000 | No internal/ package |
| `cmd/agentjail-secrets/` | Grant manager, credential backends (AWS/PG/Redis) | ~1400 | No internal/ package |

### Target state: `internal/` domain services

| Package | Interface | Owns | Audit |
|---------|-----------|------|-------|
| `internal/policyctl/` | `PolicyController` | load, save, enable/disable, mcp allow/block, skill mutations, config.Save + two-phase audit + SIGHUP | All policy.* events, eliminates 12x duplication |
| `internal/policyeval/` | `Evaluator` | OPA compile, eval, cache, per-project engine, path normalization | Decision recording |
| `internal/sandbox/` | `SandboxService` | Landlock/Seatbelt profile generation, sensitive path lists, env construction | shield.* events |
| `internal/envaudit/` | `EnvironmentAuditor` | Pre-launch checks (root, ambient creds, IMDS) | shield.audit_finding events |
| `internal/credentials/` | `CredentialService` | Grant manager, backend dispatch (AWS/PG/Redis), secret store | credential.* events |
| `internal/hookwatch/` | `HookWatcher` | Config monitoring, tamper detection, reinject | hook.* events |

## Phases

### Phase 1: PolicyController (highest impact — kills 12x duplication)

**What to extract:**

Create `internal/policyctl/policyctl.go`:

```go
package policyctl

type Controller interface {
    MCPAllow(ctx context.Context, server string) error
    MCPBlock(ctx context.Context, server string) error
    MCPToolAllow(ctx context.Context, server, tool string) error
    MCPToolBlock(ctx context.Context, server, tool string) error
    MCPToolAsk(ctx context.Context, server, tool string) error
    MCPToolClear(ctx context.Context, server, tool string) error
    SkillAllow(ctx context.Context, skill string) error
    SkillBlock(ctx context.Context, skill string) error
    SkillAsk(ctx context.Context, skill string) error
    SkillClear(ctx context.Context, skill string) error
    EnableRule(ctx context.Context, ruleID string) error
    DisableRule(ctx context.Context, ruleID string, force bool) error
    AddCustomRule(ctx context.Context, path string) error
    RemoveCustomRule(ctx context.Context, name string) error
}
```

Implementation holds `emitter audit.Emitter`, `policyPath string`, and encapsulates the entire ceremony: load config → two-phase audit → config.Save → SIGHUP.

**Files to change:**
- Create: `internal/policyctl/policyctl.go`, `internal/policyctl/policyctl_test.go`
- Simplify: `cmd/agentjail/mcp.go` (6 mutation functions become ~5 lines each)
- Simplify: `cmd/agentjail/skill.go` (4 mutation functions become ~5 lines each)
- Simplify: `cmd/agentjail/policy.go` (enable/disable become ~5 lines each)
- Simplify: `cmd/agentjail/custom_rules.go` (add/remove get audit for free)
- Simplify: `cmd/agentjail/secret.go` (set/remove get audit for free)
- Simplify: `cmd/agentjail/ui/server.go` (handlers delegate to Controller)
- Remove: `cmd/agentjail/audit.go` (appendAuditEvent + emitPolicyAudit absorbed by Controller)

**What it fixes:**
- Kills 12x copy-pasted ceremony (20+ store.Open sites → 1)
- Adds missing audit to: custom_rules add/remove, secret set/remove, install writeDefaultPolicy
- Eliminates double store open in policy enable/disable
- Unifies CLI and UI server policy mutations

**Verification:**
- All existing tests pass
- New: `TestController_MCPAllow_EmitsTwoPhaseAudit`
- New: `TestController_DisableRule_AbortsOnAuditFailure`
- New: `TestController_CustomRuleAdd_EmitsAudit` (was missing)
- New: `TestController_SecretSet_EmitsAudit` (was missing)
- grep for `emitPolicyAudit\|appendAuditEvent` — should be 0 occurrences outside policyctl

### Phase 2: Evaluator (extract policy eval from daemon)

**What to extract:**

Create `internal/policyeval/evaluator.go`:

```go
package policyeval

type Evaluator interface {
    Eval(ctx context.Context, req wire.Request) (wire.Response, error)
    Reload(ctx context.Context, modules [][2]string, cfg *config.PolicyConfig) error
    InvalidateProjectCache(repoRoot string)
}
```

Implementation holds the OPA engine, LRU cache, per-project engine map, repo root cache, AWS profile resolution, and path normalization. All the `eval`-related methods from the God object.

**Files to change:**
- Create: `internal/policyeval/evaluator.go`, `internal/policyeval/normalize.go`, `internal/policyeval/aws.go`
- Simplify: `cmd/agentjail-daemon/main.go` (server.eval → evaluator.Eval, server.reload → evaluator.Reload)

**What it fixes:**
- Testable eval logic without a full daemon
- ~500 lines extracted from main.go

### Phase 3: SandboxService + EnvironmentAuditor (extract shield domain)

**What to extract:**

Create `internal/sandbox/sandbox.go`:

```go
package sandbox

type Profile struct {
    AllowedReadPaths  []string
    AllowedWritePaths []string
    AllowedHosts      []string
    AllowedPorts      []int
    // ...
}

type Service interface {
    GenerateProfile(cfg *config.PolicyConfig) (*Profile, error)
    BuildCleanEnv(hostEnv []string, cfg *config.PolicyConfig) []string
}
```

Create `internal/envaudit/auditor.go`:

```go
package envaudit

type Auditor interface {
    Run(ctx context.Context) (*Result, error)
}
```

**Files to change:**
- Create: `internal/sandbox/sandbox.go`, `internal/sandbox/sandbox_linux.go`, `internal/sandbox/sandbox_darwin.go`
- Create: `internal/envaudit/auditor.go`, `internal/envaudit/checks.go`
- Simplify: `cmd/agentjail-shield/shield_linux.go` (profile generation → sandbox.Service)
- Simplify: `cmd/agentjail-shield/shield_darwin.go` (sbpl generation → sandbox.Service)
- Move: `cmd/agentjail-shield/audit.go` → `internal/envaudit/`
- Move: `cmd/agentjail-shield/envstrip.go` → `internal/sandbox/`

### Phase 4: CredentialService (extract secrets domain)

**What to extract:**

Create `internal/credentials/credentials.go`:

```go
package credentials

type Backend interface {
    Grant(ctx context.Context, cfg *Config, scope string, ttl time.Duration) (*Grant, error)
    Revoke(ctx context.Context, grant *Grant) error
}

type Service interface {
    Issue(ctx context.Context, name, scope string, ttl time.Duration) (*Grant, error)
    Revoke(ctx context.Context, grantID string) error
    RevokeAll(ctx context.Context) error
    Active() int
}
```

**Files to change:**
- Create: `internal/credentials/credentials.go`, `internal/credentials/aws.go`, `internal/credentials/postgres.go`, `internal/credentials/redis.go`
- Simplify: `cmd/agentjail-secrets/server.go` (handleGrant → service.Issue)
- Move: `cmd/agentjail-secrets/grant.go` → `internal/credentials/`

**What it fixes:**
- Adds missing audit for `secret stored` and `secret deleted` slog calls
- Testable credential issuance without the secrets server socket
- Backend interface enables adding new credential types

### Phase 5: HookWatcher (extract hookwatch domain)

**What to extract:**

Create `internal/hookwatch/watcher.go`:

```go
package hookwatch

type Watcher interface {
    Run(ctx context.Context) error
}
```

**Files to change:**
- Move: `cmd/agentjail-daemon/hookwatch.go` → `internal/hookwatch/watcher.go`
- Simplify: `cmd/agentjail-daemon/main.go` (hookwatch setup → hookwatch.New(emitter))

**What it fixes:**
- HookWatcher owns its audit events directly instead of via callback
- Testable tamper detection without a daemon

### Phase 6: Thin daemon router + final cleanup

**What to do:**
- Refactor `server` struct to compose services:

```go
type server struct {
    evaluator  policyeval.Evaluator
    policy     policyctl.Controller
    hooks      hookwatch.Watcher
    emitter    audit.Emitter
    store      store.EventStore
    telemetry  *telemetry.Recorder
    sessions   *activeTracker
    wg         sync.WaitGroup
}
```

- `handleConn` dispatches to `evaluator.Eval()`
- SIGHUP handler calls `evaluator.Reload()`
- Remove all direct `slog.Info` + `emitter.Emit` pairs from router layer
- Verify: grep for orphaned `emitter.Emit` calls outside service implementations — should be ≤5 (lifecycle events)

**Verification:**
- `go build ./... && go vet ./... && go test ./...` all green
- `wc -l cmd/agentjail-daemon/main.go` — target: <800 lines (down from ~1600)
- grep for `store.Open\b` outside `internal/store/` — target: 0 in mutation paths
- grep for `emitPolicyAudit\|appendAuditEvent` — target: 0

## Audit coverage gaps filled by this refactor

| Gap | Current state | After DDD |
|-----|--------------|-----------|
| Custom rule add/remove | No audit | Covered via PolicyController |
| Secret set/remove | No audit | Covered via PolicyController |
| Install writeDefaultPolicy | No audit | Covered via PolicyController |
| UI server config.Save | TODO comments | Covered via PolicyController |
| Secret stored/deleted | slog only | Covered via CredentialService |
| Grant revocation failed | slog only | Covered via CredentialService |
| Update checker auto-update | slog only | Best-effort emit in Evaluator/Lifecycle |
| Session lifecycle | No logging at all | Deferred (needs PID monitoring) |
