# ADRs 0028–0030: Jailed Execution Model

AgentJail runs coding agents inside a restricted workspace. The agent only
sees files you mount, only reaches hosts you allow, and only receives
credentials through AgentJail. Everything it does is logged. If the jail is
not active, execution is blocked.

Three architectural decisions:

1. **Jailed execution model** (0028) — what the agent can and cannot access.
2. **Verified activation and launch integration** (0029) — how AgentJail
   proves the process is jailed and how every launch path activates it.
3. **Backend guarantees** (0030) — what each enforcement backend provides,
   with an honest capability matrix.

---

# ADR 0028 — Jailed execution model

- **Status:** Proposed
- **Date:** 2026-06-29
- **Deciders:** agentjail-core
- **Related:** ADR 0001 (OS sandbox), ADR 0004 (credential broker), ADR 0029
  (activation), ADR 0030 (backend guarantees)

## Context

The current shield implementation (Tier 1.5) operates on a denylist model: the
agent sees the host filesystem, and we try to block `~/.aws`, `~/.ssh`, and
other sensitive paths. This is hard to reason about and creates an arms race
with bypass techniques — every new path pattern, encoding trick, or symlink
gadget requires a new rule.

The Rego policy layer (Tier 1) operates on command-string matching, which is
inherently bypassable:

```bash
F=~/.aws/credentials; cat $F
python3 -c "open(os.path.expanduser('~/.aws/credentials')).read()"
ln -s ~/.aws /tmp/x; cat /tmp/x/credentials
cat $'\x7e/.aws/credentials'
```

Both models share the same flaw: they start from "the agent can access
everything" and try to subtract dangerous things. The subtraction is always
incomplete.

## Decision

Invert the model. The jail is an allowlisted view. The agent starts with
nothing and receives only what is explicitly granted.

### What the agent gets

```
Workspace:    explicitly mounted project directory (read-write)
Runtime:      minimal set of required binaries and libraries
Secrets:      credentials provided through the AgentJail broker
              or an explicitly mounted session-specific .env file
Network:      access only through the AgentJail proxy
MCP:          approved servers and tools only
```

### What the agent does not get

```
Home directory:         unavailable
~/.aws, ~/.ssh, ~/.config, ~/.gnupg, ~/.docker, ~/.kube:
                        unavailable
Browser data, keychains, password stores:
                        unavailable
Files outside the mounted workspace:
                        unavailable
Host processes, /proc entries of other processes:
                        unavailable
Docker, Podman, containerd, SSH agent, GPG agent sockets:
                        unavailable
Unrestricted network:   unavailable
Anything not explicitly mounted or allowed:
                        unavailable
```

### Default posture

```
Workspace:       explicitly mounted
Credentials:     brokered or explicitly mounted
Network:         proxy only
Host filesystem: unavailable
Host processes:  unavailable
Host IPC:        unavailable
Everything:      logged
```

### Filesystem model

The jail presents an allowlisted filesystem view, not the host filesystem with
denied paths.

The jail contains only:

```
/workspace        → mounted project directory (read-write)
/runtime          → minimal binaries and libraries (read-only)
/secrets          → broker socket, optional .env (read-only)
/tmp              → session-scoped temporary directory
/dev/null, /dev/zero, /dev/urandom
```

The host filesystem is not visible. There is no `~/.aws` to protect because
there is no `~` — the home directory does not exist inside the jail. Symlink
attacks, path encoding tricks, and variable indirection are irrelevant because
the target paths do not exist.

How this is achieved depends on the backend (ADR 0030). On Linux with
namespaces, this is a mount namespace with explicit bind mounts. On macOS with
Seatbelt, this is approximated through sandbox profile rules (the host
filesystem exists but access is denied to everything outside the allowlist).
In a microVM, the guest filesystem is built from scratch.

### Credential model

Credentials follow a clear hierarchy, from most to least preferred:

**1. Capability proxy (preferred)**

The agent never sees the raw credential. It communicates with a local proxy
that holds the real token and forwards authenticated requests to the upstream
service. The agent receives an opaque session handle or connects through a
Unix socket.

```
Agent → broker socket → AgentJail proxy → AWS/GitHub/service
```

The proxy enforces:
- Which services the agent can reach
- Which operations are permitted (read-only S3, specific GitHub repos, etc.)
- Request-level logging
- Automatic credential rotation

**2. Short-lived scoped credential (good)**

The broker issues a credential that is:
- Narrowly scoped (minimum permissions for the task)
- Short-lived (expires after the session or sooner)
- Injected into the jail environment at launch
- Revoked when the session ends

**3. Session-specific .env file (compatibility)**

AgentJail generates a read-only `.env` file mounted into the jail at
`/secrets/.env`. The file contains only the minimum credentials required for
the session. The agent can read everything inside it.

This is an explicit secret grant. The user configures what goes into it:

```yaml
session:
  env_file:
    AWS_ACCESS_KEY_ID: from_broker
    GITHUB_TOKEN: from_broker
    DATABASE_URL: "postgres://..."
```

**4. Direct host secret mounting (avoid)**

Mounting the user's real `~/.aws`, `~/.ssh`, or `.env` into the jail. This
should be discouraged but available as an explicit override for environments
that require it:

```yaml
mounts:
  - source: ~/.aws/credentials
    target: /secrets/aws-credentials
    readonly: true
    warning: "Mounting host credentials directly. Prefer the credential broker."
```

AgentJail logs a warning whenever host secrets are mounted directly.

### Network model

The agent has no direct network access. All traffic goes through the AgentJail
proxy:

```
Agent → proxy socket → AgentJail netproxy → allowed destinations
```

The proxy enforces:
- `network.allowed_hosts` from `policy.yaml`
- Per-host, per-port, per-protocol rules
- TLS inspection for credential injection (capability proxy mode)
- DNS resolution (agent cannot resolve arbitrary hostnames)
- Logging of all network destinations and request metadata

IMDS (169.254.169.254) is unreachable because the agent has no direct network
interface. Cloud metadata endpoints are blocked by architecture, not by rule.

### MCP model

MCP servers are mediated through AgentJail's MCP gateway:

```yaml
mcp:
  allowed:
    - server: filesystem
      tools: [read, write, search]
      scope: /workspace
    - server: github
      tools: [create_pr, list_issues]
      credentials: from_broker
  denied_by_default: true
```

MCP calls to non-approved servers are blocked. The gateway logs every call
including tool name, input summary, and result status.

### Audit model

Everything is logged at the jail/session level:

| Category | What is logged |
|----------|---------------|
| Session | Agent identity, user identity, start/end time, jail backend, active protections |
| Workspace | Mounted directories, explicit mounts, mount permissions |
| Commands | Every shell command executed, with full argument list |
| Files | Files accessed or modified within the workspace |
| Network | Every destination reached through the proxy |
| MCP | Every MCP call: server, tool, input summary, result status |
| Credentials | Credentials issued, scope, expiration, revocation |
| Denials | Every denied action with reason |
| Policy | Policy decisions with rule references |
| Degradation | Whether any protection was degraded and why |

Logs are written to the session store (SQLite, already implemented) and are
available through `agentjail replay` and the local web UI.

### Explicit mounts

Users configure what enters the jail:

```yaml
jail:
  workspace: /home/user/projects/myapp    # mounted at /workspace
  mounts:
    - source: /home/user/.cargo/registry
      target: /runtime/cargo-registry
      readonly: true
    - source: /home/user/.npm
      target: /runtime/npm-cache
      readonly: true
  runtime:
    include: [node, python3, go, git, make, gcc]
```

Mounts are explicit. If the agent needs access to something, the user adds it
to the configuration. The default is empty — nothing from the host enters the
jail unless configured.

## Consequences

### Positive

- The security model is simple to explain and reason about: the agent sees
  only what you give it.
- Bypass techniques (path encoding, symlinks, variable indirection) are
  irrelevant — the target paths do not exist in the jail.
- Default-deny means new attack surfaces require no new rules. If it wasn't
  mounted, it's not there.
- Credential isolation is architectural, not policy-based.
- Network isolation is architectural, not rule-based.
- The audit log covers everything at the session level.

### Negative

- Requires explicit configuration of mounts and runtime dependencies. This is
  more setup than the current "install and go" experience.
- Some agent workflows require access to host tools, caches, or configuration
  that must be explicitly mounted. Missing mounts cause agent failures.
- The allowlisted filesystem model is straightforward in a microVM or
  namespace but can only be approximated on macOS with Seatbelt.
- Build caches, package registries, and language toolchains need mounting or
  the agent cannot compile/test.

### Graceful degradation

If AgentJail itself breaks, the user must be able to use claude normally.
AgentJail must never brick a development environment.

| Failure | Behavior |
|---------|----------|
| Jail fails to start | User gets a clear error. Can run `claude` directly (unjailed, no tool execution per ADR 0029). |
| Missing mount causes agent failure | Agent reports the error. User adds the mount and restarts. |
| Proxy crashes mid-session | Network calls fail. Agent reports errors. User restarts the session. |
| Broker unavailable | Credential injection fails at session start. Session does not launch. User can fall back to explicit .env. |

`agentjail uninstall` removes all hooks, wrappers, and shims. Claude returns
to its default state immediately.

### Follow-ups

1. Build a curated set of runtime profiles (Node.js, Python, Go, Rust) that
   pre-configure the right mounts and binaries for common stacks.
2. Implement `agentjail init` that detects the project type and generates a
   starter jail configuration.
3. Add `agentjail mount add <path>` for interactive mount management.

---

# ADR 0029 — Verified activation and launch integration

- **Status:** Proposed
- **Date:** 2026-06-29
- **Deciders:** agentjail-core
- **Related:** ADR 0028 (jailed execution model), ADR 0030 (backend
  guarantees), ADR 0025 (self-protection)

## Context

The jailed execution model (ADR 0028) defines what an agent can access. This
ADR answers two questions:

1. **How does AgentJail verify that the agent is actually running inside a
   jail?**
2. **How does every launch path activate the jail?**

The central behavior is:

```
No attested jail → no execution.
```

Chat, planning, and non-executing conversation remain available. But no tools
that touch the filesystem, execute processes, use credentials, or access the
network run outside the jail.

This is simpler than designing a rich "compatibility mode" for unjailed
sessions. The hook cannot safely reproduce filesystem or process isolation.
We should not pretend otherwise.

## Decision

### Part 1: Attestation

The daemon verifies that the calling process belongs to a real jailed session.
Attestation uses kernel-observed process identity, not forgeable environment
variables or shared secrets.

#### How it works

1. **agentjail-shield starts the jail.** It applies the backend-specific
   isolation (Landlock + namespaces, Seatbelt, or microVM), registers the
   session with the daemon, and launches the agent inside.

2. **The daemon records the session:**
   - Root process PID and start time
   - A `pidfd` (Linux 5.3+, obtained by the daemon via `pidfd_open`)
   - Session cgroup ID (where available)
   - Backend type and active capabilities
   - Policy bundle hash
   - Session nonce (for audit correlation)

3. **When the hook fires,** it connects to the daemon over a Unix socket. The
   daemon obtains the peer PID via `SO_PEERCRED` (Linux) or the platform
   equivalent (macOS). It verifies the caller is a descendant of a registered
   jail session, checking in priority order:
   - Session cgroup membership
   - pidfd validity
   - Process ancestry + start time

4. **The daemon returns a simple answer:**

```yaml
jailed: true
session_id: aj_7f13...
backend: landlock_namespaces
capabilities:
  filesystem: allowlist_enforced
  network: proxy_enforced
  process_isolation: namespace
  credentials: broker_active
```

Or:

```yaml
jailed: false
```

5. **If jailed, the hook evaluates normal policy** (Rego rules, MCP rules,
   etc.) within the jail's configured permissions.

6. **If not jailed, the hook blocks all execution capabilities:**

   | Capability | Unjailed behavior |
   |------------|-------------------|
   | Chat, planning, conversation | Allow |
   | File read/write | Deny |
   | Shell execution | Deny |
   | Interpreter execution | Deny |
   | Network tools | Deny |
   | MCP calls | Deny |
   | Credential broker | Deny |

   The deny message is actionable:

   ```
   This session is not running inside an AgentJail jail.
   All execution capabilities are blocked.

   Start a jailed session:
     Terminal:  agentjail claude
     VS Code:   agentjail install --for vscode
     Cursor:    agentjail install --for cursor

   Run `agentjail doctor` for setup help.
   ```

   There is no compatibility mode, no audit mode that silently allows
   unjailed execution, and no fallback to command-string matching. If the
   jail is not active, execution is blocked.

#### Registration protocol

agentjail-shield uses a two-pipe handshake to ensure the jail is fully
established before the agent can invoke tools:

```
parent shield process
  ├── control pipe: parent → child (release signal)
  └── status pipe:  child → parent (activation result)
```

Sequence:

```
parent forks child

child:
  creates namespaces (if applicable)
  configures mounts (if applicable)
  applies Landlock / Seatbelt
  sets PR_SET_NO_NEW_PRIVS
  closes non-allowlisted FDs
  writes structured activation result to status pipe
  blocks on control pipe

parent:
  reads and validates activation result
  registers session with daemon (authenticated endpoint)
  receives daemon acknowledgment
  releases child via control pipe

child:
  closes handshake FDs
  execves agent
```

The child exits if sandbox setup fails, status delivery fails, or the parent
dies unexpectedly (on Linux, `PR_SET_PDEATHSIG` ensures this).

#### Registration authentication

The daemon must authenticate who can register jail sessions. Otherwise a
same-UID process could register arbitrary PIDs as "jailed."

1. Shield requests a one-time launch capability from the daemon.
2. Daemon binds the capability to the shield's PID and start time (verified
   via `SO_PEERCRED`).
3. Shield forks, applies the jail, and registers the child using the
   capability.
4. Daemon validates the caller identity and consumes the capability
   (single-use).

`agentjail-shield` is a trusted attester. The daemon authenticates the
registration path; it cannot independently reconstruct every Landlock rule
from outside the process. For additional verification on Linux, the daemon can
inspect `/proc/<pid>/status` for `NoNewPrivs`, seccomp mode, and namespace
IDs.

#### Session lifecycle

```
CREATED → JAIL_APPLIED → REGISTERED → RUNNING → DRAINING → EXITED
```

- **RUNNING:** Attestation queries for descendants return `jailed: true`.
- **DRAINING:** Root process exited but descendants remain. Jail restrictions
  (Landlock, namespaces, seccomp) are inherited and remain active.
  Attestation continues to return `jailed: true` for descendants.
- **EXITED:** All processes in the session cgroup have exited (or drain
  timeout elapsed). Session is cleaned up.

Configurable background process policy:

```yaml
session:
  on_root_exit: kill_group | drain_timeout | track
```

#### Attestation caching

The daemon caches attestation results per (PID, start time) tuple. Cache
entries are invalidated when the session transitions to EXITED. The hook has
a timeout (default: 200ms) — if the daemon is unreachable, the hook treats
the session as unjailed and blocks execution.

### Part 2: Launch integration

Every supported launch path must enter the same jailed runtime. If a launch
integration fails, attestation fails and execution is blocked.

#### 1. Explicit launcher (primary path)

```
agentjail claude [args...]        # launch claude inside jail
agentjail run -- <command> [args...]  # generic: any agent
```

This is the recommended invocation. It ensures the daemon is running, applies
the jail, registers the session, and launches the agent.

#### 2. VS Code / Cursor wrapper

A compiled Go binary at `~/.agentjail/bin/agentjail-wrapper`. The VS Code
extension setting `claudeCode.claudeProcessWrapper` points to it. The wrapper
receives the real claude path and execs through agentjail-shield.

```
agentjail install --for vscode    # configures the wrapper
agentjail install --for cursor    # same mechanism, different settings path
```

The installer uses a JSONC-aware editor to preserve existing settings. If a
wrapper is already configured (e.g., a corporate auth wrapper), it offers
chaining rather than overwriting.

#### 3. PATH shim (opt-in)

```
agentjail install --with-path-shim
```

Places a `claude` shim at `~/.agentjail/bin/claude` that finds the real
claude binary (excluding its own directory) and execs through shield. Opt-in
because silently shadowing `claude` in the user's PATH is surprising.

#### 4. Remote environments

When the hook detects a remote context (SSH, dev container, Codespaces, WSL)
and the session is unjailed, the deny message includes context-specific
remediation:

- Remote SSH: "Install agentjail on the remote host."
- Dev container: "Add agentjail to your devcontainer.json."
- Codespaces: "Add agentjail to your dotfiles or devcontainer."
- WSL: "Install agentjail inside the WSL distribution."

#### 5. `agentjail install --all`

Sets up hooks, daemon, VS Code wrapper (if detected), Cursor wrapper (if
detected). PATH shim is NOT included — it requires `--with-path-shim`.

#### 6. `agentjail doctor`

Reports jail readiness:

```
$ agentjail doctor

Platform
  OS:             linux 6.1.0-44-amd64
  Backend:        landlock + namespaces
  Capabilities:   filesystem (allowlist), network (namespace+proxy),
                  process (pid namespace, seccomp), no_new_privs

Daemon
  Status:         running (pid 12345)

Launch Integration
  Hooks:          installed (claude-code)
  VS Code:        wrapper configured
  PATH shim:      not installed

Policy
  Path:           ~/.agentjail/policy.yaml
  Workspace:      /home/user/projects/myapp
  Mounts:         3 configured
  Network:        5 hosts allowed

Active Sessions
  aj_7f13:        jailed (pid 18231, landlock+ns)

Issues
  ! No Landlock network (kernel 6.1 < 6.7)
    → Network isolated via namespace (no direct egress)
```

#### Uncoverable launch paths

| Path | Mitigation |
|------|-----------|
| Claude desktop app | No wrapper mechanism. Unjailed → execution blocked. |
| JetBrains (unresearched) | Plugin interface unknown. Unjailed → execution blocked. |
| Absolute path / npx | Bypasses shim. Unjailed → execution blocked. |
| Agent launched via external service | Crosses process boundary. Unjailed → execution blocked. |

In every case, the fallback is the same: no attested jail means no execution.
There is no silent degradation to a weaker mode.

#### Graceful degradation

AgentJail must never prevent users from using claude. Every failure degrades
to "claude works, execution is blocked" rather than "claude is broken."

| Failure | Behavior |
|---------|----------|
| Daemon is down | Hook cannot attest. Execution blocked. Chat/planning work. User can run `claude` directly after `agentjail uninstall`. |
| Daemon hangs | Hook timeout (200ms). Treated as unjailed. Execution blocked. |
| Shield crashes | Clear error. User can run `claude` directly. |
| Wrapper crashes | VS Code falls through to direct launch. Unjailed → execution blocked. |
| PATH shim loop | Self-detection guard. Clear error. |
| Hook binary missing | Claude Code treats hook errors as allow (fail-open). Session runs with no agentjail — but also no false sense of protection. |

`agentjail uninstall` removes all hooks, wrappers, and shims. Claude returns
to its default state.

## Consequences

### Positive

- One rule: no jail, no execution. Simple to explain, implement, and audit.
- No complex compatibility/audit/strict mode matrix.
- No silent fallback to bypassable string matching.
- Launch integration failures are always visible (execution blocked, clear
  message).
- Attestation is a supporting mechanism, not the product architecture.

### Negative

- Users who cannot run the jail (unsupported platform, corporate restrictions)
  get a completely non-functional agent for tool use. This is an intentional
  trade-off — a tool that appears to protect but doesn't is worse than one
  that honestly says it can't.
- More restrictive than a graduated model. Users who want "some protection"
  must accept "full protection or none."

### Follow-ups

1. Investigate macOS peer PID retrieval across supported versions (pre-
   acceptance gate).
2. Implement the authenticated registration endpoint.
3. Define the canonical sandbox setup ordering across backends.

---

# ADR 0030 — Backend guarantees

- **Status:** Proposed
- **Date:** 2026-06-29
- **Deciders:** agentjail-core
- **Related:** ADR 0028 (jailed execution model), ADR 0029 (activation),
  ADR 0001 (OS sandbox), ADR 0016 (Tier 2 microsandbox)

## Context

The jailed execution model (ADR 0028) defines what the agent should and should
not access. This ADR defines what each enforcement backend actually provides,
with an honest capability matrix. Not all backends are equal — the model is
aspirational on some platforms and fully realized on others.

## Decision

### Backend capability matrix

| Capability | Linux (Landlock + NS + seccomp) | macOS (Seatbelt) | Tier 2 (microVM) |
|---|---|---|---|
| **Filesystem allowlist** | Strong. Mount namespace with explicit bind mounts. Agent cannot see unmounted paths. | Approximate. Seatbelt profile denies access outside allowlist, but host FS exists. Bypass difficulty: high (kernel enforcement) but not architecturally absent. | Complete. Guest filesystem built from scratch. Host FS does not exist. |
| **Network proxy-only** | Strong (kernel 6.7+, Landlock net). Good (kernel < 6.7, network namespace with no egress). | Approximate. Seatbelt restricts to localhost + proxy ports. Direct IP bypass possible on some configurations. | Complete. Guest has no network interface except virtio-net to proxy. |
| **Host process isolation** | Strong with PID namespace. Partial without (seccomp blocks ptrace, but /proc may be visible). | Partial. Seatbelt can restrict /proc-like access but process list is visible. | Complete. Separate process namespace. Host processes do not exist. |
| **Host IPC isolation** | Strong with network + mount namespace (removes abstract + filesystem sockets). Partial without namespaces (seccomp + Landlock). | Partial. Seatbelt can restrict IPC but coverage varies. | Complete. Separate IPC namespace. |
| **Credential isolation** | Strong. Credentials never enter the mount namespace. Broker socket is the only path. | Approximate. Host files exist but access is denied. A Seatbelt bypass would expose them. | Complete. Credentials never enter guest. Proxy swaps placeholders at TLS handshake. |
| **IMDS protection** | Strong. Network namespace has no route to 169.254.0.0/16. | Approximate. Seatbelt blocks the IP, but requires correct profile. | Complete. Guest has no route. |
| **Kernel exploit resistance** | None. Same kernel. | None. Same kernel. | Strong. Separate kernel. Hypervisor boundary. |
| **suid/capability escalation** | Blocked. `PR_SET_NO_NEW_PRIVS` + seccomp. | Partial. Seatbelt restricts but OS-level escalation paths may exist. | Blocked. Guest has no suid binaries. |
| **Audit completeness** | Complete. All tool calls logged via hook. Filesystem access logged where backend supports it. | Complete for tool calls. Filesystem audit is partial (Seatbelt violations are logged by the OS, not by AgentJail). | Complete. All I/O crosses the hypervisor boundary and can be logged. |

### Linux backend: Landlock + namespaces + seccomp

This is the primary backend for Linux. It composes multiple kernel primitives
to approximate the jailed execution model.

**Canonical setup ordering:**

```
1. Create user namespace (if needed for unprivileged namespace creation)
2. Create PID namespace (unshare + fork; agentjail-init becomes PID 1)
3. Create network namespace (no default route, proxy socket only)
4. Create mount namespace
5. Configure mounts:
   - /workspace → bind mount of project directory (read-write)
   - /runtime → bind mount of runtime binaries (read-only, nosuid, nodev)
   - /secrets → broker socket, optional .env (read-only)
   - /tmp → session-scoped tmpfs
   - /dev → minimal (null, zero, urandom)
   - /proc → private mount (namespace-local only)
6. Drop all capabilities
7. Set PR_SET_NO_NEW_PRIVS
8. Set PR_SET_DUMPABLE=0
9. Apply Landlock ruleset (filesystem allowlist matching the mounts)
10. Install seccomp-BPF filter (denylist of dangerous syscalls)
11. Close non-allowlisted FDs
12. Write activation status to parent
13. Wait for release
14. Close handshake FDs
15. execve agent
```

**seccomp denylist:**

Block syscalls that no coding agent should need:

| Category | Syscalls | Action |
|----------|----------|--------|
| Kernel tampering | `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `reboot` | KILL |
| Process manipulation | `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `process_madvise` | EPERM |
| Namespace/privilege | `setns`, `mount`, `umount2`, `pivot_root`, `chroot`, `unshare` (after setup) | EPERM |
| Exploit primitives | `bpf`, `userfaultfd`, `perf_event_open`, `open_by_handle_at`, `keyctl` | EPERM |
| System control | `swapon`, `swapoff`, `ioperm`, `iopl`, `quotactl`, `acct` | EPERM |

Start with a denylist, not an allowlist, to avoid breaking the diverse
tooling that agents use. Add `SCMP_ACT_LOG` for syscalls being evaluated.

**Compatibility profiles:**

```yaml
process_hardening:
  seccomp_profile: standard    # default
  # seccomp_profile: debugging   # allows ptrace of own descendants
  # seccomp_profile: permissive  # logs but does not block
```

**PID namespace init process:**

A minimal agentjail-init runs as PID 1 inside the namespace:
- Forwards signals to the agent
- Reaps orphaned child processes
- Reports session end to the daemon

Claude should not be PID 1 (special signal semantics, reaping
responsibilities).

**Degradation on older/restricted kernels:**

| Missing capability | Behavior |
|---|---|
| User namespaces disabled | Cannot create PID/mount/network namespace unprivileged. Fall back to Landlock + seccomp only. Attestation reports reduced capabilities. |
| Landlock ABI < 4 (no network) | Network namespace provides isolation instead. |
| Landlock unavailable (kernel < 5.13) | Cannot jail on this kernel. Session start fails with clear error. |
| PID namespace unavailable | seccomp blocks ptrace/process_vm_readv. /proc is visible but dangerous operations are blocked. |

Each capability is independently reported in the attestation result.

### macOS backend: Seatbelt

Seatbelt (sandbox-exec) provides kernel-level access control via sandbox
profiles. It approximates the jailed model but cannot fully implement it
because the host filesystem is structurally present.

**What Seatbelt provides:**
- Deny-by-default file access with explicit allow rules for workspace,
  runtime, and secret paths.
- Network restriction to localhost + proxy ports.
- Process inspection restrictions (partial).

**What Seatbelt cannot provide:**
- True filesystem allowlist (host paths exist but are access-denied).
- PID namespace (macOS has no equivalent).
- Network namespace (macOS has no equivalent).
- Mount namespace (macOS has no equivalent).
- seccomp (macOS has no equivalent).

**Honest assessment:** The macOS backend is weaker than Linux. A Seatbelt
bypass (documented but undisclosed sandbox DSL, possible future deprecation)
would expose the host filesystem. The attestation result should clearly state
the backend and its limitations. For high-assurance use cases on macOS, Tier 2
(microVM via HVF/libkrun) is recommended.

**macOS peer PID:** Attestation requires obtaining the peer PID from the
daemon's Unix socket. This must be validated on all supported macOS versions
before ADR 0029 can be accepted. If only UID can be reliably obtained, the
macOS attestation design needs revision.

### Tier 2: microVM (future)

Per ADR 0016. A microVM provides complete isolation:

- Separate kernel (hypervisor boundary).
- Guest filesystem built from scratch (host FS does not exist).
- Separate process, network, IPC, and mount namespaces by architecture.
- Credentials never enter the guest (placeholder swap at TLS handshake).
- ~70-320ms boot overhead per session.

The microVM backend fully implements the jailed execution model. The Linux
and macOS backends approximate it to varying degrees.

### Privileged host sockets

All backends must block access to privileged host-control sockets:

- Docker (`/var/run/docker.sock`)
- Podman (`/run/user/*/podman/podman.sock`)
- containerd (`/run/containerd/containerd.sock`)
- CRI-O, BuildKit, Lima/Colima sockets
- SSH agent socket (unless explicitly brokered)
- GPG agent socket (unless explicitly brokered)
- Kubernetes node credentials (`/var/run/secrets/kubernetes.io/`)

On Linux with namespaces, these are absent by default (not mounted). On
macOS, these must be explicitly denied in the Seatbelt profile. In a microVM,
they do not exist.

## Consequences

### Positive

- Honest capability matrix lets users choose the right backend for their
  threat model.
- No false equivalence between "macOS sandbox" and "Linux namespace
  isolation."
- Clear upgrade path: Seatbelt → Landlock+NS → microVM.
- Each backend's limitations are documented, not hidden.

### Negative

- macOS users get weaker isolation than Linux users. This is honest but may
  be commercially sensitive.
- The capability matrix must be maintained as backends evolve (new Landlock
  ABIs, new macOS versions, new microVM features).
- Users must understand which backend they're running to assess their
  security posture.

### Pre-acceptance checklist

Before accepting this ADR:

1. Prototype the Linux namespace setup on Ubuntu, Debian, Fedora, Codespaces,
   and rootless container environments.
2. Validate macOS peer PID retrieval on supported versions.
3. Test Seatbelt profile coverage against the full deny list.
4. Verify the seccomp denylist does not break Node.js, Python, Go, Git, and
   common build tools.
5. Test namespace + Landlock interaction ordering.

### Follow-ups

1. Collect seccomp telemetry to refine the denylist.
2. Evaluate `io_uring` restrictions per kernel version.
3. Investigate Yama LSM ptrace scope as a complementary control.
4. Design the agentjail-init process for PID namespace.
5. Add Landlock ABI v5 abstract Unix socket scoping when available.
6. Build runtime profiles for common stacks (Node.js, Python, Go, Rust) that
   pre-configure the right mounts and seccomp profiles.
