# agentjail-shield — OS-native sandbox

`agentjail-shield` wraps your coding agent in the operating system's kernel
sandbox **before** exec'ing it. Every subprocess the agent spawns inherits the
restrictions, so tricks like `printf x > ~/.ssh/id_rsa`, `eval $(base64 -d)`,
or `python -c "open(...).write(...)"` all return `EPERM` at the kernel level —
regardless of any hook bypass.

This is Tier 1.5 in agentjail's [isolation model](./ARCHITECTURE.md#isolation-tiers):
stronger than hooks alone, lighter than a microVM.

---

## Quick start

```sh
# Run Claude Code inside the sandbox:
agentjail-shield -- claude

# Run Codex CLI:
agentjail-shield -- codex

# Any command works:
agentjail-shield -- sh -c "cat ~/.ssh/id_rsa"
# → Operation not permitted
```

If you installed via `agentjail install --for claude-code`, the shield is
already configured. You can also invoke it manually for any command.

---

## How it works

### macOS — Apple Seatbelt (`sandbox-exec`)

agentjail-shield generates an [Apple Seatbelt](https://developer.apple.com/documentation/security)
(sbpl) profile from your policy config and execs the agent under:

```
/usr/bin/sandbox-exec -p <generated-profile> <agent-cmd> [args...]
```

The profile is **deny-list based** (allow-by-default):

- **Denies writes** to sensitive paths: `~/.ssh`, `~/.aws`, `~/.gnupg`,
  `~/.config`, `~/.agentjail`, `~/.docker`, `~/.kube`, `~/.cargo`,
  `~/Downloads`, `~/Desktop`, `/etc`, `/var`
- **Denies writes** matching sensitive filename patterns: `.env*`, `*.pem`,
  `*.key`, `id_rsa`, `credentials`, `.netrc`, `~/.npmrc`, `~/.pypirc`,
  `~/.git-credentials`
- **Denies reads** of credential paths: `~/.ssh`, `~/.aws`, `~/.gnupg`,
  `~/.docker`, `~/.kube`, private key files
- **Grants** the user keychain root (`~/Library/Keychains`, read+write) by
  default, so Claude Code's own login/token-refresh flow works — see
  [ADR 0037](./adr/0037-macos-keychain-access-shielded-agent.md). This is a
  shield-layer grant only: the hook layer (`file_policy.rego`) still denies
  an agent's own direct read of that path (e.g. a `cat` or `Read` tool call).
- **Allows reads** of system trust stores (`/private/etc/ssl`,
  `/System/Library/Keychains`, `/Library/Keychains`) so TLS works
- **Restricts network egress** (see [Network enforcement](#network-enforcement))

No sudo, no entitlement, no Developer ID required. `sandbox-exec` ships on
every macOS since 10.5.

### Linux — Landlock LSM

On Linux, agentjail-shield uses [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
(available since Linux 5.13, June 2021). Landlock is **allowlist-based** — the
opposite of the macOS deny-list:

| Allowed (read-write) | Allowed (read-only) | Denied |
|---|---|---|
| `/tmp`, current working directory | `/usr`, `/bin`, `/lib`, `/lib64`, `/sbin`, `/etc`, `/dev`, `/proc`, `/sys`, `/opt`, `/run`, `$HOME` (excluding sensitive subdirs) | Everything else |

Sensitive subdirectories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.agentjail`,
`~/.config`) are never added to the allowlist, so they are denied by default.

Landlock restrictions are **irreversible** — once applied, neither the process
nor its descendants can lift them.

**Requirements:**
- Linux kernel 5.13+ with `CONFIG_SECURITY_LANDLOCK=y`
- No special privileges (designed for unprivileged use)

**Known limitations:**
- `truncate(2)` is only covered as of ABI v3 (Linux 6.2). On older kernels, an
  agent could truncate sensitive files.
- Network egress restriction via Landlock requires **kernel 6.7+** (ABI v4),
  which adds `LANDLOCK_ACCESS_NET_CONNECT_TCP`. On 6.7+ with netproxy enabled,
  the agent is restricted to TCP connect only on the netproxy port (9100). On
  older kernels, network is unrestricted by Landlock (a warning is printed).

### Other platforms

On unsupported platforms (Windows, FreeBSD, etc.), agentjail-shield prints a
warning and execs the agent **without** any sandbox (fail-open). The hook layer
(`agentjail-hook`) still runs on every tool call.

---

## Network enforcement

### macOS with netproxy (default)

By default on macOS, agentjail-shield ensures a single shared
`agentjail-netproxy` is running on `127.0.0.1:9100` and restricts the agent to
**localhost-only** outbound TCP. The proxy is **session-aware**: the shield
registers THIS session's EFFECTIVE `network.allowed_hosts` over a control socket
and injects an unguessable session token into `HTTPS_PROXY`, so the proxy keys a
separate allowlist per session (no global list, no bleed between sessions). The
effective allowlist is three tiers, essentials first: the non-removable
essential provider hosts, then the hosts implied by any currently-allowed hosted
MCP server (non-removable while that MCP stays allowed), then the editable list
from `~/.agentjail/policy.yaml` (ADR 0038, ADR 0040). An omitted or even
explicitly empty `allowed_hosts` never blocks the agent's own provider or an
allowed MCP server.

```
Agent (sandboxed, localhost-only TCP)
  │
  │  HTTPS_PROXY=http://<session-token>:@127.0.0.1:9100
  ▼
agentjail-netproxy (localhost:9100, shared, session-aware)
  │
  │  CONNECT host:port  (Proxy-Authorization: Basic <token>)
  │  known token? → check THIS session's allowed_hosts → allow/deny
  ▼
upstream (api.github.com, registry.npmjs.org, …)
```

The shield automatically sets `HTTPS_PROXY`, `HTTP_PROXY`, and `ALL_PROXY`
(carrying the session token) in the agent's environment. The control socket that
registers allowlists is denied to the agent. See
[ADR 0042](./adr/0042-session-aware-netproxy-control-plane.md).

### macOS without netproxy (`--no-netproxy`)

With `--no-netproxy`, the sbpl profile allows outbound TCP on ports 443 and 80
to **any** host. This is less secure (no per-host filtering) but works when the
netproxy binary is unavailable or when the agent doesn't respect proxy
environment variables.

### Linux

On kernel 6.7+ (Landlock ABI v4), agentjail-shield restricts the agent's TCP
connect to the netproxy port (9100) only, using `LANDLOCK_ACCESS_NET_CONNECT_TCP`.
All other TCP connect is denied at the kernel level. The `agentjail-netproxy`
child process then enforces `network.allowed_hosts` from `policy.yaml`, the same
as on macOS.

On kernels < 6.7, Landlock network ABI is unavailable. A warning is printed and
FS-only Landlock is applied (network egress is not restricted by Landlock). Use
Tier 2 (microVM) or Tier 3 (eBPF) for network-level control on older kernels.

**`--no-netproxy` on Linux (ABI v4+, kernel 6.7+):** restricted, not
unrestricted (ADR 0039). Landlock's CONNECT rights are limited to the shared
`NoNetproxyFallbackPorts()` set (80, 443) instead of the netproxy port -- the
same fallback ports macOS's `--no-netproxy` mode allows. TCP bind is left
unhandled in this mode so it does not regress dynamic (not-yet-resolved) MCP
OAuth callback ports. There is still no per-host enforcement in this mode
(port-level only, same limitation as macOS `--no-netproxy`).

---

## CLI reference

```
agentjail-shield [flags] -- <agent-cmd> [args...]
```

The `--` separator between shield flags and the agent command is **required**.

| Flag | Default | Description |
|---|---|---|
| `--policy=PATH` | `~/.agentjail/policy.yaml` | Path to the policy config file |
| `--profile-print` | `false` | Print the generated sandbox profile to stderr and exit (does not run the agent) |
| `--no-netproxy` | `false` | Disable `agentjail-netproxy`; revert to port-based network filtering |
| `--audit-json=PATH` | `""` | Write environment audit findings as JSON to PATH (use `-` for stdout) |
| `--audit-strict` | `false` | Refuse to launch if critical audit findings (root, AdminAccess, IMDSv1) |

### Examples

```sh
# Run Claude Code in the sandbox
agentjail-shield -- claude

# Inspect the generated macOS Seatbelt profile
agentjail-shield --profile-print -- claude

# Use a custom policy file
agentjail-shield --policy=/path/to/policy.yaml -- claude

# Disable the network proxy (port-based filtering only)
agentjail-shield --no-netproxy -- claude

# Output environment audit as JSON
agentjail-shield --audit-json=- -- claude

# Refuse to launch if critical audit findings (root, AdminAccess, IMDSv1)
agentjail-shield --audit-strict -- claude

# Test: try to read a private key (should fail with EPERM)
agentjail-shield -- sh -c "cat ~/.ssh/id_rsa"
```

---

## Environment audit at launch

Before launching the agent, `agentjail-shield` performs a best-effort
environment audit and prints warnings to stderr. The audit checks for
over-permissive configuration that increases the blast radius of a foot-gun:

| Check | Severity | What it detects |
|---|---|---|
| Root | Critical | Running as root (uid 0) |
| Ambient cred files | Warning | `~/.aws/credentials` or `~/.ssh/id_rsa` is readable |
| Ambient env vars | Warning | `AWS_SECRET_ACCESS_KEY`, `PGPASSWORD`, etc. are set (pre-stripping) |
| IMDS version | Critical | IMDSv1 is enabled (should be IMDSv2 with hop-limit=1) |
| IAM role | Critical/Info | Instance role name suggests AdministratorAccess (heuristic) |

Use `--audit-json=PATH` to output structured findings as JSON (use `-` for
stdout). Use `--audit-strict` to refuse launching when critical findings
are detected.

---

## Env stripping at launch

Before exec'ing the agent, `agentjail-shield` strips ambient credentials
from the environment. This prevents the agent from using credentials that
are already in the shell's environment (e.g. `AWS_SECRET_ACCESS_KEY` set
via a shell profile), which would bypass the filesystem and network
restrictions entirely.

### `secrets.env_blocklist` — env vars to strip

```yaml
secrets:
  env_blocklist:
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
    - "*_API_KEY"           # glob: matches any var ending in _API_KEY
  strip_on_launch: true      # default: true
```

The default blocklist covers: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN`, `AWS_DELEGATION_TOKEN`,
`PGPASSWORD`, `REDIS_PASSWORD`, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`.

Glob patterns use `path.Match` semantics (`*` matches any sequence of
non-`/` characters). Set `strip_on_launch: false` to disable stripping.

If the `agentjail-secrets` broker is running, the shield adds
`AGENTJAIL_SECRETS=1` to signal that scoped creds are available via the
broker.

---

## Configuration

The shield reads `~/.agentjail/policy.yaml` (same file as the hook/daemon).
The relevant sections for the sandbox are:

### `file.extra_deny` — additional write-denied paths

```yaml
file:
  extra_deny:
    - /Users/me/secret-project
    - /opt/production-data
```

These paths are appended to the built-in sensitive path list in the generated
sbpl profile (macOS). On Linux, they are excluded from the Landlock allowlist.

### `file.extra_allow` — additional write-allowed paths

```yaml
file:
  extra_allow:
    - /data/scratch
```

On Linux only: adds paths to the Landlock read-write allowlist. On macOS, the
sbpl profile is allow-by-default so this has no effect on the sandbox (it is
used by the Rego policy layer).

### `network.allowed_hosts` — hosts the agent can reach

```yaml
network:
  allowed_hosts:
    - api.github.com
    - raw.githubusercontent.com
    - registry.npmjs.org
    - pypi.org
    - "*.example.com"          # wildcard: matches sub.example.com, not example.com
```

Enforced by `agentjail-netproxy` on macOS and Linux. Wildcards follow cert-style matching:
`*.example.com` matches `foo.example.com` and `foo.bar.example.com`, but **not**
`example.com` itself.

**Defaults** (built-in, always present unless overridden):
- `api.github.com`, `raw.githubusercontent.com`, `codeload.github.com`
- `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`
- `crates.io`, `proxy.golang.org`, `sum.golang.org`, `deno.land`

**Three enforced tiers (ADR 0038, ADR 0040), essentials first:**

1. **Essential** (`config.EssentialAllowedHosts()`) -- exact hostnames only,
   never editable. Includes each provider's core hosts plus
   `mcp-proxy.anthropic.com`, which claude.ai's hosted connectors (Gmail,
   Google Calendar, Google Drive, typefully) proxy their MCP traffic
   through.
2. **MCP-derived** (`config.MCPDerivedAllowedHosts`) -- hosts for any hosted
   MCP server (linear, typefully, posthog, context7, notion, deepwiki,
   cloudflare, githubcopilot, huggingface -- see
   `config.HostedMCPRegistry()`) that is currently allowed under
   `mcp.allowed` and not matched by `mcp.blocked`. Non-removable *while*
   that MCP server stays allowed -- allowing an MCP server is sufficient by
   itself to reach its vetted hosts, without also editing `allowed_hosts`.
   Removing the server from `mcp.allowed`, or blocking it, drops its hosts
   here on the next load.
3. **Editable** (`network.allowed_hosts` in `policy.yaml`) -- fully
   removable/replaceable, as shown above.

---

## Environment variables

| Variable | Description |
|---|---|
| `AGENTJAIL_NETPROXY` | Override path to the `agentjail-netproxy` binary |
| `AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED` | Set to `1` to allow the agent to run without a sandbox when Landlock fails on Linux (not recommended) |

---

## Fail behavior

| Scenario | Behavior |
|---|---|
| `sandbox-exec` missing (macOS) | **Fail-open** with loud warning; agent runs unsandboxed; hook layer still active |
| Landlock unsupported (Linux < 5.13) | **Fail-open** with loud warning |
| Landlock setup error (other) | **Fail-closed**: refuses to run unless `AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1` |
| `policy.yaml` missing entirely | Falls back to built-in defaults (normal first-run state) |
| `policy.yaml` present but malformed (parse or validation error, e.g. a stray tab or a bad `mcp.allowed` glob) | **Fail-closed** (ADR 0040): the shield prints the file path and error to stderr and refuses to launch the agent (`os.Exit(1)`) rather than silently falling back to the permissive built-in defaults. `agentjail-netproxy`'s initial load fails the same way; on a SIGHUP reload of a now-broken file, netproxy instead keeps its last-good allowlist and logs an error -- it does not fall open or crash the running proxy. |
| `agentjail-netproxy` not found or fails to start | **Fail-closed** (ADR 0041): if netproxy was requested (no `--no-netproxy`), the shield prints an error to stderr, emits an `audit.ShieldFailed` event, and refuses to launch the agent (`os.Exit(1)`) rather than silently downgrading to port-only egress. Pass `--no-netproxy` explicitly to opt into the old port-based-filtering behavior (TCP 80/443 only, no per-host enforcement) instead. |
| Unsupported platform | **Fail-open** with warning |

---

## Relationship to the hook layer

The sandbox does **not** replace the hook (`agentjail-hook` + `agentjail-daemon`).
They serve complementary roles:

| Capability | Hook (Tier 1) | Sandbox (Tier 1.5) |
|---|---|---|
| MCP server allowlisting | Yes | No |
| Command-intent rules (`git push --force`) | Yes | No |
| Tell the agent *why* something was blocked | Yes | No |
| UX decisions (allow / deny / ask) | Yes | No (deny only) |
| Catch shell/eval/Python file writes | No (whack-a-mole) | **Yes** (kernel-level) |
| Catch subprocess bypass | No | **Yes** (inherited by descendants) |
| Network per-host enforcement | No | **Yes** (via netproxy on macOS and Linux 6.7+) |

Use both for defense in depth. The hook catches the 90% case with good UX; the
sandbox is the safety net that catches the rest.

---

## Debugging

```sh
# Print the generated profile without running the agent
agentjail-shield --profile-print -- claude

# Watch proxy decisions in real time (stderr of the shield process)
# The netproxy logs every CONNECT request with host, port, and decision

# Test a specific operation
agentjail-shield -- sh -c "echo test > ~/.ssh/test_file"
# Expected: "Operation not permitted" on macOS; silent failure on Linux
```

---

## Further reading

- [ADR 0001 — OS sandbox enforcement layer](./adr/0001-os-sandbox-enforcement-layer.md) — the decision record
- [Architecture](./ARCHITECTURE.md) — how the sandbox fits into agentjail's isolation tiers
- [Apple Seatbelt documentation](https://developer.apple.com/documentation/security) (limited official docs)
- [Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
