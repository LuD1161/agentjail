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
- **Denies writes** matching sensitive filename patterns: secret `.env`
  forms only (`.env`, `.env.local`, `.env.*.local`,
  `.env.{production,prod,development,dev,staging,test,qa,uat,secret,secrets,vault,override}`)
  - non-secret templates like `.env.example`, `.env.sample`, `.env.docker`
    are writable, so cloning a repo that commits them works - see
    [ADR 0057](./adr/0057-env-write-deny-secret-form-denylist.md); also
    `*.pem`, `*.key`, `id_rsa`, `credentials`, `.netrc`, `~/.npmrc`,
    `~/.pypirc`, `~/.git-credentials`
- **Denies reads** of credential paths: `~/.ssh`, `~/.aws`, `~/.gnupg`,
  `~/.docker`, `~/.kube`, private key files
- **Grants** the user keychain root (`~/Library/Keychains`, read+write) by
  default, so Claude Code's own login/token-refresh flow works — see
  [ADR 0037](./adr/0037-macos-keychain-access-shielded-agent.md). This is a
  shield-layer grant only: the hook layer (`file_policy.rego`) still denies
  an agent's own direct read of that path (e.g. a `cat` or `Read` tool call).
- **Allows reads** of system trust stores (`/private/etc/ssl`,
  `/System/Library/Keychains`, `/Library/Keychains`) so TLS works
- **Allows writes** to the per-user `$TMPDIR` (`/var/folders/<xx>/<yyy>/T`),
  carved out after the `/var` deny with strict, fail-closed path
  validation -- macOS tools (compilers, `xcrun`, Go's own build tooling)
  write there, not to `/tmp`
- **Allows local AF_UNIX sockets** to match Linux Landlock's `/tmp`
  behavior: `bind()` on `/tmp`, `/private/tmp`, and the per-user temp dir;
  `connect()` only within the per-user temp dir (narrower, see residual
  boundary in [ADR 0054](./adr/0054-macos-shield-tempdir-afunix-parity.md))
- **Restricts network egress** (see [Network enforcement](#network-enforcement))

No sudo, no entitlement, no Developer ID required. `sandbox-exec` ships on
every macOS since 10.5.

### SSH and ssh-agent

Private key FILE reads are blocked by design on both platforms --
`~/.ssh/id_*` and friends match `SensitiveFilePatterns` and stay denied
regardless of shield config. The built-in standard policy enables Git over SSH
when the parent terminal has a usable SSH agent:

```sh
agentjail run -- codex
```

Set `capabilities.git_ssh: false` for the strict posture, or use
`agentjail run --no-git-ssh -- <agent>` for one launch. `--git-ssh` enables it
for one launch when the standing policy disables automatic delegation.

The shield validates the delegated socket, injects it only for that session,
and explicitly allows connecting to that socket on macOS with an exact
`network-outbound` rule. Linux Landlock does not mediate AF_UNIX `connect(2)`,
so AgentJail adds no misleading filesystem grant there; removing the variable
is not a hard Unix-socket isolation boundary on Linux. A sandboxed `ssh` can
then ask the agent to sign without ever touching the key file. See ADR
0124-explicit-ssh-delegation for the capability boundary and platform limits.

Delegating an agent is intentionally a security trade-off: any process in the
shielded session can request signatures from **every identity loaded in that
agent**. The socket protocol does not restrict use to a host or repository.
Prefer a dedicated, narrowly authorized identity. `agentjail doctor` reports
inactive, missing, unusable, and active delegation states.

When an interactive launch finds local SSH identities but no usable agent, it
offers to start a session-only native OpenSSH agent. For the current branch's
SSH push remote (falling back to `origin`), AgentJail follows the effective
OpenSSH `IdentityFile` order, including `Host` aliases. One matching identity
is loaded directly. Multiple matches produce a chooser whose default loads
only the first; loading every listed identity is explicit. Without an SSH
remote or config match, the same chooser uses the discovered local identities.
AgentJail never maps a repository owner to a key.

The next private-key passphrase prompt, if any, is owned by OpenSSH `ssh-add`.
AgentJail does not read, capture, log, or store the passphrase or private key.
The agent terminates with the coding session. Noninteractive launches never
prompt. An explicit `--git-ssh` request fails closed if setup is unavailable or
declined; automatic standard-policy launches continue without Git SSH. An
already-running inherited agent is not modified; all identities it already
holds remain within the disclosed delegation scope.

If native setup cannot load a hardware-backed or custom identity, configure it
through OpenSSH in the parent environment and launch AgentJail again. AgentJail
does not grant a read hole for the key file.

`agentjail doctor` proactively reports a delegated agent with no
identities. Neither it nor the hook suggests granting a read hole for the key
file -- private-key file access stays denied.

**Key loaded but ssh still fails (pinned `IdentityFile`).** If
`ssh-add -l` shows your key *is* loaded yet a sandboxed `ssh`/`git` still
dies with `no such identity: ~/.ssh/id_...: Operation not permitted`
followed by `Permission denied (publickey)`, your `~/.ssh/config` pins an
explicit `IdentityFile` (usually with `IdentitiesOnly yes`). `ssh` tries
to read that on-disk file first -- which the shield blocks -- and gives
up before trying the agent.

When Git over SSH is active, the shield injects an agent-backed
`GIT_SSH_COMMAND` (`ssh -o IdentitiesOnly=no -o
IdentityFile=none -o IdentityAgent='<your SSH_AUTH_SOCK>'`) so `git`
authenticates through the agent instead of the pinned file after you accept
the delegation warning. The `IdentitiesOnly=no` is the decisive part: with
`IdentitiesOnly yes` in your config, OpenSSH only offers agent keys matching a configured
`IdentityFile`, so an agent key that differs from the pinned one is never
offered -- `IdentitiesOnly=no` lifts that so the agent's real key is used.
When inactive, the socket and `GIT_SSH_COMMAND` are removed. When active, this
auto-fix is skipped -- and you are back to the manual workaround below
-- if you have already set your own `GIT_SSH_COMMAND`, or if you export
`AGENTJAIL_NO_SSH_OVERRIDE=1` to opt out (for example, to keep your
deliberate per-host identity restrictions intact for git too). See
[ADR 0056](./adr/0056-ssh-agent-pinned-identityfile-blindspot.md) for why
all three options are required, and for the accepted tradeoffs of forcing
`IdentitiesOnly=no` (it offers every agent key to the server).

For direct `ssh`/`scp`/`sftp`/`rsync` (not git), or for git when you have
opted out of the auto-fix above, apply the same recipe by hand:

```sh
# per command
GIT_SSH_COMMAND='ssh -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent=$SSH_AUTH_SOCK' \
  git clone git@github.com:owner/repo.git

# or, for direct ssh:
ssh -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent=$SSH_AUTH_SOCK git@github.com

# or drop `IdentitiesOnly yes` from ~/.ssh/config so the agent is used as
# a fallback
```

Note: a global git `url.git@github.com:.insteadOf https://github.com/`
rewrite silently sends HTTPS GitHub URLs over SSH, so an apparent HTTPS
clone can hit this same path. `agentjail doctor` and the hook's one-shot
advisory both detect this case now (agent Ready, but a pinned
`IdentityFile` the shield would block) and print the guidance above --
for git, only when the auto-fix did not already handle it.

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

> **Interim (ADR 0046):** per-host egress enforcement (`agentjail-netproxy`) is
> **opt-in and OFF by default**. The credentialed proxy URL broke Claude Code's
> MCP transport on macOS. The transparent tunnel that supersedes the proxy with
> real per-session isolation and no proxy env now **ships on Linux** behind
> `--tunnel` (ADR 0079); direct launches are opt-in per session, while the
> opt-in PATH shim supplies it by default (ADR 0127), and broader default-on is a later
> step. Until
> then the shield runs **port-only by default** (filesystem/process/keychain
> sandbox stays fully on); pass `--netproxy` to turn per-host filtering on. The
> "with netproxy" section below describes the `--netproxy` path.

### macOS with netproxy (`--netproxy`, opt-in)

With `--netproxy`, agentjail-shield ensures a single shared
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

A blocked host can be granted at runtime: the agent files a request with
`agentjail allow host <h>` through the daemon socket, and a human approves it
with `agentjail grant approve <grant_id>` from an unsandboxed terminal.
Approve/deny/list are only reachable over `daemon-ctl.sock` (agent-unreachable
by the same mechanism as `netproxy-ctl.sock`), so the agent cannot approve its
own request. In the default (no-netproxy) configuration, approval persists the
host into the project overlay for future sessions. With `--netproxy`, approval
also widens the live session's allowlist immediately.
See [ADR 0044](./adr/0044-runtime-host-grants.md) and
[ADR 0047](./adr/0047-daemon-grant-server.md).

### macOS without netproxy (default)

By default (no `--netproxy`), the sbpl profile allows outbound TCP on ports 443
and 80 to **any** host. This is the interim default (ADR 0046): no per-host
filtering, but it does not break MCP and requires no proxy env. Explicit
`--no-netproxy` selects the same port-only mode.

### Linux

With `--netproxy` on kernel 6.7+ (Landlock ABI v4), agentjail-shield restricts
the agent's TCP connect to the netproxy port (9100) only, using
`LANDLOCK_ACCESS_NET_CONNECT_TCP`. All other TCP connect is denied at the kernel
level. The `agentjail-netproxy` child process then enforces
`network.allowed_hosts` from `policy.yaml`, the same as on macOS. Without
`--netproxy` (the default, ADR 0046), Landlock CONNECT is limited to the
port-only fallback set below.

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

### Cloud metadata (IMDS) in port-only mode

Neither backend can filter port-only egress by destination IP (Landlock's
`LANDLOCK_RULE_NET_PORT` is port-scoped only; sbpl's `(remote tcp/ip
"HOST:PORT")` rejects literal IP hosts). That means in the default,
port-only mode, `169.254.169.254` (the cloud instance metadata service on
AWS/GCP/Azure/OpenStack/Alibaba) and `fd00:ec2::254` (AWS IPv6) are reachable
over the same allowlisted port 80 as any other host -- a shielded agent
running on a real cloud instance could otherwise exfiltrate IAM/service-
account credentials via IMDS.

Since no network-layer block is available in port-only mode, `agentjail-shield`
runs a launch-time metadata-egress guard instead (ADR 0049): it probes whether
the metadata IPs are reachable and, if so, either refuses to launch
(`--audit-strict`) or prints a loud warning and records a
`shield.metadata_egress_exposed` audit event (default). Pass `--netproxy` to
close the exposure entirely -- `network.allowed_hosts` does not include the
metadata IP by default, so per-host enforcement blocks it like any
non-allowlisted host.

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
| `--netproxy` | `false` | Enable `agentjail-netproxy` per-host egress enforcement (opt-in; default off until the transparent tunnel lands -- ADR 0046) |
| `--no-netproxy` | `false` | Explicitly select port-based filtering (now the default); retained for back-compat |
| `--tunnel` | `false` | Route agent traffic through the unprivileged-userns transparent forwarder (Linux only; no sudo, no daemon). Decrypts HTTPS by default so policy templates apply -- see `--no-mitm` |
| `--mitm` | *(on)* | Force TLS interception on, overriding a `network.tunnel_mitm: false` opt-out. Interception is already the default inside a tunnel, so this is normally redundant (ADR 0077) |
| `--no-mitm` | `false` | Transparent-only: relay the agent's TLS opaquely instead of decrypting it. Keeps netns isolation and IP/SNI visibility, but **HTTP(S) policy templates cannot match** -- `netpolicy` only recognizes HTTP through the interception path. Use for cert-pinned endpoints (ADR 0077) |
| `--git-ssh` | policy | Enable Git over SSH for this launch by delegating all loaded SSH-agent identities |
| `--no-git-ssh` | policy | Disable Git over SSH for this launch |
| `--audit-json=PATH` | `""` | Write environment audit findings as JSON to PATH (use `-` for stdout) |
| `--audit-strict` | `false` | Refuse to launch if critical audit findings (root, AdminAccess, IMDSv1), or if cloud metadata (IMDS) is reachable in port-only mode |

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

Separately from the above table, a launch-time metadata-egress guard checks
whether the cloud instance metadata service (`169.254.169.254` /
`fd00:ec2::254`) is reachable while running in port-only (`--no-netproxy`)
mode -- see [Cloud metadata (IMDS) in port-only mode](#cloud-metadata-imds-in-port-only-mode)
above and [ADR 0049](./adr/0049-cloud-metadata-egress-guard.md). It always
warns loudly when applicable; `--audit-strict` additionally refuses to
launch.

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
- [ADR 0054 - macOS shield temp-dir and AF_UNIX parity](./adr/0054-macos-shield-tempdir-afunix-parity.md) - why the temp-dir carve-out and AF_UNIX allows exist
- [Architecture](./ARCHITECTURE.md) — how the sandbox fits into agentjail's isolation tiers
- [Apple Seatbelt documentation](https://developer.apple.com/documentation/security) (limited official docs)
- [Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
