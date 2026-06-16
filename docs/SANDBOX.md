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
  `~/Library/Keychains`, `~/Downloads`, `~/Desktop`, `/etc`, `/var`
- **Denies writes** matching sensitive filename patterns: `.env*`, `*.pem`,
  `*.key`, `id_rsa`, `credentials`, `.netrc`, `~/.npmrc`, `~/.pypirc`,
  `~/.git-credentials`
- **Denies reads** of credential paths: `~/.ssh`, `~/.aws`, `~/.gnupg`,
  `~/.docker`, `~/.kube`, `~/Library/Keychains`, private key files
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
- Network egress restriction is **not available** via Landlock (filesystem LSM
  only). Per-host network control requires Tier 2 (microVM) or Tier 3 (eBPF).

### Other platforms

On unsupported platforms (Windows, FreeBSD, etc.), agentjail-shield prints a
warning and execs the agent **without** any sandbox (fail-open). The hook layer
(`agentjail-hook`) still runs on every tool call.

---

## Network enforcement

### macOS with netproxy (default)

By default on macOS, agentjail-shield starts `agentjail-netproxy` as a child
process on `127.0.0.1:9100` and restricts the agent to **localhost-only**
outbound TCP. All HTTPS traffic flows through the proxy, which enforces
`network.allowed_hosts` from `~/.agentjail/policy.yaml`.

```
Agent (sandboxed, localhost-only TCP)
  │
  │  HTTPS_PROXY=http://127.0.0.1:9100
  ▼
agentjail-netproxy (localhost:9100)
  │
  │  CONNECT host:port → check allowed_hosts → allow/deny
  ▼
upstream (api.github.com, registry.npmjs.org, …)
```

The shield automatically sets `HTTPS_PROXY`, `HTTP_PROXY`, and `ALL_PROXY` in
the agent's environment.

### macOS without netproxy (`--no-netproxy`)

With `--no-netproxy`, the sbpl profile allows outbound TCP on ports 443 and 80
to **any** host. This is less secure (no per-host filtering) but works when the
netproxy binary is unavailable or when the agent doesn't respect proxy
environment variables.

### Linux

Network enforcement is not available on Linux via Landlock. Use Tier 2 (microVM)
or Tier 3 (eBPF) for network-level control.

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

# Test: try to read a private key (should fail with EPERM)
agentjail-shield -- sh -c "cat ~/.ssh/id_rsa"
```

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

Enforced by `agentjail-netproxy` on macOS. Wildcards follow cert-style matching:
`*.example.com` matches `foo.example.com` and `foo.bar.example.com`, but **not**
`example.com` itself.

**Defaults** (built-in, always present unless overridden):
- `api.github.com`, `raw.githubusercontent.com`, `codeload.github.com`
- `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`
- `crates.io`, `proxy.golang.org`, `sum.golang.org`, `deno.land`

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
| `policy.yaml` missing or unreadable | Falls back to built-in defaults |
| `agentjail-netproxy` not found | Falls back to port-based filtering with warning |
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
| Network per-host enforcement | No | **Yes** (via netproxy on macOS) |

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
