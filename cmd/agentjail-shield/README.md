# agentjail-shield

**OS-native sandbox launcher for coding agents** (macOS + Linux).

For the full architectural rationale, see
[ADR 0001](../../docs/adr/0001-os-sandbox-enforcement-layer.md).

---

## What it does and why

The `PreToolUse` hook is *cooperative* — Claude Code calls it voluntarily
before each tool.  A dogfood test on 2026-05-23 showed that a Bash redirect
like:

```sh
printf 'null' > ~/.ssh/id_rsa
```

is a *single* `Bash` tool call that fires the hook once.  Content-based
pattern matching can be evaded via:

- env-var expansion (`T=$HOME/.ssh/id_rsa; printf x > $T`)
- obfuscation (`eval $(echo "…" | base64 -d)`)
- other interpreters (`python -c "open('~/.ssh/id_rsa','w').write('x')"`)

`agentjail-shield` wraps the agent process in the OS sandbox **before**
`exec`'ing it.  Subprocesses inherit the sandbox, so any write attempt to a
sensitive path returns `EPERM` directly from the kernel regardless of the
language or trick used.

The hook layer (agentjail-hook) is **not replaced** — it still owns MCP
allowlisting, command-intent rules, and the UX of explaining *why* something
was blocked.  The shield is the safety net that catches everything the hook
missed.

---

## Usage

```sh
# Basic: wrap the claude binary (netproxy auto-started if found)
agentjail-shield -- claude

# With explicit policy file
agentjail-shield --policy=/path/to/policy.yaml -- claude

# Print the generated sbpl profile (macOS) or Landlock rule summary (Linux)
# then exit without running the agent — useful for debugging
agentjail-shield --profile-print -- claude

# Disable the per-host proxy; revert to port-based filtering (no per-host enforcement)
agentjail-shield --no-netproxy -- claude

# Pass flags through to the agent
agentjail-shield -- claude --print "what's in ~/.ssh/?"
```

The `--` separator is required; without it, agentjail-shield exits 64
(`EX_USAGE`).

---

## What is protected

The following paths are denied for writes (and a subset for reads) —
mirroring the `is_sensitive_path` predicates in
[`agentpolicy/policies/file_policy.rego`](../../agentpolicy/policies/file_policy.rego):

| Path / pattern | Write | Read |
|---|---|---|
| `~/.ssh/` | deny | deny |
| `~/.aws/` | deny | deny |
| `~/.gnupg/` | deny | deny |
| `~/.agentjail/` | deny | deny |
| `~/.docker/` | deny | deny |
| `~/.kube/` | deny | deny |
| `~/.cargo/` | deny | — |
| `~/Library/Keychains/` | deny | deny |
| `~/.npmrc` (home only, exact) | deny | deny |
| `~/.pypirc` (home only, exact) | deny | deny |
| `~/.git-credentials` (home only, exact) | deny | deny |
| `~/.config/` | deny | — |
| `~/Downloads/` | deny | — |
| `~/Desktop/` | deny | — |
| `/etc/`, `/private/etc/` | deny | — |
| `/var/`, `/private/var/` | deny | — |
| `*.env`, `.envrc` | deny | — |
| `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` | deny | deny |
| `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa` | deny | deny |
| `credentials`, `secrets`, `.netrc` | deny | deny |

**Note on project-local files:** The exact home-file patterns (`~/.npmrc`, `~/.pypirc`,
`~/.git-credentials`) use anchored regex (`/Users/<user>/.<file>$`) so project-local copies
(e.g. `/Users/dev/myproject/.npmrc`) are **not** blocked by these rules.  The `~/.docker/`,
`~/.kube/`, and `~/.cargo/` subpath entries cover their entire directories regardless of depth.

### Adding custom paths

Add entries under `file.extra_deny` in `~/.agentjail/policy.yaml`:

```yaml
file:
  extra_deny:
    - /mnt/nfs/prod-secrets
    - /Users/me/private-keys
```

Then restart the shielded session for the change to take effect.

---

## macOS implementation (sandbox-exec)

On macOS, agentjail-shield generates an Apple Seatbelt SBPL profile and
execs the agent via `/usr/bin/sandbox-exec -p <profile> <agent-cmd>`.

**Apple deprecation note:** `sandbox-exec` was deprecated in macOS 10.7 but
has shipped on every macOS release through macOS 26 (Tahoe).  Apple's own
system daemons use the same mechanism.  The risk of removal exists but has
not materialised in 15+ years.  If Apple removes `sandbox-exec`, agentjail-shield
fails open with a warning and the hook layer continues to enforce.  Tier 2
(microVM) will be the structural fix when that happens.

If `/usr/bin/sandbox-exec` is absent, the shield prints a warning and runs
the agent unsandboxed (fail-open behaviour).

---

## Linux implementation (Landlock)

On Linux, agentjail-shield uses the **Landlock** LSM
(`landlock_create_ruleset` + `landlock_restrict_self`).

**Kernel version requirement:** Linux 5.13+ (June 2021) with
`CONFIG_SECURITY_LANDLOCK=y`.  Most modern distros (Ubuntu 22.04+, Fedora 35+,
Debian 12+) include Landlock by default.

**Important difference from macOS:** Landlock is allowlist-based.  You grant
access to permitted paths; everything else is denied.  This is the inverse of
the sbpl deny-list approach.  The Linux implementation allows:

- `/tmp` (read-write)
- CWD — the agent's working directory (read-write)
- `$HOME` (read-only — writes to `.ssh`, `.aws`, `.gnupg`, `.agentjail` are blocked by exclusion)
- `/usr`, `/bin`, `/lib`, `/lib64`, `/etc`, `/dev`, `/proc`, `/sys` (read-only)
- Any extra paths from `file.extra_allow` in policy.yaml (read-write)

**Kernel caveats:**

- `truncate(2)` coverage requires Landlock ABI v3 (Linux 6.2+).  On 5.13–6.1
  kernels, a truncate-to-zero write to a sensitive file is NOT blocked.
- Symlink races at the directory boundary have edge cases that are documented
  in the Landlock design but out-of-scope for this implementation.

If Landlock is unsupported (kernel < 5.13 or feature not compiled in), the
shield prints a warning and runs the agent unsandboxed (fail-open).

---

## Architecture position

```
agent (claude / codex / cursor)
  ↑ wrapped by
agentjail-shield   ← OS sandbox: EPERM at the kernel (Tier 1.5)
  +
agentjail-hook     ← PreToolUse: policy logic + UX + MCP allowlisting (Tier 1)
```

The hook still runs on every tool call.  The shield is the safety net for
what the hook cannot catch (shell tricks, other interpreters, obfuscation).
Neither replaces the other.

---

---

## Network egress

> macOS only (Tier 1.5 / 1.75).  Linux: Landlock has no network ABI; a
> warning is printed at startup and egress is unrestricted.  eBPF enforcement
> is Tier 3.

On macOS, agentjail-shield adds a **default-deny network** rule to the sbpl
profile and (by default) launches **agentjail-netproxy** to enforce per-host
allowlisting via HTTPS CONNECT proxying.

### Per-host enforcement via agentjail-netproxy (default)

When `agentjail-netproxy` is available (Tier 1.75), the shield:

1. Starts `agentjail-netproxy` as a child process on `127.0.0.1:9100`.
2. Generates an sbpl profile that restricts the agent to **localhost-only**
   outbound TCP (no wildcard `*:443` / `*:80` rules).
3. Sets `HTTPS_PROXY=http://127.0.0.1:9100`, `HTTP_PROXY`, and `ALL_PROXY`
   in the agent's environment.

All HTTPS CONNECT requests flow through the proxy.  The proxy enforces
`network.allowed_hosts` from policy.yaml:

- **Allowed host:** proxy returns `200 Connection established`, then pipes bytes
  bidirectionally to the upstream.
- **Denied host:** proxy returns `403 Forbidden` with
  `X-Agentjail-Deny: host=<hostname>` and body `host not in network.allowed_hosts`.

**Finding the netproxy binary** (first match wins):
1. `$AGENTJAIL_NETPROXY` env var
2. `~/.agentjail/bin/agentjail-netproxy`
3. Sibling of the shield binary itself

If the binary is not found, the shield falls back to port-based mode with a
warning.

**Caveat:** Non-HTTP clients (raw socket code, gRPC without proxy support,
`/dev/tcp` bash redirections) bypass the proxy entirely and will be denied by
the sbpl localhost-only rule.  This is the safer default — the agent cannot
reach arbitrary hosts via raw TCP.

### Port-only mode (--no-netproxy)

Use `--no-netproxy` to revert to port-based behaviour.  The sbpl
profile will allow outbound TCP on port 443 and 80 to any host:

| What is allowed | How |
|---|---|
| macOS system DNS resolver (mDNSResponder) | `(literal "/private/var/run/mDNSResponder")` |
| DNS over UDP (port 53, any remote address) | `(remote udp "*:53")` — raw UDP resolvers (nslookup, dig) |
| Loopback (`localhost:*`) | `(remote ip "localhost:*")` — local dev servers |
| HTTPS (port 443, any host) | `(remote tcp "*:443")` |
| HTTP (port 80, any host) | `(remote tcp "*:80")` |

Everything else — C2 beacons on non-standard ports, raw ICMP, UDP exfil — is
denied with `(deny network*)`.

**Important:** Port-only mode cannot distinguish `api.github.com` from
`attacker.com` at the network layer.  Both use port 443.

### Default `allowed_hosts` list

The hosts in `network.allowed_hosts` are used by agentjail-netproxy to build
its allowlist.  In port-only mode (`--no-netproxy`), their resolved IPs are
logged at startup for audit visibility but are not enforced.

Default hosts (from `agentpolicy/config/config.go`):

```
api.github.com
raw.githubusercontent.com
codeload.github.com
registry.npmjs.org
pypi.org
files.pythonhosted.org
crates.io
proxy.golang.org
sum.golang.org
deno.land
```

### Adding custom hosts

```yaml
network:
  allowed_hosts:
    - api.github.com        # default
    - registry.npmjs.org    # default
    - my-internal-registry.corp.example.com  # custom
```

The netproxy hot-reloads on SIGHUP — no need to restart the shield session.
In port-only mode, the shield must be restarted for changes to take effect.

---

## Building

```sh
# From the repo root
go build ./cmd/agentjail-shield/

# Run tests (macOS integration tests require sandbox-exec)
go test ./cmd/agentjail-shield/ -race -v -timeout 120s

# Smoke test (includes network egress fixtures on macOS)
bash cmd/agentjail-shield/test/smoke.sh
```
