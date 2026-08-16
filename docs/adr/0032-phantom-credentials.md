# ADR 0032 — Phantom credentials and protocol-aware proxy

- **Status:** Proposed
- **Public CLI:** Deferred by ADR 0133-cli-command-surface until the production
  phantom registry is wired
- **Date:** 2026-06-29
- **Deciders:** agentjail-core
- **Related:** ADR 0004 (credential broker), ADR 0001 (OS sandbox),
  ADR 0022 (netproxy)

## Context

The Landlock shield blocks file access to credential paths (`~/.ssh`,
`~/.aws`, `~/.gnupg`). But two exfiltration channels remain:

1. **Environment variables.** The agent process inherits env vars from the
   shell. Even with env stripping, any credential pattern not in the
   blocklist leaks. And the agent needs SOME credentials to function
   (API keys for the services it works with).

2. **Network.** On kernels < 6.7, the agent can make direct TCP connections
   bypassing the proxy. Even with the proxy, the agent holds the real
   credential in memory and could send it to any allowed host.

The fundamental problem: if the agent has a real credential in its process
memory, it can exfiltrate it through any channel we haven't blocked.

## Decision

Never give the agent a real credential. Use phantom tokens — opaque
placeholders that the proxy swaps for real credentials at the network
boundary, only when the destination matches the allowed host.

### How it works

```
HOST SIDE                           AGENT SIDE (inside shield)
─────────                           ──────────────────────────
                                    
User stores secret:                 Agent sees env var:
  agentjail secret set github \       GITHUB_TOKEN=aj_phantom_gh_a1b2c3
    --value ghp_real_secret \       
    --hosts api.github.com          Agent runs:
                                      curl -H "Authorization: Bearer $GITHUB_TOKEN" \
Shield launches agent:                  https://api.github.com/repos
  strips GITHUB_TOKEN from env      
  injects GITHUB_TOKEN=             Proxy intercepts HTTPS:
    aj_phantom_gh_a1b2c3              1. Terminates TLS (MITM with agentjail CA)
  stores mapping in proxy:            2. Reads HTTP request
    aj_phantom_gh_a1b2c3 →            3. Finds aj_phantom_gh_a1b2c3 in headers
    ghp_real_secret                   4. Destination is api.github.com → allowed
    allowed: api.github.com           5. Swaps: aj_phantom → ghp_real_secret
                                      6. Forwards to upstream with real token
                                      7. Response flows back to agent
                                    
                                    If agent sends phantom to evil.com:
                                      Proxy sees destination ≠ api.github.com
                                      Blocks request. Logs violation.
                                      Real credential never leaves the proxy.
```

### Credential sources

Users add credentials to agentjail's vault. Three source types:

#### 1. Direct value

User provides the secret directly. Stored encrypted in
`~/.agentjail/secrets/` (AES-GCM, already implemented).

```bash
agentjail secret set github --value ghp_abc123 --hosts api.github.com
agentjail secret set openai --value sk-abc123 --hosts api.openai.com
```

#### 2. Environment reference

Pull from the host's environment at launch time. The real value never
enters the agent's env.

```bash
agentjail secret set github --from-env GITHUB_TOKEN --hosts api.github.com
```

At shield launch: read `$GITHUB_TOKEN` from host env, generate phantom,
strip `$GITHUB_TOKEN` from agent env, inject phantom as
`GITHUB_TOKEN=aj_phantom_...`.

#### 3. Keyring / external provider

Pull from system keyring, 1Password, Bitwarden, or any command.

```bash
agentjail secret set github --from-keyring github-token --hosts api.github.com
agentjail secret set github --from-command "op read op://vault/github/token" --hosts api.github.com
```

### Phantom token format

```
aj_phantom_<service>_<random_hex_16>
```

Examples:
- `aj_phantom_gh_a1b2c3d4e5f6a7b8`
- `aj_phantom_aws_f0e1d2c3b4a5f6e7`
- `aj_phantom_custom_1234567890abcdef`

The prefix makes it easy to grep for accidental leaks in logs. The random
suffix prevents collision and guessing.

### Credential policy

Each credential has:

```yaml
# ~/.agentjail/policy.yaml
credentials:
  github:
    env_var: GITHUB_TOKEN
    source: vault                    # vault | env | keyring | command
    allowed_hosts:
      - api.github.com
      - uploads.github.com
    allowed_methods: [GET, POST, PUT, PATCH, DELETE]  # optional
    allowed_paths: ["/repos/LuD1161/*"]               # optional, future
    on_violation: block              # block | block-and-log | terminate
    ttl: 8h                         # phantom validity (re-generated per session)

  anthropic:
    env_var: ANTHROPIC_API_KEY
    source: env
    allowed_hosts:
      - api.anthropic.com
    on_violation: block

  aws:
    env_var: AWS_ACCESS_KEY_ID
    source: vault
    allowed_hosts:
      - "*.amazonaws.com"
    jit: true                        # generate JIT credentials (see below)
    jit_config:
      role_arn: arn:aws:iam::123456:role/agent-readonly
      duration: 15m
      policy: |
        {"Version":"2012-10-17","Statement":[
          {"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}
        ]}
```

### JIT (Just-In-Time) credentials — for later

For AWS, database, and other services that support scoped temporary
credentials, agentjail can generate a JIT credential instead of proxying
a long-lived one:

```
User stores:        Master AWS credentials (high privilege)
Agent receives:     STS-assumed role credentials (read-only S3, 15 min TTL)
```

The JIT path:
1. At session start, `agentjail-secrets` calls AWS STS AssumeRole with the
   master creds, inline policy, and short duration.
2. The temporary `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
   `AWS_SESSION_TOKEN` are injected into the agent's env.
3. These are real credentials (not phantoms) but narrowly scoped and
   short-lived. Even if exfiltrated, they expire in 15 minutes and can
   only read S3.

JIT is better than phantom for AWS because AWS SigV4 signing happens
client-side — the proxy can't swap a phantom in a signed request without
breaking the signature. (The existing `sigv4.go` in agentjail-secrets
handles this case by re-signing with the real credentials.)

**JIT is a Phase 2 feature.** Phantom tokens handle the common case (Bearer
tokens in HTTP headers). JIT handles the complex case (SigV4, mTLS, etc.).

The infrastructure for JIT already exists: `agentjail-secrets` has
`grantPostgres()` (creates scoped PG roles with TTL) and `sigV4Sign()`
(AWS STS AssumeRole). Extending this to session-start JIT issuance is
straightforward.

### Proxy architecture

The current `agentjail-netproxy` is a CONNECT tunnel — it passes encrypted
TLS bytes through without inspection. For phantom token swapping, the proxy
needs to become a **TLS-terminating reverse proxy** (MITM).

```
CURRENT (tunnel mode):
  Agent → CONNECT api.github.com:443 → proxy → raw TCP tunnel → github
  Proxy sees: hostname only. Cannot inspect HTTP headers or body.
  
PHANTOM MODE (TLS-terminating):
  Agent → CONNECT api.github.com:443 → proxy:
    1. Proxy accepts TLS from agent (using agentjail CA cert)
    2. Proxy reads HTTP request in plaintext
    3. Proxy scans headers/body for phantom tokens
    4. If found: lookup phantom → real credential + allowed hosts
    5. If destination matches: swap phantom → real
    6. If destination doesn't match: block, log violation
    7. Proxy opens real TLS connection to api.github.com
    8. Proxy forwards request with real credential
    9. Response flows back through proxy → agent
```

#### Implementation

The proxy gains a new mode: `--phantom` (or auto-enabled when credentials
are configured).

**New components in `cmd/agentjail-netproxy/`:**

```go
// phantom.go — phantom token registry and swap logic

type PhantomEntry struct {
    Phantom      string   // aj_phantom_gh_a1b2c3...
    RealValue    string   // ghp_real_secret_key
    EnvVar       string   // GITHUB_TOKEN
    AllowedHosts []string // api.github.com, uploads.github.com
    Violation    string   // block | block-and-log | terminate
}

type PhantomRegistry struct {
    entries map[string]*PhantomEntry  // phantom → entry
}

func (r *PhantomRegistry) Swap(phantom, destHost string) (string, error)
```

```go
// tls.go — TLS termination with agentjail CA

type TLSInterceptor struct {
    caCert    *x509.Certificate
    caKey     crypto.PrivateKey
    certCache sync.Map  // hostname → *tls.Certificate (on-demand generation)
}

func (t *TLSInterceptor) GenerateCert(hostname string) (*tls.Certificate, error)
func (t *TLSInterceptor) HandleCONNECT(clientConn net.Conn, targetHost string)
```

```go
// swap.go — HTTP request/response token swapping

func SwapPhantomTokens(req *http.Request, registry *PhantomRegistry, destHost string) error
// Scans: Authorization header, X-Api-Key header, request body (for JSON payloads)
// Replaces phantom tokens with real values if destHost is allowed
```

**Changes to existing proxy:**

The proxy currently handles CONNECT like this (from `main.go:213`):
```
1. Parse CONNECT target (hostname:port)
2. Check allowlist
3. Dial upstream
4. Send 200 OK to client
5. Splice client ↔ upstream (raw bytes)
```

With phantom mode, step 5 changes:
```
5a. Accept TLS from client (using agentjail CA)
5b. Read HTTP request from client
5c. Swap phantom tokens in request
5d. Open TLS to upstream
5e. Forward request to upstream
5f. Read response from upstream
5g. Forward response to client
```

This uses Go's `httputil.ReverseProxy` with a custom `Transport` that
handles the TLS interception.

#### CA certificate trust

The agentjail CA cert must be trusted by the agent process. Options:

1. **Environment variable:** Set `NODE_EXTRA_CA_CERTS` (Node.js),
   `REQUESTS_CA_BUNDLE` (Python), `SSL_CERT_FILE` (generic). The shield
   already injects `SSL_CERT_FILE` (see `envstrip.go` line that sets CA
   env vars).

2. **System trust store:** Add the CA to `/etc/ssl/certs/` at launch.
   Requires write access to system paths (which we allow via Landlock).

3. **Per-session CA:** Generate a fresh CA per session. The private key
   exists only in the proxy's memory. Even if the agent reads the CA cert
   (public), it can't generate valid certificates without the private key.

Option 1 is simplest and already partially implemented. The existing
`~/.agentjail/ca/` directory holds the CA cert.

### Shield launch sequence (updated)

```
1. Read credential config from policy.yaml
2. For each configured credential:
   a. Resolve real value (vault, env, keyring, command)
   b. Generate phantom token
   c. Register phantom → real mapping
3. Strip real credential env vars from agent environment
4. Inject phantom env vars into agent environment
5. Inject CA cert path into SSL_CERT_FILE / NODE_EXTRA_CA_CERTS
6. Start netproxy with --phantom flag and phantom registry
7. Apply Landlock / Seatbelt
8. Exec agent
```

### Env stripping fix

The existing blocklist in `envstrip.go` should be extended to catch
more patterns. Current blocklist uses `path.Match` globs. Add:

```go
// Patterns that catch most credential env vars
"*_API_KEY",
"*_SECRET*",
"*_TOKEN",
"*_PASSWORD",
"*_CREDENTIALS",
"*_AUTH",
"*_PRIVATE_KEY",
```

Any env var matching these patterns is stripped unless it's in the
configured credential list (in which case it gets a phantom replacement
instead of being removed entirely).

### Violation handling

When the proxy detects a phantom token being sent to a non-allowed host:

**block (default):** Drop the request. Return HTTP 403 to the agent.
Log the violation with: timestamp, phantom ID, destination host,
expected hosts, agent PID.

**block-and-log:** Same as block, plus emit a structured audit event
that can be forwarded to SIEM/logging.

**terminate:** Kill the agent process immediately (via the daemon).
For high-security environments where any exfiltration attempt should
end the session.

### Audit trail

Every credential operation is logged:

```json
{"event":"phantom_issued","phantom":"aj_phantom_gh_a1b2c3","env":"GITHUB_TOKEN","hosts":["api.github.com"],"session":"aj_7f13","ts":"..."}
{"event":"phantom_swapped","phantom":"aj_phantom_gh_a1b2c3","dest":"api.github.com","method":"GET","path":"/repos/LuD1161/agentjail","ts":"..."}
{"event":"phantom_violation","phantom":"aj_phantom_gh_a1b2c3","dest":"evil.com","expected":["api.github.com"],"action":"block","ts":"..."}
{"event":"phantom_expired","phantom":"aj_phantom_gh_a1b2c3","ttl":"8h","ts":"..."}
```

### What this does NOT solve

- **SigV4-signed requests** — AWS client-side signing means the proxy
  can't swap tokens without breaking the signature. Use JIT credentials
  (Phase 2) for AWS.
- **mTLS** — client certificate authentication can't be proxied with
  phantom tokens. Use JIT or direct cert provisioning.
- **Non-HTTP protocols** — database connections (Postgres, Redis, etc.)
  use protocol-specific auth, not HTTP headers. Use the existing
  `agentjail-secrets` grant system with scoped JIT credentials.
- **Binary protocols** — gRPC, WebSocket binary frames, etc. Phantom
  swap works on HTTP text headers, not arbitrary binary streams.

For these cases, the JIT credential system (already partially built in
`agentjail-secrets`) is the answer. Phantom tokens handle the common
case (REST APIs with Bearer tokens); JIT handles the rest.

## Implementation phases

### Phase 1: Phantom tokens + TLS proxy (this sprint)

1. **Phantom registry** — generate, store, lookup phantom tokens
2. **Shield integration** — resolve credentials, strip env, inject phantoms
3. **TLS termination** — MITM proxy with agentjail CA
4. **Token swap** — scan HTTP headers for phantoms, swap if host matches
5. **Violation handling** — block/log when phantom sent to wrong host
6. **Env stripping fix** — extend glob patterns to catch `*_API_KEY`, etc.
7. **CLI: `agentjail secret set`** — store credentials with host binding

### Phase 2: JIT credentials (next sprint)

1. **AWS STS** — AssumeRole at session start with inline policy
2. **Postgres** — create scoped role with TTL (already implemented)
3. **Redis** — scoped ACL user with TTL (already implemented)
4. **Generic command** — run user-provided command to generate JIT creds
5. **CLI: `agentjail secret set --jit`** — configure JIT generation

### Phase 3: External secret backends (future)

1. **OpenBao integration** — use OpenBao (open-source Vault fork) as a
   secret backend for JIT credential generation. OpenBao supports dynamic
   secrets for AWS, databases, PKI, SSH, and more. AgentJail delegates
   JIT generation to OpenBao instead of implementing each backend:
   ```yaml
   credentials:
     database:
       source: openbao
       openbao_path: database/creds/readonly
       openbao_addr: http://localhost:8200
       ttl: 15m
   ```
   This replaces the per-backend code (postgres.go, redis.go, aws.go)
   with a single OpenBao client, getting all of OpenBao's dynamic secret
   engines for free.
2. **1Password / Bitwarden** — keyring backends (nono already does this)
3. **System keyring** — macOS Keychain, Linux Secret Service

### Phase 4: Advanced proxy features (future)

1. **Request filtering** — allow only specific HTTP methods/paths per cred
2. **Response inspection** — detect credential leakage in responses
3. **Rate limiting** — per-credential request rate limits
4. **Mutual TLS** — client cert provisioning for services that require it

## Consequences

### Positive

- The agent never has a real credential in memory. Even a fully
  compromised agent cannot exfiltrate usable credentials.
- Exfiltration to any non-allowed host is blocked at the proxy level,
  regardless of what the agent does with the phantom token.
- Works with any language, framework, or tool — the agent uses env vars
  normally, the proxy handles the swap transparently.
- Audit trail covers every credential use, every swap, and every violation.
- JIT credentials (Phase 2) extend the model to AWS, databases, and
  other services that require client-side auth.

### Negative

- TLS termination adds latency per HTTPS request (~1-5ms for cert
  generation, cached after first use per hostname).
- Some tools may reject the agentjail CA cert (e.g., pinned certificates,
  Go binaries with embedded roots). Need escape hatches.
- SigV4 and mTLS cannot use phantom tokens — requires the JIT path.
- Proxy complexity increases significantly (from a simple tunnel to a
  full MITM reverse proxy).

### Graceful degradation

| Failure | Behavior |
|---------|----------|
| No credentials configured | Proxy runs in tunnel mode (current behavior) |
| CA cert not trusted by agent | HTTPS fails with cert error. Agent sees clear error. User adds CA trust. |
| Phantom token expired | Proxy returns 401. Agent retries. Shield regenerates on next session. |
| Proxy crashes | Agent loses network. Session continues for local-only work. |
| JIT credential fails | Falls back to phantom if available. Error if not. |
