# ADR 0024 — Env stripping at launch

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** agentjail-core
- **Related:** [ADR 0004](0004-credential-broker-tier1.md) (credential broker), [ADR 0023](0023-secret-server.md) (secret server)

## Context

Even with Landlock/Seatbelt filesystem restrictions and netproxy network
filtering, a sandboxed agent can still use ambient credentials that are
present in its environment variables.  If the user's shell has
`AWS_SECRET_ACCESS_KEY` set (e.g. from `~/.aws/credentials` via a shell
profile), the agent's Python script can call `boto3.client('s3')` and use
those creds directly — no filesystem read needed, no network bypass needed.

This is the "ambient credential" attack surface from ADR 0004: the agent
doesn't need to read `~/.aws/credentials` if the creds are already in its
environment.  The shield's filesystem deny doesn't help; the creds never
touched the filesystem from the agent's perspective.

## Decision

Strip ambient credentials from the agent's environment **before** exec'ing
it.  This is implemented in `agentjail-shield` via a shared `stripEnv()`
function called by both the macOS and Linux shield implementations.

### Blocklist

A configurable blocklist in `policy.yaml` determines which env vars to strip:

```yaml
secrets:
  env_blocklist:
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
    - "*_API_KEY"        # glob: matches any var ending in _API_KEY
  strip_on_launch: true   # default: true
```

The default blocklist covers common cloud/DB/SaaS credential env vars:

| Var | Why |
|---|---|
| `AWS_ACCESS_KEY_ID` | AWS direct creds |
| `AWS_SECRET_ACCESS_KEY` | AWS direct creds |
| `AWS_SESSION_TOKEN` | AWS STS session |
| `AWS_SECURITY_TOKEN` | AWS legacy session |
| `AWS_DELEGATION_TOKEN` | AWS SSO delegation |
| `PGPASSWORD` | Postgres password |
| `REDIS_PASSWORD` | Redis password |
| `GITHUB_TOKEN` | GitHub PAT |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `OPENAI_API_KEY` | OpenAI API key |

Glob patterns use `path.Match` semantics: `*` matches any sequence of
non-`/` characters.  This allows patterns like `*_API_KEY`,
`*_SECRET_ACCESS_KEY`, `*_TOKEN` to catch credential vars from other
services without enumerating every possible name.

### Placeholder replacement

If the `agentjail-secrets` broker is running (detected by probing the Unix
socket at `~/.agentjail/secrets.sock`), the shield adds
`AGENTJAIL_SECRETS=1` to the agent's environment.  This signals to the
agent (or to user scripts) that scoped creds are available via the broker
(`agentjail-secrets grant`).

Full scoped-cred injection (the shield calling `grant` and injecting the
resulting env vars) is now wired: the shield calls `agentjail-secrets grant`
for each entry in `secrets.grants`, injects the returned env vars, and
revokes grants on agent exit (Linux) or relies on TTL (macOS, which uses
`syscall.Exec`). See ADR 0023 for the secret server design.

### `StripOnLaunch` as `*bool`

`secrets.strip_on_launch` is a `*bool` in the Go config struct so that
"not specified in YAML" (nil) can be distinguished from "explicitly set to
false".  When nil, the default (true) is used.  This lets users disable
stripping explicitly:

```yaml
secrets:
  strip_on_launch: false
```

### Config integration

The `SecretsConfig` section is added to `agentpolicy/config/PolicyConfig`,
integrated with `Default()`, `Merge()`, and `ToOPAData()` so it's available
to the daemon (via OPA data) and the shield (via direct config read).

## Consequences

**Positive:**
- Ambient credentials are removed from the agent's environment before it
  starts.  A Python script doing `boto3.client('s3')` fails with
  "NoCredentialsError" instead of silently using the user's AWS creds.
- Combined with the shield's filesystem deny on `~/.aws/`, the agent has
  neither env-var creds nor file creds — it must go through the broker.
- Glob patterns allow extending the blocklist without code changes.
- The `AGENTJAIL_SECRETS=1` placeholder lets agent scripts detect the
  broker and call it for scoped creds.

**Negative:**
- Env stripping is best-effort: it only strips env vars matching the
  blocklist.  A credential in an env var with an unusual name (e.g.
  `MY_DB_PASS`) won't be stripped unless the user adds it to the blocklist.
- The `AGENTJAIL_SECRETS=1` placeholder is informational — the agent must
  be written (or configured) to use the broker.  Existing agents that
  expect `AWS_ACCESS_KEY_ID` in the environment will fail until they're
  updated or the shield injects scoped creds (future work).
- `strip_on_launch: false` disables all stripping.  This is a foot-gun
  for the user, but it's their choice (the foot-gun model).

**Implementation notes:**
- `cmd/agentjail-shield/envstrip.go` — shared `stripEnv()` function
- `agentpolicy/config/config.go` — `SecretsConfig` struct, `Default()`,
  `Merge()`, `ToOPAData()` integration
- Called from both `shield_darwin.go` and `shield_linux.go` before exec
- Tests: `envstrip_test.go` covers stripping, glob patterns, custom
  blocklist, disabled stripping, nil config, default blocklist coverage,
  YAML loading, Merge behavior, OPA data output.
