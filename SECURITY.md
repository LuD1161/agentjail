# Security policy

agentjail is a security tool — credential issuance, policy enforcement, audit. Bugs in here can leak credentials, bypass enforcement, or distort audit trails. We take that seriously.

## Supported versions

Pre-1.0. Only `main` is supported. Pinning a non-main SHA is at your own risk.

## Reporting a vulnerability

**Do not open a public GitHub issue.** Instead, email the maintainer:

📧 **security@agentjail.io** (subject prefix: `[agentjail security]`)

Include:
- A clear description of the issue and the impact you observed
- A reproducer (smallest possible — a single fixture, a curl command, a script)
- Affected component: hook binary, daemon, policy engine, kernel sandbox, or netproxy
- Whether the issue is exploitable without insider access
- Your handle / org (for credit) and whether you want it disclosed publicly

We will acknowledge receipt within **2 business days** and aim to send a first triage assessment within **7 calendar days**. We'll keep you posted as we work through it.

## Disclosure

Default: **coordinated disclosure**. We patch on `main`, publish a security advisory through GitHub once a fix is in a tagged release, then credit you in the advisory unless you ask otherwise. If we believe the bug is being exploited in the wild, we may shorten the embargo.

## Scope

In scope (priority order):

1. **Credential leakage** — anything that lets a wrapped agent retrieve or exfiltrate a credential it doesn't have a capability for, or any way to make the mitmproxy redactor miss a registered credential substring in a form we'd reasonably expect it to catch (transparent base64 / URL-encoded / JSON-string-escaped).
2. **Policy bypass** — anything that lets one principal act as another, or lets an agent circumvent hook decisions. This includes peer-credential checks and any fail-open code path on the enforcement surface.
3. **Audit integrity** — anything that lets an attacker drop, alter, or forge audit events in the local `events.jsonl` audit log.
4. **Self-tamper of agentjail state** — anything that lets a wrapped agent modify `~/.agentjail/capabilities.yaml`, `pending.jsonl`, `active-sessions/*`, or rewrite its own `events.jsonl`.
5. **Cred-path fail-open** — any code path where a credential issues despite a policy `deny`, an issuer outage, or a peer-credential rejection. The cred path is explicitly fail-closed.

Explicitly **out of scope**:

- Same-uid arbitrary code execution **outside** a wrapped agentjail session. This is the Apple/Linux sandbox boundary; agentjail doesn't claim to defend it.
- The mitmproxy substring redactor against an actively-exfiltrating agent that base64-shards the credential or invents a new encoding. This is documented as best-effort; the real boundaries are DB-side RBAC + short TTL + the credential broker (ADR 0004).
- Vulnerabilities in upstream dependencies (file those upstream — `opa`, `golang.org/x/sys`, etc.). If you find one whose patch we should ship promptly, do let us know.

## Hall of fame

Researchers who report valid security issues will be credited in `SECURITY-CREDITS.md` (created on first credit) unless they ask otherwise.

---

This policy is intentionally light at the pre-1.0 stage; expect it to harden as production deployments come online.
