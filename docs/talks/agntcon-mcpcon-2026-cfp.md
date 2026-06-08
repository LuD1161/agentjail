# CFP Submission — AGNTCon + MCPCon North America 2026

**Event:** AGNTCon + MCPCon North America 2026 (The Linux Foundation)
**Dates:** Oct 22–23, 2026 · San Jose McEnery Convention Center
**Speaker:** Aseem Shrey
**Framing:** Agent security · Conference talk (~35 min) · All audience levels
**Reminder from CFP:** community event — no product/vendor sales pitches. This talk
is built around **agentjail**, which is Apache-2.0 open source, so it stays on the
right side of that rule.

---

## Session Title

**Primary (recommended):**

> Your Agent Literally Can't Do That: Guardrails for Coding Agents and MCP

**Alternates:**

- When Your Agent Runs `rm -rf` at 2am: Defense-in-Depth for the Agentic Stack
- Stopping the Foot-Gun: Open, Enforceable Policy for Agents and MCP
- Least Privilege for Agents: Allow / Ask / Deny at the Tool-Call Layer

---

## Description  *(form limit: 1200 characters)*

Coding agents now hold your SSH keys, cloud credentials, and live database access —
and they act at machine speed. Most of the damage isn't malicious: it's a
well-meaning agent running `rm -rf ~/Downloads`, piping `.env` into `curl`, or
`curl get.sh | bash` because a tutorial said to. As we wire agents to MCP servers
and hand them real tools, the blast radius only grows.

This is a practical tour of agent security — the concrete ways agents and MCP
integrations go wrong, and the defense-in-depth patterns that contain them. Using
agentjail, an Apache-2.0 open-source guardrail, as the worked example, we'll trace a
single tool call through a PreToolUse hook, an OPA/Rego policy engine, and an
optional kernel sandbox — and watch allow/ask/deny verdicts land in ~8ms without
changing how you use your agent.

You'll leave with a mental model of agent threat surfaces (filesystem, command
execution, network egress, MCP servers), why fail-closed and default-deny matter,
and how to enforce policy at the layer agents already expose — no agent forking
required.

---

## Topic  *(pick the closest dropdown option)*

Recommended: **Security** — or, if present, **Agent Safety / Trust & Security** /
**MCP Security**. (Sessionize will show the event's fixed list; choose the nearest.)

---

## Session Format

**Session / Presentation** (single speaker, ~35 min). Not a panel or workshop.

---

## Audience Level

**Any / All levels.** The threat-surface framing is accessible to anyone using
agents; the hook → OPA → kernel internals reward the practitioners.

---

## Benefits to the Ecosystem
*"How will your proposed talk positively impact MCP and the broader agent landscape?"*

As MCP adoption accelerates, agents are being granted real-world capability —
filesystem, shell, network, and third-party servers — faster than the ecosystem has
built guardrails for them. This talk moves the community's security conversation from
"trust the model to behave" to "enforce least privilege at the tool-call boundary,"
a property MCP's own architecture makes possible.

It gives attendees a shared vocabulary for agent threat surfaces and a concrete,
**open and interoperable** pattern they can adopt the same day: policy-as-code (OPA/
Rego) evaluated in the PreToolUse hook every major agent already ships, with optional
kernel-level enforcement underneath. Because the example tooling is Apache-2.0 and
standards-based rather than a proprietary product, the patterns transfer to any
agent or MCP host — raising the security floor for the whole ecosystem rather than
one vendor's stack. Attendees leave able to write and ship a policy that contains a
real failure mode for their own agents and MCP servers.

---

## Presented this talk before?

**No** — this is a new talk. (Related themes on application/agent security have been
presented previously, e.g. at QCon, but this session and its agentjail material are
new.)

---

## Speaker Bio  *(form limit: 500 characters)*

Aseem Shrey is the founder of ShipSecure.ai, an AI-powered security agent platform,
and SecureMyOrg, a consultancy that automates security with open-source tooling.
He's been a security engineer at Yahoo, Rippling, Gojek, and Blinkit, and runs the
HackingSimplified YouTube channel teaching practical appsec. He has responsibly
disclosed critical bugs to the US DoD, Govt of India, IBM, Sony, and GM, and is the
creator of agentjail, an open-source guardrail for coding agents.

---

## Speaker logistics fields

| Field | Suggested value |
|---|---|
| Are you both submitter and speaker? | **Yes** |
| Company | **ShipSecure.ai** (or SecureMyOrg — pick your primary affiliation) |
| Speaker Title | **Founder** |
| Country of residence | *(fill in — not inferred)* |
| Fediverse | *(optional — leave blank or add handle)* |
| Co-speakers | *(none, unless you want to add one)* |
| Code of Conduct / Inclusivity / Content Quality | ✅ check all three |
| Demographic questions | *(your choice — optional/confidential)* |

> **Note on the no-pitch rule:** keep the framing on agentjail (Apache-2.0) and the
> general agent-security patterns. Avoid positioning ShipSecure.ai as a product in
> the talk; list it only in your bio/affiliation.
