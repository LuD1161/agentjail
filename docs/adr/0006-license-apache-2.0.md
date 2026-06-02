# 0006 — agentjail license: Apache-2.0 (supersedes the MPL-2.0 choice)

Status: Accepted — supersedes the 2026-05-23 MPL-2.0 decision

## Context

The 2026-05-23 decisions-log entry put the `agentjail` module under MPL-2.0,
reasoning that file-level copyleft would signal "contribute changes back"
without blocking combination with proprietary code. Since then the launch
posture clarified: **agentjail is the single open-source repository and the
adoption wedge for an open-core company.** The commercial value (the policy
control plane / SaaS in `agentpolicy` + `saas`) stays closed; the local
enforcement engine is what we want adopted everywhere.

The on-disk `LICENSE` and README were already Apache-2.0 ahead of this record;
this ADR ratifies that and retires the stale MPL-2.0 references.

## Decision

License `agentjail` under **Apache-2.0**.

Rationale, given agentjail is the sole OSS artifact and an adoption wedge:

- **Adoption with zero friction.** Apache-2.0 is the universal default for
  infrastructure/dev tooling; enterprise legal teams approve it without review.
- **Explicit patent grant + retaliation clause.** Material for a *security*
  product — and the decisive reason to choose Apache over MIT/BSD, which have
  no patent grant.
- **One consistent license.** The root module is already Apache-2.0; aligning
  the OSS layer removes the "root is Apache, layer is MPL" split.
- **The moat is elsewhere.** Value capture is the closed control plane, not the
  engine, so MPL's weak (file-level) give-back buys little and costs review
  friction. Strip-mining risk is low: agentjail is a local enforcement engine,
  not a hostable service.

Rejected:
- **MPL-2.0** (prior choice): marginal give-back for an embed-and-build-on-top
  tool; people build *around* the engine (allowed under MPL anyway) far more
  than they modify its files.
- **AGPL-3.0 / BSL / SSPL**: the defensive options if engine strip-mining were a
  real threat. AGPL stays OSI-approved but deters enterprise embedding of a
  *security* tool; BSL/SSPL are source-available, not OSS, and would undercut
  the open-source launch narrative. Revisit only if the engine itself (not the
  control plane) becomes a thing competitors host.
- **MIT/BSD**: no patent grant — wrong for a security product.

## Consequences

- **Relicense is clean and was done pre-launch.** All code is first-party with
  no external contributors yet, so we hold full copyright and can relicense
  freely. This window closes once outside PRs land (would then require every
  contributor's consent or a CLA) — hence doing it before launch.
- **Dependencies are compatible.** OPA (Apache-2.0), bubbletea (MIT), x/sys
  (BSD) are all permissive; Apache-2.0 redistribution introduces no copyleft
  obligation.
- **Contribution terms** are recorded in CONTRIBUTING.md ("By contributing, you
  agree your work is licensed under Apache-2.0") and gated by DCO sign-off
  (the `DCO` CI check) rather than a CLA.
- **If `agentpolicy` ever opens too**, revisit whether the two layers should
  share Apache-2.0 or deliberately differ.
