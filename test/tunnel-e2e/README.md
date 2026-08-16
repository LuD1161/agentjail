# Tunnel e2e scenario matrix

`scenarios.sh` exercises the tunnel the way a user meets it: real agents
(Claude Code, Codex), real TLS, real policy templates. It is the check that
`go test` cannot make — every bug it has found so far was invisible to a green
unit suite.

Run the **same list on both platforms**; an untested platform is where drift
hides (ADR 0034-platform-backend-shared-contract).

```sh
bash test/tunnel-e2e/scenarios.sh          # everything
bash test/tunnel-e2e/scenarios.sh --quick  # skip the real-agent scenarios
bash test/tunnel-e2e/baseline-agent-task.sh  # a real agent doing a real task
TUNNEL_SMOKE_RESULT=/tmp/tunnel-smoke.json \
  bash test/tunnel-e2e/smoke_darwin.sh --strict  # approved macOS golden only
```

Exit 0 when no scenario FAILs.

The Darwin strict smoke requires `golden-macos-mitm` and the exact activated
extension contract. It reuses the matrix's named host and path denials, then
adds a port-80 protocol denial and an explicit proxy-variable/`--noproxy`
bypass attempt. Its optional JSON result distinguishes PASS, FAIL, and SKIP and
records how many tunnel scenarios actually executed. It does not opportunistically
run a second coding agent: the selected testbed scenario supplies the required
real-agent assertion, so a Codex gate cannot absorb an unrelated missing-Claude
SKIP.

Policy assertions use post-watermark rows in `network.db` as their source of
truth. Terminal output is diagnostic only: changing `--verbose` must never
change PASS or FAIL. A path without a durable named-policy record remains a
failed release assertion until that persistence gap is fixed.
Allowed HTTPS checks also require a post-watermark capture row; an upstream 200
without that row proves reachability, not tunnel execution.

Darwin tunnels are dual-stack by default. The strict release command runs
without `AGENTJAIL_TUNNEL_IPV6` or another opt-in: an IPv6-first host must reach
the same gateway, policy, MITM, and request store as IPv4. An explicit
`network.tunnel_ipv6: false`/`--no-tunnel-ipv6` is a diagnostic opt-out, not the
release posture.

Port-80 traffic is intercepted before DNS metadata is guaranteed to be
available. The gateway therefore reads a bounded HTTP header, derives the host
from the request's `Host` field, and evaluates `host` and numeric `port` as
separate policy fields. With a matcher active, an incomplete or malformed HTTP
header is denied rather than relayed without L7 evaluation.

Consecutive Darwin sessions are serialized at the provider boundary. The host
helper waits for `NEVPNStatus.disconnected`, while the shield also requires the
session socket to stop accepting connections. Readiness is generation-bound:
the extension returns `ready` only after the matching WireGuard handshake, and
PID registration carries that same generation. A stale socket or legacy
extension cannot satisfy the contract. A failed readiness attempt is stopped
cleanly before one bounded restart; retrying `start` against the same not-ready
provider generation cannot satisfy the contract.

## The two are not interchangeable

`scenarios.sh` drives the network path with curl and friends. `baseline-agent-task.sh`
runs **Claude Code building and committing a web app** inside the tunnel, and
reports what was captured.

The second exists because the first cannot fail on the things that make an agent
an agent. It immediately found two bugs the 44-scenario matrix had passed
straight through:

- **AGE-231** — `--tunnel` dropped the agent into `/`. No cwd, no repo, no
  writes. curl does not care what directory it is in; a coding agent does
  nothing but.
- **AGE-232** — a vendor telemetry header (`Dd-Api-Key`) reached `network.db`
  unredacted. curl never sends one.

The baseline **fails the run** if any credential-shaped header reaches the DB in
the clear, so a capture cannot be published with a secret in it.

Add tasks to it as the surface grows — different tool calls exercise different
paths.

## Groups

| | what it covers |
|---|---|
| **A** | interception on (the default, ADR 0077): allow/deny, path-scoped rules, multi-host, Node/Python/git/Claude Code/Codex, logging, CA scoping |
| **B** | `--no-mitm`: the documented downgrade — traffic flows, HTTP(S) policy goes inert, the real cert chain is preserved |
| **C** | posture resolution: `--mitm` / `--no-mitm` / `network.tunnel_mitm` / default (ADR 0077 D2, D3) |
| **D** | no `--tunnel`: baseline, and no false claim of a tunnel |
| **E** | `--help` documents every flag and states the decryption default (ADR 0077 D4) |
| **F** | fail-open floor (ADR 0079) and honest posture reporting (ADR 0077 D5, D6) |
| **G** | chaos: broken template, bad action, malformed policy.yaml, missing/empty packs dir, concurrency, unresolvable host, exit codes, orphan processes, key-on-disk, large bodies |

## Result vocabulary

- **PASS** / **FAIL** — as expected.
- **XFAIL** — known-broken and ticketed. Does not fail the run.
- **XPASS** — an XFAIL scenario now passes. **Investigate**: the ticket may be
  fixed, or the scenario may have stopped testing anything.
- **SKIP** — not runnable here (missing tool, `--quick`), with the reason.

## Writing a scenario

Two rules, both learned the hard way in this suite:

1. **Assert the mechanism, not the symptom.** A `403` can come from our policy
   *or* from a rate-limited upstream; deny scenarios require an exact
   post-watermark `network.db` row with the expected policy template. Terminal
   logs are diagnostics, not evidence. A `200` from Python proves nothing about
   TLS if the assertion would also accept a bot-block — what is under test there
   is chain validation, so any HTTP status counts and only an SSL error fails.
2. **Prove the scenario can fail.** A9b exists partly as A8/A9's mutation probe:
   it verifies a bundle *without* our CA is rejected. If that ever passes,
   interception is not happening and the two tests above it are vacuous.

Keep generic reachability probes off rate-limited hosts (`api.github.com` allows
60 unauthenticated requests/hour — it made this suite non-deterministic until
the probes moved to `www.cloudflare.com`). Reserve it for the path-rule
scenarios, whose requests are denied before they ever reach GitHub.
