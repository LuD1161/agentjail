# Gotchas

Bugs this codebase has actually shipped or nearly shipped, and the shape of the
mistake behind each. Every entry here was **invisible to a green test suite** —
that is the entry criterion. If a bug was caught by a normal test doing its job,
it does not belong here.

Read this before touching the tunnel, the policy DSL, or anything with a
per-OS backend. The [decision log](./adr/) says what we chose; this says what
bit us.

---

## The recurring shape: silent no-ops

Almost everything below is one failure mode wearing different clothes: **a thing
that looks enforced, logs like it is enforced, and enforces nothing.** It is
worse than a crash, because a crash gets fixed on the spot. agentjail exists to
prevent exactly this, so we are held to a higher standard on it than most
codebases.

When you add enforcement, ask: *if this silently did nothing, what would tell
me?* If the answer is "nothing", that is the bug — before any code is written.

---

## 1. A test that names a literal is a claim about the system

The VIP pool (`10.78.0.0/16`) allocated hostnames from `.1` up. But `.1` is the
gateway/DNS address and `.2` is the agent's own TUN address. So the **second
distinct host of every tunneled session** was handed the agent's own interface,
and its traffic never left the box.

It survived because the tests **asserted the collision**: they pinned
`10.78.0.1` and `10.78.0.2` as the expected first two VIPs. Those literals were
a claim about the address plan, and the claim was wrong and green.

- **Lesson:** assert *properties* (in-pool, not-a-datapath-address, sticky), not
  addresses. A literal in a test encodes an assumption nobody re-checks.
- **Lesson:** it presented as flakiness — exactly one host per session failed,
  and *which* one depended on DNS order, so it never reproduced in isolation.
  "Intermittent" often means "deterministic on a variable you have not found
  yet." AGE-168 was filed as a race for that reason; there was no race.
- See [ADR 0034](./adr/0034-platform-backend-shared-contract.md) (worked
  example), AGE-168.

## 2. Two packages that must agree, and one of them re-declares

`dnsvip` owned the VIP pool. `netns` separately hardcoded `TUNAddrCIDR =
"10.78.0.2/16"`. `tunnel` documented the gateway as `10.78.0.1`. Three packages,
one address plan, no shared constant — so they drifted, and #1 happened.

- **Rule:** when two packages must agree on a value, **one owns it and the
  others derive it**. `netns.TUNAddrCIDR` is now `dnsvip.AgentV4()`.
- The same rule caught `SSL_CERT_FILE`: the bundle the env names must hold the
  same roots the bind-mount installs, so both read `netns.CATrustPaths()`.
- This is [ADR 0034](./adr/0034-platform-backend-shared-contract.md) applied off
  the OS axis. Drift is not only a per-OS problem.

## 3. Config that parses is not config that applies

`network.tunnel_mitm: false` — the documented, ADR-blessed way to refuse TLS
interception — was **silently ignored for its entire existence**. The YAML
parsed fine. `Merge` then copied `PolicyConfig` field-by-field into a fresh
struct, and nobody had added `TunnelMITM` to it. Every install that wrote the
opt-out got decrypted anyway.

- **Lesson:** field-by-field merge is a silent-dropping machine. There is now a
  reflection guard (`TestMergeCarriesEveryNetworkField`) that fails when a new
  field is added to `NetworkConfig` and not to `Merge`.
- **Lesson:** unit-testing the parser proves nothing about the **enforcement
  path**. Test the path a real launch takes (`LoadPolicyForEnforcement`), not
  just `yaml.Unmarshal`.
- See AGE-227's sibling fix; ADR 0077 (D3).

## 4. Fail-open is a floor, not a place to put errors

The tunnel is deliberately fail-open: a broken tunnel must never choke the
agent's network ([ADR 0079](./adr/0079-agent-netns-veth-vs-userns-tunfd.md)).
That is right for *infrastructure* failure. It is wrong for *user* error.

A malformed policy template made `NewForwardGateway` fail, which dropped the
session to netproxy — traffic flowed, the tunnel was never up, and **all L7
policy silently vanished**. Same for `AGENTJAIL_NETPACKS_DIR` pointing at a
typo'd path.

- **Rule:** validate user input in the **launch path**, where you can refuse.
  Never hand a user error to a component whose contract is "never fail loudly".
  A bad template now refuses to launch and names the file, matching what
  `policy.yaml` already did ([ADR 0040](./adr/), [ADR 0041](./adr/)).
- **Ask:** "if this errors, where does the error land?" If the answer is a
  fail-open path, the check is in the wrong place.

## 5. Ordering: the CA is a trapdoor

Injecting the session CA **replaces** the agent's namespace trust store. An
injected CA with no live MITM leaves the agent trusting only agentjail while
talking to real upstreams — every TLS handshake fails. Fail-*open* becomes
fail-*closed*.

So `startTunnel` does everything fallible **first** (open `network.db`), then
injects, then `SetMITM` immediately, with nothing in between that can bail.
This regressed once and is pinned by `tunnel_ca_order_test.go`.

- **Lesson:** when a step makes the system unusable until a later step
  completes, the gap between them must contain nothing that can fail.
- See [ADR 0077](./adr/0077-tunnel-mitm-default-and-consent.md) (D6).

## 6. Report what happened, not what you asked for

The launch banner printed "TLS interception ON" from the *requested* flag. When
interception then failed and fell back to a plain relay, the banner still said
ON — claiming to decrypt while relaying opaque. The exact misrepresentation
ADR 0077 D4 forbids, pointed backwards.

- **Rule:** surface the posture **achieved** (`sess.mitmActive`), never the one
  requested. Applies to any status output: it is a report, not an intention.

## 7. `filepath.Match`'s `*` does not cross `/`

`path: ["/repos/*"]` does **not** match `/repos/torvalds/linux`. It matches
`/repos/torvalds` and stops. So the obvious rule silently under-covers, and a
shallow test of `/repos/foo` passes and convinces the author it works. The
working spelling today is `re:^/repos/`.

- Unresolved by choice — making `*` cross `/` would silently **widen** every
  existing rule, which is a DSL decision, not a bug fix. AGE-230.

## 8. yaml.v3 ignores unknown keys unless you tell it not to

A template using a plausible-but-wrong shape (Nuclei's `http:` block) decoded
into an empty `MatchSpec` — **which matches everything** — with an empty action.
It logged `policy eval` on every request and denied none.

- **Rule:** `dec.KnownFields(true)` on anything user-authored, and validate
  enums (`action` must be `allow|ask|deny`; an unknown value scored 0 and was a
  silent no-op).
- Turning this on immediately found that our **own** shipped `ssh.yaml` used
  `info.description`, a field the schema lacked and had been dropping silently.
  Strictness pays for itself the day you enable it.
- **Design note that saved us:** `moreRestrictive` picks the most-restrictive
  match, so a broken template could not *shadow* a valid deny. That bounded the
  blast radius to "your only template is broken". Keep that property (scenario
  G3).

## 9. `http.ReadRequest` is not `http.Server`

The MITM reads requests with `http.ReadRequest`, which does **not** answer
`Expect: 100-continue` (`http.Server` does, via `expectContinueReader`). So the
proxy drained a body the client was still waiting for permission to send. Every
large upload hung — S3 `PutObject`, Docker pushes, any big curl POST.

- **Lesson:** dropping to a lower-level API silently drops the conveniences that
  API was providing. Enumerate what the high-level thing did for you.
- **Lesson on diagnosis:** it *looked* like the 1 MiB body-scan cap, and the
  correlation was perfect (curl adds the header for large bodies). It was not.
  Suppressing the header let a 2MB body through fine. **Test the mechanism you
  suspect before you fix it** — the obvious cause was wrong.
- AGE-226.

## 10. Trust-store env vars replace, they do not add

`SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` *replace* the trust store.
`NODE_EXTRA_CA_CERTS` *adds* to it. All three pointed at the bare CA, so the
agent trusted agentjail and nothing else.

Under full interception this mostly works — every upstream is re-signed by us —
which is why it survived. It breaks for TLS we do not terminate (any non-443
port): `verify error:num=20 unable to get local issuer certificate`.

- **Lesson:** "it works" is not "it is correct". This was load-bearing on an
  assumption (*we terminate everything*) that nobody had written down and that
  was already false.
- AGE-221.

## 11. IP literals need IP SANs

Leaf certs were minted with `DNSNames: []string{host}` always. No verifier
accepts a DNS SAN for a connection to an IP, so every `https://<ip>` failed —
with a cert error, not a policy denial, so it looked like our proxy was broken
rather than our cert.

- **Subtlety worth keeping:** `tls.Config.ServerName` must stay **set** for an
  IP target. Go omits an IP from the SNI extension itself and uses `ServerName`
  to *verify* the IP SAN — clearing it skips verification rather than fixing it.
  An earlier plan had this backwards; the comment in the code exists so nobody
  "fixes" it back.
- AGE-220.

## 12. Advertise what you serve

The MITM's `tls.Config` set no `NextProtos`, so ALPN settled on HTTP/1.1 by
omission. curl downgrades quietly; gRPC fails. AGE-222 made this honest by
saying `http/1.1` explicitly and auditing an h2 offer once per session; AGE-223
then made it real — the MITM now offers `["h2", "http/1.1"]` and serves h2 for
real when a client negotiates it ([ADR 0102](./adr/0102-mitm-serves-h2.md)).

- **Trap:** `ConnectionState().NegotiatedProtocol` **cannot** tell you what the
  client wanted from inside the handshake callback — it reports what was
  agreed, which is only known *after* `Handshake()` returns. The offer itself
  is only visible in `GetConfigForClient` (`ClientHelloInfo.SupportedProtos`),
  so recording "what was offered" and checking "what got negotiated" are two
  different points in the code, joined by a captured local, not a field on the
  config.
- **Once per session, not per connection.** An agent opens many connections;
  per-connection notices become noise, and noise is filtered out and stops being
  a notice at all. This survived AGE-223: the notice now fires only when the
  TLS stack picks something other than h2 despite an h2 offer and our
  server-preference h2-first list — a real anomaly, not the common path.
- AGE-222 (honest), AGE-223 (actually serve h2, done).

## 13. curl is not an agent

`--tunnel` started every agent in `/`, the filesystem root — `nsenter` with no
working directory uses the *target's* cwd, and the target is the namespace
holder. No project files, no repo, `getcwd()` failing outright. The feature was
unusable for its actual purpose.

A 44-scenario curl matrix passed throughout. **curl does not care what directory
it is in.** Relative paths, git, project files — everything that makes an agent
an agent — went untested until a real agent ran. Claude Code refused the task
and its refusal *was* the bug report: *"The working directory is `/` ... not
writable, not listable, and not a git repository."*

- **Rule:** the e2e suite must include a real agent doing a real task
  (`test/tunnel-e2e/baseline-agent-task.sh`). Synthetic traffic tests the
  network path; it does not test the *product*.
- **Diagnostic trap:** the first fix (`nsenter --wd`) *looked* like it worked —
  bash's `pwd` builtin reads `$PWD` and printed the right answer while
  `getcwd()` was returning EACCES and git was broken. Probe with the real
  syscall (`/bin/pwd`, `git rev-parse`), not the shell builtin.
- AGE-231.

## 14. A comment claiming single-source-of-truth is not a mechanism

`internal/store` said of its redaction list: *"This is the single source of
truth."* It was not — `internal/mitm` kept a second, weaker one, and AGENTS.md
repeated the claim. Each had a hole the other covered:

| header | store (substring) | mitm (exact list) |
|---|---|---|
| `Dd-Api-Key` | ✓ contains "key" | ✗ **leaked to network.db** |
| `Cookie` | ✗ no substring matches | ✓ |

A real session persisted a vendor API key in the clear, against ADR 0032.

- **Rule:** enumerating names loses to the next vendor's spelling. Match by
  pattern, and name exceptions explicitly with the reason attached.
- **Rule:** if two packages must agree, the agreement lives in a package they
  both import — not in a comment. (Same shape as #2, which is the point.)
- **Why it was only found now:** curl never sends a vendor telemetry header.
  Claude Code does, on every session. AGE-232.

## 15. A fixed bug can uncover an older one

Restoring the agent's cwd (#13) made the e2e git scenario start failing. It was
not a regression: the shield has **always** broken git inside a *git worktree*,
where `.git` is a file pointing at `<main>/.git/worktrees/<name>` and Landlock
grants the cwd but not that path. Before the cwd fix the agent ran in `/`, had
no repo context, and the scenario passed by having nothing to do.

- **Rule:** when a fix makes an unrelated test fail, find out which of the two
  is wrong before touching either. Here the test was right, the fix was right,
  and a third thing was broken all along.
- **Rule:** a scenario should fail for its own reason. A10 tests TLS trust for
  GnuTLS clients; it must not fail because of a filesystem bug, so it now runs
  from a neutral directory, and the worktree case has its own scenario.
- AGE-241 (open — it affects `main`, not just the tunnel).

## 16. Adapter tests must cross the policy boundary

Cursor adapter tests proved that its shell and MCP payloads reached the daemon,
but the fixtures asserted Cursor's native event and tool names. The daemon
accepted those strings while every Rego rule expected the canonical
`PreToolUse` / `mcp__<server>__<tool>` contract. The tests were green while
dangerous shell commands and blocked MCP servers both missed their policies.

The same adapter also emitted `ask` for `beforeReadFile`, although Cursor only
accepts `allow|deny` for that event, and discarded the common
`workspace_roots` field needed for project membership.

- **Rule:** an adapter test must evaluate its translated request through the
  real policy engine and assert the firing `rule_id`, not stop at socket
  serialization.
- **Rule:** response tests are event-specific. A verdict supported by one hook
  schema may be invalid in another hook from the same client.
- GitHub #12, #13, #14.

## 17. A retry is not an approval

The evaluator remembered the first `ask` for each session and rule, then
silently changed every retry to `allow`. That made repeated Codex tool calls
bypass policy even though Codex hooks cannot report an approval. The green test
suite explicitly asserted this unsafe promotion as intended behavior.

- **Rule:** authorization state must come from an authenticated approval event,
  never inferred from repetition.
- **Rule:** clients without an approval callback must keep receiving `ask`;
  their adapters decide how to present or fail closed on that verdict.

## 18. Recovery evidence outranks a stale marker

The hook's fail-open marker survived a transient daemon timeout, so `doctor`
continued saying the daemon had never restarted even after newer policy
decisions proved enforcement had resumed.

- **Rule:** a health report must reconcile historical markers with newer
  positive evidence before describing an incident as ongoing.
- **Rule:** distinguish “this call failed open” from “protection is still off.”

## 19. Read-only config is not writable agent state

The macOS shield listed `~/.codex` and `~/.cursor` as read-only in the shared
path contract, then separately denied writes to both directories. Codex could
launch, but its SQLite state initialization failed with “attempt to write a
readonly database.” The green profile tests did not exercise a real Codex
startup.

- **Rule:** every agent state directory belongs in the shared writable-path
  contract; do not duplicate a contradictory per-OS deny override.

## 20. CLI aliases can disappear upstream

Codex 0.145 removed the legacy `--yolo` spelling while users and wrappers still
invoked it. The AgentJail shim forwarded the argument faithfully, so Codex
rejected the command before a session began.

- **Rule:** compatibility belongs at the adapter boundary; translate removed
  aliases to the current explicit flag without weakening AgentJail's outer
  shield.

## 21. A pre-exec activation record is provisional

The macOS shield recorded `shield.activated` immediately before `sandbox-exec`,
but a nested Seatbelt launch can fail at `sandbox_apply` after that write. The
audit trail then claimed activation with no matching failure, even though the
agent never started under the requested inner sandbox.

- **Rule:** when an exec-based enforcement handoff returns, record its failure
  against the same launch; a pre-exec activation event alone is not proof that
  the kernel accepted the sandbox.

## 22. A rendered denial is not necessarily a policy denial

Codex PreToolUse cannot render a native interactive `ask`. The hook therefore
failed closed, but the decision store only retained the rendered result. A user
could not distinguish policy deciding `deny` from policy deciding `ask` that a
specific agent protocol had to render as deny.

- **Rule:** preserve the canonical policy action and record the adapter's
  effective action, identity, and translation reason separately.
- **Rule:** final action and enforcer answer a different question: what
  ultimately happened and whether policy or the sandbox enforced it. Do not
  overload them to explain protocol translation. See ADR 0115-agent-decision-adapters.

## 23. A wildcard matcher is not a capability classification

Codex's hook matcher admitted every `collaboration.*` tool, while policy only
listed older undotted spellings. Known calls reached `resolver/default`; a new
upstream collaboration tool would have been treated as though it were already
reviewed. The unit suites were green because matcher and policy were tested
separately.

- **Rule:** enumerate agent-internal capabilities exactly, and test that every
  matcher-admitted name has a non-default policy result. Unknown names must
  remain unclassified and fail safe.

## 24. Rego namespaces are extensible unless the extension surface is enforced

Custom rules were checked for `decision` with a text pattern, but Rego lets a
second `rule_disabled` body extend the resolver predicate. That could filter a
locked candidate before priority resolution while still compiling cleanly.

- **Rule:** validate custom modules from their AST and accept only partial
  `candidate` entries. Repeat that validation when the daemon loads files that
  were placed in the rules directory outside the CLI. See ADR 0116-custom-rule-surface.

## 25. A recovery command must not become an unconfigured service

The fail-open banner told users to run `agentjail daemon restart`, but `daemon`
was the hidden process-role dispatcher. It forwarded the positional word
`restart` to the daemon, which ignored it and started without `--rules`. That
process won the singleton lock and served `resolver/default`, allowing every
otherwise-covered request while launchd correctly stood down. Existing daemon
tests were green because they exercised the symlinked role with its explicit
flags, not the recovery command shown to users.

- **Rule:** reserve and test every human-facing verb before forwarding role
  arguments; recovery instructions are executable security surface, not prose.

## 26. Shell text is not all executable shell

The sensitive-path rule scanned the entire Bash command string. Its credential
denials were green, but a static `git commit -m` message documenting
`/etc/resolv.conf` was denied as though Git would open that path.

- **Rule:** exclude only grammar-bounded inert fields, then scan everything
  else. Double-quoted command substitutions, other arguments, chained commands,
  heredocs, and remote-shell payloads stay covered unless a real shell parser
  can prove where execution occurs. See ADR 0001-os-sandbox-enforcement-layer.

## 27. Error words are not evidence of failure

The outcome hook scanned every successful tool response for `EPERM`,
“operation not permitted,” or the words “sandbox” and “deny.” Reading
AgentJail's own documentation therefore turned policy-allowed, successful
commands into recorded sandbox blocks while all outcome tests stayed green.

- **Rule:** classify a sandbox denial only after the agent protocol proves the
  tool failed. Output prose is supporting detail, never the failure signal.
- **Rule:** model success and failure events separately when the upstream
  protocol does. See ADR 0112-final-action-outcome.

## 28. A page limit is not a snapshot definition

`agentjail logs --no-follow` queried decisions oldest-first with a 1,000-row
limit and exited after that first page. It looked like a bounded snapshot, but
on a busy database it omitted every recent decision—the exact rows a policy
investigation needed.

- **Rule:** define which window a bounded view means before applying `LIMIT`.
  Select newest-first for a "latest N" window, reverse only for chronological
  presentation, and use keyset pagination when the command promises all rows.
  See ADR 0018-sqlite-local-store.

## 29. Updating binaries does not update derived launchers

The updater correctly swapped binaries and reconciled role symlinks, so its
tests stayed green. PATH shims are generated scripts, though, and neither the
manual nor daemon updater regenerated them. A user who had opted in before
Codex and Cursor support kept only the old Claude wrapper after updating.

- **Rule:** every update path must reconcile derived launchers after the binary
  swap, using the same target and consent contract as install. See
  ADR 0062-path-shim-consent-is-the-rc-block.

## 30. A rewritten command is not evidence of approval

Codex applies `PreToolUse` input rewrites before it considers execpolicy. A
rewritten approval-broker command therefore runs under `--ignore-rules` without
emitting `PermissionRequest`; a test that only covered an approved prompt could
mistake that rewrite for user authorization. A static allow rule would make the
same bypass permanent.

- **Rule:** minting a challenge and seeing a native prompt are distinct states.
  Redeem only a one-use challenge that the matching `PermissionRequest` armed;
  cancel, bypassed rules, replay, expiry, later tool calls, and unverifiable
  process ancestry must deny.
- **Rule:** test the installed Codex version with approve, cancel, and
  `--ignore-rules` paths. A hook-schema unit test cannot establish this ordering.
  See ADR 0118-codex-approval-broker.

## 31. A latency target is not an availability deadline

The Codex SessionStart hook could connect to a healthy daemon, but the first
`git push` evaluation exceeded the hook's 45 ms round-trip deadline. The hook
reported the daemon as unavailable and failed open, so Codex displayed its own
prompt for the original command instead of AgentJail's opaque approval broker.
Warm latency tests and profile-shape tests remained green.

- **Rule:** keep the normal latency target separate from the timeout that
  classifies a dependency as unavailable.
- **Rule:** compatibility gates must exercise the first cold policy decision,
  not only warmed cache hits. See ADR 0118-codex-approval-broker.

## 32. A reinstall is not a clean-install test

The clean-VM provisioner ran the shipped `install.sh`, then redundantly ran
`agentjail install --for claude-code` and `agentjail install --for codex`.
Those extra installs restarted launchd, so the gate could observe a temporarily
stopped daemon and still pass after the supervisor recovered.

- **Rule:** an end-to-end install gate executes the documented user path once
  and immediately verifies the resulting daemon and hook state.
- **Rule:** test reinstall and idempotence separately; recovery must not repair
  the state whose first-install behavior the gate claims to prove. See ADR
  0053-vm-testbed-engine.

## 33. A command phrase is not an executable invocation

The remote-update rule recognized adjacent words in raw Bash text. Its tests
were green, but the valid global-option form `git -C <repo> push ...` fell
through to default allow, while an inert source-search argument containing the
same words prompted. Codex never saw an AgentJail `ask` in the bypass case.

- **Rule:** classify semantic operations from parsed executable argv, including
  the CLI's documented global-option grammar; do not infer execution from words
  elsewhere in the shell string.
- **Rule:** every command-policy scenario needs equivalent syntax variants and
  a text-only negative control. See ADR 0118-codex-approval-broker and AGE-263.

## 34. An unchanged target does not prove enforcement

The Codex `never` scenario placed the top-level `-a` flag after `exec`, whose
parser does not accept it in `0.146.0`. Codex exited before making a tool call,
the remote stayed unchanged, and the negative test appeared to pass.

- **Rule:** a denial test must prove the protected operation reached the
  intended policy boundary before asserting that the target was unchanged.
- **Rule:** run versioned CLI scenarios through the documented parser boundary;
  a usage error and a security denial are different outcomes. See ADR
  0118-codex-approval-broker.

---

## Testing gotchas

These made our own e2e suite lie to us.

### A 403 is not proof your policy fired

GitHub's unauthenticated API allows **60 requests/hour**, then returns 403 — the
same status as our deny template. The suite passed on the first run and failed
on the next, and the 403s looked like enforcement. Deny scenarios now grep for
`template=<id>` in the eval log, so they cannot pass for the wrong reason, and
generic reachability probes use a host with no rate limit.

### Assert the mechanism, not the symptom

A Python probe demanding `200` "failed" when Cloudflare bot-blocked its
User-Agent. But **any HTTP status proves TLS verification succeeded** — the
thing actually under test. Only an SSL error is a real failure. Ask what the
test is for, then assert that.

### A test that cannot fail is not a test

`TestUsageDocumentsEveryRegisteredFlag` passed when the docs were deliberately
broken, because the flag was still mentioned elsewhere in the file. It was a
no-op. **Mutation-probe every structural test**: break the thing on purpose and
watch it fail. Do this the day you write it.

The same lesson, from the policy engine: the Rego schema was filed at the wrong
root, type-checked nothing, and the first "all clear" sweep of the rule tree was
meaningless — both spellings compile, only one enforces. Caught by a deliberate
typo probe. See [ADR 0080](./adr/0080-rego-both-tiers.md).

### Your fixture is more likely wrong than the code

Three "bugs" found while building the e2e matrix were the harness: a malformed
template (wrong schema), a policy file with a `version:` key that does not
exist, and a query against a table named `requests` (it is `network_requests`).
Reproduce by hand before filing.

---

## Adding to this file

When you fix something that was invisible to a green suite, add an entry: what
looked fine, what was actually happening, and the general rule. Link the ticket
and the ADR. Keep it short — this file earns its keep by being read.
