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
- **Rule:** recovery is a protected control action. Require an agent-inaccessible
  credential and a real terminal confirmation, then lock both the friendly CLI
  and direct supervisor forms in online and degraded-offline policy.

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

## 35. A convenience flag can collapse an integration seam

Codex's combined bypass flag disables both its sandbox and every native
approval prompt. AgentJail still classified `git push` as `ask`, but Codex
auto-rejected the broker rule because the session approval policy was `never`.
Replacing it with broad `on-request` would have silently re-enabled unrelated
approval categories.

- **Rule:** decompose umbrella flags at integration boundaries and preserve
  each intended dimension independently.
- **Rule:** test the user's real launcher arguments, not an easier approval
  mode; assert both the enabled prompt category and every category that must
  remain disabled. See ADR 0118-codex-approval-broker and AGE-263.

## 36. A prompt is not approval context

The native Codex gate appeared and the push executed only after approval, but
the prompt displayed only `agentjail approval-exec --challenge …`. Enforcement
was correct while the human still could not tell that the pending effect was a
Git push.

- **Rule:** an approval test must assert the user-visible operation label, not
  merely that some prompt appeared.
- **Rule:** expose a bounded typed effect such as `git-push`, never the raw
  shell command; scope the broker to operations whose labels are truthful.
  See ADR 0118-codex-approval-broker and AGE-263.

## 37. An operation label is not an approval payload

Adding `--operation git-push` made the native prompt truthful but still hid the
repository, remote, and refspec the user was being asked to authorize. Unit
tests and the live gate asserted the label, so both stayed green while the
approval remained too vague for an informed decision.

- **Rule:** show the redacted effective command through a supported display
  channel next to the native gate, with a visually distinct approval marker;
  never put raw shell text into executable broker metadata.
- **Rule:** live approval tests must assert both the typed operation label and
  command-specific context such as the requested ref.
  See ADR 0118-codex-approval-broker and AGE-263.

## 38. A policy transport must not enumerate policy rules

The Codex broker worked for Git push, and its full live matrix was green. The
daemon nevertheless carried a second allowlist of the two Git rule IDs, so
publish, download, AWS, resolver, and user-authored custom Bash `ask` decisions
still became denials. Adding a policy confirmation did not automatically gain
the adapter behavior that `ask` promises.

- **Rule:** adapters translate typed actions, not known rule names. Bind the
  selected rule into the authorization record, but do not use its namespace as
  a transport allowlist.
- **Rule:** compatibility tests need an unknown custom `ask` rule. A matrix
  containing only built-in rules cannot prove the adapter is policy-agnostic.
  See ADR 0119-command-approval-transport.

## 39. Swapped binaries are not an activated update

The manual updater replaced the Linux binaries and reported success without
restarting the running daemon. Unit tests verified the files, so they stayed
green while the old process kept serving old policy and approval behavior.
Even a socket-only doctor check called that stale process healthy.

- **Rule:** update is a transaction over both disk and the supervised process:
  restart after the swap, restore the exact prior paths on activation failure,
  and restart the restored daemon.
- **Rule:** health protocols report their running version, and diagnostics
  compare it with the installed CLI. Liveness alone cannot attest deployment.
  See ADR 0088-deployed-supervisor-verified.

## 40. A successful restart command is not an activated daemon

The updater treated a zero exit from launchctl or systemctl as activation, while
the old daemon could still own the socket or the new daemon could fail before
serving. A test supervisor also waited for its own helper to become healthy, so
the production path never had to prove the release version.

- **Rule:** the update transaction ends only after a bounded versioned ping
  reports the newly installed release; a timeout or mismatch restores and
  restarts the prior generation.
- **Rule:** never trust inherited user-bus variables or `PATH` when restarting
  the policy daemon. Reconstruct and validate the same-user runtime bus first.
  See ADR 0088-deployed-supervisor-verified.

## 41. A test home must not overlap an allowed root

The shield smoke test first inherited the real shield-protected home, so the
inner shield exited before enforcement and the deny fixture passed for the
wrong reason. Moving its home under `/tmp` fixed startup but made `~/.ssh`
writable because Landlock deliberately grants all of `/tmp`. The SIGHUP
subprocess had the first half of the same bug: its default log and DB paths
were inaccessible before its test socket could appear.

- **Rule:** subprocess tests get an explicit throwaway home; sandbox tests place
  it outside every broad allow root, including `/tmp` and the launch CWD.
- **Rule:** assert both sides of enforcement. A deny-only fixture cannot prove
  the component started, and an allow-only fixture cannot prove it confined.

## 42. A SQLite query suffix is not necessarily a read-only connection

The OpenCode reader appended `?mode=ro` to a plain filesystem path. Modernc
treated that as part of the path rather than a SQLite URI, so the driver could
open or create a writable database while ordinary read tests stayed green.

- **Rule:** use an explicit `file:` URI and deny writes with a write-attempt
  test; a connection option is only a security control once the driver parsed it.
  See ADR 0120-bundled-model-pricing.

## 43. A safety bound must admit real records

The cost readers capped JSONL lines at 1 MiB after fixtures proved oversized
records were rejected. Real Claude Code and Codex transcripts already contained
valid 1–7 MiB conversation, compaction, and image records, so the scanner stopped
before later usage snapshots and silently dropped whole sessions from totals.

- **Rule:** measure the external contract before choosing a resource bound, and
  keep a real-shape fixture above the old boundary. A hostile-input test proves
  rejection works; it does not prove the accepted range is usable.
  See ADR 0120-bundled-model-pricing.

## 44. A bundled catalog has a freshness boundary

Cost tests checked two models already present in Gryph v0.7.0 while live agents
used newer identifiers absent even from Gryph's current main catalog. Pricing
lookup returned no match, the estimator converted that to `$0.00`, and millions
of correctly parsed tokens looked free. The exact Claude Opus 4.6 catalog entry
also carried zero cache rates even though the provider's `@default` variant had
them, so its non-zero total still omitted cache spend.

- **Rule:** test every model identifier emitted by current supported agents,
  including cache reads and writes. A green catalog lookup for yesterday's
  model does not attest today's report.
  See ADR 0121-current-model-pricing.

## 45. A JSONL line limit must recover at the next record

The cost readers replaced an unbounded line reader with `bufio.Scanner` and a
1 MiB cap. Limit tests passed, but real Claude and Codex transcripts embedded
larger tool results. Scanner stopped permanently at that record, so later usage
snapshots disappeared and the whole file produced only a warning.

- **Rule:** a per-record resource limit discards only that record and resumes at
  its delimiter; test valid data after the oversized fixture, not just rejection.
  See ADR 0122-transcript-record-recovery.

## 46. A cost total needs every priced token category beside it

The cost report correctly charged uncached input, cache reads, cache writes,
and output, but its model rows displayed output tokens alone. Snapshot tests
stayed green while a cache-heavy workload looked hundreds of dollars wrong.

- **Rule:** whenever a derived total combines multiple usage categories, expose
  every material category in the same view, identify estimates as API list
  price rather than subscription billing, and test the aggregate fields.
  See ADR 0123-supplemental-model-pricing.

## 47. A pass-through parser makes Cobra help incomplete

Legacy commands used `DisableFlagParsing` so their existing parsers could keep
handling argv. Cobra then printed only `--help` and the global `--agent` flag,
while real options such as `cost --period` worked but were invisible.

- **Rule:** until a legacy parser is fully migrated, mirror every supported
  runtime flag into its Cobra command and test the complete live command
  metadata. Spot-checking a subset let later `run` flags disappear from help.
  See ADR 0027-cobra-cli-framework.

## 48. A cache-write total is not a pricing category

Claude's top-level cache-creation count looked sufficient and produced
plausible totals, while a nested object identified every write as five-minute
or one-hour. Collapsing that field priced one-hour writes at the cheaper rate.
Likewise, a Codex session total cannot reveal which requests crossed a pricing
tier even when its arithmetic is exact.

- **Rule:** retain every transcript dimension that changes price, and apply
  request-level tiers only to complete per-request records. Fall back visibly
  rather than inferring a request from a cumulative session.
  See ADR 0123-supplemental-model-pricing and AGE-272.

## 49. A forked transcript contains billable and copied history

Codex fork files begin with the child metadata, then embed the parent metadata
and cumulative usage history. Treating the last metadata record as identity
collapsed separate branches; treating the first record as identity counted the
copied history again. Both approaches produced plausible totals and green
single-session tests.

- **Rule:** preserve the first session identity, follow the typed fork parent,
  remove exact ancestor usage events, and charge only the branch deltas. Test a
  fork that diverges onto another model. See ADR 0123-supplemental-model-pricing
  and AGE-272.

## 50. An unreadable credential directory is not an empty one

The SSH diagnostic used an empty key-path list for both an absent `~/.ssh`
directory and a shield-denied directory. In a shielded session with no
`SSH_AUTH_SOCK`, it therefore printed "no ssh keys -- skipping" and the final
report said all checks passed even though SSH Git could not use private keys.

- **Rule:** model unknown discovery separately from a confirmed absence. For a
  capability that the sandbox deliberately denies, diagnose the required
  delegated capability directly; never infer it is unnecessary from a failed
  enumeration. See ADR 0124-explicit-ssh-delegation and AGE-273.

## 51. A key can stay secret while its authority leaks

SSH-agent passthrough kept private-key bytes unreadable, so tests and docs
treated it as a safe compatibility carve-out. The socket still let any
shielded process enumerate loaded identities and request signatures from all
of them, while a generic signing request carried no Git repository or remote
host that AgentJail could enforce.

- **Rule:** model access to a credential operation as credential delegation,
  even when key material never crosses the boundary. Admit signing capability
  only through a validated launch policy or explicit override, disclose its
  true scope, and never claim a path check supplies protocol authorization.
  See ADR 0124-explicit-ssh-delegation, ADR 0125-default-git-ssh, and AGE-273.

## 52. One launch policy needs one launch path

The default policy enabled Git SSH and `agentjail run` could create a session
agent, but the PATH shims executed the shield directly. Both launches were
sandboxed and their unit tests passed, while ordinary `codex resume` silently
skipped the default bootstrap.

- **Rule:** every convenience launcher must converge on the canonical launch
  path before policy defaults are resolved. Test the user-facing shim command,
  not only its eventual shield execution. See ADR 0126-session-ssh-bootstrap
  and AGE-273.

## 53. Agent readiness does not select the right account

The SSH E2E loaded one identity, so broad agent delegation passed clone, push,
and pull. A real session loaded two GitHub identities; the server accepted the
first valid key as a different account and rejected the repository operation.

- **Rule:** when creating a session agent, resolve the current remote's
  effective SSH identity and load one key by default. Treat multiple matches as
  a user choice, never proof that any loaded key is the intended account. See
  ADR 0126-session-ssh-bootstrap and AGE-273.

## 54. A path grant must match the inode type

The `~/.config` allowlist tests proved credential directories were skipped and
ordinary children were offered to Landlock. They did not assert the access
mask. Regular files were offered directory-only rights, so Landlock returned
`EINVAL`; startup continued with noisy skip messages and those files remained
unreadable.

- **Rule:** preserve the file/directory type when constructing Landlock rules,
  and test the actual access mask rather than only the path list.

## 55. An environment token does not imply config-file independence

The GitHub adapter set `GH_TOKEN`, and its unit and local CLI tests passed.
GitHub CLI 2.45 still probed `~/.config/gh/hosts.yml` during startup; the clean
shielded gate correctly denied that host credential store and the command quit.

- **Rule:** test each credential adapter with a denied ambient credential store
  and the oldest supported client. Redirect optional CLI configuration into the
  private session even when the documented token variable has precedence. See
  ADR 0129-credentialed-cli-bootstrap and AGE-278.

## 56. Counting kubeconfig contexts does not make an import self-contained

The first kubeconfig validator required one cluster, context, and user, so all
positive tests passed. The raw document was still handed to kubectl unchanged;
an `exec` plugin, `tokenFile`, or certificate path could therefore reach outside
the broker material model at runtime.

- **Rule:** validate every downstream-interpreted credential source, reject
  unknown fields and extra documents, and test hostile configs through the
  user-facing import path. See ADR 0129-credentialed-cli-bootstrap and AGE-277.

## 57. Exact PATH resolution can exactly select an attacker binary

The bootstrap resolved, statted, and later rechecked the first `aws` in PATH.
Those checks all passed for an executable created inside the workspace, so the
broker would faithfully inject AWS credentials into an agent-controlled file.

- **Rule:** binary identity checks do not establish trust. Reject credentialed
  executables from agent-writable roots before requesting broker material, then
  test a real PATH-shadowing lookalike. See ADR 0129-credentialed-cli-bootstrap
  and AGE-276.

## 58. An optional live-agent gate is not a release gate

The release command included a real Claude scenario, but missing credentials
turned it into a successful skip. Every local test stayed green while machines
without the applicable plan exercised no authenticated model loop at all.

- **Rule:** a release-required integration must fail when its required auth is
  absent. Seed one explicitly selected harness immediately before the scenario,
  clean it afterward, and keep optional compatibility probes outside that gate.
  See ADR 0130-codex-live-gate.

## 59. Reading CLI configuration does not prove authenticated use

The credentialed CLI gate asked AWS CLI where it found its keys, read the
generated kubeconfig with kubectl, and echoed the GitHub token through gh. It
passed even if no CLI could authenticate a provider request with the delivered
material.

- **Rule:** credential delivery E2E must cross the tool's authentication
  protocol. Validate a secret-derived AWS SigV4 signature and a Kubernetes
  bearer request, not only environment variables or configuration output. See
  ADR 0129-credentialed-cli-bootstrap and AGE-279.

## 60. One EXIT trap can silently disable another

The macOS gate installed a VM-stop EXIT trap after the credential-cleanup trap.
Both paths looked correct in isolation, but Bash retained only the last trap;
Linux also had no gate-stop trap, so successful tests left VMs consuming RAM.

- **Rule:** one lifecycle owner must compose credential, temporary-file, partial
  creation, and VM cleanup. Test failure and retained-cache outcomes, and apply
  the same lifecycle contract to every OS driver. See ADR 0053-vm-testbed-engine.

## 61. Strict MCP parameters must include protocol metadata

The credential MCP unit test sent only `name` and `arguments`, so its strict
decoder passed. Real Codex also sent the MCP-reserved `_meta` request field;
the server rejected the entire call before credential discovery reached the
broker, despite advertising a valid tool schema.

- **Rule:** keep tool arguments strict, but model protocol-level extension
  fields separately at the serialization boundary and exercise them with a
  real client. See ADR 0131-agent-credential-discovery and AGE-276.

## 62. A remote command can inherit an interactive stdin

The deterministic testbed harness ran every guest command without a terminal,
so the real Codex gate passed locally. Tart's SSH executor inherited stdin from
an interactive host invocation; Codex consumed its prompt argument, then waited
indefinitely for additional input instead of starting the MCP session.

- **Rule:** detach stdin for non-interactive remote execution and test the SSH
  argv directly. Keep the separate interactive `ssh` command attached. See ADR
  0130-codex-live-gate and AGE-279.

## 63. A session tool inside self-protected state needs an exact capability

Credential discovery and MCP protocol tests passed, and Linux could launch the
server. The macOS profile denied reads of all `~/.agentjail`, including the
validated multicall binary Codex needed to spawn as the credential MCP server;
after that was fixed, its blanket control-socket deny still blocked the MCP
server from reaching the exact broker socket with its session token.

- **Rule:** when a trusted session helper lives beneath broad self-protection
  denies, carry its validated executable and session-authorized socket as typed
  launch capabilities, granting only those literals. Test each deny and its
  carve-out together. See ADR 0131-agent-credential-discovery and AGE-279.

## 64. A parsed flag is not necessarily a working feature

The user-facing CLI accepted and advertised `--agent <slug>`, and parser tests
confirmed that its value survived argument parsing. Nothing ever read the
value, so every command silently behaved exactly the same with or without the
flag. The real agent selector belongs to the separate hook adapter.

- **Rule:** test the observable effect of every public option, not only that it
  parses. A compatibility flag with no consumer must be hidden or removed.

## 65. Generated help can faithfully describe the wrong command tree

Cobra rendered every registered flag and the help tests passed, but several
"subcommands" were opaque positional parsers, static help topics duplicated the
live tree, and `allow --ttl` described authority the daemon never applied.
Complete output did not make the underlying contract coherent.

- **Rule:** audit help against observable behavior and one canonical command
  hierarchy. Compatibility syntax belongs in hidden aliases, and an option with
  no effect on the resulting authority must not remain public. See ADR
  0132-cli-command-surface.

## 66. A generated capability can violate its own validator

The SSH bootstrap tests passed argv through a fake exec and the standalone
acceptance test passed on Linux. On macOS, the system `TMPDIR` ended in `/`;
OpenSSH appended another separator, so AgentJail created a live session socket
whose `//` spelling its shield then rejected as unclean. Tart's release
scenarios explicitly disabled Git SSH and never entered this path.

- **Rule:** preserve strict validation for ambient capabilities, but normalize
  environment inputs before invoking a capability producer you own. Assert the
  exec environment and force native platform path shapes in acceptance tests.
  See ADR 0126-session-ssh-bootstrap.

## 67. An unavailable verifier is not a verified match

Linux CWD-mismatch tests passed, while Darwin returned an unsupported resolver
error and grant binding treated that error as permission to trust the agent's
self-reported CWD. A host approval could therefore persist an overlay in a
project selected by unverified input.

- **Rule:** cross-platform authorization fails closed when its verifier is
  unavailable; live-test every backend, not just its layout. See ADR
  0133-macos-menu-review. The Darwin ABI was verified against [Apple XNU
  `proc_info_private.h`](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/proc_info_private.h)
  on 2026-08-15.

## 68. Periodic cleanup is not an expiry check

The grant reaper made the pending queue look TTL-bounded, while list, deny,
coalescing, and approval could still act on an expired record until the next
tick. Tests that ran the reaper first stayed green and hid the authorization
window.

- **Rule:** check server time under the same lock that claims or removes an
  authorization record. A reaper controls retention, not permission. See ADR
  0133-macos-menu-review.

## 69. A decoder limit is not a frame limit

`LimitReader` bounded how many bytes the JSON decoder could request, but an
early valid object still decoded before trailing or over-limit bytes were read.
Single-object tests stayed green while the socket accepted an unbounded frame.

- **Rule:** read exactly one bounded delimited value, reject in-frame trailing
  data, and size-check the complete response before writing any byte. See ADR
  0133-macos-menu-review.
## 70. A green tunnel smoke can mean every tunnel assertion skipped

The Darwin smoke script returned zero when the Network Extension was missing,
because each extension-dependent scenario reported SKIP. The output looked
careful and the command was green, but it had exercised no tunnel, TLS
interception, policy, or evidence path at all.

- **Rule:** a required release assertion must count executed and skipped
  scenarios separately, require the exact `[activated enabled]` extension state,
  and fail when nothing exercised the intended path. Use the approved
  `golden-macos-mitm` contract and strict mode. See ADR
  0136-tunnel-golden-image.

## 71. An audited approval can outlive its hook deadline

The daemon stayed healthy, minted the Codex approval challenge, and recorded
the canonical `ask`, but its required audit write completed just after the
hook's availability ceiling. The hook mislabeled the timeout as a daemon
outage and failed open, so Codex executed the original command without the
approval prompt.

- **Rule:** security-path deadlines must include required durability work, and
  an approval-capable request must deny when its response is unavailable. A
  daemon control ping is not proof that the policy response reached the hook.
  See ADR 0118-codex-approval-broker.

## 72. `kill(pid, 0)` failure does not mean the process is dead

The approved Darwin extension was active and allowed HTTPS worked, but every
named tunnel policy returned the public upstream response and `network.db`
recorded nothing. Its session reaper removed a live shield registration when
`kill(pid, 0)` returned `EPERM`; only `ESRCH` means the process is gone.

- **Rule:** classify probe errors by their documented semantics. A liveness
  reaper may remove a PID only on `ESRCH`, and a security boundary must validate
  the registration acknowledgement before claiming that traffic is routed.

## 73. Terminal output is not durable policy evidence

The strict Darwin matrix received the expected 403 responses and SQLite held
the exact deny-template rows, but the test still failed because it searched
captured stderr for `template=<id>`. Structured shield logs are not mirrored to
stderr by default, so terminal verbosity accidentally became the assertion
contract instead of the durable record.

- **Rule:** watermark the authoritative store before a scenario and bind each
  assertion to exact post-watermark structured rows. Treat stdout and stderr as
  diagnostics only. If a security path has no durable record, add persistence
  or keep the release assertion failed; never substitute a log grep.

## 74. Root AWS credentials cannot assume a role directly

The source profile could create IAM roles and policies, but `AssumeRole` still
failed when its caller was the account root. More privilege did not make the
STS session a valid role principal, and retrying the same root call could never
exercise the broker.

- **Rule:** live credential fixtures must model the real issuance boundary. Use
  a disposable, exactly trusted bootstrap principal to assume a short-lived,
  least-privilege role; delete the bootstrap key before the agent runs, and
  never copy the source profile into the guest. See ADR
  0131-agent-credential-discovery and `docs/runbooks/aws-sts-testbed.md`.

## 75. Agent prose is not credential-path evidence

A coding agent could write the expected bucket names and denial claims without
ever executing the intended AWS binary. A valid-looking proof file therefore
did not bind its claims to the issued STS values or the broker lifecycle.

- **Rule:** observe the exact executable boundary, bind each invocation to
  non-secret credential fingerprints, and require the ordered SQLite session
  events. Treat the agent-authored proof as corroboration only. See ADR
  0131-agent-credential-discovery and `docs/runbooks/aws-sts-testbed.md`.

## 76. Correlation IDs are not resource names

The AWS provisioner embedded an ISO-like run ID containing uppercase `T` and
`Z` directly in S3 bucket names. IAM accepted the same ID shape, but S3 rejected
it before the live test started. The original cleanup flag was also set only
after bucket hardening, which could have orphaned a successfully-created bucket
when a later control failed.

- **Rule:** derive provider-valid names from a canonical correlation ID, and
  transfer every created resource to cleanup ownership immediately after its
  create call. Validate names locally before the first external mutation. See
  `docs/runbooks/aws-sts-testbed.md`.

## 77. Preflight every post-handoff output path

The live AWS provisioner successfully created and imported a temporary role,
but the VM runner had never created its gitignored report parent. It accepted
the handoff, failed at the first evidence write, and cleaned everything without
executing a scenario.

- **Rule:** validate helper files and create-probe every local output root before
  starting an external credential or infrastructure handoff. Cleanup success is
  necessary, but it cannot turn an unexecuted scenario into a pass. See
  `docs/runbooks/aws-sts-testbed.md`.

## 78. A PATH observer can contradict executable pinning

The live Codex task completed and the broker lifecycle was durable, but a test
expected an agent-writable PATH wrapper to observe AWS. AgentJail correctly
resolved and pinned the trusted AWS executable before launch, then put its own
session symlink first, so the wrapper was never invoked.

- **Rule:** do not weaken executable resolution to make a test observer work.
  Put bounded validation inside the issued session, verify AgentJail's symlink
  and resolved executable hash, and store only fingerprints and structured
  outcomes. See `docs/runbooks/aws-sts-testbed.md`.

## 79. Destination IP is not an HTTP policy host

The Darwin strict smoke requested `http://www.cloudflare.com` and received the
upstream's normal 301 even though a hostname rule claimed to deny port 80. The
transparent provider passed only the destination IP to the gateway, and the raw
TCP fallback evaluated that IP instead of parsing the HTTP `Host` field. HTTPS
looked correct because TLS SNI restored the name on a different path.

- **Rule:** recover application-layer identity before applying L7 policy, model
  the transport port separately, and fail closed when a bounded parse cannot
  establish the fields an active policy needs. Assert the exact post-watermark
  SQLite decision; a status code or terminal line is not proof.

## 80. A stopped provider may still accept sessions

`AgentjailTunnel stop` requested `stopVPNTunnel()` and exited immediately. A
rapid second test could connect to the old session socket and receive `ok`, then
lose its PID registration when Network Extension finished replacing that
provider. A socket-only readiness check also accepted a provider whose new
WireGuard generation had not completed its handshake.

- **Rule:** treat platform lifecycle commands as asynchronous unless their API
  proves otherwise. Wait for both the control endpoint and manager state to
  finish disconnecting, then bind readiness and PID registration to the exact
  provider generation. A readiness retry must stop the failed provider before
  starting again; repeating `start` against the same not-ready generation is
  not reconciliation.

## 81. Requested tunnel is not achieved tunnel

A live Codex scenario invoked the PATH shim's `--tunnel` launch, but the Network
Extension did not become ready. The shield correctly used its ordinary fallback,
then spent nearly a minute resolving fallback allowlist hosts before the harness
timed out waiting for Codex. A command line and the absence of a warning in a
captured pane could not prove which network path ran.

- **Rule:** release assertions use `--require-tunnel`, watermark `audit_log`, and
  require a successful `tunnel.session_registered` with no structured launch
  failure. Keep fallback as the normal user posture, but never let it satisfy a
  test that claims tunnel coverage. See ADR 0136-tunnel-golden-image.

## 82. `kickstart` success can precede EX_CONFIG

A macOS reinstall replaced the daemon binary and `launchctl kickstart -kp`
returned zero, so the installer announced success. launchd then marked the job
`needs LWCR update` and repeatedly exited it with `EX_CONFIG` before AgentJail
could write a crash record. A status-only provision check caught the dead daemon
only after the install had already claimed completion.

- **Rule:** after replacing a managed executable, re-register the launchd job
  with `bootout` plus `bootstrap` so its lightweight code requirement refreshes,
  derive the exact service label from that job's plist, then prove the daemon's
  real policy hot path. A generic helper with a hard-coded daemon label can
  unregister the daemon while installing a different service. A supervisor
  command's zero exit is not activation evidence. See ADR
  0088-deployed-supervisor-verified.

## 83. Virtual wall clock stalls

The native Codex approval bridge minted a valid one-use challenge, but a Tart
guest briefly stopped advancing wall time while its monotonic clock continued.
The 25 ms process-birth boundary deadline expired, so `PermissionRequest`
correctly failed closed before Codex could render the approval prompt. Ordinary
host unit tests never encountered the virtualization pause.

- **Rule:** process-freshness boundaries may wait through a bounded one-second
  virtual-clock stall, but must still fail closed if the comparable process
  birth clock does not advance. Diagnose broker failures from structured audit
  state; terminal prompt text is not the source of truth.

## 84. Clean rows can hide credential residue

A credential test deleted its fixtures and every logical SQLite query was
clean, yet a byte scan still found the values in database free pages. Decision
summaries were also able to bypass the value-level redactor even though the
structured tool input was redacted. The functional suite remained green because
it queried rows and effects, not the retained storage bytes.

- **Rule:** redact every serialization path again at the store boundary, enable
  SQLite secure deletion, and scan the database, WAL, and shared-memory files
  after credential removal. Require a secret-bearing positive control so an
  empty or broken scanner cannot report success. See ADR
  0137-credential-residue.

## 85. Credential discovery is not shell injection

A live AWS harness asked Codex to request static broker material and then pass
the returned values into a fixed shell helper. Depending on the model turn, it
either copied values into a logged command or invoked the helper without an
environment. Earlier green runs depended on agent-authored glue rather than the
broker contract.

- **Rule:** test agent discovery and exact credential request from ordered audit
  events. Test credential execution separately through AgentJail's pinned direct
  session path. Until JIT/phantom delivery replaces ADR
  0131-agent-credential-discovery bootstrap material, do not make a coding agent
  reconstruct a secret-bearing shell environment merely to satisfy the harness.

## 86. A discovered keychain can still be unusable

The headless macOS gate found `/usr/bin/security`, so body recording announced
encrypted capture. Keychain operations later exited with "User interaction is
not allowed", every body write failed, and the metadata-only tunnel assertions
still passed.

- **Rule:** probe the full authenticated wrap/unwrap path before announcing the
  recording posture. Classify a noninteractive macOS keychain as locked, switch
  to the explicit audited plaintext fallback from ADR
  0092-persist-request-bodies, and require persisted body paths in the release
  gate.

## 87. IPv4-first DNS hid a broken default

The Tart tunnel suite passed because its resolver returned IPv4 first. On an
IPv6-first Mac, Network Extension supplied an already-resolved IPv6 literal to
the same IPv4-only default tunnel. Lifecycle audits were green, but every flow
closed before the gateway, so no `network_requests` row existed.

- **Rule:** test both address families and require a request-row delta, not
  merely extension lifecycle success. A transparent tunnel must enable every
  address family it claims by default or fail the release gate explicitly. See
  ADR 0138-dual-stack-default.

## 88. Clean text can retain a symlink

The session-only OpenSSH bootstrap removed a trailing slash from macOS's
`TMPDIR`, and its unit test passed, but lexical cleaning left the system
`/var` symlink intact. OpenSSH derived `SSH_AUTH_SOCK` beneath that spelling,
so the shield correctly rejected the live agent even after the user loaded a
key.

- **Rule:** canonicalize the temp root before the trusted producer creates a
  capability path; do not weaken the consumer's no-symlink validator. Test with
  a real symlink, not a path-shaped string. See ADR
  0139-canonical-ssh-temp.

## 89. Quiet grep can invert health

The development deploy printed a healthy daemon after declaring that the same
daemon never became healthy. Its polling pipeline used `grep -q` under
`pipefail`; an early match closed the pipe, the status producer received
`SIGPIPE`, and the successful match became a non-zero pipeline status.

- **Rule:** when a producer has output after the match and `pipefail` is active,
  consume the complete stream and redirect the matcher's output instead of
  using an early-exit matcher.

## 90. Matching Darwin profiles must share a renderer

The ordinary macOS shield profile carried the validated per-user `$TMPDIR`
carve-out from ADR 0054 and its probes were green. The tunneled launch rendered
a separate Darwin profile and omitted that carve-out, so Codex image paste and
other temporary staging failed only in tunneled sessions.

- **Rule:** modes enforcing the same filesystem contract must use a shared
  renderer, making parity true by construction; tests must exercise each launch
  mode at the behavior boundary. See ADR 0034-platform-backend-shared-contract
  and ADR 0054-macos-shield-tempdir-afunix-parity.
## 91. Two credential paths can cross different audit boundaries

Agent-driven credential requests failed closed when durable request and
issuance audit was unavailable, while eager `--credential ID` delivery used a
separate broker handler whose audit was best-effort. Both paths had green tests,
but only one enforced the evidence contract before returning material.

- **Rule:** route every delivery mode through the same credential-access domain
  service, and inject an issuance-audit failure into each public path. See ADR
  0140-generic-credentials.

## 92. Returned errors can still be silent

Credential validation correctly rejected a session-control environment name,
and unit tests confirmed the returned error. The Cobra root suppressed automatic
error printing, while its executor discarded the error text, so the CLI exited
non-zero without telling the user why and the release gate caught the missing
failure evidence.

- **Rule:** when the command root owns error presentation, test both the exit
  result and the user-visible error text at the command boundary.

## 93. External settings need a return route

The macOS setup flow correctly opened Apple's Network Extension settings and
unit tests proved every coordinator transition, but the app forgot that the
user had left onboarding. System Settings covered the setup window, and the
status-bar app gave no automatic route back to the result.

- **Rule:** every handoff to an external settings app must record a one-shot
  return route that refreshes state and restores the originating window when
  the app becomes active again. See AGE-295.

## 94. A menu-bar app is not a recoverable onboarding window

The setup coordinator and its return route were correct, but the containing app
still declared `LSUIElement=true`. macOS therefore omitted AgentJail from Dock
and Cmd-Tab exactly while System Settings covered its onboarding window. Unit
tests could open the SwiftUI scene and never exercise that application-policy
behavior.

- **Rule:** an app that hands onboarding to another application must remain a
  normal foreground app, and release verification must assert `LSUIElement=false`.
  See ADR 0141-unified-macos-app.

## 95. A routed WindowGroup is not a singleton

The foreground app opened one default `WindowGroup` scene, then onboarding's
setup route opened another instance of the same scene. Every individual window
looked correct, so view tests stayed green while launch produced two dashboards.

- **Rule:** use a singleton `Window` for a routed primary macOS surface; reserve
  `WindowGroup` for documents or workflows that intentionally support multiple
  instances. See ADR 0141-unified-macos-app.

## 96. Apple's OK button is not extension approval

The extension request correctly emitted an approval callback, but the app waited
for that callback before changing its setup card. Apple's notice could cover the
window first, and its prominent **OK** button merely dismissed the notice, leaving
an indeterminate spinner behind a successful unit-tested coordinator.

- **Rule:** enter a durable, actionable approval state before submitting an
  Apple-controlled request, and keep the exact manual path visible after the
  system dialog disappears. See ADR 0141-unified-macos-app.

## 97. Process exit is not service readiness

The macOS component installer returned successfully after handing the daemon to
`launchd`, then setup sampled health once during the restart gap. The UI changed
back to an enabled install button while `launchd` was still converging, inviting
repeated clicks and repeated daemon restarts even though every command succeeded.

- **Rule:** after an installer hands work to a supervisor, keep the action
  single-flight and poll authoritative health for a bounded interval. A command's
  exit status proves handoff, not service readiness. See ADR 0141-unified-macos-app.

## 98. One slow projection can blank an otherwise healthy dashboard

The dashboard synchronously scanned local token transcripts before returning
audit and session totals. The scan took longer than the app's request timeout,
so a healthy daemon appeared unavailable even though every individual data path
and unit test passed.

- **Rule:** isolate slow optional projections behind a typed loading state and a
  bounded single-flight cache; return independently available data immediately.
  See ADR 0141-unified-macos-app.

## 99. Build identity is not installation health

The macOS app compared the installed CLI byte-for-byte with the CLI bundled in
the app. A local rebuild changed executable bytes without changing the release
or service compatibility, so the healthy daemon, hooks, and policies disappeared
behind a **Setup required** screen. The unit test asserted byte equality and
therefore made the false-positive behavior look intentional.

- **Rule:** derive readiness from executable availability and authoritative live
  service health. Report artifact drift as an update state, never as a missing
  installation.

## 70. A successful detach is not proof of an unmounted image

The approval DMG packager treated an exit-zero `hdiutil detach` as proof that
the mount was gone. A delayed detach or a failed mount query could therefore
clear its attachment state and recursively remove the staging root across a
live mount. The happy-path package test stayed green because it never made the
detach and the observed mount state disagree.

- **Rule:** cleanup may remove a staging root only after an independent
  tri-state mount check proves it absent. Active and indeterminate both retain
  the exact validated root and fail closed.

---

## Testing gotchas

These made our own e2e suite lie to us.

### A 403 is not proof your policy fired

GitHub's unauthenticated API allows **60 requests/hour**, then returns 403 — the
same status as our deny template. The suite passed on the first run and failed
on the next, and the 403s looked like enforcement. Deny scenarios now grep for
`template=<id>` in the eval log, so they cannot pass for the wrong reason, and
generic reachability probes use a host with no rate limit.

## 99. UTC projection keys must use the same calendar as the UI

The daemon returned daily activity keyed by UTC (`YYYY-MM-DD`), while the Swift
grid formatted UTC-midnight dates through the user's local timezone. Around a
day boundary every cell missed despite non-zero totals and a green test suite.

- **Rule:** when a wire projection owns a calendar, configure both date
  arithmetic and formatting with that calendar's timezone. See AGE-293.

## 100. Disabled flag parsing forwards global flags

The MCP discovery subcommand disabled Cobra flag parsing so its typed runner
could own `--json`. Cobra then forwarded the persistent `--no-color` flag as a
plain argument, and the app's real CLI invocation failed even though direct
runner tests were green.

- **Rule:** a command with `DisableFlagParsing` must explicitly accept inherited
  global flags, and its test must include the exact argument vector used by the
  product wrapper. See ADR 0143-explicit-mcp-enumeration.

## 101. A launchd daemon does not inherit your terminal PATH

MCP discovery worked in terminal-oriented tests but marked every bare `npx`
server unreachable after installation. The daemon was launched with a minimal
environment that omitted Homebrew and user toolchain directories. Resolving
`/opt/homebrew/bin/npx` was still insufficient: its `/usr/bin/env node` shebang
consulted that same minimal child `PATH` and immediately exited.

- **Rule:** resolve configured executables and their env-based shebang
  interpreters against one shared, bounded platform search contract; never
  source a login shell to manufacture daemon state. See
  ADR 0146-mcp-command-resolution.

## 102. Machine-readable inventory can bypass display redaction

The human MCP scan renderer printed metadata only, while `mcp scan --json`
serialized the internal connection struct and exposed configured argument,
environment, header, and URL credential values. Tests covered parsing and the
human report but never asserted the public JSON boundary.

- **Rule:** every machine-readable command must project an explicit safe wire
  type or sanitized copy, and its test must seed the same secret into every
  supported configuration channel. See ADR 0146-mcp-command-resolution.

## 103. Glass appearance depends on what scrolls behind it

The MCP summary looked correct at the top of the light-mode page, then turned
dark when scrolling changed the content sampled by Liquid Glass. Static view
tests exercised the initial composition only.

- **Rule:** use semantic opaque fills for data strips whose contrast must remain
  stable while scrolling; reserve sampling materials for surfaces where that
  environmental response is intentional. See ADR 0141-unified-macos-app.

## 104. Persisting successes alone erases actionable failures

Live MCP discovery persisted returned tool names but kept reachability and
authentication statuses only in the app's in-memory result. Relaunching the app
therefore changed accurate failures back to the misleading “Not discovered.”

- **Rule:** if a background operation has a bounded typed outcome that the UI
  must explain later, persist that outcome alongside successful data and project
  both through the same read model. See ADR 0143-explicit-mcp-enumeration.

## 105. Configured OAuth is not an authenticated MCP session

Codex showed Linear and OpenSEO as connected, but AgentJail independently read
their endpoint URLs from `config.toml` and opened unauthenticated HTTP sessions.
The direct client correctly received 401 responses, so transport tests stayed
green while the product incorrectly told an already-signed-in user to sign in.

- **Rule:** when an agent owns OAuth state outside its public configuration,
  enumerate through the agent's bounded machine catalog and treat raw config as
  fallback—not as proof of the agent's effective session. See
  ADR 0147-codex-catalog-bridge.

## 106. Native list selection and custom row fills stack

The sidebar used SwiftUI's native `List(selection:)` highlight and also painted
a rounded full-row hover background. Both looked plausible in isolation and the
view tests stayed green, but a selected row showed a visibly doubled boundary,
especially in dark mode.

- **Rule:** let the native list own selection and hover fills; custom sidebar
  row content may define hit testing and spacing, but must not paint another
  full-row interaction background. See ADR 0141-unified-macos-app.

## 107. One fixed panel size is not one coherent menu

The approval menu used the review list's fixed height even when it had no rows.
Snapshot and state tests stayed green, but the empty state became a large
translucent window, repeated the ready message, and promoted a footer button
with persistent focus chrome.

- **Rule:** give bounded menu states explicit layout contracts, and test the
  compact empty state separately from the scrolling work state. Use an opaque
  semantic surface when desktop sampling is not part of the design. See
  ADR 0141-unified-macos-app.

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
