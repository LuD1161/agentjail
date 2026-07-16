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
omission. curl downgrades quietly; gRPC fails. Now we say `http/1.1` explicitly
and report an h2 offer once per session.

- **Trap:** `ConnectionState().NegotiatedProtocol` **cannot** tell you what the
  client wanted once you advertise one protocol — it reports what was agreed,
  which is always yours. The offer is only visible in `GetConfigForClient`
  (`ClientHelloInfo.SupportedProtos`).
- **Once per session, not per connection.** An agent opens many connections;
  per-connection notices become noise, and noise is filtered out and stops being
  a notice at all.
- AGE-222 (honest), AGE-223 (actually serve h2).

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
