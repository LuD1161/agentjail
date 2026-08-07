# ADR 0094: the UI is a React SPA, and that is a deviation we are naming

**Status:** Accepted

Scope: the frontend of the local UI (`cmd/agentjail/ui/`). It does not touch
what the UI reads ([ADR 0092](./0092-persist-request-bodies.md)) or the shape of
the HTTP API behind it.

## Context

[`AGENTS.md`](../../AGENTS.md) lists **"frontend frameworks"** under **Avoid**,
and requires an ADR for any new dependency. This ADR is that deviation, recorded
late and on purpose. React, shadcn/ui, TanStack Table, TanStack Query, Vite,
Tailwind, Node and npm are all in the build. None of them were ever written
down: a search across every ADR for React / shadcn / TanStack / Vite / npm
returns **zero hits**. The framework was adopted once already, by shipping, and
the decision log never noticed.

That silence is the first fact of this Context, not a footnote to it. The rule
that says "new library ⇒ ADR" did not fire, and nothing in CI made it fire. So
this document is not discovering a trade-off; it is catching up to one that has
been live for ten days, and the honest version of it has to include the part
where the process failed.

**What exists.** `0a014948 feat(ui): React + Shadcn + TanStack frontend with SPA
serving` (2026-07-05) replaced the vanilla HTML UI with Vite 8 / React 19 /
TypeScript 6 / Tailwind v4, shadcn components, TanStack Table for the request
list, TanStack Query for fetching, SSE hooks for live events, and `handleSPA`
serving client-side routes out of an embedded `dist/`. A history rewrite then
orphaned that commit and **pruned the objects from this server**. It survived
only in a stale remote-tracking ref on the maintainer's Mac, and was rescued to
`rescue/burp-ui-2026-07-05` on 2026-07-15.

**The core argument is the diff, and it is bigger than anyone remembered.**
That branch is **61 commits ahead** of `feat/network-visibility` — not the five
the rewrite made it look like. Verified:

```
$ git rev-list --count feat/network-visibility..local-bare/rescue/burp-ui-2026-07-05
61
```

It carries a Policies page with syntax-highlighted rules, a session sidebar with
active/inactive detection, resizable split panels, filter counts wired to API
totals, and a clickable statusline link that auto-starts the UI server. Ten days
of iteration, most of it the unglamorous kind — `aria-orientation` on a split
handle, deny counts read from actual requests instead of a stale aggregate.
Rejecting the SPA does not mean "write the HTML instead". It means deleting 61
commits of work that runs, and re-deriving the bugs they already fixed. Nothing
on the other side of the ledger is worth that.

**Rewriting is not cheap, and the honest reason we do not is that we cannot
price it.** Nobody has costed a server-rendered replacement for a live-streaming
request inspector with resizable panels and a sortable/filterable table. The
guess would be optimistic, because the guess is always optimistic, and 61
commits of fixes is the empirical evidence for how optimistic.

**One thing the branch is not: current.** It is also **343 commits behind**.
Adopting it is a merge with real conflicts, not a fast-forward. That work is not
in scope here and is not free either.

**Prior art the decision has to answer for.** Both earlier UIs — the ones this
SPA replaced, the ones with no framework at all — shipped JSON contracts that
silently never matched the store:

| UI read | Handler / store sent | Result |
|---|---|---|
| `data.hosts` | `stats` | per-host table rendered empty |
| `count` | `request_count` | — |
| `req.status` | `status_code` | every status showed `--` |

These ran **for months**. No Go test could see them: the handler was correct, the
store was correct, the marshalling was correct, and the key the frontend read
did not exist. `undefined` renders as nothing, and nothing looks like no data.
This is the load-bearing lesson and it **cuts against the framework being the
variable at all** — vanilla HTML produced this bug class twice. Any UI, SPA or
server-rendered, needs contract tests over exact JSON keys plus a real-browser
render assertion. Adopting the SPA does not fix this and must not be read as
fixing it.

## Decision

**Adopt the SPA.** React + shadcn/ui + TanStack (Table, Query) + Vite is the
frontend of the local UI. Merge `rescue/burp-ui-2026-07-05` forward.

The macOS shield restores the rescue branch's best-effort UI auto-start and the
status line links to the shared loopback address while it is reachable. The
address lives in `internal/localui`; the CLI, shield, and status line do not
maintain separate literals.

This is an explicit, named deviation from the `AGENTS.md` **Avoid: frontend
frameworks** rule, granted for `cmd/agentjail/ui/frontend/` and nowhere else.
The rule stands everywhere else in the repo; a second frontend framework, or
this one leaking into another surface, needs its own ADR.

We accept three costs. The first two are defects **today**, owned by **AGE-251**
(in flight, parallel). They are listed here as accepted costs with an owner, not
as open risks — but this ADR is wrong if AGE-251 does not land, and a future
reader finding them unfixed should treat that as the falsification.

**Cost 1 — `go build ./...` fails on a clean clone.** `static_embed.go` declares
`//go:embed all:static/dist`; `.gitignore:61` ignores
`cmd/agentjail/ui/static/dist/`; nothing is committed under `dist/`. Verified at
`0a014948` and at the branch tip — `git ls-tree -r ... -- cmd/agentjail/ui/static/dist/`
is empty. `go:embed` on a missing directory is a **compile error**, so the Go
build now depends on a Node build having run first. CI sets up Go only. Owner:
AGE-251.

**Cost 2 — a compliance defect CI cannot see.** `scripts/gen-third-party-licenses.sh`
is `go list`-only by design ("Dependency-free: uses only `go list` + the local
module cache"). The frontend has **24 direct npm packages** (15 runtime, 9 dev)
and hundreds of transitive ones, which ship **embedded in the binary** with zero
attribution — while `make licenses-check` passes green. Green is the problem: the
check reports success over a question it never asked. Owner: AGE-251.

**Cost 3 — Node and npm are now in the supply chain of a security tool, and this
one has no owner because it has no fix.** agentjail sandboxes coding agents. Its
own dependency surface is not an implementation detail; it is the thing we ask
users to trust. We went from a Go binary with a vendored, `go list`-auditable
module graph to that plus an npm tree with hundreds of transitive packages,
executing at build time, in the artifact that enforces policy. Costs 1 and 2 get
closed by AGE-251. **This one does not close.** It is permanent, it is the real
price of the decision, and pinning a lockfile does not make it go away — it only
makes it enumerable. We are paying it because 61 commits of working inspector is
worth more than the reduction in attack surface we would buy back, and that is a
judgement call, not a proof.

## Consequences

**This decision is reversible, and here is the falsification.** A future
maintainer should reverse it — rewrite as server-rendered HTML — if *any* of the
following becomes true. Each is checkable; none requires re-litigating taste.

1. **AGE-251 does not close, or reopens.** The whole "accepted cost" framing
   rests on costs 1 and 2 being defects with an owner. If `go build ./...` on a
   clean clone still needs a Node toolchain, or `licenses-check` still passes
   green over an unattributed npm tree, then this ADR recorded wishes. Reverse
   it, or re-argue it honestly.
2. **The npm tree produces a real incident** — a compromised transitive package,
   a postinstall script, an advisory we cannot patch without a major bump. Cost 3
   is a bet against this. Losing the bet settles it; no further argument needed.
3. **The 61 commits stop being an asset.** The argument here is empirical, not
   architectural: the SPA wins because working code exists. If the merge from 343
   commits behind rots into a rewrite anyway, or the Policies/session/statusline
   work is discarded for other reasons, the premise is gone and the decision
   should be re-taken from zero — *without* the sunk cost.
4. **The UI's requirements shrink.** Resizable panels, live SSE streaming, and a
   sortable/filterable table are what make server-rendered HTML expensive here.
   If the inspector becomes a few static tables, HTML wins on every axis and the
   framework is dead weight.
5. **Node/npm becomes a user-facing install requirement.** Today it is build-time
   only. If a user ever needs `npm` to run agentjail, the trade has changed
   without anyone deciding to change it.

**What this ADR does not do.**

- It does not fix the JSON contract bug class. That class **predates the SPA and
  was produced twice by the frontend-free UI** — the framework is not the
  variable, and adopting it is not a mitigation.
- It does not bless a second frontend framework, or this one outside
  `cmd/agentjail/ui/frontend/`.
- It does not claim the SPA is better-engineered than the HTML it replaced. It
  claims it exists, it works, and it is 61 commits deep. That is the whole case.

**Required, and not optional because the deviation was granted on their basis:**

- [ ] `go build ./...` from a **clean clone with no Node installed** — the exact
      failing case, not a local tree where `dist/` happens to exist. AGE-251.
- [ ] `licenses-check` covers the npm tree, or **fails loudly** where it cannot.
      A green check over an unasked question is worse than a red one. AGE-251.
- [ ] **Contract tests over exact JSON keys**, asserting the literal strings the
      frontend reads (`hosts`, `request_count`, `status_code`) against the
      handler's real output. This guards the `data.hosts`/`stats`,
      `count`/`request_count`, `status`/`status_code` bugs — each of which ran
      for months. Assert the key, not the shape: the shape was always fine.
- [ ] **A real-browser render assertion** on the per-host table and the status
      column, asserting non-empty cells. `undefined` renders as nothing, and
      nothing is indistinguishable from an empty result set — which is exactly
      why the original bugs were invisible. A test that only checks the page
      loads reproduces the blind spot.
- [ ] The npm lockfile is committed and CI installs with `--frozen-lockfile`.
      This does not fix cost 3; it makes the surface enumerable.
