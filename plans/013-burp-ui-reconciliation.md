# Plan 013 — reconciling three network UIs into one

> **OVERRIDDEN IN PART (maintainer, 2026-07-15): the SPA is kept.** This plan
> recommended rejecting the React/Shadcn/TanStack frontend. The maintainer's
> call is to keep it — it exists, it works, and redoing it makes no sense. The
> build-break and npm-attribution defects this plan found are real and become
> the work of **AGE-251**, not a reason to walk away. Everything else here still
> stands: `/api/network/*` wins as the API, port the Burp detail panel rather
> than resurrecting `/network` as a second page, and the contract-test
> requirement applies regardless of which UI renders it.

**Status:** Proposed. Investigation only; no code changed.
**Branch:** `feat/network-visibility`
**Related:** [ADR 0092-persist-request-bodies](../docs/adr/0092-persist-request-bodies.md), AGE-79, AGE-111, AGE-149.

## Recommendation, in one line

**Keep the `/api/network/*` endpoints and the tabbed `index.html` as the single UI;
port the Jul-5 Burp viewer's *detail panel* (split req/resp, headers, body panes)
into the existing Network tab; reject the React SPA for now and write the ADR that
says so.** Do not revert `31911b1`, and do not resurrect `/network` as a second page.

---

## 1. The three candidates, and what each one actually is

| | what it is | where it lives | has tests | reads bodies | store access |
|---|---|---|---|---|---|
| **(1) plain-HTML tab** | Network tab in `index.html`, metadata table + per-host stats | current branch, `31911b1` | yes — `network_test.go`, incl. JSON contract + route registration | no | `OpenReadOnly`, headers redacted |
| **(2) Jul-5 Burp viewer** | separate `/network` page, `network.html` (~388→698 lines), split req/resp detail, SSE | `local-bare/rescue/burp-ui-2026-07-05` (`6ef49e02`…`2f3d28ce`) | none | yes (`req.request_body` TEXT column) | `NewRequestStore` — **read-write**, no redaction (predates AGE-232) |
| **(3) React SPA** | Vite 8 + React 19 + Tailwind 4 + shadcn + TanStack, `cmd/agentjail/ui/frontend/` | same rescue branch, `0a014948` + ~60 follow-ups | none | yes | via (2)'s API |

Scope note that matters: the rescue branch is **61 commits ahead** of `31911b1`
(merge-base `e56551c`), not 5. It carries a Policies page, a session sidebar,
active-session detection, and a statusline link. This is not a "port one file"
decision; it is a decision about which of 61 commits to salvage and in what order.

## 2. Q1 — does `31911b1` become redundant? (blunt answer)

**No, and reverting it would be the more expensive mistake. But half of it has a
two-week shelf life and must not be extended.**

Split it honestly:

- **Redundant (delete when (2) lands):** the recent-requests `<table>` markup and
  `renderNetRecent`/`loadNetworkRecent` in `index.html` (~80 lines). The Burp
  table does the same job better (filters, sort, click-to-detail, SSE).
- **Not redundant, and the reason to keep the commit:** everything the Jul-5 code
  *lacks*. `OpenReadOnly` (the Jul-5 UI opened the store **read-write** and would
  create it), `redactHeaders`, `DBProtectedFileNames()` (ADR 0092 D3 needs this),
  the route-registration test that caught a real 404, and
  `TestNetworkStatsJSONContract`. The Burp viewer has to inherit all of it anyway.
- **Genuinely distinct:** the **per-host stats panel** (`/api/network/stats`,
  `Stats`/`Count`). Burp has no equivalent — a flat history is not an aggregate.
  Keep it. It answers "what is this agent talking to" in one glance; the history
  table never will.

So the port is an **in-place upgrade of the tab (1) already added**, not a
replacement of it. Where I would push back on the framing: restoring (1) was not
wasted work, it was the substrate. What *would* be wasted is any further polish on
its table before (2) lands.

## 3. Q2 — the React/shadcn/TanStack SPA

### Was it ever ADR'd?

**No.** Searched `docs/adr/` on all refs: zero ADRs mention React, shadcn,
TanStack, Vite, npm, or node. `0008-readopt-charm-tui-styling` is the only
UI-toolkit ADR and it is about the TUI. `0a014948` landed a 1017-line `bun.lock`
and ~30 npm dependencies with no decision record, against an AGENTS.md that lists
"frontend frameworks" under **Avoid** and requires an ADR for any new dependency.

### Recommendation: **reject for now**, keep server-rendered vanilla HTML. Write ADR 0094 recording the rejection.

Build-tooling cost, concretely — this is not a style objection:

1. **`go build ./...` breaks on a clean clone, today.** `0a014948` adds
   `//go:embed all:static/dist` to `static_embed.go` **and** adds
   `cmd/agentjail/ui/static/dist/` to `.gitignore`. `go:embed` on a missing
   directory is a *compile error*. So a fresh clone cannot build the tree without
   first running `bun install && bun run build`. That is a hard regression of the
   single most important property of a Go repo.
2. **CI has no JS toolchain.** `.github/workflows/ci.yml` sets up Go only, on
   `ubuntu-latest` and `macos-14`, and runs `go build ./...` at line 30. Adopting
   the SPA means adding `setup-node`/`setup-bun` + a build step to CI *and* to
   `release.yml`, on both OSes, before anything compiles.
3. **`make licenses` goes silently wrong — this is a compliance defect, not a
   chore.** `scripts/gen-third-party-licenses.sh` is `go list`-only by design
   ("Dependency-free: uses only `go list` + the local module cache"). It cannot
   see npm. The Vite bundle is **compiled into the shipped binary** via
   `go:embed`, so we would be distributing hundreds of MIT/BSD/Apache-2.0
   JS packages in a binary whose `THIRD_PARTY_LICENSES` does not name one of them.
   `licenses-check` would pass while being wrong. Fixing it means a second
   generator for the npm tree — new tooling, unbudgeted.
4. **Supply chain, in a security product.** ~30 direct + several hundred
   transitive npm deps, resolved by `bun.lock`, embedded in the binary that
   polices other people's agents. That trade needs an ADR arguing *for* it, and
   nobody has written one.

Argue the other side, because it is not weak: the SPA is **~60 commits of real
work** and the vanilla page will never match TanStack Table's column filters and
virtualization. Rejecting it throws that away. Mitigation: the rescue branch is
now a durable ref — **do not delete it**. If the UI later earns the toolchain,
ADR 0094 gets superseded and the branch is the starting point. Deferring costs a
rebase; adopting now costs a broken `go build` in the same week we are trying to
land bodies.

**Deferred, not rejected forever.** ADR 0094 status: Accepted, with an explicit
"revisit when" clause (an npm license generator exists + CI has a JS stage + a
user need the vanilla page provably cannot meet).

## 4. Q3 — the two APIs, and which wins

**Jul-5 (`6ef49e02:cmd/agentjail/ui/network.go`):**
- `GET /api/requests?offset=&limit=&host=&method=&status=&policy=` → `{requests, count}` (error path emits `{requests, total, unavailable}` — an **inconsistent shape**, see §6)
- `GET /api/requests/:id` → bare `RequestLog`
- `GET /api/requests/stream` → SSE, polls `MaxID()` every 750 ms, marshals **full `RequestLog`** per row
- store side: `List`/`ListFilter`/`Get`/`MaxID` — **duplicating** the existing `Query`/`RequestFilter`. The Jul-5 store carried both. That duplication was already a smell.

**Current branch (`server.go`):**
- `GET /api/network/recent?limit=&host=&method=` → `{requests, count}`
- `GET /api/network/stats?since=` → `{hosts, total_requests, total_bytes}`
- store side: `Query`/`RequestFilter`, `Stats`, `Count`, `OpenReadOnly`, `redactHeaders`

### Winner: `/api/network/*`. `/api/requests` is deleted.

Reasons: it is the namespace with read-only access, header redaction, registered
routes proven by a test, and contract tests. `/api/requests` is also a bad name in
a server that already serves `/api/state`, `/api/events`, `/api/network/*` — it
reads like a top-level resource when it is network history.

The port therefore **moves the capabilities, not the routes**:

| Jul-5 | becomes |
|---|---|
| `GET /api/requests` | `GET /api/network/recent` (extend `RequestFilter` with `Offset`, `StatusClass`, `PolicyAction`) |
| `GET /api/requests/:id` | `GET /api/network/requests/{id}` |
| `GET /api/requests/stream` | `GET /api/network/stream` |
| `store.List`/`ListFilter` | **deleted** — fold into `Query`/`RequestFilter` |
| `store.Get`/`MaxID` | **kept**, ported onto `OpenReadOnly` handles |

**What happens to the other's tests: nothing is deleted.** `network_test.go` has no
Jul-5 counterpart to lose — (2) shipped with **zero** Go tests. Every existing test
in `network_test.go` stays valid (`/api/network/recent` and `/stats` keep their
shapes) and the file **grows** by the detail/stream/body contract tests. If any
existing assertion has to change, that is a signal the port broke a shipped
contract and needs a paragraph, not a `sed`.

## 5. Q4 — the body-capture delta (D1), concretely

The Jul-5 UI reads three JSON fields that **will not exist**:

```
36ba7ab2  RequestBody   string `json:"request_body,omitempty"`    // TEXT column
          ResponseBody  string `json:"response_body,omitempty"`   // TEXT column
          BodyTruncated bool   `json:"body_truncated,omitempty"`
network.html:448  lines.push(esc(pretty || req.request_body))
network.html:472  lines.push(esc(pretty || req.response_body))
network.html:451  req.body_truncated  → "truncated" badge
```

ADR 0092 D1 (as amended 2026-07-15) instead gives:

```
network_requests.request_body_path   TEXT  -- store-relative path
network_requests.response_body_path  TEXT
bodies live at ~/.agentjail/bodies/<generated-name>, mode 0600, dir 0700
no per-body size cap; raw bytes; not assumed UTF-8; may carry an `encoding_raw` marker
the file may be missing (crash/orphan sweep/user deletion) or short (partial capture)
```

The delta the ported UI must implement:

1. **The detail endpoint must not inline bodies.** D1's entire memory argument is
   that no `[]byte` of body size is ever resident. Marshalling the body into the
   detail JSON reintroduces exactly that on the **read** side — a 1 GB body
   would OOM the UI process instead of the daemon. Same bug, new door.
   → `GET /api/network/requests/{id}` returns metadata plus, per side:
   `body_present bool`, `body_size int64`, `body_encoding string` ("utf8"|"raw").
   **Never the bytes.**
2. **Bodies get their own streaming endpoints:**
   `GET /api/network/requests/{id}/body/{request|response}` — `os.Open` +
   `io.Copy`, `Content-Length` from `Stat`, honours `Range`. Headers:
   `X-Content-Type-Options: nosniff`; `text/plain; charset=utf-8` only after a
   UTF-8 validity check, else `application/octet-stream` + download affordance.
3. **The pane fetches a window, not the file.** No cap on storage ≠ no cap on
   render. The page requests `Range: bytes=0-262143` and shows
   "showing first 256 KB of N — [load all] [download]". A 1.3 MB body is the
   observed max; the browser must survive the case that is not.
4. **Path traversal is a new attack surface.** The path comes out of a database
   that any same-uid process can write (D3 is a *mediation* control, not a
   boundary — D3 says so itself). A row reading `../../.ssh/id_rsa` must 404.
   → `filepath.Join(bodiesDir, filepath.Clean("/"+p))`, then `EvalSymlinks`, then
   assert the result is still under `bodiesDir`. The TEXT-column design could not
   have this bug; the file design can. Test it explicitly.
5. **Missing file = absent, not error** (ADR 0092 invariant). Body endpoint → `204
   No Content`. Detail JSON → `body_present: false`. Never a 500. The row still
   lists and still renders.
6. **`body_truncated` is gone.** D1 does not truncate. The Jul-5 "truncated" badge
   must either be dropped or re-driven from a *different* signal (partial capture),
   which is a different meaning and needs a different word ("capture incomplete").
   Do not silently keep the badge wired to a field that no longer exists — that is
   the §6 bug class, pre-scheduled.
7. **Do not port `2f3d28ce` (gzip decode) or `36ba7ab2`'s mitm half.** D1 owns
   decode-at-capture with raw fallback + `encoding_raw`. **Another agent is
   porting that seam right now — `internal/mitm/` is off-limits to this plan.**
   This plan consumes `*_body_path` and `encoding` and touches no capture code.
8. **SSE must stream metadata only.** Jul-5's stream `json.Marshal`s the whole
   `RequestLog` per row. Under D1 that would push every body to every connected
   client every 750 ms. Stream the row minus bodies; the client fetches a body
   only when a pane is opened.

## 6. Q5 — making the JSON-contract bug unrepeatable

The history, so the requirement is not mistaken for ceremony. **Both** prior UIs
shipped broken and nobody could see it:

- old tab read `data.hosts`, handler emitted `stats` → per-host table empty, for months
- old tab read `count` / `total_request_bytes`, struct has `request_count` / `bytes_out`
- old tab read `req.status`, the tag is `status_code` → **every status cell showed `--`**
- Jul-5's own list handler is *already* inconsistent: success emits `{requests, count}`,
  the unavailable path emits `{requests, total, unavailable}`, and `api.ts` types it
  as `count?: number; total?: number` — a shape mismatch **encoded into the client
  as optionality**. This bug is live in the code we are about to port.

Go tests cannot see any of this: the handler is correct, the page is wrong, and
they never meet. `TestNetworkStatsJSONContract` (already on the branch) is the
right instinct and **is still not sufficient** — it pins the server's keys and has
no idea what the JS reads.

**The plan REQUIRES all four:**

1. **Exact-key contract tests, server side.** Decode into `map[string]any` (never
   the struct — decoding into the struct is what hides a renamed tag) and assert
   the precise key set for: `/api/network/recent` **rows**, `/api/network/stats`
   (exists), `/api/network/requests/{id}`, and the SSE event payload. One test per
   endpoint. Extend `network_test.go`.
2. **A browser test that asserts rendered VALUES.** `agent-browser` **0.28.0 is
   installed at `/home/openclaw/.npm-global/bin/agent-browser` and works.** Seed a
   real `network.db` + a real body file, boot the real server, drive the real page:
   - the history table contains `api.anthropic.com`
   - the status cell reads **`200`**, not `--`  ← the exact bug that shipped
   - the per-host table has ≥1 row and a non-zero request count ← the other one
   - clicking the row opens the detail panel and the request pane contains the
     seeded body text
   - a row whose body file was deleted still renders, with "body unavailable"
   - **zero console errors** (gate on it)
   Asserting *values* is load-bearing: `data.hosts || []` renders an empty table
   and `req.status || '--'` renders a dash. Both are "success" to every check that
   is not looking at pixels.
3. **Ban the idiom that hid it.** `x || fallback` on a field that must exist is how
   both bugs survived. In the ported page, unknown/absent required keys must
   `console.error` — which trips gate (2)'s console check. A missing key becomes a
   loud failure instead of a dash.
4. **A per-commit checklist rule:** *no new JSON key read by JS lands without a Go
   contract test naming that exact string, and no new rendered field lands without
   a browser assertion on its value.* Put it in the commit body.

Also port `esc()` faithfully — the Jul-5 page escapes body content
(`network.html:450,474`) but builds DOM by `innerHTML` string concat
(`:521`,`:522`). It is currently *correct* and one careless edit from stored XSS
in a panel that is same-origin with the endpoint serving every other body. Prefer
`textContent` for the body panes on port.

## 7. Q6 — security: what the viewer exposes

State it in the plan, not in a comment. **A UI that renders bodies renders the
user's source code and credentials into a browser.** ADR 0092 D4 is explicit that
header redaction is **not** mitigation: credentials are in URLs, query strings,
response headers, and in the bodies themselves, which are stored unredacted by
deliberate decision.

Requirements, all of which must land **with or before** the first body-serving
endpoint — not as follow-ups:

1. **The UI must never be launched under the shield.** D3 denies the agent
   `network.db`, its sidecars, and `bodies/`. A shielded UI does not fail loudly —
   it renders an **empty history**, which is indistinguishable from "the agent made
   no requests". That is the worst failure mode a security tool has: silence that
   reads as safety. → On startup, if the process detects it is sandboxed
   (`AGENTJAIL_SHIELD*` env / Landlock self-check), refuse to serve the network tab
   with an explicit message. Document it in README next to `agentjail ui`.
2. **DNS-rebinding / cross-origin is now critical.** The UI is loopback HTTP with
   no auth. Metadata made that boring; bodies make it a source-code exfil channel —
   any web page the user visits can point a hostname at 127.0.0.1 and read
   `/api/network/requests/1/body/response`. → **Host-header allowlist** (reject any
   `Host` that is not `127.0.0.1:<port>`/`localhost:<port>` — this is what actually
   kills rebinding), an `Origin`/`Sec-Fetch-Site` check on every `/api/` route, and
   **no** `Access-Control-Allow-Origin` header, ever. Same commit as the body
   endpoint.
3. **Never inline bodies in SSE** (§5.8) — that is a body broadcast to every client.
4. **Never log body content or paths** into `daemon.log` (ADR 0032 shape).
5. **Any export/copy affordance carries the unshippable warning.** ADR 0092:
   neither `network.db` nor `bodies/` may be attached to an issue or shared. A
   "copy as curl" button in a Burp-alike is the natural next feature and is a leak
   generator; if it lands, it copies **metadata only** unless the user confirms.
6. The viewer does not weaken D3, and the plan should not claim it hardens
   anything. It is a **reader** of the most sensitive file agentjail writes.

## 8. Q7 — commit-by-commit

Each: `go build && go vet && go test ./cmd/agentjail/ui/... ./internal/mitm/...`.
Sign off. No `internal/mitm/` capture-path edits (owned by the D1 agent).

1. `docs(adr): 0094 — reject the SPA, keep server-rendered HTML`
   Records §3, including the `go:embed` + gitignored-`dist` break, the Go-only
   license generator, and the revisit clause. Notes the rescue branch as the ref.
   Run `make adr-check` (0093 is taken; **re-check the number at merge time**).
2. `docs(plan): 013 — reconcile the three network UIs` — this file.
3. `refactor(mitm): one query path — fold ListFilter into RequestFilter`
   Adds `Offset`, `StatusClass`, `PolicyAction` to `RequestFilter`; no `List`.
   Store tests for each new filter. **Read-only store only.**
4. `feat(mitm): Get and MaxID on the read-only store` + tests.
5. `feat(ui): request detail endpoint at /api/network/requests/{id}`
   Metadata + `body_present`/`body_size`/`body_encoding`. **No bytes.**
   Exact-key contract test. Registered-route test.
6. `feat(ui): reject cross-origin and rebound Host on /api` — §7.2, standalone and
   **before** any body byte is served. Tests for a bad `Host` and a bad `Origin`.
7. `feat(ui): stream request bodies from ~/.agentjail/bodies`
   `.../body/{request|response}`, `Range`, `nosniff`, traversal guard, 204 on
   missing. Tests: traversal (`../../.ssh/id_rsa` → 404), missing → 204, `Range`
   window, large file does not grow RSS.
8. `feat(ui): SSE at /api/network/stream, metadata only`
   Ported from `6ef49e02`, bodies stripped, `MaxID` poll. Contract test on the
   event payload.
9. `feat(ui): Burp-style split req/resp detail panel in the Network tab`
   The port of `19ca0c9a`'s panel into `index.html`'s existing tab. Replaces the
   old recent-table markup (the redundant half of `31911b1`). Keeps the per-host
   stats panel. `esc()`/`textContent`. No `/network` page.
10. `test(ui): drive the real page with agent-browser and assert rendered values`
    §6.2, as `make ui-smoke`. **This is the commit that makes the whole thing
    worth doing** — land it, do not defer it.
11. `docs(readme): the network tab, and why the UI must not run shielded` — §7.1.

Commits 1–2 can land immediately. 3–5 need nothing from the D1 agent. **7 blocks on
D1's `*_body_path` columns existing.** 9 blocks on 5+7.

## 9. Adversarial review of my own recommendation

- **Most likely to go wrong: the D1 schema lands differently than ADR 0092 says.**
  Commits 7 and 9 are written against `request_body_path` / `response_body_path` /
  an `encoding_raw` marker that **do not exist yet** and are being built by another
  agent right now. ADR 0092 has already been amended once (BLOB → files) *and*
  corrected twice about what was built. A third divergence lands us re-porting the
  panel against a third schema. **Mitigation: do not start commit 7 until the
  columns are merged and readable.** Commits 3–6 are safe today.
- **Second: "reject the SPA" ages badly.** The vanilla page has no virtualization;
  the first user with 50k rows makes the history table unusable and the SPA looks
  prescient. I still recommend rejecting, because a broken `go build` on a clean
  clone is a certain cost this week and the 50k-row user is hypothetical — but the
  ADR must carry the revisit clause honestly, not as a fig leaf.
- **Third: I am recommending we walk away from ~60 commits.** That is the biggest
  single cost here and I want it named. The Policies page, the session sidebar, and
  the statusline link on that branch may each be independently worth salvaging into
  vanilla HTML. This plan does not schedule that, and the branch will rot. Someone
  should triage those 61 commits separately; if that triage says "most of the value
  is in the SPA-shaped parts", my §3 recommendation gets weaker, not stronger.
- **Fourth: the browser test is the load-bearing new thing and it is the most
  likely to be quietly dropped.** It is the slowest, flakiest commit and the one
  with the weakest CI story (§10). If it becomes "local only, run it sometimes",
  we have rebuilt the exact conditions that let `req.status` render `--` for
  months. If commit 10 is cut, cut commit 9 too — a body panel with no rendered
  assertion is a repeat, not a port.
- **Fifth: the rebasing story.** `31911b1` and the D1 work and this port all touch
  `server.go` and `network_test.go`. Three agents, one file. Expect conflicts;
  keep the commits small (which the plan does) and land 3–6 early to shrink them.

## 10. What I could not determine

- **Whether `agent-browser` can run in CI.** It is installed and working on this
  box; nothing in `.github/workflows/ci.yml` sets up a browser. Commit 10 may be
  local/`make`-only at first. **A human decision:** is a local-only gate
  acceptable, or does CI get a browser stage? (I lean: local-only now, CI stage
  next — but see §9's fourth bullet.)
- **The exact D1 column names and encoding-marker representation.** Read from ADR
  0092's prose, not from merged code. `encoding_raw` may be a column, a flag, or a
  filename suffix. Commit 7 must be written against the real thing.
- **Whether the ~60 post-`0a014948` rescue commits contain non-SPA fixes worth
  cherry-picking.** I read commit subjects, not diffs. `9648cc6 fix(ui): network
  deny count from actual requests` and `e3f6338 fix(ui): filter network requests by
  session time window` sound like they encode real product knowledge that is not
  React-specific.
- **Whether `/api/network/sessions`** (referenced by `0a014948:api.ts`) ever existed
  server-side. I did not find its handler. If the ported panel wants session
  filtering, that endpoint may itself be a phantom — worth 10 minutes before
  anyone relies on it.
- **Whether the UI process can reliably self-detect that it is shielded** (§7.1).
  The env-var check is trivial to bypass and a Landlock self-check may not be
  readable from inside. The requirement stands; the mechanism is unproven.
- **What the human wants `/network` to be.** I am recommending one tabbed page. If
  the intent was always a separate Burp-alike window, say so now — it changes
  commit 9, and only commit 9.

## 11. Decisions the human must make

1. **Adopt / reject / defer the React SPA.** I recommend reject + ADR 0094, with a
   revisit clause. This is the only decision that cannot be deferred cheaply — the
   longer the rescue branch sits, the worse the rebase.
2. **Triage the other ~60 rescue commits** — separate plan, or let the branch rot?
3. **`agent-browser` in CI**, or a local-only `make ui-smoke` gate? (§10)
4. **One tabbed page, or a separate `/network` Burp window?** (§10)
5. **Confirm `internal/mitm/` stays off-limits** to this plan and that D1's column
   names will be published before commit 7 starts.
