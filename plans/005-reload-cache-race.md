# Plan 005: Fix the SIGHUP reload cache race in the daemon

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 11129c5..HEAD -- cmd/agentjail-daemon/main.go`
> If the file changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as
> a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: MED
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `11129c5`, 2026-06-11

## Why this matters

When a policy reload (`SIGHUP`) tightens the rules, the daemon swaps the engine
and invalidates the decision cache so stale "allow" verdicts can't survive into
the new rule set. But there is a race: `eval()` reads the engine + cache under a
read-lock, **releases the lock**, then evaluates and writes the result back with
`cache.Set`. If a `reload()` runs in that gap — it takes the write lock, swaps
the engine, and calls `cache.Invalidate()` — the in-flight `eval()` then writes
a decision **computed by the old engine** into the freshly-invalidated cache.
That stale verdict is now served to future callers until the entry is evicted.
For a reload meant to *deny* a newly-dangerous pattern, this re-opens the exact
hole the reload was closing. This plan makes `eval()` discard its cache write if
a reload happened during evaluation, using a generation counter.

## Current state

`cmd/agentjail-daemon/main.go`.

The `server` struct (line 82):

```go
type server struct {
	engineMu sync.RWMutex
	engine   policy.HookEngine
	cache    policy.Cache

	// wg tracks in-flight connections so graceful shutdown can drain them.
	wg sync.WaitGroup

	// telemetry is nil-safe: a nil recorder records nothing.
	telemetry *telemetry.Recorder
}
```

`eval()` (lines 140–196), the relevant part:

```go
	s.engineMu.RLock()
	eng := s.engine
	cache := s.cache
	s.engineMu.RUnlock()

	if d, ok := cache.Get(cacheKey); ok {
		return Response{ ... }, nil
	}

	d, err := eng.Eval(ctx, input)
	if err != nil {
		// Fail-safe: on evaluation error, return "ask" ...
		return Response{ ID: req.ID, Action: "ask", Reason: "policy evaluation error: " + err.Error() }, err
	}

	cache.Set(cacheKey, d)   // <-- line 187: stale write can land here after a concurrent Invalidate

	return Response{ ... }, nil
```

`reload()` (lines 508–529):

```go
	s.engineMu.Lock()
	s.engine = eng
	// Invalidate the cache on reload so decisions from the old rule set
	// cannot leak into the new one. ...
	s.cache.Invalidate()
	s.engineMu.Unlock()
```

Note `reload()` mutates the cache **in place** (`s.cache.Invalidate()`) rather
than replacing the cache object, and `eval()` captured the same `cache` pointer
— so the stale `cache.Set` lands in the live cache. The `policy.Cache` interface
(`agentpolicy/internal/policy/lru_cache.go`) is `Get`, `Set`, `Invalidate`,
`Stats`; the cache itself is internally mutex-guarded (its methods are
thread-safe), so the race is at the *daemon's* engine/cache coordination layer,
not inside the cache.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Build | `go build ./...` | exit 0 |
| Vet | `go vet ./...` | exit 0 |
| Daemon tests w/ race detector | `go test ./cmd/agentjail-daemon/ -race` | all pass |
| Run the new test | `go test ./cmd/agentjail-daemon/ -race -run TestReload` | passes |
| Full suite | `go test ./... -race` | all pass |

## Scope

**In scope**:
- `cmd/agentjail-daemon/main.go` (add a generation counter; guard the cache write)
- `cmd/agentjail-daemon/main_test.go` (add a regression test)

**Out of scope** (do NOT touch):
- `agentpolicy/internal/policy/lru_cache.go` and the `Cache` interface — the
  cache is already internally thread-safe; do not change its API.
- The fail-safe "ask on error" behavior — leave it exactly as is.
- Any `.rego` file.

## Git workflow

- Branch: `advisor/005-reload-cache-race`
- Conventional Commits with sign-off (`git commit -s`). Suggested:
  `fix(daemon): discard stale cache write when policy reloads mid-eval`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add a generation counter to `server`

Add a field to the `server` struct and import `sync/atomic` if not already
imported. Use an `atomic.Uint64` so it can be read without holding `engineMu`:

```go
type server struct {
	engineMu sync.RWMutex
	engine   policy.HookEngine
	cache    policy.Cache
	gen      atomic.Uint64   // bumped on every reload; guards stale cache writes

	wg        sync.WaitGroup
	telemetry *telemetry.Recorder
}
```

**Verify**: `go build ./...` → exit 0.

### Step 2: Bump the generation in `reload()`

In `reload()`, inside the existing write-locked section, bump the counter
alongside the engine swap and invalidate:

```go
	s.engineMu.Lock()
	s.engine = eng
	s.gen.Add(1)
	s.cache.Invalidate()
	s.engineMu.Unlock()
```

**Verify**: `go build ./...` → exit 0.

### Step 3: Guard the cache write in `eval()`

Capture the generation when reading the engine/cache, and only write to the
cache if the generation is unchanged after evaluation. Change the capture block
and the `cache.Set` call:

```go
	s.engineMu.RLock()
	eng := s.engine
	cache := s.cache
	genAtStart := s.gen.Load()
	s.engineMu.RUnlock()

	if d, ok := cache.Get(cacheKey); ok {
		return Response{ ... }, nil   // unchanged
	}

	d, err := eng.Eval(ctx, input)
	if err != nil {
		// unchanged fail-safe "ask"
		...
	}

	// Only cache the decision if no reload happened during evaluation.
	// A reload swaps the engine and invalidates the cache; a verdict computed
	// by the old engine must not be written back into the new epoch.
	if s.gen.Load() == genAtStart {
		cache.Set(cacheKey, d)
	}

	return Response{ ... }, nil   // unchanged: still returns d to the caller
```

Note: the *caller still receives the freshly-computed verdict `d`* — we only
skip persisting it. The next call for the same input will recompute against the
new engine and cache that (correct) result. This is the conservative choice: a
verdict is never served from a stale epoch's cache.

**Verify**: `go build ./... && go vet ./...` → exit 0.

### Step 4: Add a regression test

In `cmd/agentjail-daemon/main_test.go`, add a test that drives the race
deterministically without relying on timing. The cleanest approach: construct a
`server` with a real `NewLRUCache`, set `genAtStart` semantics by calling the
pieces directly, OR — simpler and timing-free — unit-test the invariant: after a
reload bumps `gen`, a cache `Set` keyed by the old generation must not persist.

Model the test on existing daemon tests (see `cmd/agentjail-daemon/main_test.go`
for how a `server` is constructed in tests — reuse that helper). Write a test
named `TestReloadDiscardsStaleCacheWrite` that:

1. Builds a `server` with an engine and `policy.NewLRUCache(...)`.
2. Captures `gen := s.gen.Load()`.
3. Calls `s.reload(ctx, modules, cfg)` (or directly bumps via the same path) so
   `s.gen` increments and the cache is invalidated.
4. Simulates the in-flight write: asserts that the guard `s.gen.Load() == gen`
   is now **false**, so `eval` would skip the `Set`. If the daemon test harness
   makes it easy to call `eval` concurrently, prefer an end-to-end form: start an
   eval against a slow/stub engine, trigger reload, and assert the post-reload
   cache does not contain the stale key. If a stub engine is not readily
   available, the invariant-level test (steps 1–4) is acceptable and sufficient.

If `reload()` requires real Rego modules to construct, reuse whatever module
fixtures existing daemon tests already use (grep `main_test.go` for `reload(` or
`NewHookOPAEngine`).

**Verify**: `go test ./cmd/agentjail-daemon/ -race -run TestReload` → passes.

### Step 5: Full suite under the race detector

**Verify**:
- `go test ./cmd/agentjail-daemon/ -race` → all pass, no `DATA RACE` reports.
- `go test ./... -race` → all pass.

## Test plan

- New test `TestReloadDiscardsStaleCacheWrite` in
  `cmd/agentjail-daemon/main_test.go` proving a verdict computed before a reload
  is not persisted into the post-reload cache epoch.
- Structural pattern: the existing `server` construction in
  `cmd/agentjail-daemon/main_test.go`.
- Verification: `go test ./cmd/agentjail-daemon/ -race` green; full
  `go test ./... -race` green.

## Done criteria

ALL must hold:

- [ ] `server` has a `gen atomic.Uint64` field; `reload()` calls `s.gen.Add(1)` inside the write lock
- [ ] `eval()` captures `genAtStart` under the RLock and only calls `cache.Set` when `s.gen.Load() == genAtStart`
- [ ] `eval()` still returns the freshly-computed verdict to the caller in all non-error cases (behavior for the *caller* unchanged)
- [ ] `TestReloadDiscardsStaleCacheWrite` exists and passes
- [ ] `go test ./cmd/agentjail-daemon/ -race` exits 0 with no DATA RACE output
- [ ] `go test ./... -race` exits 0
- [ ] Only the two in-scope files modified (`git status`)
- [ ] `plans/README.md` status row for 005 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `eval()` or `reload()` does not match the "Current state" excerpts (drift) — in
  particular, if `reload()` already replaces the cache object instead of calling
  `Invalidate()` in place, the race may already be handled differently; report it.
- You cannot construct a `server` in a test without large new fixtures — report
  what `main_test.go` provides and propose the invariant-level test instead.
- Adding the guard changes any existing daemon test's expected behavior (it
  should not — callers still get their verdict).

## Maintenance notes

- The guard trades a negligible cache-hit-rate dip (decisions computed exactly
  during a reload aren't cached) for correctness. Reloads are rare (SIGHUP), so
  the cost is immeasurable in practice.
- A reviewer should confirm `gen` is read with `Load()` (atomic) outside the lock
  and bumped with `Add(1)` inside the write lock — never mixed with non-atomic
  access.
- If a future change replaces `s.cache.Invalidate()` with swapping in a fresh
  cache object, this guard still holds (the captured `cache` pointer would be the
  old object and the gen check still discards the write) — but simplify then if
  desired.
