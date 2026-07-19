# 010 — Linux tunnel: full HTTP/2 MITM, end-to-end

**Claim board.** This is the coordination surface so two models don't pick the
same task. Owner of this workstream: the **Linux orchestrator** (this box,
branch `feat/network-visibility`). Mirrors Linear AGE-223 / AGE-81 — keep both in
sync. macOS work is out of scope here (tunnel is Linux-only; see AGE-149).

**Protocol.** Every task carries `STATUS` (`todo` / `in-progress` / `done`) and
`OWNER` (the worker branch, or a model id). A task is claimed by setting
`in-progress` + OWNER before work starts, and `done` + merge SHA when verified &
merged. Do not start a task already `in-progress` under another OWNER.

**Ready-to-use gate.** The feature is "ready" only when Round 4's automated
h2 + gRPC TUN-interception e2e is green. Docs (Round 5) start only after that.

---

## Round 1 — h2 MITM core — ✅ DONE (merged `e3ab92a`)
- [x] Offer `[h2, http/1.1]` ALPN + branch on negotiated proto — `feat/net-h2-core`
- [x] h2 client-serving via `http2.Server.ServeConn` — done
- [x] h2 upstream via `http2.Transport` (ForceAttemptHTTP2) — done
- [x] recording/policy/deny/body parity with h1 — done
- [x] h1 path untouched; `TestE2ETUNInterception` green — done
- ADR 0102-mitm-serves-h2. Verified: independent tests + mutation probe + codex.

## Round 2 — additive (parallel) — status: in-progress
Worker A (`feat/net-h2-hardening`, internal/mitm) owns R2.1–R2.6.
- [ ] **R2.1** gRPC over h2: trailers end-to-end, `grpc-status`/`application/grpc`, unary — STATUS: in-progress — OWNER: feat/net-h2-hardening
- [ ] **R2.2** hop-by-hop header stripping (Connection, Transfer-Encoding, Keep-Alive, TE, Upgrade) on both legs — STATUS: in-progress — OWNER: feat/net-h2-hardening
- [ ] **R2.3** h2 body capture soak: gzip decode + redaction over h2 (req+resp), large (>maxBodyScan) bodies — STATUS: in-progress — OWNER: feat/net-h2-hardening
- [ ] **R2.4** streaming: server-streaming / SSE over h2 flows incrementally, no unbounded buffering (assert flush) — STATUS: in-progress — OWNER: feat/net-h2-hardening
- [ ] **R2.5** request trailers forwarded + covered by a test — STATUS: in-progress — OWNER: feat/net-h2-hardening
- [ ] **R2.6** upstream transport lifecycle: reuse across streams of one tunnel without per-CONNECT thrash — STATUS: in-progress — OWNER: feat/net-h2-hardening

## Round 3 — integration + e2e — status: in-progress (parallel with R2)
Worker B (`feat/net-h2-e2e`, internal/tunnel) owns R3.2–R3.4. Tests validate
once R2 merges; B builds scaffolding in parallel on disjoint files.
- [x] **R3.1** h2 already flows through the tunnel: the gateway calls `MITMHandler.Handle`, which now branches to `serveH2` (landed Round 1). No separate wiring needed — STATUS: done (Round 1)
- [ ] **R3.2** `TestE2ETUNInterceptionH2` — real TUN, unprivileged, h2 decrypt+record — STATUS: in-progress — OWNER: feat/net-h2-e2e
- [ ] **R3.3** gRPC-over-TUN e2e — STATUS: in-progress — OWNER: feat/net-h2-e2e
- [ ] **R3.4** ALPN edge cases: h2-only pinned, h1-only, both offered — STATUS: in-progress — OWNER: feat/net-h2-e2e

## Round 4 — ready-to-use gate (Opus orchestrator) — status: blocked
- [ ] Full `go build/vet/test` + h2/gRPC TUN e2e green
- [ ] Scripted `agentjail run --tunnel` vs an h2+gRPC server → decrypted rows in `network.db`
- [ ] Completeness critic → loop back to fix-tasks until green
- [ ] (Live: real Claude Code over the h2 tunnel — human final check, flagged not auto)

## Round 5 — DOCS (only after Round 4 green) — status: blocked
- [ ] README/SANDBOX: h2 + gRPC shipped; `--mitm/--no-mitm`, `--trusted-host`, `--retention-interval`
- [ ] ADR superseding the h1-only downgrade note; GOTCHAS update
- [ ] Changelog + release SVG + `agentjail.io/src/data/releases.ts`
