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

## Round 2 — additive — ✅ DONE (merged `a2fd26c`..HEAD, worker `feat/net-h2-hardening`)
- [x] **R2.1** gRPC unary over h2 (raw application/grpc, `grpc-status`/`grpc-message` trailers) — done, e2e-proven
- [x] **R2.2** hop-by-hop stripping (Connection/Proxy-Connection/Keep-Alive/Transfer-Encoding/TE/Upgrade/Trailer + Connection-by-value) both legs — done, mutation-probed
- [x] **R2.3** gzip decode + redaction over h2 + >maxBodyScan RequestSize — done
- [x] **R2.4** streaming/flush over h2 — done (already streamed; test added)
- [x] **R2.5** request trailers on streamed bodies — **real bug fixed** (`.Clone()` froze an all-nil map before net/http2 filled it) — done, mutation-probed
- [x] **R2.6** transport reuse (1 conn / 20 reqs) + no goroutine leak on exit — done, mutation-probed

## Round 3 — streaming pre-drain — ✅ DONE (worker `feat/net-h2-streaming`)
- [x] `isStreamingRequest` (application/grpc or ContentLength<0) → stream body upstream, no pre-drain; header/path policy still fires; body-scan non-coverage stated in ADR 0102. No-deadlock test mutation-probed.
- Caveat (in ADR): any chunked h2 POST without Content-Length also skips body-content scan — broader than gRPC-only, intentional (no-deadlock > full scan on an unbounded body).

## READY GATE — ✅ GREEN, COMPLETELY DONE (automated)
- mitm suite (~90 tests) · `TestE2ETUNInterception` (baseline) + `…H2` + `…GRPC` + `…ALPN` — **4/4 PASS** over the real TUN (`unshare -rn` + lo up).
- Covers: h2 decrypt, gRPC unary (grpc-status via trailer), ALPN edge cases, hop-by-hop stripping, trailers, gzip/redaction, transport reuse, and no client-streaming deadlock.
- **One human step remains (not automatable headless):** a live `agentjail run --tunnel -- <real agent>` over the deployed build. The real-TUN harness exercises the same serveH2 + gVisor + handleConn path minus install/CA-injection.

## Round 5 — DOCS — status: in-progress (gate is green)

## Round 3 — integration + e2e — ✅ DONE (merged `a2fd26c`)
Core h2/gRPC interception already passes the real-TUN e2e against the Round-1
core — no hardening needed for these scenarios.
- [x] **R3.1** h2 flows through the tunnel by construction: gateway → `Handle` → `serveH2` (Round 1)
- [x] **R3.2** `TestE2ETUNInterceptionH2` — PASS (h2 decrypt over TUN, upstream ProtoMajor=2)
- [x] **R3.3** gRPC-over-TUN — PASS (unary, `grpc-status=0` through the trailer)
- [x] **R3.4** ALPN edge cases (h2-only / h1-only / both) — PASS (3/3 subtests)

### How to actually RUN the TUN e2e (don't lose this)
These tests bind literal `127.0.0.1:443`, which needs privilege. On a plain host
they `t.Skip` cleanly. To run for real without root, use a user+net namespace and
bring loopback up (else the MITM→upstream dial fails 502):
```
unshare -rn bash -c 'ip link set lo up; go test -timeout 300s -count=1 -v \
  -run "TestE2ETUNInterception" ./internal/tunnel/'
```
Verified 3/3 green on this box. CI running as root satisfies the bind directly.

## Round 4 — ready-to-use gate (Opus orchestrator) — status: blocked
- [ ] Full `go build/vet/test` + h2/gRPC TUN e2e green
- [ ] Scripted `agentjail run --tunnel` vs an h2+gRPC server → decrypted rows in `network.db`
- [ ] Completeness critic → loop back to fix-tasks until green
- [ ] (Live: real Claude Code over the h2 tunnel — human final check, flagged not auto)

## Round 5 — DOCS (only after Round 4 green) — status: blocked
- [ ] README/SANDBOX: h2 + gRPC shipped; `--mitm/--no-mitm`, `--trusted-host`, `--retention-interval`
- [ ] ADR superseding the h1-only downgrade note; GOTCHAS update
- [ ] Changelog + release SVG + `agentjail.io/src/data/releases.ts`
