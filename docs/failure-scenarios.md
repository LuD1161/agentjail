# agentjail — Failure-Scenario Matrix

This document enumerates how agentjail breaks, what should happen, and what
happens today. It exists because of AGE-212: the policy daemon stopped on
2026-07-10 and was not restarted for three days. The shield kept activating
(464 `shield.activated` events), the hook fell back to `levelAllow`
(`cmd/agentjail-hook/hookfallback.go:49`), the `decisions` table recorded zero
rows for two days, and the status line kept rendering
`🔒 [secured by agentjail]` the entire time, because the badge keyed on
`AGENTJAIL_SHIELDED` alone and never probed the daemon.

Both halves of that badge are now fixed: ADR 0085-statusline-attests-daemon
adds a `POLICY OFF` state for a dead daemon, and ADR 0087-shielded-means-sandboxed
makes `AGENTJAIL_SHIELDED` mean a sandbox was actually applied (C2, H7).
The darwin sbpl-validation window (C7) remains open.

Every one of the 16 testbed scenarios (`test/testbed/scenarios/`) passed
throughout. All 16 are happy-path feature tests; **none kills or stops the
daemon, and none asserts anything about the daemon being down**. That is the
gap this matrix closes.

## How to read this

- **Actual behaviour** is read from the code and cited `file.go:line`. Where
  behaviour cannot be determined without executing it, the row says
  **UNVERIFIED — needs a live test**. Nothing here is inferred and presented
  as fact.
- **Priority** is testing priority, not severity. **P0** = would have caught
  AGE-212 or an incident of the same class. **P1** = silent enforcement loss
  by another route. **P2** = loud or self-correcting.
- Related: [ADR 0050](./adr/0050-daemon-unreachable-policy.md),
  [ADR 0070](./adr/0070-supervisor-restarts-daemon-on-clean-exit.md),
  [ADR 0072](./adr/0072-dropped-decisions-are-auditable.md),
  [ADR 0073](./adr/0073-fail-open-notice-uses-systemmessage.md),
  [ADR 0074](./adr/0074-degraded-is-the-default-posture.md),
  [ADR 0082](./adr/0082-doctor-attests-enforcement.md).

## Scenario count

| Axis | Scenarios | UNVERIFIED |
|---|---|---|
| A. Daemon lifecycle | 10 | 3 |
| B. Hook | 9 | 2 |
| C. Shield | 9 | 3 |
| D. Store / SQLite | 7 | 4 |
| E. Install / upgrade | 7 | 3 |
| F. Multi-agent contract | 5 | 3 |
| G. OS backend drift | 5 | 2 |
| H. Tampering / adversarial | 7 | 4 |
| **Total** | **59** | **24** |

---

## A. Daemon lifecycle

| # | Trigger | Expected | Actual (cited) | Detectable? | Test | Pri |
|---|---|---|---|---|---|---|
| A1 | `systemctl --user stop agentjail-daemon` / `launchctl bootout` — an *intentional* stop | Supervisor does not fight it (correct), but the user must be told enforcement is off | Systemd does not restart a `systemctl --user stop`; this is explicit and intended (`docs/adr/0070-supervisor-restarts-daemon-on-clean-exit.md`, "Consequences"). The hook then fails open per sidecar level. **This is the AGE-212 shape.** | `agentjail doctor` → Enforcement check (`cmd/agentjail/doctor_protection.go:45`), the `systemMessage` banner (ADR 0073), and — since ADR 0085-statusline-attests-daemon — the status line's `POLICY OFF` badge. | none in testbed | **P0** |
| A2 | Daemon exits 0 (auto-update handoff) and supervisor does not restart | Supervisor restarts on any exit | `Restart=always` + `RestartSec=2` (`cmd/agentjail/install.go:1935-1936`); launchd `KeepAlive=<true/>` (`cmd/agentjail/install.go:1831-1832`). Pinned by `TestInstallSystemdUnitContent`. | Yes, if the unit on disk is current | `TestInstallSystemdUnitContent` (unit *content* only — no live restart test) | P1 |
| A3 | **Installed unit predates ADR 0070** (`Restart=on-failure`) | Upgrade repairs the deployed restart invariant; doctor flags and can repair it | Implemented by `ensureDaemonRestartPolicy`; manual update then explicitly restarts the service and rolls back if activation fails. The clean-machine live upgrade path remains a release-gate concern. | Doctor reads the deployed unit/plist and also compares the running daemon version with the installed CLI | invariant, updater rollback, and doctor skew unit tests | P1 |
| A4 | SIGKILL mid-session | Supervisor restarts within ~2s; in-flight decisions lost but counted | Restart is supervised (A2). The final `flushDroppedDecisions` never runs, so drops in the last ≤30s window are unrecorded — accepted in ADR 0072 ("any drop after the final flush, e.g. SIGKILL"). | `decisions.dropped` gap is invisible by construction | none | P1 |
| A5 | Daemon panics | Restart + a durable trace | No `recover()` exists anywhere in non-test Go source. The runtime dump lands in `crash.log` via the supervisor's stdout/stderr redirect (`install.go:1833-1836` launchd, `install.go:1937-1938` systemd). The flock releases on process death (`internal/daemonapp/singleton.go:39-40`). | `crash.log` — but **launchd opens it `O_TRUNC` per restart, so macOS wipes it every restart** (`install.go:1814-1816`), while systemd uses `append:` (`install.go:1920-1922`). A macOS crash loop erases its own evidence. | none | **P0** |
| A6 | Crash loop (bad policy, missing dep) | Loud, rate-bounded, visible | Restarts forever with no backoff — accepted in ADR 0070 ("a genuine crash loop restarts forever rather than backing off"), bounded only by `RestartSec=2` and the ADR 0060 flock. | Only `crash.log`, which on macOS is truncated each restart (A5) | none | P1 |
| A7 | Two daemons start (race, double-install) | Second stands down | `acquireInstanceLock` flocks `daemon.lock`, 10×100ms retries (`internal/daemonapp/singleton.go:44`, constants `:27-33`). Loser logs "standing down" and **returns 0** (`internal/daemonapp/main.go:838-841`). | Yes — `daemon.log` | `TestSingleInstance_SecondStartStandsDownAtLock` (`internal/daemonapp/singleton_test.go:122`) | P2 |
| A8 | A7 + supervisor: loser exits 0, `Restart=always` restarts it | Should converge, not spin | UNVERIFIED — needs a live test. The stand-down path returns 0 and the supervisor restarts on exit 0 by design (ADR 0070). Whether this produces a restart loop until the first daemon dies is not determinable from source. | `crash.log` / journal noise | none | P1 |
| A9 | Socket file left behind, no listener (unclean kill) | Unlink and rebind | `bindAgentSocket` probes with a real `ControlOpPing` (200ms, `singleton.go:76`, `:61`) — a bare `connect()` is explicitly not "live" (`singleton.go:74-75`). `probeNoListener` → unlink + bind (`singleton.go:107-111`). | Yes | `TestBindAgentSocket_RemovesStaleSocketFile` (`singleton_test.go:66`) | P2 |
| A10 | Socket held by an unresponsive non-agentjail process | Refuse to unlink; fail loudly | Errors out: "socket %s is held by an unresponsive non-agentjail process; refusing to unlink it" (`singleton.go:105-106`). Daemon does not start → hook fails open. | `daemon.log` only; combined with A1's blind spot this is a silent unprotected window | `TestBindAgentSocket_ErrorsForUnresponsiveSquatter` (`singleton_test.go:96`) | P1 |

---

## B. Hook

| # | Trigger | Expected | Actual (cited) | Detectable? | Test | Pri |
|---|---|---|---|---|---|---|
| B1 | Daemon unreachable, sidecar **absent** | Some floor of enforcement | Falls to `levelAllow` — **zero policy** (`cmd/agentjail-hook/hookfallback.go:48-53`). Named explicitly in ADR 0074: "a missing sidecar still resolves to `allow`, and this default does not fix that". The gap is the daemon that *never started*. | `systemMessage` banner (ADR 0073) + `fail_open` telemetry | none end-to-end | **P0** |
| B2 | Daemon unreachable, sidecar present, level=`degraded` (default since ADR 0074) | Locked rules still enforced offline | `resolveFailOpenDecision` matches `fb.OfflineRules` (`hookfallback.go:134-147`); default coerced to degraded at `internal/daemonapp/hookfallback.go:26-28`. | Yes — banner + denials | Writer only: `TestWriteHookFallbackEmptyLevelDefaultsToDegraded` (`internal/daemonapp/hookfallback_test.go:176`). **No test exercises a hook failing open against a dead daemon.** | **P0** |
| B3 | Sidecar **stale** (daemon died before rewriting level) | Documented, low-risk | Named as a known new failure mode in ADR 0050 ("Consequences"). Hook has no freshness check — no mtime, no nonce (`hookfallback.go:48-70` checks only `Version` and `Level`). | No | none | P1 |
| B4 | Sidecar corrupt / unknown `Level` / future `Version` | Fail open, not crash | All three → `{Level: allow}, false` (`hookfallback.go:56-69`). Deliberate. | Banner only | none | P1 |
| B5 | `compileOfflineRules()` fails on the daemon side | Loud | Sidecar written with **empty** `offline_rules`, so `degraded` is vacuously `allow` until the next reload; logged at Warn (`internal/daemonapp/hookfallback.go:38-44`). Silent to the user. | `daemon.log` only | none | P1 |
| B6 | Daemon alive but slow (>30ms dial / >45ms round-trip) | Fail open, counted | Fail open (`cmd/agentjail-hook/main.go:479`, `:486`); category `read-response` or `dial-daemon` (`main.go:596-601`). **A DoS lever**: keep the daemon busy and the next call is unpoliced — the concern ADR 0074 blunts but does not remove. | `fail_open` telemetry frequency | none | P1 |
| B7 | Hook stderr on an exit-0 allow | User sees the warning | Claude Code **discards hook stderr on exit 0** — the AGE-212 root cause (ADR 0073). Fixed by riding `systemMessage` (`main.go:110-111`, `:347-358`). | Now yes, on Claude | none end-to-end | **P0** |
| B8 | Daemon returns an unrecognised `action` value | Fail closed or ask | Falls through to **allow** (`main.go:636-647` `default:`, comment: "fail-open semantics for unknown future action values"). | No | none | P2 |
| B9 | `AGENTJAIL_SOCKET` points at an attacker "always-allow" socket | Ignored | Honoured only under `~/.agentjail` (`main.go:153-179`, `:186-191`); not in the shield env allowlist. But: a hook that failed open against an *overridden* socket while a healthy daemon ran makes doctor's sentinel check misreport — named in ADR 0082 "Consequences". | Partially | UNVERIFIED — needs a live test for the override-vs-sentinel interaction | P2 |

---

## C. Shield

The shield's independence from the daemon is the property that made AGE-212
invisible **and** the property that makes it detectable after the fact
(ADR 0082). Both facts belong in the same row set.

| # | Trigger | Expected | Actual (cited) | Detectable? | Test | Pri |
|---|---|---|---|---|---|---|
| C1 | Shield launches while the daemon is **down** | Refuse, or at minimum warn | **No daemon liveness check exists in the shield launch path.** `internal/shieldapp/main.go` contains zero daemon probes; `daemon.sock` appears only as a Landlock path grant (`internal/shieldapp/shield_agentpaths.go:86`). The shield activates, writes `shield.activated`, and execs the agent. **This is exactly the 464-events-vs-0-decisions divergence.** | Only retroactively via `enforcementGapCheck` (`cmd/agentjail/doctor_protection.go:45`) | none | **P0** |
| C2 | `AGENTJAIL_SHIELDED=1` set without kernel enforcement | Badge must attest real enforcement | **FIXED** (ADR 0087-shielded-means-sandboxed). Was set unconditionally after the `applyLandlock` branch, incl. the `errLandlockUnsupported` fail-open path and the `AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1` override; on darwin also inside `execAgent`, the explicit no-sandbox path. Now written only by `AppendShieldedEnv(env, SandboxState)` in the tag-free contract (`shield_contract.go`) — the single site in the tree, so the backends cannot drift. `NotSandboxed` is the zero value. | Yes — badge reads `UNSECURED` | `TestAppendShieldedEnv`, `TestNotSandboxedIsZeroValue` (`internal/shieldapp/shield_contract_shielded_test.go`) assert the **premise** (state→env), not just env→badge | P2 |
| C3 | Store open fails (locked / corrupt / no `$HOME`) | Warn at least | Silently swallowed: emitter stays `audit.NopEmitter{}`, `store.Open` wired only `if err == nil` (`internal/shieldapp/main.go:106-114`). No log, no warning. **A fully-sandboxed launch may record no `shield.activated` at all** — which also silently defeats doctor's C1 cross-check. | No | none | **P0** |
| C4 | Old kernel, Landlock ABI absent | Fail loud; ideally refuse | Fails **open**: prints "Landlock unavailable — sandbox enforcement disabled", emits `ShieldFailed`, execs unsandboxed (`shield_linux.go:249-258`). Probe at `:456-462`. | stderr warning — which scrolls away under Claude Code's TUI, the exact problem ADR 0064 names | `internal/shieldapp/shield_linux_enforce_test.go` (enforcement, not the unsupported path) | P1 |
| C5 | Landlock ABI present but `landlock_create_ruleset` rejected | Fail closed | Fails **closed**: `os.Exit(1)` (`shield_linux.go:271`), unless `AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1` (`:269`). Note the asymmetry with C4. | Yes — the agent does not start | none | P2 |
| C6 | `/usr/bin/sandbox-exec` missing (macOS) | Fail closed, or loud | Fails **open**: warns, emits `ShieldFailed`, then `execAgent()` with **no sandbox** (`shield_darwin.go:720-734`). | stderr only (C4's problem) | none | P1 |
| C7 | macOS sbpl profile **rejected by `sandbox-exec`** | Detected before attesting | **Not detected.** There is no profile pre-validation, and `shield.activated` is emitted at `shield_darwin.go:763-766` *before* `syscall.Exec` (`:769`). If the profile is rejected, the process image is already replaced — the audit log says "activated" and the shield cannot observe otherwise. `os.Exit(1)` at `:771` fires only if `execve` itself fails. | **No — the audit trail is wrong here.** | UNVERIFIED — needs a live test with a deliberately malformed profile | **P0** |
| C8 | `agents.EnsureHookRegistered` fails at re-assert | Fail loud | Explicitly fail-open: warns, emits `ShieldFailed` with `stage=hook_reassert`, launch proceeds (`internal/shieldapp/shield_hook_reassert.go:59-101`). | stderr + audit (if the emitter isn't a Nop — see C3) | `internal/shieldapp/shield_hook_reassert_test.go` | P1 |
| C9 | Agent invoked under a name that isn't `claude`/`codex`/`cursor`/`cursor-agent` | Warn | **Silently skipped**, no warning (`shield_hook_reassert.go:43-54`, `:71-76`). | No | `shield_hook_reassert_test.go` | P2 |

---

## D. Store / SQLite

| # | Trigger | Expected | Actual (cited) | Detectable? | Test | Pri |
|---|---|---|---|---|---|---|
| D1 | Daemon can't open the DB | Enforcement continues, logging degrades loudly | Non-fatal, daemon continues without persistence (`internal/daemonapp/main.go:909-921`). Enforcement is unaffected — correct per ADR 0018. But `decisions` then stays flat while the shield writes nothing either (C3), so **doctor's C1 cross-check sees an idle machine, not a broken one**. | `daemon.log` Warn only | none | P1 |
| D2 | Decision buffer (1024) full | Count and audit the loss | `enqueueDecision` drops with an atomic add (`main.go:174-184`, buffer at `:911`); flushed as `decisions.dropped` every 30s (`main.go:190-202`, `:207-240`; ADR 0072). | `agentjail doctor` → Decision recording (`doctor_protection.go:98`) | `TestDroppedDecisionsCheck` (`cmd/agentjail/doctor_protection_test.go:88`) — pure function, no DB | P2 |
| D3 | `SQLITE_BUSY` > 5s | Retry or surface | Only mitigation is `busy_timeout=5000` + `SetMaxOpenConns(1)` (`internal/store/sqlite.go:54-57`, `:62`). **No retry/backoff anywhere in the file.** After 5s the error propagates; in the daemon it becomes a dropped decision (`main.go:217-220`), in the shield it is discarded (`shieldapp/main.go:110`). | Via D2's counter, in the daemon only | `internal/store/soak_test.go` | P1 |
| D4 | Disk full (`SQLITE_FULL`) | Loud | UNVERIFIED — needs a live test. No `SQLITE_FULL` branch exists in `internal/store/sqlite.go`; the driver error propagates through the generic `error` return and is treated as any other write failure. | Presumably D2's counter | none | P1 |
| D5 | Corrupt DB or WAL | Refuse to attest; do not silently run unrecorded | UNVERIFIED — needs a live test. No `SQLITE_CORRUPT` branch, no recovery/rebuild path. `db.Ping()` at `sqlite.go:63` is what would surface it at open; `OpenReadOnly` fails hard (`sqlite.go:997-1015`). Runtime corruption (post-open) behaviour is not determinable from source. | `agentjail doctor` reads best-effort and yields zero signals on an unreadable DB (`doctor_protection.go:138` doc) — i.e. **a corrupt DB looks like an idle machine** | none | **P0** |
| D6 | WAL grows unbounded | Periodic checkpoint | `Cleanup` runs `wal_checkpoint(TRUNCATE)` best-effort (`sqlite.go:583-588`), warning on a busy checkpoint (`:587`). **Its only caller is daemon startup** (`main.go:913-915`). There is **no periodic cleanup** — a daemon that never restarts never checkpoints and never purges (ADR 0071). | No | `internal/store/cleanup_wal_test.go` | P1 |
| D7 | `VACUUM` interrupted / DB left locked | Recover | UNVERIFIED — needs a live test. `VACUUM` runs outside the transaction, only when `totalDeleted > 0` (`sqlite.go:574-578`). | No | none | P2 |

---

## E. Install / upgrade

| # | Trigger | Expected | Actual (cited) | Detectable? | Test | Pri |
|---|---|---|---|---|---|---|
| E1 | Auto-update swaps binaries, daemon exits 0 | Supervisor brings back the new one | The documented handoff (ADR 0070); `Restart=always` / `KeepAlive=<true/>` (`install.go:1935`, `:1831`). This exact contract was broken on Linux before ADR 0070 and produced a silent unprotected window each update. | Via doctor | `TestInstallSystemdUnitContent` | P1 |
| E2 | Binary swapped mid-session (upgrade while an agent runs) | Old shield keeps enforcing; new hook talks to old daemon | UNVERIFIED — needs a live test. The hook↔daemon wire is versioned only for the sidecar (`wire.HookFallbackVersion`), not for `wire.Request`/`wire.Response`. A version-skewed request's behaviour is not determinable from source. | No | none | P1 |
| E3 | PATH shim missing but the rc block still opts in | Fail | Reported as **fail**: "MISSING but your shell profile opts into it — `claude` is running UNSHIELDED" (`cmd/agentjail/cmd_doctor.go:308-317`; ADR 0062). Good precedent — this is the one place doctor reasons about a *gap* rather than presence. | `agentjail doctor` | none in testbed | P2 |
| E4 | Shield binary missing/not executable when the shim runs | Fail open, loudly | Shim warns and `exec "$REAL_CLAUDE"` unshielded (`cmd/agentjail/install_wrapper.go:218-227`; ADR 0063). The `-x` test also catches a dangling role symlink (`:221`). | stderr warning — scrolls away (ADR 0064); but the badge then correctly shows UNSECURED, since `AGENTJAIL_SHIELDED` is never set | none | P1 |
| E5 | Shield **exists but crashes** | Same fail-open treatment as E4 | **Not handled.** The shim's check is `-x` at invocation time only; after `exec "$SHIELD"` (`install_wrapper.go:229`) the shim is gone and the shield's exit code becomes claude's. "Fails open" covers *missing*, not *failing*. | No | none | P1 |
| E6 | PATH shim bypassed (user calls `/usr/local/bin/claude` directly) | Badge says UNSECURED | Correct by construction: `AGENTJAIL_SHIELDED` unset → `⚠ [UNSECURED · agentjail]` (`cmd_statusline.go:130`). Hook still applies if registered. | Yes, badge | `TestShieldBadge_Unshielded` (`cmd_statusline_badge_test.go:24`) | P2 |
| E7 | Uninstall / statusline entry removed | Total uninstall (ADR 0063) | By construction the statusline code stops running (`cmd_statusline.go:117-121`). Note the coupling: **anything that removes the statusLine entry also removes the only surviving warning channel**, without removing enforcement. | UNVERIFIED — needs a live test for the partial-uninstall state | P1 |

---

## F. Multi-agent contract differences

The three agents have different output contracts, so the *same* failure
surfaces differently — or not at all — per agent.

| # | Trigger | Expected | Actual (cited) | Detectable? | Test | Pri |
|---|---|---|---|---|---|---|
| F1 | Fail-open notice, Claude Code | User sees it | `systemMessage` on the allow response (`cmd/agentjail-hook/main.go:347-358`; ADR 0073). stderr is discarded on exit 0. | Yes | none end-to-end | **P0** |
| F2 | Fail-open notice, Codex | User sees it | `writeCodexSystemMessage` emits `{"systemMessage": ...}` only, preserving Codex's empty-stdout allow convention (`main.go:328-342`). | UNVERIFIED — needs a live test. ADR 0073 states Codex documents `systemMessage` for PreToolUse; that it renders is not verifiable from this repo. | none | P1 |
| F3 | Fail-open notice, Cursor | User sees it | Cursor gets `user_message` on the allow (`main.go:384-388`, via `failOpenCursor` `main.go:280-293`). **Note the asymmetry**: Cursor carries `decision.Reason`, while Claude/Codex carry `failOpenSystemMessage(fb.Level)`. Cursor's message therefore does **not** name the protection level or the restart command. | Weaker than Claude's | none | P1 |
| F4 | Policy says `ask`, agent is Codex | Native review or honest failure | Bash asks use the one-use `shell-command` broker, including custom policy rules. Non-Bash asks collapse to **deny** because Codex PreToolUse cannot initiate a prompt for those tool types (ADR 0119-command-approval-transport). | Yes | Codex approval compatibility gate | P1 |
| F5 | `daemon_unreachable: deny` in CI / non-interactive | Hard stop by design | Denies unconditionally regardless of tool identity (`hookfallback.go:128-133`). ADR 0050 names this: `degraded` is the right default for non-interactive contexts. | Yes | none | P2 |

---

## G. OS backend drift (Linux Landlock vs macOS sbpl)

`AGENTS.md` records the cautionary case: `shield_linux.go` and
`shield_darwin.go` once listed "paths Claude Code needs" separately and
drifted. These rows track drift that exists **today**.

| # | Trigger | Expected | Actual (cited) | Detectable? | Test | Pri |
|---|---|---|---|---|---|---|
| G1 | Sandbox unavailable | Same posture on both platforms | **Drifted.** Linux fails open on unsupported ABI but fails *closed* on a rejected ruleset (`shield_linux.go:249-271`). macOS fails open when `sandbox-exec` is missing (`shield_darwin.go:720-734`) and has **no** fail-closed branch. Same conceptual failure, opposite outcomes. | No | none | **P0** |
| G2 | `crash.log` after a restart | Same retention on both | **Drifted, same filename, opposite behaviour.** launchd `O_TRUNC`s it per restart (`install.go:1814-1816`); systemd uses `append:` "so a crash loop doesn't erase prior history" (`install.go:1920-1922`). macOS loses the evidence. | No | none | **P0** |
| G3 | Unsupported platform (not linux/darwin) | Shield refuses or scrubs env | `shield_other.go:21-52` execs with the **raw `os.Environ()`** — no `BuildCleanEnv`/`StripEnv` scrubbing, unlike both real backends. `AGENTJAIL_SHIELDED` is not set (so the badge correctly says UNSECURED). Doctor warns "no OS-native sandbox on this platform" (`cmd_doctor.go:186-191`). | Badge + doctor | `internal/shieldapp/testmain_other_test.go` | P2 |
| G4 | Shared-contract path list drifts again | Compile-time or test-time failure | `shield_contract.go` + `shield_agentpaths.go` are the single source (ADR 0034/0039), guarded by `shield_contract_test.go`. | Yes, at test time | `internal/shieldapp/shield_contract_test.go` | P2 |
| G5 | Landlock grants `~/.agentjail` read-only + write on `daemon.sock` only; sbpl equivalent | Parity | UNVERIFIED — needs a live test. `ARCHITECTURE.md` documents the Linux rule precisely (`daemon.sock` write, `run/daemon-ctl.sock` excluded); the darwin equivalent is not stated in the same terms. Whether the macOS carve-out is equivalent needs a live check on both. | No | `shield_darwin_fixes_test.go`, `shield_linux_paths_test.go` (per-OS, not parity) | P1 |

---

## H. Tampering / adversarial

| # | Trigger | Expected | Actual (cited) | Detectable? | Test | Pri |
|---|---|---|---|---|---|---|
| H1 | Agent runs `agentjail policy disable` while the daemon is up | Deny | Locked `command_policy/no-policy-mutation`, unsuppressible via `disabled_rules` (`resolver.rego` locked set; `ARCHITECTURE.md` §Tuning). | Yes | `test/testbed/scenarios/policy-mgmt.sh` (non-TTY refusal) | P2 |
| H2 | Same, while the daemon is **down** | Deny | Denied under `degraded` (`hookfallback.go:174-179`, `:259-286`) — this is exactly why ADR 0074 moved the default. **Allowed** under `allow`, and under `degraded` with a missing sidecar (B1). | Banner | `TestOfflineCommandPatternsMatchRego` (`internal/daemonapp/offlinerules_drift_test.go:150`) — drift only, not the live path | **P0** |
| H3 | Agent unlinks `~/.agentjail/daemon.sock` | Blocked by the sandbox | UNVERIFIED — needs a live test. Landlock grants `~/.agentjail` read-only and `daemon.sock` has no write grant at all (the one it had was measured a no-op and removed — ADR 0067-control-plane-token-auth); unlink needs write on the *directory*, which is not granted either. Not verified live, and macOS parity is G5. | No | none | P1 |
| H4 | Agent kills the daemon | Speed bump only | `library/no-daemon-kill` is on by default but disableable with `--force`; the supervisor restarts (`cmd/agentjail/rule_registry.go:234`; `ARCHITECTURE.md`). | Yes, via restart | none | P2 |
| H5 | Agent DoSes the daemon to force fail-open | Bounded | The known lever (B6). `maxAgentConns` semaphore (`internal/daemonapp/main.go:898`); reload rate bounded (ADR 0075); control sockets token-gated (ADR 0067-0069). | `fail_open` telemetry rate | UNVERIFIED — needs a live test | P1 |
| H6 | Agent deletes its own hook entry from `~/.claude/settings.json` | Re-asserted next launch | `EnsureHookRegistered` re-asserts pre-exec (`shield_hook_reassert.go:91`) — **but only for the next launch**; the current session stays unhooked. Bash-based writes deny, Write/Edit ask (ADR 0025). | Doctor's hook check (`cmd_doctor.go:270-291`) — a `strings.Contains` on the file | `shield_hook_reassert_test.go` | P1 |
| H7 | Agent sets `AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1` | Ignored inside a sandboxed session | `shield_linux.go:269` honours it to downgrade a fail-closed Landlock error to fail-open. Whether it survives the shield's own env scrubbing into a nested launch is UNVERIFIED — needs a live test. It no longer produces a padlock: the override path resolves `NotSandboxed`, so no `AGENTJAIL_SHIELDED` is set (ADR 0087-shielded-means-sandboxed). | Yes — badge reads `UNSECURED` | `TestAppendShieldedEnv` | P1 |

---

## Top 5 that would have caught AGE-212

Ranked by whether the test would have failed on 2026-07-10.

1. **C1 — shield activates while the daemon is down.** The literal incident:
   464 `shield.activated`, 0 decisions. A testbed scenario that stops the
   daemon, runs a shielded session, and asserts `decisions` advances is the
   single highest-value test missing today. Nothing in the shield launch path
   probes the daemon.
2. **C2 — `AGENTJAIL_SHIELDED=1` is set on fail-open paths.** The badge said
   🔒 for three days. The badge tests
   (`cmd_statusline_badge_test.go:9`) verify env→badge, never
   enforcement→env. Assert the *premise*: `shield_linux.go:295` sets the
   variable on the Landlock-unsupported path with zero kernel enforcement.
3. **B1/B2 — no end-to-end test of the hook failing open.** Every existing
   test covers the sidecar *writer*
   (`internal/daemonapp/hookfallback_test.go`) or *drift*
   (`offlinerules_drift_test.go`). None runs the hook against a dead socket.
   `levelAllow` at `hookfallback.go:49` was the code path that ran for three
   days and it has no integration coverage.
4. **A3 — nothing reads the installed unit/plist.** `KeepAlive=<true/>`
   should have restarted the daemon and did not. The most likely explanation
   is a stale on-disk unit or an out-of-band `bootout`, and **no check reads
   the deployed unit's contents** — `TestInstallSystemdUnitContent` asserts
   what the installer *would* write, not what is on the box. Verifying this
   is the highest-value unknown in this document.
5. **A1 + the testbed gap itself.** `test/testbed/scenarios/e2e-smoke.sh:28,30`
   asserts the daemon is *active* — the only daemon-lifecycle assertion in
   all 16 scenarios, and it points the wrong way. A `daemon-down.sh` scenario
   that stops the daemon mid-session and asserts (a) `agentjail doctor` exits
   non-zero on the Enforcement check, (b) the badge does not claim 🔒, and
   (c) `degraded` still denies a policy mutation, closes the class rather than
   the instance.

## Cross-cutting observation

Three of the top five are the same defect in different clothing: **the shield
attests enforcement it has not verified.** `shield.activated` is written
before `syscall.Exec` on macOS (C7), `AGENTJAIL_SHIELDED=1` is set on paths
with no kernel enforcement (C2), and the audit emitter that would record any
of it may silently be a `NopEmitter` (C3). ADR 0082 made the *daemon* side of
this detectable after the fact. The shield side is not yet.
