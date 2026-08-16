# Plan 033: Sanitize untrusted macOS display text

> **Executor instructions:** Implement only the pure presentation sanitizer
> split from plan 022. Read the accepted menu-review ADR, plan 022, plan 032's
> harness handoff, and the shared-worktree protocol. Do not add views, state,
> transport, notification, or app-composition code.

## Status

- **Priority:** P0
- **Effort:** S
- **Risk:** MED
- **Depends on:** plans 019 and 032
- **Category:** app / security UX
- **Added at:** local orchestrator execution, 2026-08-15

## Why this matters

The daemon deliberately carries an agent-provided reason to help the operator
review a request. That text is untrusted persuasion and may contain terminal
controls, bidirectional formatting, multiline spoofing, or Unicode sequences
that are unsafe to truncate by byte or scalar. This pure boundary is
independent of the later state and SwiftUI views, so it can be implemented and
tested in parallel.

## Scope

**In scope:**

- `macos/AgentjailApproval/Sources/AgentjailApprovalCore/Presentation/DisplaySanitizer.swift`
- `macos/AgentjailApproval/Tests/AgentjailApprovalCoreTests/Presentation/DisplaySanitizerTests.swift`
- `plans/macos-app/handoffs/033.md`

**Out of scope:** every other Presentation file, SwiftUI/UI, Models, State,
Transport, Notifications, app entry/composition, Package.swift, Go, scripts,
dependencies, assets, and user-owned dirty paths.

## Required contract

Define an `Equatable`, `Sendable` result containing sanitized text, whether an
unsafe scalar was removed or replaced, and whether grapheme truncation
occurred. Define pure `text` and `reason` entry points. The implementation must:

1. iterate Unicode scalars and remove ESC U+001B plus U+061C, U+200E–U+200F,
   U+202A–U+202E, and U+2066–U+2069; removal takes precedence over replacement;
2. replace every remaining C0/C1 control (U+0000–U+001F and U+007F–U+009F),
   including CR, LF, and tab, with one ASCII space;
3. collapse all resulting whitespace runs to one ASCII space and trim both
   ends;
4. bound positive limits by Swift `Character` count, returning the first
   `limit - 1` extended grapheme clusters plus one `…` when truncated, so a
   combining sequence, skin-tone sequence, flag, or ZWJ emoji is never split;
5. make `reason` return exactly `No reason provided` when the sanitized input
   is empty; and
6. use only Swift/Foundation facilities already available in the package.

The later UI must use this helper only for agent-controlled display text.
Verified host/project authority is never silently altered or truncated into an
actionable target; plan 022 handles that typed fail-closed presentation rule.

## Verification and acceptance criteria

- Table tests exercise every individual C0/C1 scalar, ESC, every scalar in all
  listed bidi ranges, an ANSI escape sequence, CR/LF/tab, repeated and Unicode
  whitespace, empty/controls-only input, and ordinary text.
- A regression assertion proves no forbidden scalar survives any result.
- Combining-mark, skin-tone, regional-indicator, and ZWJ inputs remain whole
  across truncation and receive exactly one ellipsis.
- Result flags distinguish unsafe-scalar changes from length truncation.
- `reason` maps nil, empty, whitespace-only, and controls-only input to the
  exact fallback without becoming empty or misleading.
- `rtk ./scripts/test-macos-approval.sh` discovers and passes the new tests and
  production sources type-check for arm64 and x86_64.
- A focused source scan finds no terminal/ANSI parser, bidi reordering, logging,
  callback, authority/action, networking, or third-party dependency code.
- Signed local commit `feat(macos): sanitize approval display text` contains
  only the two exact Swift paths and handoff 033; no remote action.

## STOP conditions

- Correct sanitization requires changing a wire/authority field or adding a
  dependency.
- Swift's `Character` iteration cannot preserve a tested grapheme sequence on
  the installed toolchain.
- Another task has uncommitted changes in either exact owned Swift path.
