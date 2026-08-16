# Plan 022: Build the menu-bar review UI

> **Executor instructions:** Start after plans 019, 021, and 033 are reviewed DONE.
> Read the product design and state API. Build views against injected/fake state;
> do not edit the app entry or connect the daemon.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the exact new UI/Presentation/test paths and handoff. Committed
> scaffold/state drift is expected; uncommitted overlap is a STOP condition.

## Status

- **Priority:** P1
- **Effort:** M
- **Risk:** LOW
- **Depends on:** plans 019, 021, and 033
- **Category:** app / UX
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

An approval UI must show enough verified context for an informed decision while
making agent-authored text visibly untrusted. Clear empty/disconnected/error
states, precise future-session copy, keyboard/VoiceOver support, and no
color-only meaning are part of the security interface, not polish.

## Current state

Plan 019 supplies the placeholder MenuBarExtra app. Plan 021 supplies an
observable state store with actionability and per-row action state. The design
spec fixes a roughly 420×520 panel, review cards, exact approval wording,
generic status states, Settings/Quit footer, and no Dashboard action yet.

Apple's current MenuBarExtra docs state the title is used by accessibility, and
Apple's accessibility guidance calls for VoiceOver, Voice Control, Switch
Control, and Accessibility Inspector testing on Mac.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Presentation tests | `rtk swift test --package-path macos/AgentjailApproval --filter DisplaySanitizer` | pass |
| Full tests | `rtk swift test --package-path macos/AgentjailApproval` | pass |
| Build | `rtk swift build --package-path macos/AgentjailApproval --product AgentjailApproval` | pass |
| Copy guard | `rtk rg -n 'Allow once|Allow now|temporary|current session' macos/AgentjailApproval/Sources/AgentjailApprovalApp/UI` | no misleading approval copy |

## Scope

**In scope:**

- `macos/AgentjailApproval/Sources/AgentjailApprovalApp/UI/**`
- `macos/AgentjailApproval/Sources/AgentjailApprovalCore/Presentation/**`
  except plan 033's `DisplaySanitizer.swift`
- `macos/AgentjailApproval/Tests/AgentjailApprovalCoreTests/Presentation/**`
  except plan 033's `DisplaySanitizerTests.swift`
- `plans/macos-app/handoffs/022.md`

**Out of scope:** app entry/Composition/Settings/Lifecycle, transport/state
changes, notifications, assets outside the subtree, custom fonts, animations,
network/dashboard launch, Go, Package.swift, or tunnel UI.

## Git workflow

One signed local commit: `feat(macos): build approval menu interface`. Use only
owned paths and the commit lock. Do not push.

## Steps

### Step 1: Consume the reviewed display sanitizer

Plan 033 owns the pure sanitizer and its scalar/grapheme tests. Use that helper
for agent-provided reason text. Label the result “Agent-provided reason”. Keep
the full verified project path available through accessible help/expansion
without putting it in a notification. Never apply display sanitization to an
authority field and then leave it actionable; altered authority fails into the
typed context-unavailable/deny-only presentation.

### Step 2: Build status and empty/error views

Create reusable views for starting/connecting, ready-empty, disconnected,
unsupported protocol, and action failure. Disconnected cached rows must be
visually labeled stale and contain no enabled action controls. Include a Retry
button only where the state API supports it.

Use text/icon/shape together; do not encode ready/pending/error by color alone.

Define a pure `PanelPresentation`/sample-state matrix consumed by the views.
**Verify:** a table test constructs every state, asserts its visible status,
action availability, and accessibility text, then `swift build` compiles every
view branch without a snapshot dependency.

### Step 3: Build the review card

Each project-host card shows:

- host;
- project name and verified full path;
- bounded agent reason in a distinct group;
- “Adds this host to the project policy for future sessions. The current
  session is unchanged.”;
- **Approve for future sessions** and **Deny**.

An `unbound` or `unrepresentable` row instead shows a typed “Project context is
not available for approval” explanation, omits any partial authority field,
offers Deny only, and never suggests that a truncated host/path is the target.

Buttons use only review ID callbacks. Approve is disabled when `canApprove` is
false; Deny follows `canDeny`; both are disabled during an in-flight action.
Show progress/failure without optimistically removing the row.

**Verify:** pure presentation-model tests assert exact copy and action-disable
logic for verified, unbound, unrepresentable, stale, expired, and in-flight rows;
the SwiftUI view consumes that model rather than re-deriving authority.

### Step 4: Assemble the 420×520 panel and label

Create `ApprovalPanelView` with header, pending count, scrollable newest-first
cards, footer Settings/Quit callbacks, and system spacing/colors/SF Symbols.
Create a menu-label view for ready/pending/connecting/disconnected that exposes
an accessibility label/value including exact pending count.

All controls need explicit accessibility labels/hints where the visible copy is
not enough, useful focus order, and keyboard reachability. Do not add a single
keystroke shortcut that can approve while the panel is closed.

**Verify:** `swift build` passes; plan 026 performs the real accessibility/UI
gate.

### Step 5: Verify and commit

Run tests/build/copy scan, record manual checks that remain, write the handoff,
and commit under the lock.

## Done criteria

- [ ] Every state in the design has a compiled view.
- [ ] Untrusted text sanitizer handles controls/bidi/length and is tested.
- [ ] Approval copy says future sessions and current session unchanged.
- [ ] Stale/unbound/in-flight rows cannot approve.
- [ ] Status is not color-only; controls have accessibility labels/hints.
- [ ] No daemon, notification, dashboard, or tunnel wiring is added.
- [ ] Tests/build pass in a signed local commit.

## STOP conditions

- State API cannot express stale/actionable independently.
- Correct accessibility requires changing app composition or Package.swift.
- Product asks for hidden context, notification-only approval, or current-session copy.
- A third-party UI/snapshot dependency appears necessary.

## Maintenance notes

The project path is verified authority context; the agent reason is untrusted
persuasion. Preserve that visual distinction. New review kinds need new
truthful effect copy, not a generic “Approve” card.
