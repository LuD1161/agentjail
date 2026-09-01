# AgentJail macOS application

This Swift package contains the native menu-bar, settings, review, and fixed
Network Extension command surfaces used by the unified `AgentJail.app`. The
package and module retain their historical `AgentjailApproval` names internally;
the public application identity is `AgentJail` and `make macos-app` assembles the
release bundle. See ADR 0141-unified-macos-app.

## Behavior

The menu-bar panel polls the local AgentJail daemon and shows only its typed
review snapshot. **Approve for future sessions** changes the verified project's
future-session policy; it never changes the currently running sandbox. Deny is
also sent only to the daemon. The app does not read AgentJail SQLite data,
write policy files, retain the control token, or provide a path for Codex
command approvals. Its tunnel command surface accepts only fixed verbs used by
`agentjail-shield`; it is not an arbitrary shell interface.

The panel uses a compact, opaque empty layout with one authoritative status
summary. It expands to a bounded scrolling review layout only while approvals
are present; status failures remain visible alongside stale non-actionable
cards. Footer actions use explicit hover surfaces without persistent keyboard
focus chrome, while retaining labels, help text, and accessibility hints.

The native MCP inventory is a separate read-only presentation path. Versioned
Core adapters read only `~/.claude.json`, `~/.codex/config.toml`, and
`~/.cursor/mcp.json`, then return typed records whose commands and origins are
already redacted. The inventory has no process runner, network client,
configuration writer, database, policy, or telemetry dependency. Malformed
entries remain visible as fixed configuration issues and never prevent other
clients from loading. See ADR 0142-readonly-mcp-inventory.

The Policies destination is another bounded read-only path. The bundled CLI
joins installed active Rego with typed selected-decision aggregates from one
read-only store handle. SwiftUI receives exact match totals, bounded
agent/session rows, `…/basename` folder labels, and each source module once. It
does not open SQLite, edit policy, or describe resolver-selected rows as every
candidate OPA considered. See ADR 0148-policy-inventory.

The active table sorts defaults, Bash/command rules, and Git rules before the
remaining policies, with local search, category filters, domain-specific icons,
and description tooltips. Policy details show plain Rego immediately while a
bounded cache prepares each shared module's syntax colors once. The two-axis,
syntax-colored Rego viewer has a tall reading viewport and compact end marker,
and clipboard actions
acknowledge a successful copy in place without retaining keyboard-focus chrome.
A present but older installed CLI is shown as an
available component update rather than as a missing installation.

Settings uses a deterministic two-column desktop grid for service and privacy
controls. Its displayed semantic version links to the exact GitHub release, and
the persistent About destination presents the app identity, principles, build,
release notes, source repository, feedback and issue entry point, and muted
creator link in an open centered composition.

Notifications are off until enabled from Settings. Their content is generic;
Review opens the supplemental review window and refreshes the daemon snapshot
before focusing a request, while Deny revalidates through the daemon. Launch at
login is likewise an explicit Settings choice backed by macOS's login-item
status. If notification access is denied, Settings links directly to AgentJail's
notification controls, with the Notifications pane as a fallback. Removing the
menu-bar item stops the app rather than leaving an invisible menu-only process
running; it does not change daemon state or login registration.

The dashboard summarizes audited activity and daily token usage. The token chart
shows weekly date markers, the displayed-series total, and supports per-day
inspection without blocking the primary dashboard refresh. Missing calendar
days render as zero, and the chart never smooths nonnegative totals below zero.

Network and Logs are authenticated, versioned daemon projections rather than
direct database readers. Network displays at most the latest 200 sanitized
intercept records and states when the optional Network Extension is missing.
Logs provides a bounded recent-session picker and at most the latest 500 actions
for one exact session ID. Rows open a detail sheet; Bash details fetch one full
recorded command on demand from the persisted store-redacted input. The
repeating timeline remains byte-bounded below the control transport limit. Neither
projection includes headers, bodies, full
URLs, full working directories, or raw tool input, and each polls only while its
destination is visible. See ADR 0149-local-activity-feed.

Build the executable from the repository root:

```sh
swift build --package-path macos/AgentjailApproval --product AgentjailApproval
```

Run the package tests:

```sh
swift test --package-path macos/AgentjailApproval
```

## Component packaging harness

The legacy component harness builds separate macOS 13 arm64 and x86_64 release products,
combines them into `AgentjailApproval.app`, and checks the exact bundle
identity, empty entitlement dictionary, hardened-runtime signature, and local
disk image contents.

```sh
make macos-approval-app
make macos-approval-dmg
```

The default local artifacts are
`build/macos-approval/AgentjailApproval.app` and
`build/macos-approval/AgentjailApproval.dmg`. The scripts prefer an explicit
`DEVELOPER_DIR`, then `/Applications/Xcode.app/Contents/Developer`, and finally
the active Command Line Tools developer directory. The selected compiler must
support Swift language mode 6; packaging fails before compilation otherwise.
They compile the manifest's
fixed Core and executable source sets with `swiftc`: this avoids treating a
restricted host's SwiftPM manifest sandbox as a packaging dependency while
still rejecting package dependencies, plugins, resources, unsafe flags, target
drift, and dynamic Core linkage. The accepted manifest is pinned to SHA-256
`388d7e67eae25baa948ad517133c425e934be8c16ceb7f627ee5a793651af801`;
changing it stops packaging until this direct compiler boundary is deliberately
reviewed. For a disposable artifact directory, set
`APPROVAL_ARTIFACT_ROOT` to a path under
`/private/tmp/agentjail-macos-approval-*`.

The component harness is ad-hoc signed locally with the hardened-runtime flag
and no entitlements. It exists for focused UI packaging tests only; it is not the
public application. It does not install the app, use a Developer ID, contact a
timestamp or notarization service, or make a Gatekeeper distribution claim.
`spctl --assess` is expected to reject this local ad-hoc build; Developer ID
signing and notarization remain deferred.

Run the physical-Mac packaging check with:

```sh
./test/macos-approval/packaging/verify.sh
```

Build the customer bundle with `make macos-app`; follow
`docs/runbooks/macos-tunnel-release.md` for Developer ID distribution.
