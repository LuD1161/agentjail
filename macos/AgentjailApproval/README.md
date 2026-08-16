# AgentJail Approval

AgentJail Approval is the standalone macOS menu-bar companion for reviewing
project-host grant requests. It is separate from `AgentjailTunnel` and does not
own the Network Extension or its entitlements.

## Behavior

The menu-bar panel polls the local AgentJail daemon and shows only its typed
review snapshot. **Approve for future sessions** changes the verified project's
future-session policy; it never changes the currently running sandbox. Deny is
also sent only to the daemon. The app does not read AgentJail SQLite data,
write policy files, retain the control token, or provide a path for Codex
command approvals.

Notifications are off until enabled from Settings. Their content is generic;
Review opens the supplemental review window and refreshes the daemon snapshot
before focusing a request, while Deny revalidates through the daemon. Launch at
login is likewise an explicit Settings choice backed by macOS's login-item
status. Removing the menu-bar item stops the companion rather than leaving an
invisible menu-only process running; it does not change daemon state or login
registration.

Build the executable from the repository root:

```sh
swift build --package-path macos/AgentjailApproval --product AgentjailApproval
```

Run the package tests:

```sh
swift test --package-path macos/AgentjailApproval
```

## Local packaging

SwiftPM creates an executable, not an application bundle. The approval-only
packaging path builds separate macOS 13 arm64 and x86_64 release products,
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
the active Command Line Tools developer directory. They compile the manifest's
fixed Core and executable source sets with `swiftc`: this avoids treating a
restricted host's SwiftPM manifest sandbox as a packaging dependency while
still rejecting package dependencies, plugins, resources, unsafe flags, target
drift, and dynamic Core linkage. The accepted manifest is pinned to SHA-256
`388d7e67eae25baa948ad517133c425e934be8c16ceb7f627ee5a793651af801`;
changing it stops packaging until this direct compiler boundary is deliberately
reviewed. For a disposable artifact directory, set
`APPROVAL_ARTIFACT_ROOT` to a path under
`/private/tmp/agentjail-macos-approval-*`.

The package is ad-hoc signed locally with the hardened-runtime flag and no
entitlements. It does not install the app, use a Developer ID, contact a
timestamp or notarization service, or make a Gatekeeper distribution claim.
`spctl --assess` is expected to reject this local ad-hoc build; Developer ID
signing and notarization remain deferred.

Run the physical-Mac packaging check with:

```sh
./test/macos-approval/packaging/verify.sh
```

Install instructions remain deferred until Plan 027.
