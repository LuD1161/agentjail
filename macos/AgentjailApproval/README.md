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

SwiftPM creates an executable, not a distributable `.app` bundle. Plan 025
will assemble and sign the app bundle; install instructions are intentionally
deferred until Plan 027.
