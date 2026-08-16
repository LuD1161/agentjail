# AgentJail Approval

AgentJail Approval is the standalone macOS menu-bar companion for reviewing
project-host grant requests. It is separate from `AgentjailTunnel` and does not
own the Network Extension or its entitlements.

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
