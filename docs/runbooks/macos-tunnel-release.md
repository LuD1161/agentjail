# macOS tunnel build, notarization, and golden-image runbook

Use this runbook whenever `AgentJail.app` or its Network Extension is
built, replaced, or baked into `golden-macos-mitm`. It covers the custom
`swiftc` build used by this repository; there is no Xcode archive or App Store
submission in this workflow.

## Invariants

- Keep the app at `/Applications/AgentJail.app` in the guest.
- The app ID is `com.blinkerlm.agentjail`.
- The extension ID is `com.blinkerlm.agentjail.extension`.
- The app and extension use Team ID `Q98Z3744J2`.
- Embed the matching Developer ID provisioning profile in each bundle before
  signing. Both profiles use `ProvisionsAllDevices=true`; Tart guests do not
  need Apple Developer device registration.
- Sign nested code first and the containing app last.
- Never rebuild, mutate, or re-sign an app after notarization. Any byte-changing
  rebuild produces a new artifact that must be signed and notarized again.
- Never copy signing keys, `.env`, keychain material, or notarization credentials
  into a Tart guest.
- Never disable AgentJail policy to read signing credentials. Run the sensitive
  submission step manually through a small audited script outside the sandbox,
  or use a preconfigured `notarytool` keychain profile.
- Never automate or bypass macOS Network Extension approval.
- Never bake the MITM CA into a golden image. AgentJail creates a fresh in-memory
  CA per session and applies process-local trust.

## 1. Inspect the current artifact and activation

Before building, record only non-secret metadata:

```sh
APP=/Applications/AgentJail.app
EXT="$APP/Contents/Library/SystemExtensions/com.blinkerlm.agentjail.extension.systemextension"

defaults read "$APP/Contents/Info" CFBundleShortVersionString
defaults read "$APP/Contents/Info" CFBundleVersion
codesign -dvvvv "$APP" 2>&1 | grep -E '^(Identifier|CDHash|TeamIdentifier|Authority)='
codesign -dvvvv "$EXT" 2>&1 | grep -E '^(Identifier|CDHash|TeamIdentifier|Authority)='
systemextensionsctl list | grep -F com.blinkerlm.agentjail.extension
```

Do not assume a repository `build/AgentJail.app` matches the installed and
activated artifact. Compare IDs, versions, Team ID, entitlements, profile UUIDs,
and CDHashes.

## 2. Set one app and extension version

An updated extension must have a higher version than the activated extension.
Set `MACOS_APP_VERSION=X.Y.Z` and a monotonically increasing
`MACOS_BUILD_NUMBER=N` for the release build. The builder injects both values
into the staged app and extension plists and rejects drift. macOS may reuse an
installed extension whose version is unchanged even if its executable changed.

No Apple Developer website update is required for a build-number change. The
website-side identifiers, capabilities, and provisioning profiles are tied to
the Team ID, bundle IDs, and entitlements, not each local build number.

## 3. Build, embed profiles, and sign inside-out

The canonical path is:

```sh
PROFILE_DIR=/absolute/path/to/private/profiles \
SIGNING_MODE=developer-id \
NOTARY_PROFILE=agentjail-notary \
NOTARIZE=1 \
MACOS_APP_VERSION=X.Y.Z \
MACOS_BUILD_NUMBER=N \
make macos-app
```

`scripts/build-macos-app.sh` must perform this order:

1. Build the Go C archive, extension, and containing app.
2. Assemble the containing bundle.
3. Embed the matching app and extension Developer ID provisioning profiles.
4. Sign the extension with its entitlements, hardened runtime, and timestamp.
5. Sign the containing app with its entitlements, hardened runtime, and
   timestamp.

For an internal manual run where notarization is performed separately, do not
install the intermediate ad-hoc build. Embed the profiles and Developer ID-sign
the final bundle before creating the submission ZIP.

Verify before submission:

```sh
APP=build/AgentJail.app
EXT="$APP/Contents/Library/SystemExtensions/com.blinkerlm.agentjail.extension.systemextension"

plutil -lint "$APP/Contents/Info.plist"
plutil -lint "$EXT/Contents/Info.plist"
codesign --verify --deep --strict "$APP"
codesign -d --entitlements :- "$APP"
codesign -d --entitlements :- "$EXT"
codesign -dvvvv "$APP" 2>&1 | grep -E '^(Identifier|CDHash|TeamIdentifier|Authority)='
codesign -dvvvv "$EXT" 2>&1 | grep -E '^(Identifier|CDHash|TeamIdentifier|Authority)='
```

Decode each embedded profile with `security cms -D -i` and verify:

- its application identifier matches the signed bundle;
- its Team ID is `Q98Z3744J2`;
- `ProvisionsAllDevices` is true;
- the authorized Network Extension entitlement matches the signed entitlement;
- it has not expired.

`codesign --verify` is necessary but not sufficient. A SIP-enabled Mac also
requires valid restricted-entitlement profiles and Gatekeeper/notarization
acceptance before it will load the system extension.

## 4. Notarize with `xcrun notarytool`

There is no App Store Connect browser upload for this pre-existing ZIP workflow.
Use `xcrun notarytool`, Xcode Organizer for an actual Xcode archive, or the Notary
REST API. This repository uses `notarytool`.

Create the ZIP without changing the signed app:

```sh
ditto -c -k --keepParent build/AgentJail.app build/AgentJail.zip
```

Prefer an App Store Connect API key:

```sh
xcrun notarytool submit build/AgentJail.zip \
  --key /private/path/to/AuthKey.p8 \
  --key-id "$ASC_KEY_ID" \
  --issuer "$ASC_ISSUER_ID" \
  --wait
```

Alternatively, configure a keychain profile once and reference only its name:

```sh
xcrun notarytool store-credentials agentjail-notary \
  --key /private/path/to/AuthKey.p8 \
  --key-id "$ASC_KEY_ID" \
  --issuer "$ASC_ISSUER_ID"

xcrun notarytool submit build/AgentJail.zip \
  --keychain-profile agentjail-notary \
  --wait
```

Apple-ID plus app-specific-password authentication remains a fallback, but it
can fail after password or account changes. In one observed run it returned
repeated immediate HTTP 500 responses without creating a submission, while the
same archive uploaded and was accepted immediately with the configured App
Store Connect API key.

Handle failures by their shape:

- **Immediate HTTP 5xx with no submission ID:** retry a small bounded number of
  times. Do not launch parallel submissions. If the Apple-ID path keeps failing,
  switch to the configured ASC API key or keychain profile.
- **A submission ID followed by `Invalid`:** do not blindly retry. Retrieve the
  diagnostic log with `xcrun notarytool log` using the same authentication and
  fix the reported signing or bundle problem.
- **`Accepted`:** proceed to stapling. Record the submission ID as non-secret
  build metadata.

Never print credential values, shell tracing, `.env`, private-key content, or
notary authentication arguments containing a password.

## 5. Staple and assess

```sh
xcrun stapler staple build/AgentJail.app
xcrun stapler validate build/AgentJail.app
codesign --verify --deep --strict build/AgentJail.app
spctl -a -vvv -t exec build/AgentJail.app
```

Required Gatekeeper result:

```text
accepted
source=Notarized Developer ID
```

An old notarization ticket does not transfer to a rebuilt executable. A result
of `source=Unnotarized Developer ID` means do not copy or install that build in
the golden VM.

## 6. Replace the app in the GUI golden VM

1. Confirm the sole persistent image is the stopped `golden-macos-mitm` golden.
2. Stop any temporary validation clone; only one Darwin tunnel session may run.
3. Start `golden-macos-mitm` with its GUI.
4. Transfer the exact stapled app with `ditto` ZIP or another method that
   preserves bundle structure, executable permissions, xattrs, profiles, and
   signatures.
5. Validate `codesign`, `stapler`, `spctl`, IDs, versions, Team ID, and CDHashes
   inside the guest before replacing `/Applications/AgentJail.app`.
6. Keep the previous app recoverably outside `/Applications` until activation is
   proven.
7. Run:

```sh
/Applications/AgentJail.app/Contents/MacOS/AgentJail install-extension
```

macOS may reuse the existing consent when Team ID and extension bundle ID are
unchanged. If it requires approval, instruct the user only:

> System Settings → General → Login Items & Extensions → Network Extensions → enable Agentjail Network Extension.

Do not attempt to bypass or automate the approval.

Verify the new version, not merely any matching line:

```sh
systemextensionsctl list | grep -F com.blinkerlm.agentjail.extension
```

Required state for the new version is `[activated enabled]`. The old version may
temporarily appear as terminated and waiting for uninstall on reboot during an
upgrade.

## 7. Exercise, save, and validate the golden

Run one serialized strict tunnel test using binaries built from the same source
as the extension:

```sh
test/tunnel-e2e/smoke_darwin.sh --strict
```

The run must distinguish extension activation, executed scenarios, skips,
policy denials, bypass attempts, TLS interception, and evidence rows. A 200 from
an allowed request alone proves only reachability. A 403 without a correlated
named policy/audit record is not sufficient proof of the intended denial. An
all-SKIP result is never successful validation.

Run the release command without an IPv6 opt-in override. Dual-stack is the
default because Network Extension can supply an IPv6-first destination as an
already-resolved literal; the strict run must prove that such traffic reaches
the gateway and creates a post-watermark request row. Use
`network.tunnel_ipv6: false` or `--no-tunnel-ipv6` only for explicit IPv4-only
diagnosis.

After a satisfactory exercise:

1. Shut down `golden-macos-mitm` cleanly. The stopped Tart VM is the saved golden;
   there is no separate snapshot command.
2. Clone it to an explicitly named temporary validation VM.
3. Boot the clone headlessly.
4. Verify the exact new extension version remains `[activated enabled]`.
5. Rerun the strict tunnel test and require at least one executed scenario.
6. Stop the temporary validation VM cleanly. Do not delete a VM until its exact
   identity and temporary purpose have been established.

Update the fingerprint/version table in `test/testbed/README.md` and rebuild the
golden whenever the app or extension version, CDHash, Team ID, bundle ID,
profile, entitlement, or relevant macOS activation state changes.

## 8. Timezone and clock checks

Tart guests may display UTC while the host displays local time. That does not
affect signatures, profiles, TLS certificates, or notarization; those checks use
absolute time. Compare epoch seconds if validity errors suggest clock skew:

```sh
date +%s
ssh guest date +%s
```

Different displayed hours with matching epoch seconds are harmless. Correct a
real clock skew before diagnosing certificate validity.
