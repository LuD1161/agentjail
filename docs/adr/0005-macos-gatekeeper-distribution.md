# 0005 — macOS distribution: rely on quarantine-free transport, defer notarization

Status: Accepted

## Context

agentjail ships pre-built binaries for macOS (arm64 + amd64) and Linux
(arm64 + amd64). The launch UX is `curl -fsSL https://agentjail.io/install.sh | sh`
and `brew install agentjail/tap/agentjail`. macOS has two mechanisms that can
stop an unsigned third-party binary from running, and they are frequently
conflated:

1. **AMFI** (Apple Mobile File Integrity). On Apple Silicon (arm64) the kernel
   refuses to execute a binary that carries *no* signature at all, SIGKILLing it
   before `main()`. An **ad-hoc** signature (`codesign -s -`, free, no Apple
   account) satisfies AMFI. The macOS toolchain linker applies an ad-hoc
   signature automatically to any binary linked **on a macOS host**.
2. **Gatekeeper** evaluates a file *only* if it carries the
   `com.apple.quarantine` extended attribute. That xattr is set exclusively by
   applications that opt into `LSFileQuarantineEnabled` — browsers, Finder,
   Mail, Messages, AirDrop. It is **not** set by `curl`, `wget`, `git`, `tar`,
   `brew`, or the terminal. A file with no quarantine xattr is never evaluated
   by Gatekeeper, even if unsigned by a Developer ID.

`spctl -a -t exec` is *not* a reliable signal for a CLI tool: it reports
"rejected" for any non-notarized binary even though that same binary runs fine
when launched from a shell. The observable source of truth is the quarantine
xattr plus actual execution.

Full Developer ID signing + notarization removes the prompt even for
browser-downloaded binaries, but requires a paid Apple Developer Program
membership ($99/yr) and a `notarytool` round-trip in CI.

## Decision

**Launch without Developer ID signing or notarization.** Make Gatekeeper a
non-event by controlling the transport and the build host instead:

1. **Build all darwin targets on macOS runners** (`macos-14` for arm64,
   `macos-13` for amd64). This gets the automatic ad-hoc signature for free,
   which is sufficient for AMFI on Apple Silicon. Never cross-compile a darwin
   target from a Linux runner — that skips ad-hoc signing and the arm64 binary
   will not run.
2. **Distribute only via quarantine-free transport** — `curl | sh` and
   `brew`. Neither sets `com.apple.quarantine`, so Gatekeeper never engages.
3. **Treat the quarantine xattr as the source of truth and gate the release on
   it.** `test/macos-gatekeeper/verify.sh` asserts, on each darwin artifact's
   native-arch runner, that the extracted binary (a) has no
   `com.apple.quarantine` xattr and (b) actually executes
   (`agentjail version` exits 0). The `gatekeeper-verify` job is a hard
   dependency of `release`, so a regression that reintroduces quarantine — or a
   binary that fails to run — blocks publication.
4. **Document the one manual escape hatch.** Users who download a tarball via a
   browser instead of the install script will get a quarantined file; the README
   troubleshooting section gives them `xattr -d com.apple.quarantine <path>`.

**Notarization is a fast-follow, not a launch blocker.** It is the first
post-launch macOS hardening item: agentjail is a security tool, and a
Developer-ID-signed, notarized binary is a real trust signal for that audience
and is sometimes an enterprise requirement. When the Apple Developer cert is
available, add a `codesign --options runtime` + `notarytool submit --wait` +
`stapler staple` step to the darwin build matrix; the `verify.sh` gate already
accepts a Developer ID / notarized signature.

## Consequences

- **Positive.** Zero cost and zero new secrets to launch. The happy paths
  (`curl|sh`, `brew`) have no Gatekeeper prompt today. The release pipeline
  proves the property on every tag rather than asserting it in prose; the gate
  catches a future transport change that silently reintroduces quarantine.
- **Negative.** A user who manually downloads from the GitHub Releases web page
  hits the "cannot verify developer" prompt and must run one `xattr` command.
  This is documented but is a rough edge until notarization lands.
- **Windows is out of scope at launch.** agentjail's enforcement surfaces
  (PATH shim, seccomp, Endpoint Security, libkrun) are macOS/Linux only;
  `install.sh` rejects other platforms. No Windows binaries are built.
- **Follow-up.** Notarization (above). Tracked as the first macOS hardening
  item post-launch.
