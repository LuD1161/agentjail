# 0049 - cloud-metadata (IMDS) egress guard in port-only mode

Status: Accepted

## Context

ADR 0046 made per-host egress enforcement (`agentjail-netproxy`) opt-in and
port-only (TCP 22/80/443, no host filtering) the shipped default. In that
default mode, an agent running under the shield can reach the cloud instance
metadata service (IMDS) at `169.254.169.254` over the same allowlisted port
80 as any other host:

```
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

On a real cloud instance (AWS/GCP/Azure/OpenStack/Alibaba all use this
address; AWS additionally exposes `fd00:ec2::254` over IPv6) this exfiltrates
the instance's IAM/service-account credentials, regardless of Landlock or
Seatbelt sandboxing, because neither enforcement primitive can filter
port-only egress by destination IP:

- **Linux (Landlock).** `LANDLOCK_RULE_NET_PORT` (ABI v4+) is port-scoped
  only -- the rule attribute is `{allowed_access, port}`, with no address
  component. A CONNECT rule for port 80 admits any destination on port 80.
- **macOS (sbpl).** `(remote tcp/ip "HOST:PORT")` accepts only `*` or
  `localhost` as the host component; a literal IP (e.g.
  `"169.254.169.254:80"`) is rejected by `sandbox-exec` at profile-compile
  time (already documented in `shield_darwin_test.go` prior to this ADR, in
  the context of `NoNetproxyFallbackPorts()`).

Both backends already name a similar non-parity (`CapLoopbackScopedBind`,
"port-scoped, not interface-scoped") for the same underlying reason: neither
enforcement primitive has an address/interface axis in port-only mode. This
is the same gap applied to destination IP instead of source interface.

`internal/envaudit.CheckIMDS` already runs a best-effort pre-launch audit,
but it only flags **IMDSv1 being enabled** as critical -- a host correctly
running IMDSv2-only still leaves IMDS reachable to the agent process itself
(the agent can request its own IMDSv2 token and read credentials; IMDSv2's
SSRF mitigation is against server-side proxying, not against a process with
direct network access), so it does not cover this finding.

## Decision

Since no backend can express "deny this specific destination IP inside an
otherwise-broader port allow" in port-only mode, add a launch-time
**metadata-egress guard** instead of a network rule:

1. **Shared contract data** (`cmd/agentjail-shield/shield_contract.go`, per
   ADR 0034): `CloudMetadataDenyIPs()` (169.254.169.254, fd00:ec2::254),
   `CloudMetadataDenyCIDR` (169.254.0.0/16), and `IsCloudMetadataIP(ip)` as
   the single, typed source of truth for what counts as a metadata
   endpoint. A new `CapMetadataIPFilter` capability key is added and named
   Unsupported by both `darwinCapabilities()` and
   `buildLandlockNetPlan`'s `Unsupported` map, so the gap is documented and
   test-enforced rather than silently dropped (mirroring
   `CapLoopbackScopedBind`).
2. **OS-agnostic guard, run once at startup** (`shield_metadata_guard.go`,
   invoked from `main.go` before `runShield`/exec, for both platforms):
   `probeMetadataReachable()` does a short-timeout TCP dial to the metadata
   IPs; the pure function `decideMetadataEgress(reachable, noNetproxy,
   strict)` decides the outcome without any I/O (fully unit-testable):
   - netproxy enabled: not applicable (per-host enforcement is netproxy's
     job there).
   - port-only mode, metadata unreachable (the common non-cloud case):
     not applicable.
   - port-only mode, metadata reachable, `--audit-strict`: **refuse to
     launch** -- there is no network-layer mitigation available, so
     refusing is the only fail-closed option.
   - port-only mode, metadata reachable, not strict: **allow the launch**
     (unchanged default behavior) but emit a loud stderr warning and a
     `shield.metadata_egress_exposed` audit event so the exposure is
     visible rather than silent.

This is option (b) from the finding: a network-layer block where the
codebase can enforce one, otherwise refuse/warn -- chosen because neither
backend's port-only primitive has a destination-IP axis to enforce with.

## Consequences

- **No regression to default port-only egress** for ordinary hosts: 80/443
  to any non-metadata destination is unaffected.
- **Fail-closed path exists** (`--audit-strict`) for operators who want a
  hard guarantee that a shielded session never launches with IMDS
  reachable, at the cost of refusing to launch on real cloud instances
  running with default flags.
- **Default (non-strict) path is now honest**: the exposure was always
  present in port-only mode; it is now surfaced loudly (stderr + audit log)
  instead of being invisible.
- **Cannot be validated end-to-end off a real cloud host.** The probe and
  decision logic are unit-tested against a synthetic `reachable` bool; the
  actual "IMDS answers on 169.254.169.254:80" condition can only be
  observed on AWS/GCP/Azure/etc. **Human verification required on a real
  cloud instance**: run the shield in default (port-only) mode on an EC2/GCE/
  Azure VM and confirm the guard fires (stderr warning, or refusal under
  `--audit-strict`), and that `curl http://169.254.169.254/latest/meta-data/`
  from inside a shielded session still succeeds in non-strict mode (proving
  the warning is accurate) and that the shield refuses to launch in
  `--audit-strict` mode.
- **`--netproxy` remains the actual mitigation** for egress in general (not
  just IMDS): `network.allowed_hosts` does not include the metadata IP by
  default, so switching per-host enforcement on removes the exposure
  entirely rather than merely warning about it.
