// Package main -- launch-time cloud-metadata (IMDS) egress guard.
//
// Finding P2/M2 (High): in the shipped default (port-only, --no-netproxy)
// mode, both shield backends allow outbound TCP to the shared contract's
// NoNetproxyFallbackPorts() (22, 80, 443) with NO destination-host
// filtering (Landlock net rules are port-scoped only; sbpl rejects literal
// IP hosts -- see CapMetadataIPFilter in shield_contract.go). That means
// `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
// reaches the cloud instance metadata service over allowlisted port 80 and
// can exfiltrate the instance's IAM credentials, regardless of Landlock/
// sbpl.
//
// Neither backend has a primitive that can carve out a per-IP deny inside
// the port-only allowlist (named Unsupported: CapMetadataIPFilter), so this
// guard runs ONCE at shield startup (main.go, before runShield/exec), OS
// -agnostic: it probes whether the metadata IPs are TCP-reachable and,
// if so, either refuses to launch (--audit-strict) or emits a loud warning
// + audit event (default). This is option (b) from the task brief -- a
// network-layer block is not implementable in default mode with the
// primitives this codebase has today.
//
// See docs/adr/0049-cloud-metadata-egress-guard.md.
package main

import (
	"fmt"
	"net"
	"time"
)

// metadataProbeTimeout is the per-IP TCP dial timeout for the reachability
// probe. Short, matching the pattern in internal/envaudit.CheckIMDS's
// fast-bail dial, so a non-cloud host (the overwhelmingly common case) does
// not pay a noticeable latency cost at every launch.
const metadataProbeTimeout = 15 * time.Millisecond

// metadataProbePort is the port probed for reachability. 169.254.169.254:80
// is the IMDS HTTP endpoint on every provider that uses this address.
const metadataProbePort = 80

// probeMetadataReachable performs a real network probe (TCP dial with a
// short timeout) against every CloudMetadataDenyIPs() address on
// metadataProbePort. It returns true if ANY of them accept a TCP
// connection, which is the signal that the shield's default port-only
// egress path can reach the cloud metadata service from this host.
//
// This is the only I/O in this file; decideMetadataEgress (below) is a pure
// function of the resulting bool so the launch-refusal/warn decision is
// unit-testable without a real cloud instance.
func probeMetadataReachable() bool {
	for _, m := range CloudMetadataDenyIPs() {
		addr := net.JoinHostPort(m.IP, fmt.Sprintf("%d", metadataProbePort))
		conn, err := net.DialTimeout("tcp", addr, metadataProbeTimeout)
		if err != nil {
			continue
		}
		_ = conn.Close()
		return true
	}
	return false
}

// MetadataEgressDecision is the outcome of evaluating the metadata-egress
// guard: whether the launch should be refused, and the message to surface
// to the operator (stderr) and the audit log either way.
type MetadataEgressDecision struct {
	// Applicable is false if the guard did not apply at all (netproxy
	// enabled, so per-host enforcement already covers this, or the caller
	// should not have invoked the guard). When false, Refuse is always
	// false and Message is empty -- callers should not act on this
	// decision.
	Applicable bool
	// Refuse is true if the shield must abort the launch rather than exec
	// the agent.
	Refuse bool
	// Message is a human-readable explanation, non-empty whenever
	// Applicable is true.
	Message string
}

// decideMetadataEgress is the pure decision logic behind the metadata-egress
// guard -- no I/O, so it is fully unit-testable. It answers: given that the
// metadata service either is or isn't reachable (reachable, from
// probeMetadataReachable), that the shield either is or isn't running in
// the unfiltered port-only default mode (noNetproxy), and whether the
// operator asked for fail-closed behavior (strict, mirroring
// --audit-strict): should the shield refuse to launch, and what should it
// say?
//
//   - netproxy enabled (noNetproxy=false): the guard does not apply. Per-
//     host enforcement is netproxy's job (network.allowed_hosts), and IMDS
//     is not normally in that allowlist.
//   - netproxy disabled (noNetproxy=true) and metadata NOT reachable: this
//     host cannot reach IMDS at all (not cloud, or already firewalled
//     upstream) -- nothing to warn about.
//   - netproxy disabled and metadata IS reachable and strict=true: refuse
//     to launch. There is no network-layer mitigation available (see
//     CapMetadataIPFilter), so refusing is the only fail-closed option.
//   - netproxy disabled and metadata IS reachable and strict=false: allow
//     the launch (unchanged default behavior) but emit a loud warning and
//     an audit finding so the exposure is visible.
func decideMetadataEgress(reachable, noNetproxy, strict bool) MetadataEgressDecision {
	if !noNetproxy {
		return MetadataEgressDecision{}
	}
	if !reachable {
		return MetadataEgressDecision{}
	}
	const detail = "the cloud instance metadata service (IMDS) is reachable from this host, and the shield's " +
		"default port-only egress mode (--no-netproxy) allows outbound TCP on port 80 to ANY destination -- " +
		"neither Landlock (Linux) nor sbpl (macOS) can filter port-only egress by destination IP (see " +
		"CapMetadataIPFilter), so IMDS credentials ARE exfiltratable via e.g. " +
		"'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/'. " +
		"Pass --netproxy to restrict egress to network.allowed_hosts (IMDS excluded by default)."
	if strict {
		return MetadataEgressDecision{
			Applicable: true,
			Refuse:     true,
			Message:    "refusing to launch: " + detail,
		}
	}
	return MetadataEgressDecision{
		Applicable: true,
		Refuse:     false,
		Message:    "WARNING: " + detail,
	}
}
