# 0105 - Sign the MITM leaf cert for the ClientHello SNI

Status: Accepted

## Context

On the macOS transparent path the agent dials the real destination IP - DNS
resolution happens out-of-band on the host, so there is no DNS-VIP mapping to
recover a hostname from. `handleConn` hands the MITM the raw IP as the
connection's host. Signing the leaf certificate for that IP made TLS clients
reject the handshake with a SAN mismatch, since the client's TLS stack
verifies against the hostname it asked for (via SNI), not the IP it happened
to dial.

## Decision

Choose the leaf certificate via `tls.Config.GetCertificate`, keyed on the
ClientHello's `ServerName` (SNI), falling back to the caller-supplied host
when there is no SNI (the agent dialed by IP with no TLS server name) or on
the DNS-VIP path (the host is already a hostname there). After the handshake
completes, adopt the SNI as the canonical host for upstream verification,
upstream dialing, and audit logging.

This composes with the h2 ALPN negotiation (ADR 0102-mitm-serves-h2):
`GetCertificate` serves the SNI-matched leaf for both the h1.1 and h2
branches, since certificate selection happens before ALPN is inspected.

## Consequences

- Interception works on the macOS transparent path without needing tunnel-side
  DNS or a VIP mapping.
- The certificate served always matches the name the client verifies against,
  on both the DNS-VIP path and the direct-IP path.
