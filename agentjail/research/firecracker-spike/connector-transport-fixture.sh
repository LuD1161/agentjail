#!/usr/bin/env bash
# Demonstrates the currently missing production microVM connector primitive.
set -euo pipefail

guest_socket="${AGENTJAIL_GUEST_CONNECTOR_SOCKET:-/run/agentjail/connectors/chrome-cdp.sock}"

if [[ -S "${guest_socket}" ]]; then
    echo "FAIL: found ${guest_socket}, but no production Firecracker launcher registered its session/token/connector route" >&2
    exit 1
fi

echo "UNAVAILABLE: Firecracker spike has virtio-net only; no vsock device or shared AF_UNIX mount is registered."
echo "UNAVAILABLE: guest loopback must not be used as a substitute for the host connector."
echo "NEXT: production launch must register a session-scoped vsock or bind-mounted AF_UNIX endpoint before this fixture can CONNECT."
exit 2
