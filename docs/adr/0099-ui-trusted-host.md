# 0099 - UI trusted-host escape hatch

Status: Accepted

## Context

The local UI (`agentjail ui`) is unauthenticated and serves the decision and
network stores. [ADR 0092-persist-request-bodies](./0092-persist-request-bodies.md)
(D1) added `guardRebinding`: every request whose `Host` or `Origin` is not a
loopback address is rejected, so a page the user visits cannot DNS-rebind to the
UI port and read the store.

That guard makes the UI unreachable behind a reverse proxy on the same host — a
common dev setup (`<port>.example.com` → nginx → `127.0.0.1:<port>`). The proxy
forwards the public `Host`, which the guard treats as a rebinding attempt and
403s, even though the request came through a trusted proxy the operator set up.
`--insecure-bind` only relaxes the *bind* address; it does nothing for the guard.

## Decision

Add a repeatable `--trusted-host H` flag to `agentjail ui`. Listed hostnames are
allow-listed for both the `Host` and `Origin` checks; the bind stays loopback so
only a local proxy can reach it. Default (no flag) is unchanged: loopback only.

The guard logic moves from `loopbackHost`/`loopbackOrigin` (unchanged) to
`hostAllowed`/`originAllowed`, which pass loopback OR an explicitly trusted host.
The allow-list is startup-only (`Server.SetTrustedHosts`), case-folded, and empty
by default.

This is a dev-only convenience, not a production auth story. It does not add
TLS or authentication; it only stops the guard from rejecting a host the operator
named. Exposure to a network is still the operator's decision (they must also run
the proxy and, for non-loopback bind, pass `--insecure-bind`).

## Consequences

- The UI can sit behind a same-host reverse proxy without disabling the rebinding
  guard wholesale — only the named host is allowed, arbitrary rebinds still 403.
- The guard's default posture is unchanged: a build with no `--trusted-host`
  behaves exactly as before ADR 0099.
- The flag widens the trust surface by exactly the hosts named. A wildcard is
  deliberately not supported — each host is explicit, so a typo fails closed.
- Still no auth/TLS in the UI itself; anyone who can reach the proxy reaches the
  store. That trade is the operator's to make, the same as `--insecure-bind`.
