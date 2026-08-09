# ADR 0130 — Codex live gate

- **Status:** Accepted
- **Date:** 2026-08-09
- **Deciders:** agentjail-core
- **Related:** [ADR 0053-vm-testbed-engine](0053-vm-testbed-engine.md), [ADR 0129-credentialed-cli-bootstrap](0129-credentialed-cli-bootstrap.md)

## Context

The clean-VM release gate used Claude Code for its only authenticated live-agent
scenario. Missing Claude credentials produced a successful skip, so a machine
without the applicable paid plan could pass the release gate without exercising
an agent model loop through AgentJail's tunnel.

The active development session is authenticated with Codex and the credentialed
CLI milestone must be proven through the Codex harness. Authentication is a
versioned external contract and cannot be reconstructed from remembered token
fields.

The official OpenAI authentication documentation was verified on 2026-08-09.
It documents `codex login status`, file-backed credentials under
`$CODEX_HOME/auth.json`, and copying that cache to a headless machine as a
supported fallback. It also states that the file contains access tokens and
must be treated like a password. The locally verified client was Codex CLI
0.147.0. Source: [OpenAI Codex authentication](https://developers.openai.com/codex/auth).

## Decision

The default release gate uses Codex for its authenticated live-agent scenario:

1. Require a readable, mode-0400 or mode-0600 host auth cache from
   `CODEX_AUTH_FILE` or `$CODEX_HOME/auth.json`.
2. Require `codex login status` to succeed and install the same Codex CLI
   version in the clean guest.
3. Do not seed the optional Claude credential during the release provision.
4. Copy only `auth.json` into the guest immediately before `tunnel-agent`.
5. Run Codex non-interactively through the canonical `agentjail run --tunnel`
   path and assert a real file-and-git task completes.
6. Require decrypted OpenAI/ChatGPT model traffic and redacted
   credential-shaped headers in `network.db`.
7. Delete both the transfer file and guest auth cache after success, failure,
   or interruption. Recording paths never accept the auth cache.

The separate Codex approval-compatibility gate retains its independently pinned
client version. Its existing disposable-auth transfer uses the same lifecycle.

## Consequences

`make e2e-release` no longer succeeds by skipping the only live model loop when
Claude credentials are unavailable. It now requires the release operator to
have a valid local Codex session and a private file-backed auth cache.

The guest receives a bearer-capable file for the duration of one trusted test.
The VM is disposable, has no host mounts, and the cache is removed immediately
afterward, but this is credential delegation to the testbed and carries the
authority of that Codex session. Testbed recordings and committed artifacts
must never contain the cache.
