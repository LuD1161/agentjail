# ADR 0124-explicit-ssh-delegation

**Status:** Accepted; default posture superseded by ADR 0125-default-git-ssh

## Context

ADR 0054-macos-shield-tempdir-afunix-parity and ADR
0056-ssh-agent-pinned-identityfile-blindspot treated `SSH_AUTH_SOCK`
passthrough as a safer substitute for private-key file access. The key bytes do
remain inside `ssh-agent`, but possession of its socket is still a signing
capability: a client can enumerate loaded public identities and request
signatures that authenticate as any principal accepting those identities.
OpenSSH explicitly warns that a party with access to a forwarded agent socket
can authenticate with its loaded identities even though it cannot extract the
private keys.

The generic agent signing request does not identify the intended Git
repository or remote host. AgentJail therefore cannot make raw socket
passthrough repository-scoped by validating a pathname or wrapping the socket.
OpenSSH destination constraints are enforced by an OpenSSH agent for keys that
the user loaded with those constraints; they are not constraints AgentJail can
retrofit around an already-loaded unconstrained key.

Ambient passthrough also made an attacker-influenced path part of sandbox
construction. A stale tmux environment, symlink, non-socket file, different-user
socket, or AgentJail control-socket alias could be mistaken for an SSH agent.
Path validation narrows mistakes but cannot establish durable peer identity
across path replacement on a path-based sandbox.

Linux and macOS have different enforcement limits. ADR
0067-control-plane-token-auth measured that Landlock does not mediate Unix
socket `connect(2)`, so a Landlock path grant cannot authorize or deny an SSH
agent connection. Seatbelt does mediate the connection by path, but that path
rule is not a cryptographic peer identity.

Compatibility was rechecked on 2026-08-05 with OpenSSH 9.2p1 and tmux 3.5a.
The current OpenSSH manuals document agent-access and destination-constraint
caveats; the tmux manual documents that `update-environment` copies selected
variables from an attaching client and removes them when absent:

- <https://man.openbsd.org/ssh_config.5#ForwardAgent>
- <https://man.openbsd.org/ssh-add.1#h>
- <https://man.openbsd.org/ssh-agent.1>
- <https://man7.org/linux/man-pages/man1/tmux.1.html#GLOBAL_AND_SESSION_ENVIRONMENT>

## Decision

Do not pass `SSH_AUTH_SOCK` or inject an agent-backed `GIT_SSH_COMMAND` into
every shielded session. SSH-agent delegation is default-deny and must be
requested for one launch with `--git-ssh`.

An explicit request fails closed unless the inherited socket path passes the
shared typed validator. The path must be absolute, free of control characters,
contain no symlink component, name a Unix socket owned by the current
effective user, and not name an AgentJail control socket. The single validated
canonical path is used for the child environment, Git override, and the macOS
Seatbelt rule so those consumers cannot drift. Validation is defense-in-depth;
it is not represented as host, repository, or durable peer attestation.

An accepted delegation request injects an unspoofable shield marker and prints
a warning that the coding agent may use every identity loaded in that agent and that Tier
1 does not constrain the remote host. Inherited markers are stripped. Invalid,
missing, or stale explicit delegation aborts before the coding agent starts.
Socket paths are not written to audit detail; the best-effort delegation event
records only the fixed scope `all_loaded_identities`.

The daemon does not discover, retain, proxy, or recreate SSH-agent sockets. A
long-running daemon has the wrong session lifetime and would become a signing
confused deputy. Users who need Git SSH inside a coding session should use a
separate minimally privileged agent/key, preferably with server-side and
OpenSSH destination, confirmation, or lifetime constraints appropriate to
their workflow.

Linux removes its dynamic SSH-socket path grant because it was measured not to
control Unix-socket connections. macOS retains only the exact rule derived from
an explicitly delegated, validated socket.

`agentjail doctor` treats shielded key-file inventory as unknown rather than
empty. A shielded session without the delegation marker reports that SSH-agent
access is unavailable by secure default; it must not conclude that no keys
exist or claim an entirely healthy SSH setup.

## Consequences

- A default shielded coding session cannot discover the agent through its
  environment and receives no AgentJail-created signing delegation.
- Existing workflows that relied on ambient Git SSH must opt in per launch.
- Opt-in remains a broad signing grant. AgentJail cannot honestly label it as
  repository- or host-scoped at Tier 1.
- A validated path reduces accidental and control-plane aliasing but does not
  eliminate same-UID or post-validation replacement risks.
- On Linux, hiding the variable is not a complete Unix-socket isolation
  boundary because Landlock does not mediate `connect(2)`. Strong isolation
  requires Tier 2 plus destination-aware network and signing mediation.
- HTTPS credentials brokered through narrower AgentJail mechanisms remain the
  preferred path for routine unattended Git operations.
