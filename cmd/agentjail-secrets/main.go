// Package main is agentjail-secrets — a local secrets store and credential
// broker that issues scoped, short-lived credentials to sandboxed coding agents.
//
// The agent never reads long-lived secrets directly.  Instead, the shield
// calls agentjail-secrets to grant scoped creds before exec'ing the agent,
// injects them into the agent's environment, and strips ambient credentials
// (see P2.4 — env stripping).
//
// Storage: secrets are encrypted at rest with AES-256-GCM.  The master key
// is a 32-byte random key stored at ~/.agentjail/secrets.key (0600).  Future
// enhancement: integrate with OS keystore (macOS Keychain, Linux
// secret-service) for key management.
//
// Backends:
//   - AWS: STS AssumeRole with inline session policy (Kind-A scoped creds)
//   - Postgres: CREATE ROLE with scoped privileges + VALID UNTIL
//   - Redis: ACL SETUSER with allowed-key globs + command subset
//
// Protocol: Unix socket at ~/.agentjail/secrets.sock, newline-delimited JSON
// (same pattern as agentjail-daemon).
//
// See also: docs/adr/0018-secret-server.md, docs/adr/0004-credential-broker-tier1.md
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: agentjail-secrets <command> [args...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  serve                          Start the secrets RPC server (Unix socket)")
		fmt.Fprintln(os.Stderr, "  set <name> <value>             Store a secret (encrypted at rest)")
		fmt.Fprintln(os.Stderr, "  list                           List secret names (never values)")
		fmt.Fprintln(os.Stderr, "  delete <name>                  Delete a secret")
		fmt.Fprintln(os.Stderr, "  grant <name> --scope=<policy>  Issue scoped, short-lived credentials")
		fmt.Fprintln(os.Stderr, "    --ttl=<duration>             (e.g. --scope=read-only --ttl=15m)")
		fmt.Fprintln(os.Stderr, "  revoke <grant-id>              Revoke an active grant")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		fmt.Fprintln(os.Stderr, "  --socket=PATH                  Path to Unix socket (default: ~/.agentjail/secrets.sock)")
		fmt.Fprintln(os.Stderr, "  --store=PATH                   Path to secrets store (default: ~/.agentjail/secrets/)")
		os.Exit(64)
	}

	if len(os.Args) < 2 {
		flag.Usage()
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "serve":
		runServer(args)
	case "set":
		runSet(args)
	case "list":
		runList(args)
	case "delete":
		runDelete(args)
	case "grant":
		runGrant(args)
	case "revoke":
		runRevoke(args)
	default:
		fmt.Fprintf(os.Stderr, "agentjail-secrets: unknown command %q\n", cmd)
		flag.Usage()
	}
}
