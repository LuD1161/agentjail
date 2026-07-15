// Package buildinfo holds the single shared version symbol injected at build
// time via -ldflags into every agentjail binary. Before the multicall binary
// (see cmd/agentjail's role dispatch and internal/{daemonapp,shieldapp,
// netproxyapp,secretsapp}), each role binary carried its own private
// `main.version` (or package-local `version`) var, set independently by
// -ldflags "-X main.version=...". That only worked because each role was its
// own `package main`; once cmd/agentjail-daemon, cmd/agentjail-netproxy, etc.
// became thin wrappers that import internal/daemonapp and internal/netproxyapp
// (see T3), a `-X main.version=...` ldflag targeting `main` no longer reaches
// the version var living in the imported package -- it silently no-ops.
//
// buildinfo.Version is the one symbol every binary's Makefile target injects
// via its own fully-qualified path:
//
//	-X github.com/LuD1161/agentjail/internal/buildinfo.Version=$(DIST_VERSION)
//
// and every reporter (CLI `agentjail version`, the daemon startup log,
// netproxy's control/fingerprint response, the hook's fail-open telemetry)
// reads buildinfo.Version directly instead of a package-private copy.
package buildinfo

// Version is the agentjail release version (e.g. "v0.6.2" or a
// `git describe --tags --dirty` string). It defaults to "dev" for
// unversioned local builds (`go build` with no -ldflags).
var Version = "dev"
