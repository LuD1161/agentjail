// Package eslogger implements the tamper-evidence cross-check between
// macOS Endpoint Security (consumed via /usr/bin/eslogger) and the
// agentjail user-space capture surfaces (PATH shim, runtime hook).
//
// The package is file-oriented: it reads an eslogger JSON-Lines capture
// and an agentjail events.jsonl, joins exec events on a bounded
// (ppid, exec.path, time window) key, and emits "ES-only" deltas — execs
// the kernel saw that our user-space capture did not. Those deltas are
// the primary tamper-evidence signal.
//
// A package-local reconcile job may be added: a 1-minute ticker can re-run
// the diff against growing files, retain recent deltas with bounded
// memory, and expose them to a daemon call site without moving daemon
// concerns into the diff engine itself.
//
// Design notes live in agentjail/docs/DECISIONS.md.
package eslogger
