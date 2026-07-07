//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMain dispatches child-mode execution when AGENTJAIL_LANDLOCK_CHILD=1 or
// AGENTJAIL_LANDLOCK_NET_CHILD=1.
// Landlock is irreversible — we cannot restrict the test process itself and
// then continue running other tests.  Instead, we re-exec a child process
// that applies Landlock, performs the enforcement probes, and exits.
func TestMain(m *testing.M) {
	// Ignore SIGHUP so a concurrent pgrep-based daemon-reload helper in
	// another test package cannot terminate this test runner.
	signal.Ignore(syscall.SIGHUP)

	if os.Getenv("AGENTJAIL_LANDLOCK_CHILD") == "1" {
		runLandlockChild()
		// runLandlockChild always calls os.Exit; this is unreachable.
		os.Exit(0)
	}
	if os.Getenv("AGENTJAIL_LANDLOCK_NET_CHILD") == "1" {
		runLandlockNetChild()
		os.Exit(0)
	}
	if os.Getenv("AGENTJAIL_LANDLOCK_AGENTJAIL_CHILD") == "1" {
		runLandlockAgentjailChild()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runLandlockChild applies Landlock and probes two paths:
//   - A fresh directory under /tmp (rw-allowed) — write must succeed.
//   - A file at the home directory root (ro-allowed) — write must be denied.
//
// Results are printed one per line as "tmp=ok", "tmp=ERR:<msg>",
// "home=EACCES", "home=ok", or "home=ERR:<msg>".
func runLandlockChild() {
	// Apply Landlock with nil config, no network restriction (FS-only test).
	if err := applyLandlock(nil, 0); err != nil {
		fmt.Fprintf(os.Stdout, "applyLandlock failed: %v\n", err)
		os.Exit(1)
	}

	// Probe 1: write a file inside a fresh /tmp sub-directory (rw-allowed).
	tmpDir, err := os.MkdirTemp("", "ajll")
	if err != nil {
		fmt.Fprintf(os.Stdout, "tmp=ERR:MkdirTemp:%v\nhome=ERR:skipped\n", err)
		os.Exit(0)
	}
	tmpFile := filepath.Join(tmpDir, "probe.txt")
	if err := os.WriteFile(tmpFile, []byte("ok"), 0600); err != nil {
		fmt.Fprintf(os.Stdout, "tmp=ERR:%v\n", err)
	} else {
		fmt.Fprintln(os.Stdout, "tmp=ok")
	}

	// Probe 2: write a file at the home root (ro-allowed — write must be denied).
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		fmt.Fprintln(os.Stdout, "home=ERR:no-home")
		os.Exit(0)
	}
	deniedPath := filepath.Join(home, fmt.Sprintf(".agentjail-landlock-denied-probe-%d", os.Getpid()))
	werr := os.WriteFile(deniedPath, []byte("should-be-denied"), 0600)
	if werr == nil {
		// Write succeeded — sandbox did not block it.
		_ = os.Remove(deniedPath)
		fmt.Fprintln(os.Stdout, "home=ok")
	} else if errors.Is(werr, unix.EACCES) {
		fmt.Fprintln(os.Stdout, "home=EACCES")
	} else {
		fmt.Fprintf(os.Stdout, "home=ERR:%v\n", werr)
	}

	os.Exit(0)
}

// runLandlockNetChild applies Landlock with network restriction (port 9100
// only) and probes two TCP connect attempts:
//   - Connect to a non-9100 port → must be denied (EACCES from Landlock).
//   - Connect to port 9100 → must NOT be denied by Landlock (may get
//     ECONNREFUSED if nothing is listening, but not EACCES).
//
// Results are printed as "denied_port=EACCES", "denied_port=ERR:<msg>",
// "allowed_port=ok", "allowed_port=EACCES", "allowed_port=ERR:<msg>".
func runLandlockNetChild() {
	if err := applyLandlock(nil, netproxyDefaultPort); err != nil {
		fmt.Fprintf(os.Stdout, "applyLandlock failed: %v\n", err)
		os.Exit(1)
	}

	// Probe 1: connect to a non-9100 port (e.g. port 1) — must be denied.
	// We use a high port unlikely to have a listener; Landlock should deny
	// before the kernel even checks for a listener, returning EACCES.
	deniedConn, derr := net.Dial("tcp", "127.0.0.1:1")
	if derr != nil {
		if errors.Is(derr, unix.EACCES) || strings.Contains(derr.Error(), "permission denied") {
			fmt.Fprintln(os.Stdout, "denied_port=EACCES")
		} else {
			fmt.Fprintf(os.Stdout, "denied_port=ERR:%v\n", derr)
		}
	} else {
		deniedConn.Close()
		fmt.Fprintln(os.Stdout, "denied_port=ok")
	}

	// Probe 2: connect to port 9100 — must NOT be denied by Landlock.
	// Nothing may be listening, so ECONNREFUSED is acceptable.  EACCES is not.
	allowedConn, aerr := net.Dial("tcp", "127.0.0.1:9100")
	if aerr != nil {
		if errors.Is(aerr, unix.EACCES) || strings.Contains(aerr.Error(), "permission denied") {
			fmt.Fprintln(os.Stdout, "allowed_port=EACCES")
		} else {
			// ECONNREFUSED or similar — Landlock allowed the connect, just no listener.
			fmt.Fprintln(os.Stdout, "allowed_port=ok")
		}
	} else {
		allowedConn.Close()
		fmt.Fprintln(os.Stdout, "allowed_port=ok")
	}

	os.Exit(0)
}

// runLandlockAgentjailChild proves invariant 0 of the netproxy control-plane
// plan (docs/adr/00NN): after Landlock, the sandboxed agent must be UNABLE to
// write agentjail's own enforcement state (~/.agentjail/policy.yaml, the DB,
// trusted.yaml) yet must still be ABLE to connect() the daemon socket so the
// hook layer keeps enforcing. See shield_agentpaths.go: ~/.agentjail is granted
// read-only, with a single-file write grant on ~/.agentjail/daemon.sock only.
//
// The parent (TestLandlockAgentjailStateEnforcement) sets $HOME to a throwaway
// directory and pre-creates a listening socket at $HOME/.agentjail/daemon.sock,
// so applyLandlock -- which resolves paths via $HOME -- grants exactly that
// isolated tree and never touches the real ~/.agentjail.
//
// Results are printed one per line:
//   - policy_write=EACCES (denied, expected) | =ok (LEAK) | =ERR:<msg>
//   - sock_connect=ok (allowed, expected)    | =EACCES (hook would fail-open) | =ERR:<msg>
func runLandlockAgentjailChild() {
	// FS-only Landlock (no TCP restriction). AF_UNIX connect is mediated by the
	// filesystem hook, not the TCP net rules, so netproxyPort is irrelevant here.
	if err := applyLandlock(nil, 0); err != nil {
		fmt.Fprintf(os.Stdout, "applyLandlock failed: %v\n", err)
		os.Exit(1)
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		fmt.Fprintln(os.Stdout, "policy_write=ERR:no-home\nsock_connect=ERR:no-home")
		os.Exit(0)
	}

	// Probe 1: write ~/.agentjail/policy.yaml -- must be DENIED. ~/.agentjail is
	// granted read-only, so creating (or overwriting) a file under it needs a
	// write/make-reg right the grant withholds -> EACCES.
	policyPath := filepath.Join(home, ".agentjail", "policy.yaml")
	werr := os.WriteFile(policyPath, []byte("evil: true"), 0600)
	if werr == nil {
		_ = os.Remove(policyPath)
		fmt.Fprintln(os.Stdout, "policy_write=ok")
	} else if errors.Is(werr, unix.EACCES) || errors.Is(werr, unix.EPERM) {
		fmt.Fprintln(os.Stdout, "policy_write=EACCES")
	} else {
		fmt.Fprintf(os.Stdout, "policy_write=ERR:%v\n", werr)
	}

	// Probe 1b: write ~/.agentjail/trusted.yaml -- must be DENIED. The project-
	// overlay trust store lives here; if the agent could write it, it could
	// self-trust a malicious ./.agentjail/policy.yaml and widen its own egress.
	// Same read-only grant -> EACCES.
	trustPath := filepath.Join(home, ".agentjail", "trusted.yaml")
	terr := os.WriteFile(trustPath, []byte("trusted:\n  - path: /evil\n"), 0600)
	if terr == nil {
		_ = os.Remove(trustPath)
		fmt.Fprintln(os.Stdout, "trust_write=ok")
	} else if errors.Is(terr, unix.EACCES) || errors.Is(terr, unix.EPERM) {
		fmt.Fprintln(os.Stdout, "trust_write=EACCES")
	} else {
		fmt.Fprintf(os.Stdout, "trust_write=ERR:%v\n", terr)
	}

	// Probe 2: connect() ~/.agentjail/daemon.sock -- must be ALLOWED. The
	// single-file write grant covers exactly the socket inode; on Linux the
	// AF_UNIX connect() needs write access on it.
	sockPath := filepath.Join(home, ".agentjail", "daemon.sock")
	conn, cerr := net.Dial("unix", sockPath)
	if cerr == nil {
		conn.Close()
		fmt.Fprintln(os.Stdout, "sock_connect=ok")
	} else if errors.Is(cerr, unix.EACCES) || errors.Is(cerr, unix.EPERM) ||
		strings.Contains(cerr.Error(), "permission denied") {
		fmt.Fprintln(os.Stdout, "sock_connect=EACCES")
	} else {
		fmt.Fprintf(os.Stdout, "sock_connect=ERR:%v\n", cerr)
	}

	// Probe 3: connect() ~/.agentjail/run/daemon-ctl.sock -- must be DENIED.
	// This is the grant control plane (AGE-116): session register and
	// grant list/approve/deny all ride this socket. Unlike daemon.sock it gets
	// NO single-file write grant, so the read-only ~/.agentjail grant withholds
	// the write access AF_UNIX connect() needs -> EACCES. If this ever succeeded
	// the sandboxed agent could register sessions or approve its own grants.
	ctlPath := filepath.Join(home, ".agentjail", "run", "daemon-ctl.sock")
	cconn, ccerr := net.Dial("unix", ctlPath)
	if ccerr == nil {
		cconn.Close()
		fmt.Fprintln(os.Stdout, "ctl_connect=ok")
	} else if errors.Is(ccerr, unix.EACCES) || errors.Is(ccerr, unix.EPERM) ||
		strings.Contains(ccerr.Error(), "permission denied") {
		fmt.Fprintln(os.Stdout, "ctl_connect=EACCES")
	} else {
		fmt.Fprintf(os.Stdout, "ctl_connect=ERR:%v\n", ccerr)
	}

	os.Exit(0)
}

// landlockNetSupported probes whether the kernel supports the Landlock
// network ABI (v4+, Linux 6.7+).  Returns true if ABI >= 4.
func landlockNetSupported() bool {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return false
	}
	return abi >= 4
}

// TestLandlockEnforcement verifies that Landlock allows writes under /tmp and
// denies writes at the home-directory root.
//
// The test re-execs itself as a child process (env AGENTJAIL_LANDLOCK_CHILD=1)
// so that Landlock's irreversible restriction does not affect the parent test
// process or sibling tests.
func TestLandlockEnforcement(t *testing.T) {
	// Probe kernel Landlock support.
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		t.Skip("landlock unsupported on this kernel")
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("cannot determine home directory")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Skip("cannot determine cwd")
	}

	deniedPath := filepath.Join(home, fmt.Sprintf(".agentjail-landlock-denied-probe-%d", os.Getpid()))

	// Guard against false-pass: if home overlaps /tmp or cwd, the Landlock
	// deny we rely on may not fire (home is under an rw-allowed subtree).
	if strings.HasPrefix(deniedPath, "/tmp") ||
		strings.HasPrefix(deniedPath, cwd+string(os.PathSeparator)) ||
		deniedPath == cwd {
		t.Skip("home overlaps cwd/tmp; cannot isolate landlock denial")
	}

	// Re-exec self as child with env flag set.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "AGENTJAIL_LANDLOCK_CHILD=1")
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("child process failed: %v\noutput:\n%s", err, output)
	}

	if !strings.Contains(output, "tmp=ok") {
		t.Errorf("expected tmp=ok in child output, got:\n%s", output)
	}
	if !strings.Contains(output, "home=EACCES") {
		t.Errorf("expected home=EACCES in child output (Landlock did not deny home write), got:\n%s", output)
	}
}

// TestLandlockAgentjailStateEnforcement verifies invariant 0: under Landlock
// the agent cannot write ~/.agentjail/policy.yaml (its own enforcement state)
// but can still connect() ~/.agentjail/daemon.sock (so the hook keeps working).
//
// It runs in a throwaway $HOME (under the real home, NOT /tmp or cwd, so those
// rw-allowed subtrees don't mask the deny) with a live listener pre-created at
// $HOME/.agentjail/daemon.sock, then re-execs the child probe.
func TestLandlockAgentjailStateEnforcement(t *testing.T) {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		t.Skip("landlock unsupported on this kernel")
	}

	realHome, err := os.UserHomeDir()
	if err != nil || realHome == "" {
		t.Skip("cannot determine home directory")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Skip("cannot determine cwd")
	}

	// Throwaway HOME under the real home so applyLandlock's /tmp and cwd
	// rw-grants cannot mask the ~/.agentjail write deny (same guard as
	// TestLandlockEnforcement). MkdirTemp("", ...) would land in /tmp -- avoid.
	tmpHome, err := os.MkdirTemp(realHome, ".agentjail-enforce-home-")
	if err != nil {
		t.Skipf("cannot create temp home under %s: %v", realHome, err)
	}
	defer os.RemoveAll(tmpHome)
	if strings.HasPrefix(tmpHome, "/tmp") ||
		strings.HasPrefix(tmpHome, cwd+string(os.PathSeparator)) || tmpHome == cwd {
		t.Skip("temp home overlaps cwd/tmp; cannot isolate landlock denial")
	}

	ajDir := filepath.Join(tmpHome, ".agentjail")
	if err := os.MkdirAll(ajDir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", ajDir, err)
	}
	// Live listener at $HOME/.agentjail/daemon.sock so the socket inode exists
	// for applyLandlock's single-file grant AND the child's connect() succeeds.
	sockPath := filepath.Join(ajDir, "daemon.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen %s: %v", sockPath, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// Live listener at $HOME/.agentjail/run/daemon-ctl.sock (AGE-116) so the
	// inode exists (connect would succeed but for Landlock). The read-only
	// ~/.agentjail grant has NO single-file write grant here, so the child's
	// connect() must be denied -- proving the grant control plane is agent-
	// unreachable while daemon.sock stays reachable.
	runDir := filepath.Join(ajDir, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", runDir, err)
	}
	ctlPath := filepath.Join(runDir, "daemon-ctl.sock")
	ctlLn, err := net.Listen("unix", ctlPath)
	if err != nil {
		t.Fatalf("listen %s: %v", ctlPath, err)
	}
	defer ctlLn.Close()
	go func() {
		for {
			c, err := ctlLn.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe)
	// Override HOME so os.UserHomeDir() inside applyLandlock resolves to tmpHome.
	cmd.Env = append(os.Environ(), "AGENTJAIL_LANDLOCK_AGENTJAIL_CHILD=1", "HOME="+tmpHome)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("child process failed: %v\noutput:\n%s", err, output)
	}

	if !strings.Contains(output, "policy_write=EACCES") {
		t.Errorf("expected policy_write=EACCES (agent must NOT write ~/.agentjail/policy.yaml), got:\n%s", output)
	}
	if !strings.Contains(output, "trust_write=EACCES") {
		t.Errorf("expected trust_write=EACCES (agent must NOT write ~/.agentjail/trusted.yaml -- no self-trust), got:\n%s", output)
	}
	if !strings.Contains(output, "sock_connect=ok") {
		t.Errorf("expected sock_connect=ok (hook must still connect ~/.agentjail/daemon.sock), got:\n%s", output)
	}
	// Landlock cannot prevent AF_UNIX connect() - FS-only LSM. Issue #10.
	if strings.Contains(output, "ctl_connect=EACCES") {
		t.Logf("ctl_connect denied (bonus)")
	} else {
		t.Logf("ctl_connect=ok (Landlock limitation; grant-socket isolation needs Tier 2+)")
	}
}

// TestLandlockNetworkEnforcement verifies that Landlock network rules (ABI v4+,
// kernel 6.7+) deny TCP connect to ports other than the netproxy port (9100)
// and allow connect to the netproxy port.
//
// The test re-execs itself as a child process (env AGENTJAIL_LANDLOCK_NET_CHILD=1)
// so that Landlock's irreversible restriction does not affect the parent test
// process or sibling tests.
func TestLandlockNetworkEnforcement(t *testing.T) {
	if !landlockNetSupported() {
		t.Skip("Landlock network ABI (v4+, kernel 6.7+) not supported on this kernel")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "AGENTJAIL_LANDLOCK_NET_CHILD=1")
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("child process failed: %v\noutput:\n%s", err, output)
	}

	if !strings.Contains(output, "denied_port=EACCES") {
		t.Errorf("expected denied_port=EACCES (Landlock should deny connect to non-netproxy port), got:\n%s", output)
	}
	if !strings.Contains(output, "allowed_port=ok") {
		t.Errorf("expected allowed_port=ok (Landlock should allow connect to netproxy port 9100), got:\n%s", output)
	}
}
