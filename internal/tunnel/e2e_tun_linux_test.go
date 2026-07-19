//go:build linux

// Real-TUN, unprivileged-userns end-to-end interception test (AGE-148).
//
// Unlike fdtun_linux_test.go (which pumps a SOCK_DGRAM socketpair as a TUN
// stand-in) and the packet-injection unit tests, this test stands up the WHOLE
// mechanism on a real kernel TUN device inside a real unprivileged user +
// network namespace and drives real traffic through it:
//
//	in-ns client (bash /dev/tcp) --> kernel ajtun0 TUN --> fd handoff (SCM_RIGHTS)
//	  --> fdPump --> forwardStack (gVisor) --> handleConn --> real host upstream
//	  --> relay back --> client reads banner
//
// It requires unprivileged user namespaces and an openable /dev/net/tun; on a
// host lacking either it SKIPs cleanly rather than hanging or failing.
//
// IMPORTANT: netns.CreateWithTUN re-execs /proc/self/exe as the namespace
// holder. Under `go test` that exe is THIS test binary, so TestMain must call
// netns.MaybeRunReexec() before m.Run() — otherwise the holder re-exec would run
// the whole test suite instead of the holder logic. See TestMain below.
package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/netns"
)

// TestMain intercepts the namespace-holder / hardened-exec re-exec before the
// test runner starts. netns.CreateWithTUN launches /proc/self/exe (this binary)
// with a marker first arg; MaybeRunReexec runs that role and never returns. In
// the normal case it returns immediately and the suite runs.
//
// It also intercepts h2HelperArg the same way: the h2/gRPC e2e tests
// (h2client_helper_linux_test.go) re-exec this same test binary INSIDE the
// netns to drive a real TLS+ALPN client, since bash's /dev/tcp cannot do a
// TLS handshake. Checked first for the same reason MaybeRunReexec must run
// before flag parsing / m.Run().
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == h2HelperArg {
		h2HelperMain(os.Args[2:]) // never returns
	}
	netns.MaybeRunReexec()
	os.Exit(m.Run())
}

// preflightTUN skips the test cleanly if this host cannot support a real TUN in
// an unprivileged userns: /dev/net/tun must be openable, and unprivileged user
// namespaces must be enabled. EPERM/ENODEV/ENOENT => Skip, not Fail.
func preflightTUN(t *testing.T) {
	t.Helper()

	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		// EPERM/ENODEV/ENOENT all mean this host cannot give us a real TUN.
		if errors.Is(err, os.ErrNotExist) ||
			errors.Is(err, os.ErrPermission) ||
			errors.Is(err, unix.ENODEV) ||
			errors.Is(err, unix.EPERM) {
			t.Skipf("skipping: /dev/net/tun not usable here: %v", err)
		}
		t.Skipf("skipping: /dev/net/tun open failed: %v", err)
	}
	_ = f.Close()
}

// TestE2ETUNInterception is the core end-to-end proof: a real client inside a
// real userns/netns dials a VIP over a real kernel TUN, and its bytes reach a
// real host-side upstream through the full forward path.
func TestE2ETUNInterception(t *testing.T) {
	preflightTUN(t)

	// nsenter, timeout, and bash are required to run the in-ns client.
	requireTool(t, "nsenter")
	requireTool(t, "timeout")
	clientSh, ok := lookPathAny("bash")
	if !ok {
		t.Skip("skipping: no bash for the in-ns /dev/tcp client")
	}

	// --- Host-side upstream: a plain TCP server that reads a request byte then
	// replies with a known banner and closes. handleConn PEEKS (reads) from the
	// client before dialing upstream, so the client must send first; the server
	// therefore reads before replying to mirror that ordering. ---
	const banner = "HELLO_FROM_REAL_UPSTREAM_AGE148"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("host upstream listen: %v", err)
	}
	defer ln.Close()
	upstreamPort := ln.Addr().(*net.TCPAddr).Port

	gotConn := make(chan string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				select {
				case gotConn <- string(buf[:n]):
				default:
				}
				_, _ = c.Write([]byte(banner))
			}(c)
		}
	}()

	// --- VIP registry: map the hostname "127.0.0.1" to a VIP. handleConn does
	// registry.Lookup(dstIP) -> hostname, then dials net.JoinHostPort(hostname,
	// dstPort). By registering "127.0.0.1" the upstream dial lands on our host
	// server; dstPort is whatever the agent connected to (== upstreamPort). ---
	registry := dnsvip.NewRegistry()
	vip, err := registry.Allocate("127.0.0.1")
	if err != nil {
		t.Fatalf("allocate VIP: %v", err)
	}
	t.Logf("allocated VIP %s -> upstream 127.0.0.1:%d", vip, upstreamPort)

	// --- Gateway (transparent forward stack) ---
	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	gw, err := NewForwardGateway(Config{}, registry, logger)
	if err != nil {
		t.Fatalf("NewForwardGateway: %v", err)
	}
	defer gw.Close()

	// --- Real kernel TUN inside a fresh unprivileged user+net+mount ns ---
	ns, tun, err := netns.CreateWithTUN(netns.TUNIfName, netns.TUNAddrCIDR)
	if err != nil {
		if errors.Is(err, netns.ErrUnsupported) {
			t.Skipf("skipping: unprivileged userns unsupported: %v", err)
		}
		// On THIS host support was confirmed, so a failure here is a real
		// mechanism bug worth surfacing loudly (but still classify the classic
		// unsupported errnos as skips for portability).
		msg := err.Error()
		if strings.Contains(msg, "operation not permitted") ||
			strings.Contains(msg, "no such device") ||
			strings.Contains(msg, "no such file") {
			t.Skipf("skipping: TUN/userns setup unsupported here: %v", err)
		}
		t.Fatalf("CreateWithTUN failed (real bug on a supposedly-supported host): %v", err)
	}
	defer ns.Close()
	defer tun.Close()
	t.Logf("created netns holder pid=%d with TUN %s", ns.PID(), netns.TUNIfName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := gw.AttachTUN(ctx, tun); err != nil {
		t.Fatalf("AttachTUN: %v", err)
	}
	go func() { _ = gw.ListenAndServe(ctx) }()

	// --- Drive real traffic from INSIDE the netns via bash /dev/tcp. The client
	// connects to VIP:upstreamPort, sends "PING", and cat-reads until the server
	// closes (prints the banner). timeout guards against a hang. ---
	vipStr := vip.String()
	script := fmt.Sprintf(
		`exec 3<>/dev/tcp/%s/%d || { echo CONNECT_FAILED >&2; exit 1; }; printf PING >&3; cat <&3`,
		vipStr, upstreamPort,
	)
	clientOut, clientErr := runInNS(t, ns, 15*time.Second, clientSh, "-c", script)
	t.Logf("in-ns client stdout=%q stderr=%q", clientOut, clientErr)

	if !strings.Contains(clientOut, banner) {
		t.Fatalf("in-ns client did not receive upstream banner over the TUN.\n"+
			"want substring %q, got stdout=%q stderr=%q", banner, clientOut, clientErr)
	}

	// The server must actually have observed the client's request bytes.
	select {
	case req := <-gotConn:
		if req != "PING" {
			t.Fatalf("upstream got unexpected request %q, want %q", req, "PING")
		}
		t.Logf("PASS: full TCP interception path exercised; upstream observed request %q", req)
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never observed a connection despite client receiving banner")
	}

	// --- DNS leg: from inside the ns, issue an A query to an arbitrary
	// resolver:53. The forwardStack intercepts UDP:53 to any dst and answers
	// from the VIP registry, so a 10.78.x.y VIP-range answer proves the DNS
	// interception works over a real TUN. Best-effort: skip just this leg if no
	// DNS client tool is present. ---
	t.Run("DNSLeg", func(t *testing.T) {
		var dnsOut, dnsErr string
		switch {
		case toolExists("dig"):
			dnsOut, dnsErr = runInNS(t, ns, 10*time.Second, "dig",
				"+time=3", "+tries=1", "+short", "@192.0.2.123", "dnsleg.age148.test", "A")
		case toolExists("nslookup"):
			dnsOut, dnsErr = runInNS(t, ns, 10*time.Second, "nslookup",
				"dnsleg.age148.test", "192.0.2.123")
		default:
			t.Skip("skipping DNS leg: no dig/nslookup available")
		}
		t.Logf("in-ns DNS stdout=%q stderr=%q", dnsOut, dnsErr)
		if !strings.Contains(dnsOut, "10.78.") {
			t.Fatalf("DNS query over TUN did not return a VIP-range (10.78.x.y) answer; "+
				"stdout=%q stderr=%q", dnsOut, dnsErr)
		}
		t.Logf("PASS: DNS interception over TUN returned a VIP-range answer")
	})
}

// runInNS runs a command inside the namespace and returns its stdout and stderr
// separately. It uses ns.ExecIn (nsenter into the holder's user+net+mount
// namespaces). ns.ExecIn builds its OWN nsenter command and does not honor a
// context, so we hard-cap the in-ns process with the coreutils `timeout` wrapper
// — otherwise a blocked client (e.g. a TCP handshake that never completes) would
// hang the whole test to the package deadline. The wrapper is required: without
// it there is no other way to bound ExecIn.
func runInNS(t *testing.T, ns *netns.Namespace, timeout time.Duration, name string, args ...string) (stdout, stderr string) {
	t.Helper()

	var outBuf, errBuf bytes.Buffer
	secs := strconv.Itoa(int(timeout.Seconds()))
	wrapped := append([]string{"-k", "2", secs, name}, args...)
	cmd := exec.Command("timeout", wrapped...)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := ns.ExecIn(cmd)
	if err != nil {
		// timeout exits 124 on deadline; other non-zero is the client's own
		// exit. Callers assert on captured output, so just record here.
		t.Logf("in-ns command %s returned err=%v", name, err)
	}
	return outBuf.String(), errBuf.String()
}

func requireTool(t *testing.T, name string) {
	t.Helper()
	if !toolExists(name) {
		t.Skipf("skipping: required tool %q not found in PATH", name)
	}
}

func toolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func lookPathAny(names ...string) (string, bool) {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, true
		}
	}
	return "", false
}

// testWriter adapts *testing.T to io.Writer so gateway logs land in test output.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("gw: %s", bytes.TrimRight(p, "\n"))
	return len(p), nil
}

var _ io.Writer = testWriter{}
