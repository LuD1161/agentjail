//go:build linux

package hostconnector

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/proxyctl"
)

func TestLinuxGuestSocketRoutesOnlyConfiguredConnectorAndCleansUp(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	seen := make(chan *http.Request, 1)
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		seen <- req
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		_, _ = io.Copy(conn, conn)
	}()

	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bridge, err := newLinuxConnectorBridge(LinuxContainerConfig{
		SessionID: "session-a", Token: "token-a", RuntimeDir: runtimeDir,
	}, "chrome-cdp", proxy.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}

	client, err := net.Dial("unix", bridge.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("exact configured route")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("exact configured route"))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if got := string(buf); got != "exact configured route" {
		t.Fatalf("echo = %q", got)
	}
	_ = client.Close()

	request := <-seen
	if request.Method != http.MethodConnect || request.Host != "chrome-cdp.connector.agentjail:443" {
		t.Fatalf("bridge request = %s %s", request.Method, request.Host)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("token-a:"))
	if got := request.Header.Get("Proxy-Authorization"); got != wantAuth {
		t.Fatalf("Proxy-Authorization = %q, want session token", got)
	}
	if endpoint := bridge.endpoint; endpoint.SocketPath() != "/run/agentjail/connectors/chrome-cdp.sock" {
		t.Fatalf("guest endpoint = %q", endpoint.SocketPath())
	}

	path := bridge.path
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.Dial("unix", path); err == nil {
		t.Fatal("guest endpoint remained reachable after cleanup")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket cleanup error = %v", err)
	}
}

func TestLinuxGuestSocketRejectsInvalidPrivateRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := newLinuxConnectorBridge(LinuxContainerConfig{SessionID: "session-a", Token: proxyctl.Token("token-a"), RuntimeDir: dir}, "chrome-cdp", "127.0.0.1:1", time.Second)
	if err == nil {
		t.Fatal("world-readable runtime directory was accepted")
	}
}

func TestLinuxGuestSocketCannotReuseWrongConnectorPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := LinuxContainerConfig{SessionID: "session-a", Token: "token-a", RuntimeDir: dir}
	bridge, err := newLinuxConnectorBridge(config, "chrome-cdp", "127.0.0.1:1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	if filepath.Base(bridge.path) != "chrome-cdp.sock" {
		t.Fatalf("host socket = %q", bridge.path)
	}
	other, err := newLinuxConnectorBridge(config, "other-connector", "127.0.0.1:1", time.Second)
	if err != nil {
		t.Fatalf("independent configured connector endpoint refused: %v", err)
	}
	defer other.Close()
}
