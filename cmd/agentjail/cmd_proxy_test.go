package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/hostproxy"
	"github.com/LuD1161/agentjail/internal/wire"
	"github.com/spf13/cobra"
)

func TestRunHostProxyReportsMissingApprovalToDaemon(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	t.Setenv(hostproxy.ProofEnvironmentName, "")
	t.Setenv(hostproxy.TargetEnvironmentName, "")
	if err := os.MkdirAll(filepath.Dir(wire.DefaultSocketPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", wire.DefaultSocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	received := make(chan hostproxy.WireRequest, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var request hostproxy.WireRequest
		if json.NewDecoder(conn).Decode(&request) == nil {
			received <- request
		}
		_ = json.NewEncoder(conn).Encode(hostproxy.WireResponse{Error: "host proxy authorization unavailable or invalid"})
	}()

	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)
	code := runHostProxy(cmd, []string{"--reason", "verify the local binary", "--", "/bin/true"})
	if code == 0 || !strings.Contains(stderr.String(), "no native one-time approval") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	request := <-received
	if request.Type != hostproxy.RequestType || request.Request.Proof != "" {
		t.Fatalf("request = %#v", request)
	}
	if len(request.Request.Target.Argv) != 1 || request.Request.Target.Argv[0] != "/bin/true" {
		t.Fatalf("argv = %#v", request.Request.Target.Argv)
	}
	if request.Request.Reason != "verify the local binary" {
		t.Fatalf("reason = %q", request.Request.Reason)
	}
}

func TestRunHostProxyRequiresReasonAndReportsMalformedDenial(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	t.Setenv(hostproxy.ProofEnvironmentName, "")
	t.Setenv(hostproxy.TargetEnvironmentName, "")
	if err := os.MkdirAll(filepath.Dir(wire.DefaultSocketPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", wire.DefaultSocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	received := make(chan hostproxy.WireRequest, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var request hostproxy.WireRequest
		if json.NewDecoder(conn).Decode(&request) == nil {
			received <- request
		}
		_ = json.NewEncoder(conn).Encode(hostproxy.WireResponse{Error: "malformed host proxy request"})
	}()

	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)
	if code := runHostProxy(cmd, []string{"--", "/bin/true"}); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "requires --reason") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	request := <-received
	if request.Type != hostproxy.RequestType || request.Request.Proof != "" || request.Request.Reason != "" {
		t.Fatalf("request = %#v", request)
	}
	if len(request.Request.Target.Argv) != 0 {
		t.Fatalf("malformed argv escaped into audit request: %#v", request.Request.Target.Argv)
	}
}
