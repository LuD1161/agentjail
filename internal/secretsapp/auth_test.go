package secretsapp

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/credentials"
)

// brokerFixture starts a broker on a short socket path with one raw secret
// stored, and returns (socketPath, token). It calls handleConn directly rather
// than runServer so the test does not fork a process or touch the real ~.
func brokerFixture(t *testing.T, token string) (string, *Store) {
	t.Helper()

	dir, err := os.MkdirTemp("", "sb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	store, err := NewStore(filepath.Join(dir, "secrets"), filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("MY_PROD_API_KEY", `{"password":"sk-live-SUPER-SECRET"}`); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "secrets.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	gm := credentials.NewGrantManager()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go handleConn(conn, store, gm, audit.NopEmitter{}, token)
		}
	}()
	return sock, store
}

// ask sends one RPC and returns the raw response line.
func ask(t *testing.T, sock string, req RPCRequest) RPCResponse {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		t.Fatal("no response")
	}
	var resp RPCResponse
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, sc.Text())
	}
	return resp
}

// TestBroker_NoTokenIsRejected is the AGE-214 regression: a sandboxed agent can
// reach this socket (Landlock does not mediate AF_UNIX connect) and shares the
// broker's UID (so SO_PEERCRED cannot exclude it). The token is the only
// boundary, so a request without one must never be served.
func TestBroker_NoTokenIsRejected(t *testing.T) {
	sock, _ := brokerFixture(t, "the-real-token")

	// Byte-for-byte what the proven exploit sent.
	resp := ask(t, sock, RPCRequest{Action: "grant", Name: "MY_PROD_API_KEY", TTL: "15m"})

	if resp.OK {
		t.Fatal("broker served a grant to an unauthenticated caller")
	}
	if len(resp.EnvVars) != 0 {
		t.Fatalf("credential leaked to unauthenticated caller: %v", resp.EnvVars)
	}
	if !strings.Contains(resp.Error, "unauthorized") {
		t.Errorf("expected an unauthorized error, got %q", resp.Error)
	}
}

// TestBroker_WrongTokenIsRejected: a guessed token must not work either.
func TestBroker_WrongTokenIsRejected(t *testing.T) {
	sock, _ := brokerFixture(t, "the-real-token")

	resp := ask(t, sock, RPCRequest{Action: "grant", Token: "wrong-token", Name: "MY_PROD_API_KEY"})
	if resp.OK || len(resp.EnvVars) != 0 {
		t.Fatalf("wrong token was accepted: ok=%v envvars=%v", resp.OK, resp.EnvVars)
	}
}

// TestBroker_EveryVerbRequiresToken: grant is the crown jewel, but list
// enumerates secret names and set/delete mutate the store. All are privileged.
func TestBroker_EveryVerbRequiresToken(t *testing.T) {
	sock, _ := brokerFixture(t, "the-real-token")

	for _, req := range []RPCRequest{
		{Action: "list"},
		{Action: "set", Name: "X", Value: "y"},
		{Action: "delete", Name: "MY_PROD_API_KEY"},
		{Action: "grant", Name: "MY_PROD_API_KEY"},
		{Action: "revoke", GrantID: "whatever"},
	} {
		t.Run(req.Action, func(t *testing.T) {
			resp := ask(t, sock, req)
			if resp.OK {
				t.Errorf("%q served without a token", req.Action)
			}
			if len(resp.Names) != 0 {
				t.Errorf("%q leaked secret names without a token: %v", req.Action, resp.Names)
			}
		})
	}
}

// TestBroker_ValidTokenStillWorks: the fix must not break the legitimate caller
// (the shield, which captures the token before applying Landlock).
func TestBroker_ValidTokenStillWorks(t *testing.T) {
	const tok = "the-real-token"
	sock, _ := brokerFixture(t, tok)

	resp := ask(t, sock, RPCRequest{Action: "grant", Token: tok, Name: "MY_PROD_API_KEY", TTL: "15m"})
	if !resp.OK {
		t.Fatalf("authenticated grant failed: %s", resp.Error)
	}
	if !strings.Contains(resp.EnvVars["MY_PROD_API_KEY"], "SUPER-SECRET") {
		t.Errorf("authenticated caller should receive the credential, got %v", resp.EnvVars)
	}

	if list := ask(t, sock, RPCRequest{Action: "list", Token: tok}); !list.OK || len(list.Names) != 1 {
		t.Errorf("authenticated list failed: ok=%v names=%v", list.OK, list.Names)
	}
}

// TestBroker_EmptyServerTokenFailsClosed: a broker that somehow has no token
// must reject everything, not accept everything. Belt-and-braces for Valid's
// empty-want rule at the layer that matters.
func TestBroker_EmptyServerTokenFailsClosed(t *testing.T) {
	sock, _ := brokerFixture(t, "")

	for _, req := range []RPCRequest{
		{Action: "grant", Name: "MY_PROD_API_KEY"},
		{Action: "grant", Name: "MY_PROD_API_KEY", Token: ""},
		{Action: "list", Token: "anything"},
	} {
		if resp := ask(t, sock, req); resp.OK {
			t.Errorf("server with no token served %q", req.Action)
		}
	}
}
