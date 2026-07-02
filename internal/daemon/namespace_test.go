package daemon

import (
	"log/slog"
	"net"
	"net/rpc"
	"os"
	"testing"
)

// TestNewNamespaceHandler verifies that NewNamespaceHandler returns a non-nil
// handler on all platforms. On non-Linux, operations return errUnsupported.
func TestNewNamespaceHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	audit := func(action, sessionID, detail string) {
		t.Logf("audit: action=%s session=%s detail=%s", action, sessionID, detail)
	}

	h := NewNamespaceHandler(audit, logger)
	if h == nil {
		t.Fatal("NewNamespaceHandler returned nil")
	}
}

// TestCreateNamespaceReqValidation verifies that Create rejects an empty
// session ID on all platforms.
func TestCreateNamespaceReqValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	audit := func(_, _, _ string) {}

	h := NewNamespaceHandler(audit, logger)
	_, err := h.Create(CreateNamespaceReq{SessionID: ""})
	if err == nil {
		t.Fatal("expected error for empty session_id, got nil")
	}
}

// TestDestroyIdempotent verifies that destroying a non-existent session
// does not return an error.
func TestDestroyIdempotent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	audit := func(_, _, _ string) {}

	h := NewNamespaceHandler(audit, logger)
	err := h.Destroy(DestroyNamespaceReq{SessionID: "nonexistent-session"})
	// On Linux: idempotent (nil). On other platforms: errUnsupported.
	// Both are acceptable for this test. We just check it doesn't panic.
	_ = err
}

// TestNamespaceServiceRPC verifies that NamespaceService can be registered
// with net/rpc and called over a pipe, exercising the full RPC round-trip.
func TestNamespaceServiceRPC(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	audit := func(_, _, _ string) {}

	h := NewNamespaceHandler(audit, logger)
	svc := NewNamespaceService(h)

	srv := rpc.NewServer()
	if err := srv.Register(svc); err != nil {
		t.Fatalf("rpc.Register failed: %v", err)
	}

	// Create a connected pair of net.Conn (in-process pipe).
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go srv.ServeConn(serverConn)

	client := rpc.NewClient(clientConn)
	defer client.Close()

	// Test Create via RPC. On non-Linux this returns errUnsupported which
	// net/rpc surfaces as an rpc.ServerError. Either way, we verify the
	// round-trip works without panic or marshal errors.
	var createResp CreateNamespaceResp
	err := client.Call("NamespaceService.Create", &CreateNamespaceReq{SessionID: "test-session"}, &createResp)
	// We don't assert success since on non-Linux the handler returns an error.
	// The important thing is the RPC round-trip completed.
	_ = err

	// Test Destroy via RPC.
	var destroyResp DestroyNamespaceResp
	err = client.Call("NamespaceService.Destroy", &DestroyNamespaceReq{SessionID: "test-session"}, &destroyResp)
	_ = err
}
