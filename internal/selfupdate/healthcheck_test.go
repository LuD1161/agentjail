package selfupdate

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthCheck_Success(t *testing.T) {
	socketPath := startMockDaemon(t, "v1.2.3")
	err := HealthCheck(context.Background(), socketPath, "v1.2.3")
	if err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestHealthCheck_VersionMismatch(t *testing.T) {
	socketPath := startMockDaemon(t, "v1.2.3")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := HealthCheck(ctx, socketPath, "v9.9.9")
	if err == nil {
		t.Fatal("expected error on version mismatch")
	}
}

func TestHealthCheck_NoSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := HealthCheck(ctx, "/tmp/nonexistent-socket-test.sock", "v1.0.0")
	if err == nil {
		t.Fatal("expected error on missing socket")
	}
}

func TestHealthCheck_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := HealthCheck(ctx, "/tmp/nonexistent.sock", "v1.0.0")
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

// startMockDaemon creates a Unix socket that responds to version requests.
// It uses os.MkdirTemp with an empty base to avoid macOS's 104-char socket path limit.
func startMockDaemon(t *testing.T, version string) string {
	t.Helper()
	// Use /tmp directly to keep the path short (macOS limit: 104 chars).
	dir, err := os.MkdirTemp("", "aj-hc-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	socketPath := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close(); os.RemoveAll(dir) })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req map[string]string
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				if req["type"] == "version" {
					resp := map[string]string{"version": version}
					json.NewEncoder(c).Encode(resp) //nolint:errcheck
				}
			}(conn)
		}
	}()
	return socketPath
}
