package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// HealthCheck connects to the daemon's Unix socket and verifies it responds
// with the expected version. Retries every second for up to 15 seconds.
func HealthCheck(ctx context.Context, socketPath, expectedVersion string) error {
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("health check timed out after 15s: %w", lastErr)
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("health check cancelled: %w", err)
		}
		lastErr = healthCheckOnce(socketPath, expectedVersion)
		if lastErr == nil {
			return nil
		}
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return fmt.Errorf("health check cancelled: %w", ctx.Err())
		}
	}
}

func healthCheckOnce(socketPath, expectedVersion string) error {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", socketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := map[string]string{"type": "version"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("write version request: %w", err)
	}
	var resp struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("read version response: %w", err)
	}
	if resp.Version != expectedVersion {
		return fmt.Errorf("version mismatch: got %q, want %q", resp.Version, expectedVersion)
	}
	return nil
}
