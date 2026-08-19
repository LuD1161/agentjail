package hostconnector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// SameHostBackend is the deliberately narrow Tier-1 bridge. It dials and
// probes only the configured loopback CDP endpoint from the host process. It
// is not a guest transport and must not be selected for a namespace, container,
// or microVM until that platform registers an authenticated routing endpoint.
// See ADR 0141-runtime-grants.
type SameHostBackend struct {
	dialTimeout  time.Duration
	probeTimeout time.Duration
}

func NewSameHostBackend() *SameHostBackend {
	return &SameHostBackend{dialTimeout: time.Second, probeTimeout: 2 * time.Second}
}

func (b *SameHostBackend) Activate(ctx context.Context, activation Activation) (Adapter, error) {
	if activation.Transport() != TransportCDP {
		return nil, fmt.Errorf("%w: same-host backend supports CDP only", ErrPlatformUnavailable)
	}
	destination := activation.connector.Destination()
	if !destination.loopback() {
		return nil, fmt.Errorf("%w: non-loopback CDP destination", ErrActivation)
	}
	if err := b.probeChromeCDP(ctx, destination); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrActivation, err)
	}
	return closedAdapter{}, nil
}

func (b *SameHostBackend) probeChromeCDP(ctx context.Context, destination Destination) error {
	dialer := &net.Dialer{Timeout: b.dialTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(destination.Host(), fmt.Sprint(destination.Port())))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: b.probeTimeout}
	requestURL := (&url.URL{Scheme: "http", Host: "connector.invalid", Path: destination.Path()}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("dial configured CDP destination: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CDP readiness status %d", resp.StatusCode)
	}
	var version struct {
		Browser              string `json:"Browser"`
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64*1024)).Decode(&version); err != nil {
		return fmt.Errorf("decode CDP readiness: %w", err)
	}
	if version.Browser == "" || version.WebSocketDebuggerURL == "" {
		return fmt.Errorf("invalid CDP readiness response")
	}
	return nil
}

type closedAdapter struct{}

func (closedAdapter) Close() error { return nil }
