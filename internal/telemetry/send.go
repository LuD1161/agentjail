package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrNoBackend is returned by SendFeedback when the build has no telemetry backend
// configured (apiKey empty) — the caller should fall back to a GitHub issue link.
var ErrNoBackend = errors.New("telemetry: no backend configured")

// SendFeedback sends a single feedback event immediately (synchronous), regardless
// of the usage-telemetry opt-out, because it is an explicit, user-initiated action.
// It reuses the anonymous ID from telemetry.json. Returns ErrNoBackend if there is
// no backend to send to.
func SendFeedback(ctx context.Context, p Paths, getenv func(string) string, version, goos, message, contact string) error {
	client := DefaultClient()
	if !client.HasBackend() {
		return ErrNoBackend
	}
	c, err := LoadConsent(p) // for the anonymous ID only
	if err != nil {
		return err
	}
	ev := NewFeedbackEvent(c.AnonymousID, version, goos, message, contact)
	return client.Send(ctx, []Event{ev})
}

// apiKey is injected at release build time via:
//
//	-ldflags "-X github.com/LuD1161/agentjail/internal/telemetry.apiKey=phc_xxx"
//
// It is a PostHog write-only project key (safe to embed). Empty (the default for
// all source/dev/CI builds) means telemetry is fully inert — nothing is sent.
var apiKey = ""

// endpoint is the PostHog batch capture URL (overridable for tests/EU region).
var endpoint = "https://us.i.posthog.com/batch/"

// Client posts batched events to PostHog.
type Client struct {
	APIKey   string
	Endpoint string
	HTTP     *http.Client
}

// DefaultClient builds a Client from the ldflags-injected key/endpoint.
func DefaultClient() *Client {
	return &Client{
		APIKey:   apiKey,
		Endpoint: endpoint,
		HTTP:     &http.Client{Timeout: 5 * time.Second},
	}
}

// HasBackend reports whether a backend key is configured.
func (c *Client) HasBackend() bool { return c.APIKey != "" }

// Send POSTs events as a single PostHog /batch/ request. No-op without a backend.
func (c *Client) Send(ctx context.Context, events []Event) error {
	if !c.HasBackend() || len(events) == 0 {
		return nil
	}
	body := map[string]interface{}{"api_key": c.APIKey, "batch": events}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("telemetry: backend returned %d", resp.StatusCode)
	}
	return nil
}
