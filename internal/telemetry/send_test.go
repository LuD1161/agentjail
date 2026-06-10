package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendFeedback_NoBackendReturnsSentinel(t *testing.T) {
	// DefaultClient uses the empty package apiKey in tests → no backend.
	err := SendFeedback(context.Background(), Paths{Base: t.TempDir()}, func(string) string { return "" }, "0.1.0", "darwin", "hi", "")
	if err != ErrNoBackend {
		t.Fatalf("got %v want ErrNoBackend", err)
	}
}

func TestSend_PostsBatchWithAPIKey(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := &Client{APIKey: "phc_test", Endpoint: srv.URL, HTTP: srv.Client()}
	evs := []Event{NewFeatureEvent("anon", "0.1.0", "logs", nil)}
	if err := c.Send(context.Background(), evs); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotBody["api_key"] != "phc_test" {
		t.Fatalf("api_key=%v", gotBody["api_key"])
	}
	if batch, ok := gotBody["batch"].([]interface{}); !ok || len(batch) != 1 {
		t.Fatalf("batch=%v", gotBody["batch"])
	}
}

func TestSend_NonenoBackendNoSend(t *testing.T) {
	c := &Client{APIKey: "", Endpoint: "http://127.0.0.1:0"}
	if c.HasBackend() {
		t.Fatal("HasBackend should be false with empty key")
	}
	// Send is a no-op (no panic, no error) with no backend.
	if err := c.Send(context.Background(), []Event{NewFeatureEvent("a", "v", "logs", nil)}); err != nil {
		t.Fatalf("Send no-op: %v", err)
	}
}

func TestSend_ServerErrorReturnsErr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	c := &Client{APIKey: "phc_test", Endpoint: srv.URL, HTTP: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Send(ctx, []Event{NewFeatureEvent("a", "v", "logs", nil)}); err == nil {
		t.Fatal("expected error on 500")
	}
}

// TestSendInstall_NoBackendReturnsSentinel verifies the no-backend path.
func TestSendInstall_NoBackendReturnsSentinel(t *testing.T) {
	err := SendInstall(context.Background(), Paths{Base: t.TempDir()},
		func(string) string { return "" }, "0.1.0", "darwin", "arm64", "curl", []string{"claude-code"}, 1)
	if err != ErrNoBackend {
		t.Fatalf("got %v want ErrNoBackend", err)
	}
}

// TestSendInstall_OptOutSkipsSend verifies that telemetry disable prevents the send.
func TestSendInstall_OptOutSkipsSend(t *testing.T) {
	sent := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Override apiKey and endpoint for the duration of this test.
	orig := apiKey
	origEP := endpoint
	apiKey = "phc_test"
	endpoint = srv.URL
	defer func() { apiKey = orig; endpoint = origEP }()

	p := Paths{Base: t.TempDir()}
	getenv := func(k string) string {
		if k == EnvVar {
			return "false" // opt-out
		}
		return ""
	}
	if err := SendInstall(context.Background(), p, getenv, "0.1.0", "darwin", "arm64", "", nil, 0); err != nil {
		t.Fatalf("expected nil (opt-out), got %v", err)
	}
	if sent {
		t.Fatal("should not have sent when telemetry is disabled")
	}
}

// TestSendUninstall_NoBackendReturnsSentinel verifies the no-backend path.
func TestSendUninstall_NoBackendReturnsSentinel(t *testing.T) {
	err := SendUninstall(context.Background(), Paths{Base: t.TempDir()},
		func(string) string { return "" }, "0.1.0", "linux", "amd64")
	if err != ErrNoBackend {
		t.Fatalf("got %v want ErrNoBackend", err)
	}
}

// TestSendFailOpen_NoBackendReturnsSentinel verifies the no-backend path.
func TestSendFailOpen_NoBackendReturnsSentinel(t *testing.T) {
	err := SendFailOpen(context.Background(), Paths{Base: t.TempDir()},
		func(string) string { return "" }, "0.1.0", "darwin", "dial-daemon")
	if err != ErrNoBackend {
		t.Fatalf("got %v want ErrNoBackend", err)
	}
}

// TestSendHeartbeat_NoBackendReturnsSentinel verifies the no-backend path.
func TestSendHeartbeat_NoBackendReturnsSentinel(t *testing.T) {
	err := SendHeartbeat(context.Background(), Paths{Base: t.TempDir()},
		func(string) string { return "" }, "v1.0.0", "v1.1.0", "darwin", true)
	if err != ErrNoBackend {
		t.Fatalf("got %v want ErrNoBackend", err)
	}
}
