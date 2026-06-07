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
