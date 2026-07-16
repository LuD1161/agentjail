package ui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/mitm"
)

// The Network tab reads real rows or it is a decoration. Guards the recovery of
// the orphaned 6ceecc3 tab. See ADR 0092-persist-request-bodies.
func TestNetworkEndpointsServeRealRows(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "network.db")
	st, err := mitm.NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	if err := st.Log(&mitm.RequestLog{
		Ts: time.Now(), Host: "api.anthropic.com", Method: "POST",
		Path: "/v1/messages", URL: "https://api.anthropic.com/v1/messages",
		StatusCode: 200, RequestSize: 1234, ResponseSize: 5678,
		RequestHeaders: map[string]string{"Authorization": "Bearer sk-secret-value"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	st.Close()

	ro, err := mitm.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	s := &Server{netStore: ro}

	rec := httptest.NewRecorder()
	s.handleNetworkRecent(rec, httptest.NewRequest(http.MethodGet, "/api/network/recent", nil))
	if rec.Code != 200 {
		t.Fatalf("recent: got %d, body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Requests []mitm.RequestLog `json:"requests"`
		Count    int               `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Count != 1 || len(got.Requests) != 1 {
		t.Fatalf("count=%d len=%d, want 1/1", got.Count, len(got.Requests))
	}
	r := got.Requests[0]
	if r.Host != "api.anthropic.com" || r.Method != "POST" || r.StatusCode != 200 {
		t.Errorf("row wrong: %+v", r)
	}
	if r.ResponseSize != 5678 {
		t.Errorf("ResponseSize = %d, want 5678", r.ResponseSize)
	}
	// The tab renders headers. A live credential must not reach the browser.
	if v := r.RequestHeaders["Authorization"]; v != "[REDACTED]" {
		t.Errorf("SECURITY: Authorization served as %q, want [REDACTED]", v)
	}

	rec2 := httptest.NewRecorder()
	s.handleNetworkStats(rec2, httptest.NewRequest(http.MethodGet, "/api/network/stats", nil))
	if rec2.Code != 200 {
		t.Fatalf("stats: got %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var stats struct {
		Hosts []mitm.HostStats `json:"hosts"`
		Total int64            `json:"total_requests"`
	}
	json.Unmarshal(rec2.Body.Bytes(), &stats)
	if stats.Total != 1 || len(stats.Hosts) != 1 || stats.Hosts[0].Host != "api.anthropic.com" {
		t.Fatalf("stats wrong: %+v", stats)
	}
	if stats.Hosts[0].BytesIn != 5678 || stats.Hosts[0].BytesOut != 1234 {
		t.Errorf("byte totals wrong: %+v", stats.Hosts[0])
	}
}

// An absent store is normal (no tunnel has run); it must read as "nothing yet".
func TestNetworkEndpointsAbsentStore(t *testing.T) {
	s := &Server{netPath: filepath.Join(t.TempDir(), "does-not-exist.db")}
	rec := httptest.NewRecorder()
	s.handleNetworkRecent(rec, httptest.NewRequest(http.MethodGet, "/api/network/recent", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("absent store: got %d, want 503", rec.Code)
	}
}

// The handler tests above call the funcs directly, which cannot catch an
// unregistered route -- the 404 that a real curl found. This boots Start()'s
// actual mux. Guards the recovery of the orphaned 6ceecc3 tab.
func TestNetworkRoutesAreRegistered(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "network.db")
	st, err := mitm.NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	if err := st.Log(&mitm.RequestLog{
		Ts: time.Now(), Host: "api.anthropic.com", Method: "POST",
		Path: "/v1/messages", URL: "https://api.anthropic.com/v1/messages",
		StatusCode: 200, ResponseSize: 3500,
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	st.Close()

	addr := "127.0.0.1:9247"
	srv := NewServer(addr, filepath.Join(dir, "daemon.log"), filepath.Join(dir, "agentjail.db"), false, NewStore(), "test")
	srv.netPath = dbPath

	go srv.Start(
		func() []string { return nil },
		func() []string { return nil },
		func(string) []byte { return nil },
	)

	base := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := http.Get(base + "/api/network/stats"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	for _, path := range []string{"/api/network/stats", "/api/network/recent?limit=5"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s -> %d (route not registered?), body=%s", path, resp.StatusCode, body)
			continue
		}
		if !strings.Contains(string(body), "api.anthropic.com") {
			t.Errorf("GET %s served no rows: %s", path, body)
		}
	}
}

// The tab's JS reads these exact keys. The original 6ceecc3 tab read count /
// total_request_bytes / total_response_bytes and the handler emitted "stats",
// so the per-host table rendered empty from the day it shipped -- a contract
// nobody could see break. Pin it. See ADR 0092-persist-request-bodies.
func TestNetworkStatsJSONContract(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "network.db")
	st, err := mitm.NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	if err := st.Log(&mitm.RequestLog{
		Ts: time.Now(), Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages",
		URL: "https://api.anthropic.com/v1/messages", StatusCode: 200,
		RequestSize: 1000, ResponseSize: 500, ElapsedMs: 300,
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	st.Close()

	ro, err := mitm.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	s := &Server{netStore: ro}
	rec := httptest.NewRecorder()
	s.handleNetworkStats(rec, httptest.NewRequest(http.MethodGet, "/api/network/stats", nil))

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"hosts", "total_requests", "total_bytes"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("response is missing %q, which renderNetStats reads", k)
		}
	}
	if got := raw["total_requests"]; got != float64(1) {
		t.Errorf("total_requests = %v, want 1", got)
	}
	if got := raw["total_bytes"]; got != float64(1500) {
		t.Errorf("total_bytes = %v, want 1500 (bytes_out+bytes_in)", got)
	}
	hosts, _ := raw["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("hosts len = %d, want 1", len(hosts))
	}
	h, _ := hosts[0].(map[string]any)
	for _, k := range []string{"host", "request_count", "bytes_out", "bytes_in", "avg_latency_ms"} {
		if _, ok := h[k]; !ok {
			t.Errorf("host row is missing %q, which the per-host table reads", k)
		}
	}
	if h["avg_latency_ms"] != float64(300) {
		t.Errorf("avg_latency_ms = %v, want 300", h["avg_latency_ms"])
	}
}
