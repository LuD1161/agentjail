package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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

func TestNetworkStreamDeliversBurstAcrossPages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network.db")
	st, err := mitm.NewRequestStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Log(&mitm.RequestLog{Ts: time.Now(), Host: "example.test", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	ro, err := mitm.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	s := &Server{netStore: ro}
	server := httptest.NewServer(http.HandlerFunc(s.handleRequestsStream))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	if !scanner.Scan() || scanner.Text() != ":ok" {
		t.Fatalf("missing ready frame: %s, %v", scanner.Text(), scanner.Err())
	}
	for n := 0; n < 451; n++ {
		if err := st.Log(&mitm.RequestLog{Ts: time.Now(), Host: "example.test", Method: "GET"}); err != nil {
			t.Fatal(err)
		}
	}
	var received int
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var row mitm.RequestLog
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &row); err != nil {
			t.Fatal(err)
		}
		received++
		if row.ID != int64(received+1) {
			t.Fatalf("received ID %d, want %d", row.ID, received+1)
		}
		if received == 451 {
			return
		}
	}
	t.Fatalf("received only %d rows: %v", received, scanner.Err())
}

func TestNetworkStreamPollIsBoundedAndCatchesUp(t *testing.T) {
	st, err := mitm.NewRequestStore(filepath.Join(t.TempDir(), "network.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const total = defaultStreamPage*maxStreamPages + 51
	for n := 0; n < total; n++ {
		if err := st.Log(&mitm.RequestLog{Ts: time.Now(), Host: "example.test", Method: "GET"}); err != nil {
			t.Fatal(err)
		}
	}
	first := httptest.NewRecorder()
	last, err := streamRequestBatch(context.Background(), st, first, 0)
	if err != nil {
		t.Fatal(err)
	}
	if last != defaultStreamPage*maxStreamPages {
		t.Fatalf("first poll cursor = %d", last)
	}
	if count := strings.Count(first.Body.String(), "data: "); count != defaultStreamPage*maxStreamPages {
		t.Fatalf("first poll rows = %d", count)
	}
	second := httptest.NewRecorder()
	last, err = streamRequestBatch(context.Background(), st, second, last)
	if err != nil || last != total || strings.Count(second.Body.String(), "data: ") != 51 {
		t.Fatalf("catch-up cursor = %d, error = %v", last, err)
	}
}

func TestNetworkHistoryCursorSurvivesNewTraffic(t *testing.T) {
	st, err := mitm.NewRequestStore(filepath.Join(t.TempDir(), "network.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for n := 0; n < 650; n++ {
		if err := st.Log(&mitm.RequestLog{Ts: time.Now(), Host: "example.test", Method: "GET"}); err != nil {
			t.Fatal(err)
		}
	}
	server := &Server{netStore: st}
	type page struct {
		Requests []mitm.RequestLog `json:"requests"`
		More     bool              `json:"has_more"`
	}
	read := func(url string) page {
		t.Helper()
		response := httptest.NewRecorder()
		server.handleRequestsList(response, httptest.NewRequest(http.MethodGet, url, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("response = %d: %s", response.Code, response.Body.String())
		}
		var got page
		if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	first := read("/api/requests?limit=500")
	if len(first.Requests) != 500 || first.Requests[0].ID != 650 || !first.More {
		t.Fatalf("first page length = %d, more = %v", len(first.Requests), first.More)
	}
	if err := st.Log(&mitm.RequestLog{Ts: time.Now(), Host: "example.test", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	second := read("/api/requests?limit=500&before_id=151")
	if len(second.Requests) != 150 || second.More {
		t.Fatalf("second page length = %d, more = %v", len(second.Requests), second.More)
	}
	for n, row := range second.Requests {
		if row.ID != int64(150-n) {
			t.Fatalf("history skipped ID: %d", row.ID)
		}
	}
	for _, cursor := range []string{"-1", "0", "invalid"} {
		response := httptest.NewRecorder()
		server.handleRequestsList(response, httptest.NewRequest(http.MethodGet, "/api/requests?before_id="+cursor, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid cursor %q accepted", cursor)
		}
	}
}

type interruptedStreamReader struct {
	store *mitm.RequestStore
	calls int
	err   error
}

func (r *interruptedStreamReader) Query(ctx context.Context, filter mitm.RequestFilter) ([]mitm.RequestLog, error) {
	r.calls++
	if r.calls == 2 {
		return nil, r.err
	}
	return r.store.Query(ctx, filter)
}

type failedStreamWriter struct{ err error }

func (w failedStreamWriter) Write([]byte) (int, error) { return 0, w.err }

func TestNetworkStreamRetriesQueryFailureFromLastEmittedID(t *testing.T) {
	st, err := mitm.NewRequestStore(filepath.Join(t.TempDir(), "network.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for n := 0; n < 451; n++ {
		if err := st.Log(&mitm.RequestLog{Ts: time.Now(), Host: "example.test", Method: "GET"}); err != nil {
			t.Fatal(err)
		}
	}
	transient := errors.New("temporary read interruption")
	reader := &interruptedStreamReader{store: st, err: transient}
	response := httptest.NewRecorder()
	last, err := streamRequestBatch(context.Background(), reader, response, 0)
	if last != defaultStreamPage || !errors.Is(err, errRequestStreamQuery) || !errors.Is(err, transient) {
		t.Fatalf("interrupted batch cursor = %d, error = %v", last, err)
	}
	last, err = streamRequestBatch(context.Background(), reader, response, last)
	if err != nil || last != 451 {
		t.Fatalf("retry cursor = %d, error = %v", last, err)
	}
	scanner := bufio.NewScanner(response.Body)
	received := 0
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "data: ") {
			continue
		}
		var row mitm.RequestLog
		if err := json.Unmarshal([]byte(strings.TrimPrefix(scanner.Text(), "data: ")), &row); err != nil {
			t.Fatal(err)
		}
		received++
		if row.ID != int64(received) {
			t.Fatalf("out-of-sequence ID %d after %d rows", row.ID, received)
		}
	}
	if scanner.Err() != nil || received != 451 {
		t.Fatalf("received %d rows: %v", received, scanner.Err())
	}
	writeErr := errors.New("client disconnected")
	last, err = streamRequestBatch(context.Background(), st, failedStreamWriter{writeErr}, 0)
	if last != 0 || !errors.Is(err, writeErr) || errors.Is(err, errRequestStreamQuery) {
		t.Fatalf("write failure cursor = %d, error = %v", last, err)
	}
}

func TestNetworkDetailFindsRequestBeyondNewestPage(t *testing.T) {
	st, err := mitm.NewRequestStore(filepath.Join(t.TempDir(), "network.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for n := 0; n < netQueryCeiling+1; n++ {
		if err := st.Log(&mitm.RequestLog{Ts: time.Now(), Host: "example.test", Method: "GET", SessionID: "capture", ClaudeSessionID: "canonical"}); err != nil {
			t.Fatal(err)
		}
	}
	server := &Server{netStore: st}
	response := httptest.NewRecorder()
	server.handleRequestDetail(response, httptest.NewRequest(http.MethodGet, "/api/requests/1", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("old detail status = %d: %s", response.Code, response.Body.String())
	}
	var row mitm.RequestLog
	if err := json.Unmarshal(response.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row.ID != 1 || row.SessionID != "canonical" {
		t.Fatalf("old detail = %+v", row)
	}
	for _, id := range []string{"0", "-1", "invalid"} {
		response := httptest.NewRecorder()
		server.handleRequestDetail(response, httptest.NewRequest(http.MethodGet, "/api/requests/"+id, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid ID %q accepted", id)
		}
	}
	missing := httptest.NewRecorder()
	server.handleRequestDetail(missing, httptest.NewRequest(http.MethodGet, "/api/requests/999999", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing ID status = %d", missing.Code)
	}
}
