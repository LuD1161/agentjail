package ui

import (
	"bytes"
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

// liveServer boots Start()'s real mux. Calling handlers directly cannot catch
// an unregistered route or a missing middleware -- both shipped broken once.
func liveServer(t *testing.T, addr string, tune func(*Server)) string {
	t.Helper()
	dir := t.TempDir()
	srv := NewServer(addr, filepath.Join(dir, "daemon.log"), filepath.Join(dir, "agentjail.db"), false, NewStore(), "test")
	if tune != nil {
		tune(srv)
	}
	go srv.Start(
		func() []string { return nil },
		func() []string { return nil },
		func(string) []byte { return nil },
	)
	base := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := http.Get(base + "/"); err == nil {
			return base
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s never came up", addr)
	return ""
}

// get issues a request through the real mux with an explicit Host/Origin.
func get(t *testing.T, url, host, origin string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

// The root must render a UI whether or not `make ui` has run. A clean clone
// embeds only static/dist/.gitkeep and served a blank page before this.
func TestSPARootServesAUIEitherWay(t *testing.T) {
	base := liveServer(t, "127.0.0.1:9251", nil)
	resp, body := get(t, base+"/", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / -> %d, want 200; body=%s", resp.StatusCode, body)
	}
	if len(body) == 0 {
		t.Fatal("GET / served an empty page")
	}
	if spaBuilt() {
		if !bytes.Contains(body, []byte(`id="root"`)) {
			t.Errorf("dist/ is built but / did not serve the SPA shell: %.200s", body)
		}
	} else if !bytes.Contains(body, []byte("<html")) {
		t.Errorf("dist/ is empty; / must serve the legacy UI, got: %.200s", body)
	}
}

// react-router uses BrowserRouter, so /policies and /network are client-side
// routes: the server must answer them with index.html, not 404.
func TestSPADeepLinksServeIndex(t *testing.T) {
	if !spaBuilt() {
		t.Skip("dist/ not built; deep-link routing is an SPA-only contract")
	}
	base := liveServer(t, "127.0.0.1:9252", nil)
	_, root := get(t, base+"/", "", "")
	for _, p := range []string{"/policies", "/network"} {
		resp, body := get(t, base+p, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s -> %d, want 200 (client-side route)", p, resp.StatusCode)
			continue
		}
		if !bytes.Equal(body, root) {
			t.Errorf("GET %s did not serve index.html", p)
		}
	}
}

// An unknown /api/ path must 404, not fall through to the SPA shell -- a JSON
// client that gets HTML back reports a parse error, not a missing route.
func TestUnknownAPIRouteIs404(t *testing.T) {
	base := liveServer(t, "127.0.0.1:9253", nil)
	resp, body := get(t, base+"/api/nope", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /api/nope -> %d, want 404; body=%.120s", resp.StatusCode, body)
	}
}

// writeBody stores a body through the real capture path and returns its
// relative path.
func writeBody(t *testing.T, dir, session string, content []byte, keys mitm.KeyWrapper) string {
	t.Helper()
	bs, err := mitm.NewBodyStore(dir, session, keys)
	if err != nil {
		t.Fatalf("NewBodyStore: %v", err)
	}
	c, err := bs.Create(mitm.SideResponse, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := c.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	rel, _, err := bs.Finish(c)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return rel
}

// A captured body must stream back byte-identical. Bodies are unbounded, so
// this is the only path that may carry them. See ADR 0092 (D1).
func TestBodyStreamsByteIdentical(t *testing.T) {
	dir := t.TempDir()
	want := bytes.Repeat([]byte("payload-\x00\xffbytes"), 5000)
	rel := writeBody(t, dir, "abc123", want, nil)

	base := liveServer(t, "127.0.0.1:9254", func(s *Server) { s.bodyDir = dir })
	resp, got := get(t, base+"/api/network/body?path="+rel, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("body -> %d, want 200; %s", resp.StatusCode, got)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body not byte-identical: got %d bytes, want %d", len(got), len(want))
	}
	// Range is not supported: the format is chunk-granular. See ADR 0092.
	if ar := resp.Header.Get("Accept-Ranges"); ar != "none" {
		t.Errorf("Accept-Ranges = %q, want \"none\"", ar)
	}
}

// A row can outlive its body file. Absent is not an error -- never a 500.
func TestMissingBodyIsAbsentNotError(t *testing.T) {
	dir := t.TempDir()
	writeBody(t, dir, "abc123", []byte("x"), nil) // realise the session dir
	base := liveServer(t, "127.0.0.1:9255", func(s *Server) { s.bodyDir = dir })

	for _, tc := range []struct{ name, path string }{
		{"missing file", "abc123/deadbeef.body"},
		{"missing session", "nosuchsession/deadbeef.body"},
	} {
		resp, body := get(t, base+"/api/network/body?path="+tc.path, "", "")
		if resp.StatusCode >= 500 {
			t.Errorf("%s -> %d (must never 500); body=%.120s", tc.name, resp.StatusCode, body)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s -> %d, want 404", tc.name, resp.StatusCode)
		}
	}
}

// A body must never be inlined into a JSON detail response: that reintroduces
// the OOM bodies are streamed to avoid. Decode into map[string]any -- decoding
// into the struct is what hid a renamed tag for months. See ADR 0092 (D1).
func TestBodyNeverInlinedInRecentJSON(t *testing.T) {
	dir := t.TempDir()
	secret := "SENTINEL-BODY-CONTENT-NOT-FOR-JSON"
	rel := writeBody(t, dir, "abc123", []byte(secret), nil)

	dbPath := filepath.Join(t.TempDir(), "network.db")
	st, err := mitm.NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	if err := st.Log(&mitm.RequestLog{
		Ts: time.Now(), Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages",
		URL: "https://api.anthropic.com/v1/messages", StatusCode: 200,
		RequestBodyPath: rel, ResponseBodyPath: rel,
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	st.Close()
	ro, err := mitm.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}

	s := &Server{netStore: ro, bodyDir: dir}
	rec := httptest.NewRecorder()
	s.handleNetworkRecent(rec, httptest.NewRequest(http.MethodGet, "/api/network/recent", nil))
	if rec.Code != 200 {
		t.Fatalf("recent -> %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("SECURITY: body content was inlined into /api/network/recent JSON")
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	reqs, _ := raw["requests"].([]any)
	if len(reqs) != 1 {
		t.Fatalf("requests len = %d, want 1", len(reqs))
	}
	row, _ := reqs[0].(map[string]any)
	// Metadata carries presence; bytes come from /api/network/body.
	for _, k := range []string{"request_body_path", "response_body_path"} {
		if got, ok := row[k]; !ok || got != rel {
			t.Errorf("row[%q] = %v (ok=%v), want %q", k, got, ok, rel)
		}
	}
	for k, v := range row {
		if s, ok := v.(string); ok && strings.Contains(s, secret) {
			t.Errorf("SECURITY: key %q carries body content", k)
		}
	}
}

// The UI is unauthenticated on loopback, so any page the user visits could
// read it via DNS rebinding. Host and Origin are the only things standing
// between a captured body and the open web. See ADR 0092 (D1).
func TestRebindingGuardRejectsNonLoopbackHostAndOrigin(t *testing.T) {
	dir := t.TempDir()
	rel := writeBody(t, dir, "abc123", []byte("secret-body"), nil)
	base := liveServer(t, "127.0.0.1:9256", func(s *Server) { s.bodyDir = dir })
	bodyURL := base + "/api/network/body?path=" + rel

	rejected := []struct{ name, host, origin string }{
		{"rebound host", "evil.com", ""},
		{"rebound host with port", "evil.com:9256", ""},
		{"public ip host", "93.184.216.34:9256", ""},
		{"cross-origin", "127.0.0.1:9256", "http://evil.com"},
		{"cross-origin https", "127.0.0.1:9256", "https://evil.com"},
	}
	for _, tc := range rejected {
		resp, body := get(t, bodyURL, tc.host, tc.origin)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: Host=%q Origin=%q -> %d, want 403", tc.name, tc.host, tc.origin, resp.StatusCode)
		}
		if bytes.Contains(body, []byte("secret-body")) {
			t.Errorf("SECURITY: %s leaked the body", tc.name)
		}
	}

	allowed := []struct{ name, host, origin string }{
		{"loopback ip", "127.0.0.1:9256", ""},
		{"localhost", "localhost:9256", ""},
		{"same origin", "127.0.0.1:9256", "http://127.0.0.1:9256"},
	}
	for _, tc := range allowed {
		resp, body := get(t, bodyURL, tc.host, tc.origin)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: Host=%q Origin=%q -> %d, want 200", tc.name, tc.host, tc.origin, resp.StatusCode)
			continue
		}
		if !bytes.Equal(body, []byte("secret-body")) {
			t.Errorf("%s: body = %q", tc.name, body)
		}
	}
}

// The guard protects every route, not just bodies: /api/network/recent is a
// source-code exfil channel too.
func TestRebindingGuardCoversAllRoutes(t *testing.T) {
	base := liveServer(t, "127.0.0.1:9257", nil)
	for _, p := range []string{"/", "/api/state", "/api/network/recent", "/api/network/stats"} {
		resp, _ := get(t, base+p, "evil.com", "")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s with Host: evil.com -> %d, want 403", p, resp.StatusCode)
		}
	}
}

// seedRows logs n rows and returns a read-only store over them.
func seedRows(t *testing.T, rows ...mitm.RequestLog) *mitm.RequestStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "network.db")
	st, err := mitm.NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	for i := range rows {
		if err := st.Log(&rows[i]); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	st.Close()
	ro, err := mitm.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	return ro
}

// The SPA calls /api/requests and reads these exact keys. It called a route
// that did not exist on this branch, so the table rendered empty against a
// full database -- the third instance of this bug class. Decode into
// map[string]any: decoding into the struct is what hides a renamed tag.
func TestRequestsListJSONContract(t *testing.T) {
	ro := seedRows(t, mitm.RequestLog{
		Ts: time.Now(), Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages",
		URL: "https://api.anthropic.com/v1/messages", StatusCode: 200,
		RequestSize: 1000, ResponseSize: 500, ElapsedMs: 300,
		PolicyAction: "allow", SessionID: "sess01",
		RequestHeaders: map[string]string{"Authorization": "Bearer sk-secret-value"},
	})
	s := &Server{netStore: ro}
	rec := httptest.NewRecorder()
	s.handleRequestsList(rec, httptest.NewRequest(http.MethodGet, "/api/requests?limit=50&offset=0", nil))
	if rec.Code != 200 {
		t.Fatalf("list -> %d: %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"requests", "count", "total"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("response is missing %q, which lib/api.ts reads", k)
		}
	}
	reqs, _ := raw["requests"].([]any)
	if len(reqs) != 1 {
		t.Fatalf("requests len = %d, want 1", len(reqs))
	}
	row, _ := reqs[0].(map[string]any)
	// Every key the Network table's columns render.
	for _, k := range []string{"id", "ts", "host", "method", "path", "url", "status_code", "response_size", "elapsed_ms", "policy_action"} {
		if _, ok := row[k]; !ok {
			t.Errorf("row is missing %q, which the table renders", k)
		}
	}
	if row["status_code"] != float64(200) {
		t.Errorf("status_code = %v, want 200 (the tab once read req.status and showed --)", row["status_code"])
	}
	// A live credential must not reach the browser on this route either.
	hdrs, _ := row["request_headers"].(map[string]any)
	if v := hdrs["Authorization"]; v != "[REDACTED]" {
		t.Errorf("SECURITY: Authorization served as %v, want [REDACTED]", v)
	}
	// Bodies stream from /api/network/body; they are never inlined here.
	for _, k := range []string{"request_body", "response_body"} {
		if _, ok := row[k]; ok {
			t.Errorf("row inlines %q -- bodies are unbounded and must stream. See ADR 0092 (D1)", k)
		}
	}
}

// total must count the matching set. A total capped at the page size makes
// "Page 1 of 1" render over a database with more rows.
func TestRequestsListPaginationTotal(t *testing.T) {
	var rows []mitm.RequestLog
	for i := 0; i < 5; i++ {
		rows = append(rows, mitm.RequestLog{
			Ts: time.Now(), Host: "h.example", Method: "GET",
			Path: "/p", URL: "https://h.example/p", StatusCode: 200,
		})
	}
	s := &Server{netStore: seedRows(t, rows...)}
	rec := httptest.NewRecorder()
	s.handleRequestsList(rec, httptest.NewRequest(http.MethodGet, "/api/requests?limit=2&offset=0", nil))
	var raw map[string]any
	json.Unmarshal(rec.Body.Bytes(), &raw)
	if raw["count"] != float64(2) {
		t.Errorf("count = %v, want 2 (the page)", raw["count"])
	}
	if raw["total"] != float64(5) {
		t.Errorf("total = %v, want 5 (the matching set, not the page)", raw["total"])
	}
	rec2 := httptest.NewRecorder()
	s.handleRequestsList(rec2, httptest.NewRequest(http.MethodGet, "/api/requests?limit=2&offset=4", nil))
	var raw2 map[string]any
	json.Unmarshal(rec2.Body.Bytes(), &raw2)
	if raw2["count"] != float64(1) {
		t.Errorf("offset=4 count = %v, want 1", raw2["count"])
	}
}

// The sessions sidebar reads these exact keys.
func TestNetworkSessionsJSONContract(t *testing.T) {
	s := &Server{netStore: seedRows(t,
		mitm.RequestLog{Ts: time.Now(), Host: "h.example", Method: "GET", Path: "/a", URL: "https://h.example/a", SessionID: "sess01"},
		mitm.RequestLog{Ts: time.Now(), Host: "h.example", Method: "GET", Path: "/b", URL: "https://h.example/b", SessionID: "sess01"},
	)}
	rec := httptest.NewRecorder()
	s.handleNetworkSessions(rec, httptest.NewRequest(http.MethodGet, "/api/network/sessions", nil))
	if rec.Code != 200 {
		t.Fatalf("sessions -> %d: %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"sessions", "count"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("response is missing %q", k)
		}
	}
	sessions, _ := raw["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1", len(sessions))
	}
	si, _ := sessions[0].(map[string]any)
	for _, k := range []string{"session_id", "first_seen", "last_seen", "request_count"} {
		if _, ok := si[k]; !ok {
			t.Errorf("session is missing %q, which the sidebar reads", k)
		}
	}
	if si["request_count"] != float64(2) {
		t.Errorf("request_count = %v, want 2", si["request_count"])
	}
}

// The detail route backs the request/response panel.
func TestRequestDetailServesOneRow(t *testing.T) {
	s := &Server{netStore: seedRows(t, mitm.RequestLog{
		Ts: time.Now(), Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages",
		URL: "https://api.anthropic.com/v1/messages", StatusCode: 200,
		RequestHeaders: map[string]string{"Authorization": "Bearer sk-secret-value"},
	})}
	rec := httptest.NewRecorder()
	s.handleRequestDetail(rec, httptest.NewRequest(http.MethodGet, "/api/requests/1", nil))
	if rec.Code != 200 {
		t.Fatalf("detail -> %d: %s", rec.Code, rec.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &row); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if row["id"] != float64(1) || row["host"] != "api.anthropic.com" {
		t.Errorf("wrong row: %v", row)
	}
	hdrs, _ := row["request_headers"].(map[string]any)
	if v := hdrs["Authorization"]; v != "[REDACTED]" {
		t.Errorf("SECURITY: Authorization served as %v, want [REDACTED]", v)
	}

	rec2 := httptest.NewRecorder()
	s.handleRequestDetail(rec2, httptest.NewRequest(http.MethodGet, "/api/requests/999", nil))
	if rec2.Code != http.StatusNotFound {
		t.Errorf("missing row -> %d, want 404", rec2.Code)
	}
}

// The SPA's data routes must be registered on the real mux. /api/requests
// 404'd through Start()'s mux while the handler existed and passed its tests.
func TestSPADataRoutesAreRegistered(t *testing.T) {
	ro := seedRows(t, mitm.RequestLog{
		Ts: time.Now(), Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages",
		URL: "https://api.anthropic.com/v1/messages", StatusCode: 200, SessionID: "sess01",
	})
	base := liveServer(t, "127.0.0.1:9258", func(s *Server) { s.netStore = ro })
	for _, p := range []string{"/api/requests?limit=5&offset=0", "/api/requests/1", "/api/network/sessions"} {
		resp, body := get(t, base+p, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s -> %d (route not registered?), body=%.120s", p, resp.StatusCode, body)
			continue
		}
		if !bytes.Contains(body, []byte("api.anthropic.com")) && !bytes.Contains(body, []byte("sess01")) {
			t.Errorf("GET %s served no rows: %.120s", p, body)
		}
	}
}
