// ui/server.go — HTTP server for the agentjail local web UI.
//
// NOT in v0.1.0-alpha release. Local dev tool / demo prop only.
//
// Routes:
//
//	GET  /                       SPA from static/dist, else legacy index.html
//	GET  /events                 Server-Sent Events stream of daemon log lines
//	GET  /api/state              JSON snapshot (sessions + recent events + counters)
//	GET  /api/session            redacted chronological replay or downloadable bundle
//	GET  /api/audit              recent policy-mutation audit events
//	GET  /api/rules              JSON list of all rules with enabled status
//	GET  /api/policy/config      current PolicyConfig as JSON
//	POST /api/policy/config      edit mode only: save PolicyConfig + SIGHUP
//	GET  /api/policy/mcp-tools   server->tools map from audit history
//	POST /api/policy/enable      edit mode only: enable a library rule
//	POST /api/policy/disable     edit mode only: disable a library rule
//	POST /api/policy/reload      edit mode only: send SIGHUP to daemon
//	GET  /api/policy/mcp-scan   full MCP server scan (read-only)
//	GET  /api/policy/projects     list known projects with policy status
//	GET  /api/policy/project-config  read/write project-level policy.yaml
//	GET  /api/network/recent     recent intercepted requests (tunnel + MITM only)
//	GET  /api/network/stats      per-host traffic totals (tunnel + MITM only)
//	GET  /api/network/body       streams one captured body (never inlined in JSON)
package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/claudesess"
	"github.com/LuD1161/agentjail/internal/keyring"
	"github.com/LuD1161/agentjail/internal/mcpclient"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/procutil"
	localstore "github.com/LuD1161/agentjail/internal/store"
	_ "modernc.org/sqlite"
)

// Server is the local web UI HTTP server.
type Server struct {
	addr       string
	logPath    string
	dbPath     string
	editPolicy bool
	version    string

	// trustedHosts allow-lists non-loopback Host/Origin values for the rebinding
	// guard. Empty = loopback only (the default). Dev opt-in via `--trusted-host`
	// for access behind a trusted reverse proxy. See ADR 0092-persist-request-bodies.
	trustedHosts map[string]bool

	store *Store

	// Cached read-only SQLite connection (lazily opened, shared across requests).
	dbMu   sync.Mutex
	dbConn localstore.ReadOnlyStore

	// network.db is a separate database from agentjail.db, so it needs its own
	// handle. Read-only: the UI must never write the transcript store.
	// See ADR 0092-persist-request-bodies (D3).
	netMu sync.Mutex
	// netPath empty means mitm.DefaultDBPath(). Injectable so a test cannot
	// reach the real ~/.agentjail/network.db.
	netPath  string
	netStore *mitm.RequestStore

	// bodyDir empty means mitm.DefaultBodyDir(). Injectable for the same reason
	// as netPath. See ADR 0092-persist-request-bodies (D3).
	bodyDir string
	// bodyKeys nil reads plaintext bodies only; a sealed body then fails with
	// ErrBodyKeyUnavailable rather than streaming ciphertext. Injectable: a
	// test must not reach the real keychain. See ADR 0095-chunked-body-envelope.
	keysOnce sync.Once
	bodyKeys mitm.KeyWrapper

	// SSE broadcaster state.
	subsMu sync.Mutex
	subs   map[chan string]struct{}
}

// RuleInfo is the JSON shape for one rule in GET /api/rules.
type RuleInfo struct {
	Name     string `json:"name"`
	Source   string `json:"source"` // "core" | "library"
	Enabled  bool   `json:"enabled"`
	Editable bool   `json:"editable"`
}

// NewServer constructs (but does not start) the web UI server.
func NewServer(addr, logPath, dbPath string, editPolicy bool, store *Store, version string) *Server {
	return &Server{
		addr:       addr,
		logPath:    logPath,
		dbPath:     dbPath,
		editPolicy: editPolicy,
		version:    version,
		store:      store,
		subs:       make(map[chan string]struct{}),
	}
}

// SetTrustedHosts allow-lists non-loopback hostnames for the rebinding guard.
// Startup-only; empty leaves the guard loopback-only. See ADR 0092-persist-request-bodies.
func (s *Server) SetTrustedHosts(hosts []string) {
	if len(hosts) == 0 {
		return
	}
	m := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			m[h] = true
		}
	}
	s.trustedHosts = m
}

// Start registers handlers, launches the log-tail goroutine, and begins
// serving. It blocks until the server exits.
func (s *Server) Start(
	coreRuleNames func() []string,
	libraryRuleNames func() []string,
	libraryRuleContent func(string) []byte,
) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleSPA)
	mux.HandleFunc("/events", s.handleSSE)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/session", s.handleSession)
	mux.HandleFunc("/api/audit", s.handleAudit)
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		s.handleRules(w, r, coreRuleNames, libraryRuleNames)
	})
	mux.HandleFunc("/api/policy/config", s.handlePolicyConfig)
	mux.HandleFunc("/api/policy/mcp-tools", s.handlePolicyMCPTools)
	mux.HandleFunc("/api/policy/enable", func(w http.ResponseWriter, r *http.Request) {
		s.handlePolicyEnable(w, r, libraryRuleNames, libraryRuleContent)
	})
	mux.HandleFunc("/api/policy/disable", func(w http.ResponseWriter, r *http.Request) {
		s.handlePolicyDisable(w, r, libraryRuleNames)
	})
	mux.HandleFunc("/api/network/recent", s.handleNetworkRecent)
	mux.HandleFunc("/api/network/stats", s.handleNetworkStats)
	mux.HandleFunc("/api/network/body", s.handleNetworkBody)
	mux.HandleFunc("/api/network/sessions", s.handleNetworkSessions)
	mux.HandleFunc("/api/requests", s.handleRequestsList)
	mux.HandleFunc("/api/requests/stream", s.handleRequestsStream)
	mux.HandleFunc("/api/requests/", s.handleRequestDetail)
	mux.HandleFunc("/api/policy/reload", s.handlePolicyReload)
	mux.HandleFunc("/api/policy/mcp-scan", s.handlePolicyMCPScan)
	mux.HandleFunc("/api/policy/mcp-where", s.handlePolicyMCPWhere)
	mux.HandleFunc("/api/policy/mcp-projects", s.handlePolicyMCPProjects)
	mux.HandleFunc("/api/policy/projects", s.handlePolicyProjects)
	mux.HandleFunc("/api/policy/project-config", s.handlePolicyProjectConfig)

	go s.tailLog()

	srv := &http.Server{
		Addr:    s.addr,
		Handler: guardRebinding(mux, s.trustedHosts),
	}
	return srv.ListenAndServe()
}

// guardRebinding rejects any request whose Host or Origin is not loopback.
// The UI is unauthenticated on loopback, so a DNS rebind would let any page
// the user visits read this store. See ADR 0092-persist-request-bodies (D1).
func guardRebinding(next http.Handler, trusted map[string]bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, trusted) {
			http.Error(w, "forbidden: non-loopback Host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !originAllowed(o, trusted) {
			http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostAllowed passes loopback, or a hostname explicitly trusted via --trusted-host.
func hostAllowed(host string, trusted map[string]bool) bool {
	if loopbackHost(host) {
		return true
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return trusted[strings.ToLower(strings.Trim(h, "[]"))]
}

// originAllowed passes a loopback Origin, or one whose host is trusted.
func originAllowed(origin string, trusted map[string]bool) bool {
	if loopbackOrigin(origin) {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return trusted[strings.ToLower(u.Hostname())]
}

// loopbackHost reports whether a Host header names a loopback address.
func loopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// loopbackOrigin reports whether an Origin header names a loopback address.
func loopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return loopbackHost(u.Host)
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

// spaBuilt reports whether `make ui` produced real assets. A clean clone
// embeds only static/dist/.gitkeep, and must still serve a working UI.
func spaBuilt() bool {
	_, err := spaFS.ReadFile("static/dist/index.html")
	return err == nil
}

// handleSPA serves the built SPA, falling back to the legacy UI when dist/ is
// empty. Unmatched non-asset paths get index.html: react-router uses
// BrowserRouter, so /policies and /network are client-side routes.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if !spaBuilt() {
		s.handleIndex(w, r)
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name != "" && name != "." {
		if content, err := spaFS.ReadFile("static/dist/" + name); err == nil {
			if ct := mime.TypeByExtension(filepath.Ext(name)); ct != "" {
				w.Header().Set("Content-Type", ct)
			}
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Write(content)
			return
		}
	}
	content, err := spaFS.ReadFile("static/dist/index.html")
	if err != nil {
		s.handleIndex(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(content)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	content, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	// Inject runtime version into the HTML template.
	v := s.version
	if v == "" {
		v = "dev"
	}
	html := strings.Replace(string(content), "{{VERSION}}", v, 1)
	w.Write([]byte(html))
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Verify the client accepts SSE (optional but polite).
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	fmt.Fprint(w, ":ok\n\n")
	flusher.Flush()

	ch := make(chan string, 64)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()

	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
		// Drain channel so the broadcaster doesn't block.
		for len(ch) > 0 {
			<-ch
		}
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func parseFilterParams(r *http.Request) localstore.Filter {
	q := r.URL.Query()
	var f localstore.Filter
	if a := q.Get("action"); a != "" {
		f.Actions = strings.Split(a, ",")
	}
	f.Tool = q.Get("tool")
	f.Rule = q.Get("rule")
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			f.Limit = n
		}
	}
	return f
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	f := parseFilterParams(r)
	if snap, err := s.sqliteSnapshot(r.Context(), f); err == nil {
		snap.Source = s.sqliteSourceStatus()
		enrichSessions(snap.Sessions)
		writeJSON(w, snap)
		return
	}
	snap := s.store.Snapshot()
	snap.Source = s.logSourceStatus()
	enrichSessions(snap.Sessions)
	writeJSON(w, snap)
}

// enrichSessions joins daemon sessions against Claude's per-process session
// metadata: Name comes from the user's /rename, Active from that process's
// liveness. Agents without such metadata (codex, cursor) fall back to a
// recency window so a currently-deciding session never renders inactive.
func enrichSessions(sessions []*SessionState) {
	byID := claudesess.BySessionID(claudesess.Load())
	for _, ss := range sessions {
		if m, ok := byID[ss.ID]; ok {
			ss.Name = m.Name
			ss.Active = procutil.Alive(m.PID)
			continue
		}
		ss.Active = time.Since(ss.LastSeen) < 2*time.Minute
	}
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	sessionID := r.URL.Query().Get("id")
	if sessionID == "" {
		writeJSONError(w, "missing ?id=", http.StatusBadRequest)
		return
	}
	st, err := s.openSQLite()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("open db: %v", err), http.StatusInternalServerError)
		return
	}
	f := parseFilterParams(r)
	f.SessionID = sessionID
	if f.Limit == 0 {
		f.Limit = 5000
	}
	rows, err := st.ListDecisions(r.Context(), f)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("query session: %v", err), http.StatusInternalServerError)
		return
	}
	response := map[string]any{
		"version":        1,
		"exported_at":    time.Now().UTC(),
		"session_id":     sessionID,
		"source":         s.sqliteSourceStatus(),
		"events":         decisionsToEvalLines(rows, true),
		"filtered_count": len(rows),
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="agentjail-session-%s.json"`, safeFilename(sessionID)))
	}
	writeJSON(w, response)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	st, err := s.openSQLite()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("open db: %v", err), http.StatusServiceUnavailable)
		return
	}
	rows, err := st.ListAuditEvents(r.Context(), localstore.AuditFilter{Limit: 500, OrderDesc: true})
	if err != nil {
		writeJSONError(w, fmt.Sprintf("query audit events: %v", err), http.StatusInternalServerError)
		return
	}
	events := make([]AuditEvent, 0, len(rows))
	for _, row := range rows {
		events = append(events, AuditEvent{
			ID:     row.ID,
			Time:   row.Ts,
			Action: row.Action,
			RuleID: row.RuleID,
			User:   row.User,
		})
	}
	writeJSON(w, map[string]any{"events": events})
}

func (s *Server) handleRules(
	w http.ResponseWriter,
	r *http.Request,
	coreNames func() []string,
	libNames func() []string,
) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rulesDir, err := getRulesDir()
	if err != nil {
		writeJSONError(w, "cannot determine rules dir", http.StatusInternalServerError)
		return
	}

	var rules []RuleInfo
	for _, name := range coreNames() {
		rules = append(rules, RuleInfo{Name: name, Source: "core", Enabled: true})
	}
	for _, name := range libNames() {
		target := filepath.Join(rulesDir, name+".rego")
		_, statErr := os.Stat(target)
		rules = append(rules, RuleInfo{
			Name:     name,
			Source:   "library",
			Enabled:  statErr == nil,
			Editable: s.editPolicy,
		})
	}
	writeJSON(w, rules)
}

func (s *Server) handlePolicyEnable(
	w http.ResponseWriter,
	r *http.Request,
	libNames func() []string,
	libContent func(string) []byte,
) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.editPolicy {
		writeJSONError(w, "policy editing is disabled; restart with --edit-policy", http.StatusForbidden)
		return
	}
	if !checkCSRFOrigin(w, r) {
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		writeJSONError(w, "missing ?name=", http.StatusBadRequest)
		return
	}

	// Validate it's a known library rule.
	known := false
	for _, n := range libNames() {
		if n == name {
			known = true
			break
		}
	}
	if !known {
		writeJSONError(w, fmt.Sprintf("unknown library rule %q", name), http.StatusBadRequest)
		return
	}

	content := libContent(name)
	if content == nil {
		writeJSONError(w, "embedded content missing", http.StatusInternalServerError)
		return
	}

	dir, err := getRulesDir()
	if err != nil {
		writeJSONError(w, "cannot determine rules dir", http.StatusInternalServerError)
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeJSONError(w, fmt.Sprintf("mkdir: %v", err), http.StatusInternalServerError)
		return
	}
	target := filepath.Join(dir, name+".rego")
	if err := os.WriteFile(target, content, 0o640); err != nil {
		writeJSONError(w, fmt.Sprintf("write: %v", err), http.StatusInternalServerError)
		return
	}

	sighupDaemonFn()
	writeJSON(w, map[string]string{"status": "enabled", "name": name})
}

func (s *Server) handlePolicyDisable(
	w http.ResponseWriter,
	r *http.Request,
	libNames func() []string,
) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.editPolicy {
		writeJSONError(w, "policy editing is disabled; restart with --edit-policy", http.StatusForbidden)
		return
	}
	if !checkCSRFOrigin(w, r) {
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		writeJSONError(w, "missing ?name=", http.StatusBadRequest)
		return
	}

	known := false
	for _, n := range libNames() {
		if n == name {
			known = true
			break
		}
	}
	if !known {
		writeJSONError(w, fmt.Sprintf("unknown library rule %q", name), http.StatusBadRequest)
		return
	}

	dir, err := getRulesDir()
	if err != nil {
		writeJSONError(w, "cannot determine rules dir", http.StatusInternalServerError)
		return
	}
	target := filepath.Join(dir, name+".rego")
	if removeErr := os.Remove(target); removeErr != nil && !os.IsNotExist(removeErr) {
		writeJSONError(w, fmt.Sprintf("remove: %v", removeErr), http.StatusInternalServerError)
		return
	}

	sighupDaemonFn()
	writeJSON(w, map[string]string{"status": "disabled", "name": name})
}

func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.editPolicy {
		writeJSONError(w, "policy editing is disabled; restart with --edit-policy", http.StatusForbidden)
		return
	}
	if !checkCSRFOrigin(w, r) {
		return
	}
	sighupDaemonFn()
	writeJSON(w, map[string]string{"status": "sighup_sent"})
}

// policyConfigPath returns ~/.agentjail/policy.yaml.
func policyConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".agentjail", "policy.yaml"), nil
}

// handlePolicyConfig serves GET (read) and POST (write) for the full PolicyConfig.
func (s *Server) handlePolicyConfig(w http.ResponseWriter, r *http.Request) {
	cfgPath, err := policyConfigPath()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("config path: %v", err), http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		cfg, err := config.LoadOrDefault(cfgPath)
		if err != nil {
			writeJSONError(w, fmt.Sprintf("load config: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, cfg)

	case http.MethodPost:
		if !s.editPolicy {
			writeJSONError(w, "policy editing is disabled; restart with --edit-policy", http.StatusForbidden)
			return
		}
		if !checkCSRFJSON(w, r) {
			return
		}
		var cfg config.PolicyConfig
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			writeJSONError(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
		if dec.More() {
			writeJSONError(w, "unexpected trailing data in request body", http.StatusBadRequest)
			return
		}
		// Advisory warnings: returned alongside success, not blocking the save.
		warns := config.Validate(&cfg)
		dir := filepath.Dir(cfgPath)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			writeJSONError(w, fmt.Sprintf("mkdir: %v", err), http.StatusInternalServerError)
			return
		}
		if err := config.Save(&cfg, cfgPath); err != nil {
			writeJSONError(w, fmt.Sprintf("save config: %v", err), http.StatusInternalServerError)
			return
		}
		// TODO(Plan 009 Phase 5): wire two-phase audit here when the UI
		// server gains an EventStore reference (currently read-only).
		sighupDaemonFn()
		resp := map[string]any{"status": "saved"}
		if len(warns) > 0 {
			resp["warnings"] = warns
		}
		writeJSON(w, resp)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// mcpToolEntry is the JSON shape for one tool in the /api/policy/mcp-tools response.
type mcpToolEntry struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"` // "live" or "audit"
}

// mcpServerInfo is the JSON shape for one server in the response.
type mcpServerInfo struct {
	Tools   []mcpToolEntry `json:"tools"`
	Status  string         `json:"status"`  // "connected", "auth_required", "unreachable", "timeout", "audit_only"
	Source  string         `json:"source"`  // "claude", "cursor", "plugin", "audit"
	Scope   string         `json:"scope"`   // "global", "project"
	Trust   string         `json:"trust"`   // "official-marketplace", "third-party-marketplace", "user-installed", "project-local"
	Package string         `json:"package"` // package identifier or binary path
}

// handlePolicyMCPTools returns a map of MCP servers with their tools, merging
// live discovery (tools/list protocol) with tools seen in audit history.
// Each server includes provenance metadata: scope, trust level, and package source.
func (s *Server) handlePolicyMCPTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	result := make(map[string]*mcpServerInfo)

	// Live discovery is opt-in: spawning MCP servers inherits the parent
	// process environment (even after sanitization) and should only run
	// when explicitly requested.
	discover := r.URL.Query().Get("discover") == "true"

	// --- Phase 1: live discovery ---
	if discover {
		home, err := os.UserHomeDir()
		if err == nil {
			entries := mcpclient.DiscoverServersWithConfig(home)
			configs := make([]mcpclient.MCPServerConfig, 0, len(entries))
			metaMap := make(map[string]mcpclient.MCPServerEntry)
			for _, e := range entries {
				configs = append(configs, e.Config)
				metaMap[e.Name] = e
			}

			if len(configs) > 0 {
				live := mcpclient.ListAllTools(r.Context(), configs)
				for name, res := range live {
					meta := metaMap[name]
					info := &mcpServerInfo{
						Status:  res.Status,
						Source:  meta.Source,
						Scope:   meta.Scope,
						Trust:   meta.Trust,
						Package: meta.Package,
					}
					for _, t := range res.Tools {
						info.Tools = append(info.Tools, mcpToolEntry{
							Name:        t.Name,
							Description: t.Description,
							Source:      "live",
						})
					}
					if info.Tools == nil {
						info.Tools = []mcpToolEntry{}
					}
					result[name] = info
				}
			}
		}
	}

	// --- Phase 2: merge audit history ---
	auditTools := s.mcpToolsFromAudit(r.Context())
	for server, tools := range auditTools {
		info, exists := result[server]
		if !exists {
			info = &mcpServerInfo{
				Status: "audit_only",
				Source: "audit",
				Scope:  "unknown",
				Trust:  "unknown",
				Tools:  []mcpToolEntry{},
			}
			result[server] = info
		}
		liveSet := make(map[string]struct{})
		for _, t := range info.Tools {
			liveSet[t.Name] = struct{}{}
		}
		for _, tool := range tools {
			if _, found := liveSet[tool]; !found {
				info.Tools = append(info.Tools, mcpToolEntry{
					Name:   tool,
					Source: "audit",
				})
			}
		}
	}

	writeJSON(w, map[string]any{"servers": result})
}

// mcpToolsFromAudit queries the store for distinct MCP tool names.
func (s *Server) mcpToolsFromAudit(_ context.Context) map[string][]string {
	st, err := s.openSQLite()
	if err != nil {
		return nil
	}
	return mcpclient.AuditToolsFromStore(st)
}

// handlePolicyMCPScan performs a full MCP scan and returns the JSON result.
// This is always read-only, no --edit-policy gate needed.
func (s *Server) handlePolicyMCPScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	home, err := os.UserHomeDir()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("home dir: %v", err), http.StatusInternalServerError)
		return
	}

	st, _ := s.openSQLite()
	result := mcpclient.FullScan(home, st)
	writeJSON(w, result)
}

// handlePolicyMCPWhere returns the reverse index entry for one MCP server.
// GET /api/policy/mcp-where?server=<name>
func (s *Server) handlePolicyMCPWhere(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server := r.URL.Query().Get("server")
	if server == "" {
		writeJSONError(w, "missing ?server= parameter", http.StatusBadRequest)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	home, err := os.UserHomeDir()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("home dir: %v", err), http.StatusInternalServerError)
		return
	}

	st2, _ := s.openSQLite()
	projectDirs := mcpclient.KnownProjectDirs(st2)
	idx := mcpclient.BuildReverseIndex(home, projectDirs)

	entries := idx[server]
	writeJSON(w, map[string]any{
		"server":    server,
		"found":     entries != nil,
		"locations": entries,
	})
}

// handlePolicyMCPProjects returns the full reverse MCP index.
// GET /api/policy/mcp-projects
func (s *Server) handlePolicyMCPProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	home, err := os.UserHomeDir()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("home dir: %v", err), http.StatusInternalServerError)
		return
	}

	st3, _ := s.openSQLite()
	projectDirs := mcpclient.KnownProjectDirs(st3)
	idx := mcpclient.BuildReverseIndex(home, projectDirs)
	writeJSON(w, idx)
}

// projectInfo is the JSON shape for one project in GET /api/policy/projects.
type projectInfo struct {
	Dir        string   `json:"dir"`
	HasPolicy  bool     `json:"hasPolicy"`
	MCPServers []string `json:"mcpServers"`
}

// handlePolicyProjects returns known projects (from session CWDs) with their
// policy status and MCP server names.
func (s *Server) handlePolicyProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	st, err := s.openSQLite()
	if err != nil {
		writeJSON(w, []projectInfo{})
		return
	}

	sessions, err := st.ListSessions(r.Context())
	if err != nil {
		writeJSON(w, []projectInfo{})
		return
	}

	// Collect unique CWDs.
	seen := make(map[string]struct{})
	var dirs []string
	for _, sess := range sessions {
		cwd := sess.CWD
		if cwd == "" {
			continue
		}
		if _, ok := seen[cwd]; ok {
			continue
		}
		seen[cwd] = struct{}{}
		dirs = append(dirs, cwd)
	}

	projects := make([]projectInfo, 0, len(dirs))
	for _, dir := range dirs {
		p := projectInfo{Dir: dir}

		// Check for project-level policy.yaml.
		policyPath := filepath.Join(dir, ".agentjail", "policy.yaml")
		if _, statErr := os.Stat(policyPath); statErr == nil {
			p.HasPolicy = true
		}

		// Read MCP server names from .claude/settings.json.
		entries := mcpclient.DiscoverServersWithConfig("", dir)
		serverSet := make(map[string]struct{})
		for _, e := range entries {
			serverSet[e.Name] = struct{}{}
		}
		for name := range serverSet {
			p.MCPServers = append(p.MCPServers, name)
		}
		if p.MCPServers == nil {
			p.MCPServers = []string{}
		}

		projects = append(projects, p)
	}

	writeJSON(w, projects)
}

// handlePolicyProjectConfig handles GET and POST for a project-level policy.yaml.
func (s *Server) handlePolicyProjectConfig(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		writeJSONError(w, "missing ?dir= parameter", http.StatusBadRequest)
		return
	}

	// Validate that dir is an absolute path and exists.
	if !filepath.IsAbs(dir) {
		writeJSONError(w, "dir must be an absolute path", http.StatusBadRequest)
		return
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		writeJSONError(w, "dir does not exist or is not a directory", http.StatusBadRequest)
		return
	}

	cfgPath := filepath.Join(dir, ".agentjail", "policy.yaml")

	switch r.Method {
	case http.MethodGet:
		cfg, err := config.Load(cfgPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// No project policy; return null to signal inheritance.
				writeJSON(w, nil)
				return
			}
			writeJSONError(w, fmt.Sprintf("load project config: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, cfg)

	case http.MethodPost:
		if !s.editPolicy {
			writeJSONError(w, "policy editing is disabled; restart with --edit-policy", http.StatusForbidden)
			return
		}
		if !checkCSRFJSON(w, r) {
			return
		}
		var cfg config.PolicyConfig
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			writeJSONError(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
		if dec.More() {
			writeJSONError(w, "unexpected trailing data in request body", http.StatusBadRequest)
			return
		}
		warns := config.Validate(&cfg)
		cfgDir := filepath.Dir(cfgPath)
		if err := os.MkdirAll(cfgDir, 0o700); err != nil {
			writeJSONError(w, fmt.Sprintf("mkdir: %v", err), http.StatusInternalServerError)
			return
		}
		if err := config.Save(&cfg, cfgPath); err != nil {
			writeJSONError(w, fmt.Sprintf("save project config: %v", err), http.StatusInternalServerError)
			return
		}
		// TODO(Plan 009 Phase 5): wire two-phase audit for project config saves.
		sighupDaemonFn()
		resp := map[string]any{"status": "saved", "path": cfgPath}
		if len(warns) > 0 {
			resp["warnings"] = warns
		}
		writeJSON(w, resp)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Log tailer + SSE broadcaster
// ---------------------------------------------------------------------------

// tailLog opens the daemon log file and follows it, ingesting new lines into
// the store and broadcasting to SSE subscribers. Never returns (runs as goroutine).
func (s *Server) tailLog() {
	for {
		if err := s.tailOnce(); err != nil {
			// Log file not yet available; retry shortly.
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// tailOnce opens the log file and reads until it is unavailable.
func (s *Server) tailOnce() error {
	f, err := os.Open(s.logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 256*1024)
	var pending []byte

	for {
		chunk, readErr := reader.ReadString('\n')
		if len(chunk) > 0 {
			if len(pending) > 0 {
				chunk = string(pending) + chunk
				pending = pending[:0]
			}
			if readErr == nil {
				line := strings.TrimRight(chunk, "\n")
				s.processLine([]byte(line))
				continue
			}
			pending = append(pending[:0], chunk...)
		}
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		// EOF — sleep briefly and retry (follow mode).
		time.Sleep(100 * time.Millisecond)
	}
}

// processLine ingests one raw log line and broadcasts to SSE subscribers.
func (s *Server) processLine(raw []byte) {
	line, ok := s.store.Ingest(raw)
	if !ok {
		return
	}

	// Serialize the eval line for broadcast.
	b, err := json.Marshal(line)
	if err != nil {
		return
	}
	msg := string(b)

	// Fan out to all connected SSE subscribers. Non-blocking: slow clients
	// are dropped rather than blocking the tail goroutine.
	s.subsMu.Lock()
	for ch := range s.subs {
		select {
		case ch <- msg:
		default:
			// Slow client — skip this event.
		}
	}
	s.subsMu.Unlock()
}

func (s *Server) sqliteSnapshot(ctx context.Context, f localstore.Filter) (StateSnapshot, error) {
	st, err := s.openSQLite()
	if err != nil {
		return StateSnapshot{}, err
	}

	sessions, err := st.ListSessions(ctx)
	if err != nil {
		return StateSnapshot{}, err
	}
	sessionByID := make(map[string]*SessionState, len(sessions))
	snap := StateSnapshot{Sessions: make([]*SessionState, 0, len(sessions))}
	for _, sess := range sessions {
		ss := &SessionState{
			ID:        sess.SessionID,
			Agent:     sess.Agent,
			CWD:       sess.CWD,
			FirstSeen: sess.StartTs,
			LastSeen:  sess.EndTs,
			Total:     sess.DecisionCount,
		}
		if ss.LastSeen.IsZero() {
			ss.LastSeen = sess.StartTs
		}
		if !ss.LastSeen.IsZero() {
			ss.LastEvent = ss.LastSeen.UTC().Format(time.RFC3339)
		}
		if ss.CWD != "" {
			ss.Branch, ss.RepoName = gitInfo(ss.CWD)
		}
		sessionByID[sess.SessionID] = ss
		snap.Sessions = append(snap.Sessions, ss)
	}

	counts, err := st.CountActionsBySession(ctx)
	if err != nil {
		return StateSnapshot{}, err
	}
	for _, ac := range counts {
		ss := sessionByID[ac.SessionID]
		if ss == nil && ac.SessionID != "" {
			ss = &SessionState{ID: ac.SessionID}
			sessionByID[ac.SessionID] = ss
			snap.Sessions = append(snap.Sessions, ss)
		}
		if ss != nil {
			switch ac.Action {
			case "allow":
				ss.Allow += ac.Count
				snap.TotalAllow += ac.Count
			case "deny":
				ss.Deny += ac.Count
				snap.TotalDeny += ac.Count
			case "ask":
				ss.Ask += ac.Count
				snap.TotalAsk += ac.Count
			}
		}
	}

	snap.TotalDecisions = snap.TotalAllow + snap.TotalDeny + snap.TotalAsk

	rf := f
	rf.OrderDesc = true
	if rf.Limit == 0 || rf.Limit > maxEvents {
		rf.Limit = maxEvents
	}
	recent, err := st.ListDecisions(ctx, rf)
	if err != nil {
		return StateSnapshot{}, err
	}
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	snap.RecentEvents = decisionsToEvalLines(recent, false)
	snap.FilteredCount = len(recent)

	// Populate CWD and last event time from recent events for sessions that
	// don't already have them (e.g. sessions only found via CountActionsBySession).
	for _, ev := range recent {
		if ev.SessionID == "" {
			continue
		}
		ss, ok := sessionByID[ev.SessionID]
		if !ok {
			continue
		}
		if ss.CWD == "" && ev.CWD != "" {
			ss.CWD = ev.CWD
		}
		evTime := ev.Ts.UTC().Format(time.RFC3339)
		if ss.LastEvent == "" || evTime > ss.LastEvent {
			ss.LastEvent = evTime
		}
	}

	return snap, nil
}

// openNetworkStore lazily opens network.db read-only. An absent store is the
// normal case (no tunnel has ever run), so callers report 503, not an error.
func (s *Server) openNetworkStore() (*mitm.RequestStore, error) {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.netStore != nil {
		return s.netStore, nil
	}
	path := s.netPath
	if path == "" {
		path = mitm.DefaultDBPath()
	}
	st, err := mitm.OpenReadOnly(path)
	if err != nil {
		return nil, err
	}
	s.netStore = st
	return st, nil
}

// netUnavailableMsg names why the history is empty. An empty Network tab is
// indistinguishable from "no traffic", and silence reads as safety.
const netUnavailableMsg = "no network history yet — requests are recorded only under `agentjail-shield --tunnel` with interception on"

// handleNetworkRecent lists recent intercepted requests, newest first.
func (s *Server) handleNetworkRecent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	st, err := s.openNetworkStore()
	if err != nil {
		writeJSONError(w, netUnavailableMsg, http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	limit := 50
	if l := q.Get("limit"); l != "" {
		if n, perr := strconv.Atoi(l); perr == nil && n > 0 {
			limit = n
		}
	}
	results, err := st.Query(r.Context(), mitm.RequestFilter{
		Host:   q.Get("host"),
		Method: q.Get("method"),
		Limit:  limit,
	})
	if err != nil {
		writeJSONError(w, fmt.Sprintf("query error: %v", err), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []mitm.RequestLog{}
	}
	writeJSON(w, map[string]any{"requests": results, "count": len(results)})
}

// handleNetworkStats returns per-host traffic totals.
func (s *Server) handleNetworkStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	st, err := s.openNetworkStore()
	if err != nil {
		writeJSONError(w, netUnavailableMsg, http.StatusServiceUnavailable)
		return
	}

	var since time.Duration
	if v := r.URL.Query().Get("since"); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil {
			since = d
		}
	}
	stats, err := st.Stats(r.Context(), since)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("stats error: %v", err), http.StatusInternalServerError)
		return
	}
	if stats == nil {
		stats = []mitm.HostStats{}
	}
	total, err := st.Count(r.Context())
	if err != nil {
		writeJSONError(w, fmt.Sprintf("count error: %v", err), http.StatusInternalServerError)
		return
	}
	var totalBytes int64
	for _, h := range stats {
		totalBytes += h.BytesOut + h.BytesIn
	}
	writeJSON(w, map[string]any{
		"hosts":          stats,
		"total_requests": total,
		"total_bytes":    totalBytes,
	})
}

// netQueryCeiling mirrors internal/mitm's own LIMIT ceiling: rows past it are
// unreachable by paging, so it bounds both the page scan and total.
const netQueryCeiling = 10000

// SessionInfo is the JSON shape for one session in GET /api/network/sessions.
// The frontend's types.ts calls it internal/mitm.SessionInfo, which does not
// exist on this branch; the shape below is what the page actually reads.
type SessionInfo struct {
	SessionID    string `json:"session_id"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	RequestCount int64  `json:"request_count"`
	// OwnerPID is the shield process that logged this session's rows; Active is
	// its liveness. The network session id and the daemon session id are
	// different identities, so "active" is keyed on the PID, not a join.
	// See ADR 0100-network-active-pid.
	OwnerPID int  `json:"owner_pid,omitempty"`
	Active   bool `json:"active"`
	// Agent and Cwd label the session (agent binary name, launch directory) so
	// the sidebar can show the agent's logo and repo name instead of the
	// opaque session id. Stamped per-row by the shield; rows written before
	// that existed fall back to a User-Agent sniff in aggregateSessions.
	Agent string `json:"agent,omitempty"`
	Cwd   string `json:"cwd,omitempty"`
	// Name is the user-assigned Claude session name, resolved through the
	// owning shield pid's descendants (see handleNetworkSessions).
	Name string `json:"name,omitempty"`
}

// agentFromUserAgent maps a captured User-Agent header to an agent label for
// rows that predate the per-row agent column. Best-effort, empty on no match.
func agentFromUserAgent(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "claude"):
		return "claude"
	case strings.Contains(l, "codex") || strings.Contains(l, "openai"):
		return "codex"
	case strings.Contains(l, "cursor"):
		return "cursor"
	}
	return ""
}

// aggregateSessions groups request rows into per-session summaries and marks
// each active by the liveness of its owning shield PID (procutil.Alive), not a
// network-recency window. All rows of one session share the PID; the last
// non-zero one wins. See ADR 0100-network-active-pid.
func aggregateSessions(rows []mitm.RequestLog) []SessionInfo {
	byID := map[string]*SessionInfo{}
	order := []string{}
	for _, rl := range rows {
		if rl.SessionID == "" {
			continue
		}
		ts := rl.Ts.UTC().Format(time.RFC3339)
		si, ok := byID[rl.SessionID]
		if !ok {
			si = &SessionInfo{SessionID: rl.SessionID, FirstSeen: ts, LastSeen: ts}
			byID[rl.SessionID] = si
			order = append(order, rl.SessionID)
		}
		si.RequestCount++
		if rl.OwnerPID > 0 {
			si.OwnerPID = rl.OwnerPID
		}
		if rl.Agent != "" {
			si.Agent = rl.Agent
		} else if si.Agent == "" {
			si.Agent = agentFromUserAgent(rl.RequestHeaders["User-Agent"])
		}
		if rl.Cwd != "" {
			si.Cwd = rl.Cwd
		}
		if ts < si.FirstSeen {
			si.FirstSeen = ts
		}
		if ts > si.LastSeen {
			si.LastSeen = ts
		}
	}
	out := make([]SessionInfo, 0, len(order))
	for _, id := range order {
		si := byID[id]
		si.Active = procutil.Alive(si.OwnerPID)
		out = append(out, *si)
	}
	return out
}

// networkRows returns rows matching the SQL-expressible filters. Status,
// policy and session are filtered in Go: RequestFilter cannot express them and
// internal/mitm is not this package's to change.
// unifySessionIDs collapses the two session identities into one: rows the
// shield stamped with their Claude session id are re-keyed to it, so the
// network tab groups, filters, and links on the SAME identifier the monitor
// tab uses (AGE-111). Unstamped rows (a session's first seconds) keep the
// capture id and merge on the next poll.
func unifySessionIDs(rows []mitm.RequestLog) {
	for i := range rows {
		if rows[i].ClaudeSessionID != "" {
			rows[i].SessionID = rows[i].ClaudeSessionID
		}
	}
}

func (s *Server) networkRows(r *http.Request, limit int) ([]mitm.RequestLog, error) {
	st, err := s.openNetworkStore()
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	rows, err := st.Query(r.Context(), mitm.RequestFilter{
		Host:   q.Get("host"),
		Method: q.Get("method"),
		Limit:  limit,
	})
	if err != nil {
		return nil, err
	}
	unifySessionIDs(rows)
	status, policy, session := q.Get("status"), q.Get("policy"), q.Get("session")
	if status == "" && policy == "" && session == "" {
		return rows, nil
	}
	out := rows[:0]
	for _, rl := range rows {
		if status != "" && strconv.Itoa(rl.StatusCode) != status {
			continue
		}
		if policy != "" && rl.PolicyAction != policy {
			continue
		}
		if session != "" && rl.SessionID != session {
			continue
		}
		out = append(out, rl)
	}
	return out, nil
}

// handleRequestsList backs the Network table. The SPA calls /api/requests, not
// /api/network/recent -- the route it wanted 404'd, so the table rendered empty
// against a full database. See ADR 0092-persist-request-bodies.
func (s *Server) handleRequestsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	q := r.URL.Query()
	limit, offset := 50, 0
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
		offset = n
	}
	// Fetch to the store's own ceiling, not offset+limit: total counts the
	// matching set, and a total capped at the page size makes pagination lie.
	rows, err := s.networkRows(r, netQueryCeiling)
	if err != nil {
		writeJSONError(w, netUnavailableMsg, http.StatusServiceUnavailable)
		return
	}
	total := len(rows)
	if offset < len(rows) {
		rows = rows[offset:]
	} else {
		rows = nil
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []mitm.RequestLog{}
	}
	writeJSON(w, map[string]any{"requests": rows, "count": len(rows), "total": total})
}

// handleRequestDetail serves one row. Bodies are referenced by path, never
// inlined: see handleNetworkBody and ADR 0092-persist-request-bodies (D1).
func (s *Server) handleRequestDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	idStr := strings.TrimPrefix(r.URL.Path, "/api/requests/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSONError(w, "bad request id", http.StatusBadRequest)
		return
	}
	st, err := s.openNetworkStore()
	if err != nil {
		writeJSONError(w, netUnavailableMsg, http.StatusServiceUnavailable)
		return
	}
	// No Get(id) on RequestStore; scan the newest page for it.
	rows, err := st.Query(r.Context(), mitm.RequestFilter{Limit: netQueryCeiling})
	if err != nil {
		writeJSONError(w, fmt.Sprintf("query error: %v", err), http.StatusInternalServerError)
		return
	}
	unifySessionIDs(rows)
	for _, rl := range rows {
		if rl.ID == id {
			writeJSON(w, rl)
			return
		}
	}
	http.NotFound(w, r)
}

// handleRequestsStream pushes newly logged rows as SSE. The store has no
// change feed, so this polls; the shield writes network.db from another
// process, which rules out an in-process broadcaster.
func (s *Server) handleRequestsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	st, err := s.openNetworkStore()
	if err != nil {
		writeJSONError(w, netUnavailableMsg, http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	fmt.Fprint(w, ":ok\n\n")
	flusher.Flush()

	// Only rows logged after the client connected: the table loads history via
	// /api/requests, and replaying it here would double every row.
	var lastID int64
	if rows, err := st.Query(r.Context(), mitm.RequestFilter{Limit: 1}); err == nil && len(rows) > 0 {
		lastID = rows[0].ID
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rows, err := st.Query(ctx, mitm.RequestFilter{Limit: defaultStreamPage})
			if err != nil {
				continue
			}
			unifySessionIDs(rows)
			for i := len(rows) - 1; i >= 0; i-- { // Query is newest-first; emit oldest-first.
				if rows[i].ID <= lastID {
					continue
				}
				b, err := json.Marshal(rows[i])
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "data: %s\n\n", b)
				lastID = rows[i].ID
			}
			flusher.Flush()
		}
	}
}

// defaultStreamPage bounds one poll. A burst larger than this catches up on
// the next tick, since lastID only advances over rows actually emitted.
const defaultStreamPage = 200

// handleNetworkSessions aggregates rows per session. The store has no
// Sessions() and internal/mitm is not this package's to change.
func (s *Server) handleNetworkSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	rows, err := s.networkRows(r, netQueryCeiling)
	if err != nil {
		writeJSONError(w, netUnavailableMsg, http.StatusServiceUnavailable)
		return
	}
	out := aggregateSessions(rows)
	// The network store only knows the shield pid, so a live session's
	// user-assigned name resolves through process ancestry (the claude
	// process is the shield's descendant). Dead sessions keep their
	// directory-derived label.
	metas := claudesess.Load()
	byID := claudesess.BySessionID(metas)
	for i := range out {
		// Unified id first (the shield stamped the claude session id onto the
		// rows), ancestry as the pre-stamp fallback for a just-started session.
		if m, ok := byID[out[i].SessionID]; ok {
			out[i].Name = m.Name
			continue
		}
		if out[i].Active {
			out[i].Name = sessionNameByAncestor(metas, out[i].OwnerPID)
		}
	}
	writeJSON(w, map[string]any{"sessions": out, "count": len(out)})
}

// handleNetworkBody streams one captured body. Bodies are unbounded, so they
// stream from here and are never inlined into a JSON detail response.
// See ADR 0092-persist-request-bodies (D1).
func (s *Server) handleNetworkBody(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rel := r.URL.Query().Get("path")
	if rel == "" {
		writeJSONError(w, "missing path parameter", http.StatusBadRequest)
		return
	}

	dir := s.bodyDir
	if dir == "" {
		dir = mitm.DefaultBodyDir()
	}
	if _, err := os.Stat(dir); err != nil {
		http.NotFound(w, r)
		return
	}
	rc, err := mitm.OpenBodyStoreReadOnly(dir, s.keys()).Open(rel)
	// A sealed body with no key is reported, never dribbled out as content.
	// See ADR 0095-chunked-body-envelope.
	if errors.Is(err, mitm.ErrBodyKeyUnavailable) {
		writeJSONError(w, bodyLockedMsg, http.StatusConflict)
		return
	}
	if err != nil {
		writeJSONError(w, "invalid body path", http.StatusBadRequest)
		return
	}
	if rc == nil {
		http.NotFound(w, r)
		return
	}
	defer rc.Close()

	// Sequential only: the body format is chunk-granular, so no Range support.
	w.Header().Set("Accept-Ranges", "none")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, rc)
}

// bodyLockedMsg explains a sealed body this host cannot open, in the terms a
// user can act on. See ADR 0095-chunked-body-envelope.
const bodyLockedMsg = "this body is encrypted and no key for it is available on this machine"

// keys resolves the keyring once. No keychain is not an error: bodies written
// in the clear still stream, sealed ones report ErrBodyKeyUnavailable.
// See ADR 0095-chunked-body-envelope.
func (s *Server) keys() mitm.KeyWrapper {
	s.keysOnce.Do(func() {
		if s.bodyKeys != nil {
			return
		}
		kr, err := keyring.Open()
		if err != nil {
			if !errors.Is(err, keyring.ErrNoKeychain) {
				slog.Warn("ui: keyring unavailable, encrypted bodies will not open", "err", err)
			}
			return
		}
		s.bodyKeys = kr
	})
	return s.bodyKeys
}

func (s *Server) openSQLite() (localstore.ReadOnlyStore, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if s.dbConn != nil {
		return s.dbConn, nil
	}
	if s.dbPath == "" {
		return nil, fmt.Errorf("db path is empty")
	}
	if _, err := os.Stat(s.dbPath); err != nil {
		return nil, err
	}
	conn, err := localstore.OpenReadOnly(s.dbPath)
	if err != nil {
		return nil, err
	}
	s.dbConn = conn
	return conn, nil
}

func decisionsToEvalLines(in []localstore.DecisionRecord, includeToolInput bool) []EvalLine {
	out := make([]EvalLine, 0, len(in))
	for _, d := range in {
		line := EvalLine{
			Time:      d.Ts,
			Level:     "INFO",
			Msg:       "eval",
			Tool:      d.ToolName,
			SessionID: d.SessionID,
			Agent:     d.Agent,
			CWD:       d.CWD,
			Summary:   d.Summary,
			Action:    d.Action,
			RuleID:    d.RuleID,
			Reason:    d.Reason,
			Impact:    d.Impact,
			ElapsedUs: d.ElapsedUs,
		}
		if includeToolInput {
			line.ToolInputRedacted = d.ToolInputRedacted
		}
		out = append(out, line)
	}
	return out
}

// AuditEvent is the stable JSON shape returned by GET /api/audit.
type AuditEvent struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	RuleID string    `json:"rule_id,omitempty"`
	User   string    `json:"user,omitempty"`
}

func (s *Server) sqliteSourceStatus() SourceStatus {
	status := SourceStatus{
		Kind:     "sqlite",
		Path:     s.dbPath,
		LivePath: s.logPath,
	}
	status.ModifiedAt = latestModTime(s.dbPath, s.dbPath+"-wal")
	logModified := latestModTime(s.logPath)
	if !status.ModifiedAt.IsZero() && logModified.After(status.ModifiedAt.Add(5*time.Second)) {
		status.Warning = "SQLite is older than daemon.log; replay data may still be catching up."
	}
	return status
}

func (s *Server) logSourceStatus() SourceStatus {
	return SourceStatus{
		Kind:       "log",
		Path:       s.logPath,
		Fallback:   true,
		Warning:    "SQLite is unavailable; showing legacy daemon.log fallback, which may be stale or incomplete.",
		ModifiedAt: latestModTime(s.logPath),
	}
}

func latestModTime(paths ...string) time.Time {
	var latest time.Time
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest
}

func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "session"
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// checkCSRFJSON rejects cross-origin POST requests that carry a JSON body.
// Requiring application/json Content-Type triggers a CORS preflight in
// browsers, which the server does not allow.  Sec-Fetch-Site further
// confirms same-origin for browser clients; non-browser clients (curl)
// send no header, which is fine.
func checkCSRFJSON(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		writeJSONError(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return checkCSRFOrigin(w, r)
}

// checkCSRFOrigin rejects cross-origin requests using the Sec-Fetch-Site header.
// Non-browser clients (curl, etc.) that send no Sec-Fetch-Site header are allowed.
func checkCSRFOrigin(w http.ResponseWriter, r *http.Request) bool {
	fetchSite := r.Header.Get("Sec-Fetch-Site")
	if fetchSite != "" && fetchSite != "same-origin" {
		writeJSONError(w, "cross-origin requests not allowed", http.StatusForbidden)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeJSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// getRulesDir returns the path to the user's active rules directory.
func getRulesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".agentjail", "rules"), nil
}

// sighupDaemonFn is the function called whenever a policy mutation handler
// wants to trigger a daemon reload.  It is a package-level variable so that
// tests can replace it with a no-op and avoid accidentally signalling
// unrelated processes (e.g. agentjail-daemon.test binaries running
// concurrently under go test ./...).
var sighupDaemonFn = sighupDaemon

// daemonProcessName is the daemon binary's name, as reported by the kernel.
const daemonProcessName = "agentjail-daemon"

// sighupDaemon sends SIGHUP to the agentjail-daemon process if found.
//
// Candidates are verified against their comm: `pgrep -f` matches any process
// whose command LINE contains the pattern (a build, a test binary, an editor),
// and SIGHUP terminates by default, so an unverified match could kill an
// unrelated process. Skips ourselves.
func sighupDaemon() {
	out, err := exec.Command("pgrep", "-f", daemonProcessName).Output()
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, field := range strings.Fields(strings.TrimSpace(string(out))) {
		pid, convErr := strconv.Atoi(field)
		if convErr != nil || pid <= 1 || pid == self {
			continue
		}
		if !procutil.PIDHasComm(pid, daemonProcessName) {
			continue
		}
		proc, findErr := os.FindProcess(pid)
		if findErr != nil {
			return
		}
		_ = proc.Signal(syscall.SIGHUP)
		return
	}
}

// isLoopback reports whether the host part of addr is a loopback address.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost"
	}
	return ip.IsLoopback()
}

// IsLoopback is exported for use by the subcommand entry point.
func IsLoopback(addr string) bool {
	return isLoopback(addr)
}
