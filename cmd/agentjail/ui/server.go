// ui/server.go — HTTP server for the agentjail local web UI.
//
// NOT in v0.1.0-alpha release. Local dev tool / demo prop only.
//
// Routes:
//
//	GET  /                       embedded index.html
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
package ui

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/mcpclient"
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

	store *Store

	// Cached read-only SQLite connection (lazily opened, shared across requests).
	dbMu   sync.Mutex
	dbConn localstore.ReadOnlyStore

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

// Start registers handlers, launches the log-tail goroutine, and begins
// serving. It blocks until the server exits.
func (s *Server) Start(
	coreRuleNames func() []string,
	libraryRuleNames func() []string,
	libraryRuleContent func(string) []byte,
) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleIndex)
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
	mux.HandleFunc("/api/policy/reload", s.handlePolicyReload)
	mux.HandleFunc("/api/policy/mcp-scan", s.handlePolicyMCPScan)
	mux.HandleFunc("/api/policy/mcp-where", s.handlePolicyMCPWhere)
	mux.HandleFunc("/api/policy/mcp-projects", s.handlePolicyMCPProjects)
	mux.HandleFunc("/api/policy/projects", s.handlePolicyProjects)
	mux.HandleFunc("/api/policy/project-config", s.handlePolicyProjectConfig)

	go s.tailLog()

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}
	return srv.ListenAndServe()
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
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
		writeJSON(w, snap)
		return
	}
	snap := s.store.Snapshot()
	snap.Source = s.logSourceStatus()
	writeJSON(w, snap)
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

// mcpToolsFromAudit queries the decisions table for distinct MCP tool names.
func (s *Server) mcpToolsFromAudit(ctx context.Context) map[string][]string {
	if s.dbPath == "" {
		return nil
	}
	db, err := sql.Open("sqlite", fmt.Sprintf(
		"file:%s?mode=ro&_pragma=busy_timeout(3000)",
		strings.NewReplacer("?", "%3f", "#", "%23").Replace(s.dbPath),
	))
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT tool_name FROM decisions WHERE tool_name LIKE 'mcp__%' ORDER BY tool_name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var toolName string
		if err := rows.Scan(&toolName); err != nil {
			continue
		}
		rest := strings.TrimPrefix(toolName, "mcp__")
		idx := strings.Index(rest, "__")
		var server, tool string
		if idx > 0 {
			server = rest[:idx]
			tool = rest[idx+2:]
		} else {
			server = rest
			tool = rest
		}
		result[server] = append(result[server], tool)
	}
	return result
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

	result := mcpclient.FullScan(home, s.dbPath)
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

	projectDirs := mcpclient.KnownProjectDirs(s.dbPath)
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

	projectDirs := mcpclient.KnownProjectDirs(s.dbPath)
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

// sighupDaemon sends SIGHUP to the agentjail-daemon process if found.
func sighupDaemon() {
	out, err := exec.Command("pgrep", "-f", "agentjail-daemon").Output()
	if err != nil {
		return
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return
	}
	parts := strings.Fields(line)
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = proc.Signal(syscall.SIGHUP)
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
