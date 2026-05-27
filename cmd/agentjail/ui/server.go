// ui/server.go — HTTP server for the agentjail local web UI.
//
// NOT in v0.1.0-alpha release. Local dev tool / demo prop only.
//
// Routes:
//   GET  /                       embedded index.html
//   GET  /events                 Server-Sent Events stream of daemon log lines
//   GET  /api/state              JSON snapshot (sessions + recent events + counters)
//   GET  /api/rules              JSON list of all rules with enabled status
//   POST /api/policy/enable      ?name=<rule>  enable a library rule
//   POST /api/policy/disable     ?name=<rule>  disable a library rule
//   POST /api/policy/reload      send SIGHUP to daemon
package ui

import (
	"bufio"
	"encoding/json"
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
)

// Server is the local web UI HTTP server.
type Server struct {
	addr    string
	logPath string

	store *Store

	// SSE broadcaster state.
	subsMu sync.Mutex
	subs   map[chan string]struct{}
}

// RuleInfo is the JSON shape for one rule in GET /api/rules.
type RuleInfo struct {
	Name    string `json:"name"`
	Source  string `json:"source"` // "core" | "library"
	Enabled bool   `json:"enabled"`
}

// NewServer constructs (but does not start) the web UI server.
func NewServer(addr, logPath string, store *Store) *Server {
	return &Server{
		addr:    addr,
		logPath: logPath,
		store:   store,
		subs:    make(map[chan string]struct{}),
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
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		s.handleRules(w, r, coreRuleNames, libraryRuleNames)
	})
	mux.HandleFunc("/api/policy/enable", func(w http.ResponseWriter, r *http.Request) {
		s.handlePolicyEnable(w, r, libraryRuleNames, libraryRuleContent)
	})
	mux.HandleFunc("/api/policy/disable", func(w http.ResponseWriter, r *http.Request) {
		s.handlePolicyDisable(w, r, libraryRuleNames)
	})
	mux.HandleFunc("/api/policy/reload", s.handlePolicyReload)

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
	w.Write(content)
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

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := s.store.Snapshot()
	writeJSON(w, snap)
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
			Name:    name,
			Source:  "library",
			Enabled: statErr == nil,
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

	sighupDaemon()
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

	sighupDaemon()
	writeJSON(w, map[string]string{"status": "disabled", "name": name})
}

func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sighupDaemon()
	writeJSON(w, map[string]string{"status": "sighup_sent"})
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
