// Package mcpclient provides a minimal MCP (Model Context Protocol) client
// that can connect to stdio and HTTP MCP servers to enumerate their tools.
package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// MCPServerConfig holds the connection parameters for a single MCP server.
type MCPServerConfig struct {
	Name    string            // human-readable server name
	Type    string            // "stdio" or "http"
	Command string            // for stdio: path to executable
	Args    []string          // for stdio: command arguments
	Env     map[string]string // for stdio: extra environment variables
	URL     string            // for http: endpoint URL
	Headers map[string]string // for http: extra headers (auth tokens, etc.)
}

// ToolInfo describes a single tool exposed by an MCP server.
type ToolInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ErrAuthRequired is returned when an HTTP MCP server responds with 401/403.
var ErrAuthRequired = errors.New("mcpclient: authentication required")

// ErrTimeout is returned when a server does not respond within the deadline.
var ErrTimeout = errors.New("mcpclient: server timed out")

// sensitiveEnvVars is the set of environment variable names stripped before
// spawning MCP server processes during discovery.
var sensitiveEnvVars = []string{
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
	"GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
	"ANTHROPIC_API_KEY", "OPENAI_API_KEY",
	"PGPASSWORD", "DATABASE_URL",
	"HOMEBREW_GITHUB_API_TOKEN",
}

// sanitizedEnv returns a copy of the current process environment with
// sensitive credential variables removed.
func sanitizedEnv() []string {
	env := os.Environ()
	clean := make([]string, 0, len(env))
	for _, e := range env {
		skip := false
		for _, s := range sensitiveEnvVars {
			if strings.HasPrefix(e, s+"=") {
				skip = true
				break
			}
		}
		if !skip {
			clean = append(clean, e)
		}
	}
	return clean
}

// ListTools connects to the MCP server described by cfg and returns its
// available tools. The context should carry a deadline; if none is set, a
// 5-second timeout is applied automatically.
func ListTools(ctx context.Context, cfg MCPServerConfig) ([]ToolInfo, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	switch cfg.Type {
	case "stdio", "":
		return listToolsStdio(ctx, cfg)
	case "http", "sse":
		return listToolsHTTP(ctx, cfg)
	default:
		return nil, fmt.Errorf("mcpclient: unsupported server type %q", cfg.Type)
	}
}

// --------------------------------------------------------------------------
// stdio transport
// --------------------------------------------------------------------------

// scanResult is a single line read from the MCP server's stdout.
type scanResult struct {
	line []byte
	ok   bool
	err  error
}

func listToolsStdio(ctx context.Context, cfg MCPServerConfig) ([]ToolInfo, error) {
	cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)

	// Security: strip sensitive environment variables before spawning MCP
	// server processes.  Discovery runs outside the agent sandbox, so we
	// must not leak ambient credentials to third-party server binaries.
	cmd.Env = sanitizedEnv()

	// Apply server-specific env overrides on top of the sanitized env.
	for k, v := range cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcpclient: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcpclient: stdout pipe: %w", err)
	}
	// Discard stderr so noisy servers don't block.
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcpclient: start %q: %w", cfg.Command, err)
	}

	// Ensure the process is cleaned up no matter what.
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	// Single scanner goroutine feeding a shared channel. This avoids the bug
	// where multiple readResponse calls each spawn their own goroutine and
	// race over scanner.Scan().  The goroutine checks ctx.Done() so it can
	// exit early if the caller returns before stdout closes.
	lineCh := make(chan scanResult, 4)
	done := ctx.Done()
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
		for {
			ok := scanner.Scan()
			sr := scanResult{
				line: append([]byte(nil), scanner.Bytes()...),
				ok:   ok,
				err:  scanner.Err(),
			}
			select {
			case lineCh <- sr:
			case <-done:
				close(lineCh)
				return
			}
			if !ok {
				close(lineCh)
				return
			}
		}
	}()

	// Step 1: send initialize
	initReq := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		ID:      1,
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]string{
				"name":    "agentjail",
				"version": "0.1",
			},
		},
	}
	if err := writeJSONLine(stdin, initReq); err != nil {
		return nil, fmt.Errorf("mcpclient: write initialize: %w", err)
	}

	// Read initialize response.
	if _, err := readResponseFromCh(ctx, lineCh, 1); err != nil {
		return nil, fmt.Errorf("mcpclient: initialize response: %w", err)
	}

	// Step 2: send notifications/initialized (no id, no response expected).
	notif := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
		Params:  map[string]any{},
	}
	if err := writeJSONLine(stdin, notif); err != nil {
		return nil, fmt.Errorf("mcpclient: write initialized notification: %w", err)
	}

	// Step 3: send tools/list
	toolsReq := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      2,
		Params:  map[string]any{},
	}
	if err := writeJSONLine(stdin, toolsReq); err != nil {
		return nil, fmt.Errorf("mcpclient: write tools/list: %w", err)
	}

	// Read tools/list response.
	resp, err := readResponseFromCh(ctx, lineCh, 2)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: tools/list response: %w", err)
	}

	return parseToolsResult(resp)
}

// --------------------------------------------------------------------------
// HTTP transport
// --------------------------------------------------------------------------

func listToolsHTTP(ctx context.Context, cfg MCPServerConfig) ([]ToolInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	// Helper to POST a JSON-RPC request and read the response body.
	doRequest := func(req jsonRPCRequest) (json.RawMessage, error) {
		body, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, "POST", cfg.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		for k, v := range cfg.Headers {
			httpReq.Header.Set(k, v)
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ErrTimeout
			}
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, ErrAuthRequired
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("mcpclient: HTTP %d", resp.StatusCode)
		}

		data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB max
		if err != nil {
			return nil, err
		}
		return json.RawMessage(data), nil
	}

	// Step 1: initialize
	initReq := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		ID:      1,
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]string{
				"name":    "agentjail",
				"version": "0.1",
			},
		},
	}
	if _, err := doRequest(initReq); err != nil {
		return nil, fmt.Errorf("mcpclient: HTTP initialize: %w", err)
	}

	// Step 2: notifications/initialized (fire and forget).
	notif := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
		Params:  map[string]any{},
	}
	_, _ = doRequest(notif) // best effort

	// Step 3: tools/list
	toolsReq := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      2,
		Params:  map[string]any{},
	}
	resp, err := doRequest(toolsReq)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: HTTP tools/list: %w", err)
	}

	return parseToolsResult(resp)
}

// --------------------------------------------------------------------------
// JSON-RPC helpers
// --------------------------------------------------------------------------

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	ID      any    `json:"id,omitempty"`
	Params  any    `json:"params,omitempty"`
}

func writeJSONLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// readResponseFromCh reads lines from a shared channel until it finds a
// JSON-RPC response with the given id. It skips notifications (messages
// without an id). Respects ctx cancellation.
func readResponseFromCh(ctx context.Context, lineCh <-chan scanResult, wantID int) (json.RawMessage, error) {
	type rpcMsg struct {
		ID     any             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ErrTimeout
		case sr, ok := <-lineCh:
			if !ok || !sr.ok {
				if sr.err != nil {
					return nil, sr.err
				}
				return nil, io.ErrUnexpectedEOF
			}

			if len(sr.line) == 0 {
				continue
			}

			var msg rpcMsg
			if err := json.Unmarshal(sr.line, &msg); err != nil {
				continue // skip non-JSON lines
			}

			// Skip notifications (no id).
			if msg.ID == nil {
				continue
			}

			// Check if the id matches (JSON numbers decode as float64).
			var msgID int
			switch v := msg.ID.(type) {
			case float64:
				msgID = int(v)
			default:
				continue
			}

			if msgID != wantID {
				continue
			}

			if msg.Error != nil {
				return nil, fmt.Errorf("mcpclient: server error: %s", string(msg.Error))
			}

			return sr.line, nil
		}
	}
}

// parseToolsResult extracts []ToolInfo from a tools/list JSON-RPC response.
func parseToolsResult(raw json.RawMessage) ([]ToolInfo, error) {
	var envelope struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("mcpclient: parse tools: %w", err)
	}

	tools := make([]ToolInfo, 0, len(envelope.Result.Tools))
	for _, t := range envelope.Result.Tools {
		tools = append(tools, ToolInfo{
			Name:        t.Name,
			Description: t.Description,
		})
	}
	return tools, nil
}

// --------------------------------------------------------------------------
// Cached concurrent discovery
// --------------------------------------------------------------------------

// cachedResult holds a cached tool listing for one server.
type cachedResult struct {
	Tools  []ToolInfo
	Status string // "connected", "auth_required", "unreachable", "timeout"
}

var (
	cacheMu          sync.Mutex
	cacheData        map[string]cachedResult
	cacheStamp       time.Time
	cacheFingerprint string
	cacheTTL         = 60 * time.Second
)

// configFingerprint builds a deterministic string from the server list so the
// cache can be invalidated when the configured servers change.  It includes
// Args, Env, and Headers so that changes to these fields also bust the cache.
func configFingerprint(servers []MCPServerConfig) string {
	var parts []string
	for _, s := range servers {
		part := s.Name + "|" + s.Type + "|" + s.Command + "|" + s.URL
		part += "|args:" + strings.Join(s.Args, ",")
		// Sort env keys for determinism.
		var envKeys []string
		for k := range s.Env {
			envKeys = append(envKeys, k)
		}
		sort.Strings(envKeys)
		for _, k := range envKeys {
			part += "|env:" + k + "=" + s.Env[k]
		}
		// Sort header keys for determinism.
		var hdrKeys []string
		for k := range s.Headers {
			hdrKeys = append(hdrKeys, k)
		}
		sort.Strings(hdrKeys)
		for _, k := range hdrKeys {
			part += "|hdr:" + k + "=" + s.Headers[k]
		}
		parts = append(parts, part)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// ServerToolResult is the external result for one server after live discovery.
type ServerToolResult struct {
	Tools  []ToolInfo
	Status string // "connected", "auth_required", "unreachable", "timeout"
}

// ListAllTools connects to all provided servers concurrently, returning a map
// of server name to result. Results are cached for 60 seconds.
func ListAllTools(ctx context.Context, servers []MCPServerConfig) map[string]ServerToolResult {
	fp := configFingerprint(servers)

	cacheMu.Lock()
	if cacheData != nil && time.Since(cacheStamp) < cacheTTL && cacheFingerprint == fp {
		result := make(map[string]ServerToolResult, len(cacheData))
		for k, v := range cacheData {
			result[k] = ServerToolResult{Tools: v.Tools, Status: v.Status}
		}
		cacheMu.Unlock()
		return result
	}
	cacheMu.Unlock()

	results := make(map[string]cachedResult, len(servers))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, srv := range servers {
		wg.Add(1)
		go func(s MCPServerConfig) {
			defer wg.Done()
			perCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			tools, err := ListTools(perCtx, s)
			cr := cachedResult{Tools: tools}
			if err == nil {
				cr.Status = "connected"
			} else if errors.Is(err, ErrAuthRequired) {
				cr.Status = "auth_required"
			} else if errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
				cr.Status = "timeout"
			} else {
				cr.Status = "unreachable"
			}

			mu.Lock()
			results[s.Name] = cr
			mu.Unlock()
		}(srv)
	}

	wg.Wait()

	// Cache the results.
	cacheMu.Lock()
	cacheData = results
	cacheStamp = time.Now()
	cacheFingerprint = fp
	cacheMu.Unlock()

	out := make(map[string]ServerToolResult, len(results))
	for k, v := range results {
		out[k] = ServerToolResult{Tools: v.Tools, Status: v.Status}
	}
	return out
}
