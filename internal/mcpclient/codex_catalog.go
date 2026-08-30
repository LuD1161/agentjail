package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	codexCatalogTimeout      = 35 * time.Second
	codexCatalogPageLimit    = 32
	codexCatalogServerLimit  = 256
	codexCatalogToolLimit    = 2048
	codexCatalogMessageLimit = 32 << 20
)

// AuthenticatedToolCatalog exposes tool names from an agent runtime that owns
// an authenticated MCP session. See ADR 0147-codex-catalog-bridge.
type AuthenticatedToolCatalog interface {
	ListTools(context.Context) (map[string]ServerToolResult, error)
}

// CodexAuthenticatedCatalog reads Codex's initialized MCP catalog through the
// app-server protocol. It never requests a model turn or invokes an MCP tool.
type CodexAuthenticatedCatalog struct {
	command string
}

func NewCodexAuthenticatedCatalog() CodexAuthenticatedCatalog {
	return CodexAuthenticatedCatalog{command: "codex"}
}

func (c CodexAuthenticatedCatalog) ListTools(ctx context.Context) (map[string]ServerToolResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, codexCatalogTimeout)
		defer cancel()
	}
	command, err := resolveConfiguredCommand(c.command)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: resolve Codex catalog command: %w", err)
	}
	cmd := exec.CommandContext(ctx, command, "app-server", "--stdio")
	cmd.Env = sanitizedEnv()
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcpclient: Codex catalog stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcpclient: Codex catalog stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcpclient: start Codex catalog: %w", err)
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	return readCodexAuthenticatedCatalog(ctx, stdout, stdin)
}

type codexCatalogRequest struct {
	Method string `json:"method"`
	ID     int    `json:"id"`
	Params any    `json:"params"`
}

type codexCatalogEnvelope struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

type codexCatalogPage struct {
	Data []struct {
		Name       string                     `json:"name"`
		ServerInfo json.RawMessage            `json:"serverInfo"`
		Tools      map[string]json.RawMessage `json:"tools"`
		AuthStatus string                     `json:"authStatus"`
	} `json:"data"`
	NextCursor *string `json:"nextCursor"`
}

func readCodexAuthenticatedCatalog(ctx context.Context, reader io.Reader, writer io.Writer) (map[string]ServerToolResult, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), codexCatalogMessageLimit)
	if err := writeCodexCatalogRequest(writer, codexCatalogRequest{
		Method: "initialize",
		ID:     1,
		Params: map[string]any{
			"clientInfo": map[string]any{
				"name": "agentjail", "title": "AgentJail", "version": "1.6.0",
			},
			"capabilities": nil,
		},
	}); err != nil {
		return nil, err
	}
	if _, err := readCodexCatalogResponse(ctx, scanner, 1); err != nil {
		return nil, fmt.Errorf("mcpclient: initialize Codex catalog: %w", err)
	}

	results := make(map[string]ServerToolResult)
	var cursor *string
	for page := 0; page < codexCatalogPageLimit; page++ {
		requestID := 2 + page
		params := map[string]any{"detail": "toolsAndAuthOnly", "limit": 100}
		if cursor != nil && *cursor != "" {
			params["cursor"] = *cursor
		}
		if err := writeCodexCatalogRequest(writer, codexCatalogRequest{
			Method: "mcpServerStatus/list", ID: requestID, Params: params,
		}); err != nil {
			return nil, err
		}
		raw, err := readCodexCatalogResponse(ctx, scanner, requestID)
		if err != nil {
			return nil, fmt.Errorf("mcpclient: list Codex catalog: %w", err)
		}
		var catalogPage codexCatalogPage
		if err := json.Unmarshal(raw, &catalogPage); err != nil {
			return nil, fmt.Errorf("mcpclient: decode Codex catalog: %w", err)
		}
		for _, server := range catalogPage.Data {
			if len(results) == codexCatalogServerLimit {
				break
			}
			name := strings.TrimSpace(server.Name)
			if name == "" {
				continue
			}
			tools := make([]ToolInfo, 0, min(len(server.Tools), codexCatalogToolLimit))
			for toolName := range server.Tools {
				toolName = strings.TrimSpace(toolName)
				if toolName == "" {
					continue
				}
				tools = append(tools, ToolInfo{Name: toolName})
				if len(tools) == codexCatalogToolLimit {
					break
				}
			}
			sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

			status := ""
			switch {
			case server.AuthStatus == "notLoggedIn":
				status = "auth_required"
			case len(tools) > 0 || initializedCodexServer(server.ServerInfo):
				status = "connected"
			}
			if status != "" {
				results[name] = ServerToolResult{Tools: tools, Status: status}
			}
		}
		cursor = catalogPage.NextCursor
		if cursor == nil || *cursor == "" {
			return results, nil
		}
	}
	return nil, fmt.Errorf("mcpclient: Codex catalog exceeded page limit")
}

func writeCodexCatalogRequest(writer io.Writer, request codexCatalogRequest) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("mcpclient: encode Codex catalog request: %w", err)
	}
	encoded = append(encoded, '\n')
	if _, err := writer.Write(encoded); err != nil {
		return fmt.Errorf("mcpclient: write Codex catalog request: %w", err)
	}
	return nil
}

func readCodexCatalogResponse(ctx context.Context, scanner *bufio.Scanner, requestID int) (json.RawMessage, error) {
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var envelope codexCatalogEnvelope
		if json.Unmarshal(scanner.Bytes(), &envelope) != nil || !codexCatalogResponseID(envelope.ID, requestID) {
			continue
		}
		if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
			return nil, fmt.Errorf("Codex app-server returned an error")
		}
		if len(envelope.Result) == 0 {
			return nil, fmt.Errorf("Codex app-server returned no result")
		}
		return envelope.Result, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.ErrUnexpectedEOF
}

func codexCatalogResponseID(raw json.RawMessage, want int) bool {
	var got int
	return json.Unmarshal(raw, &got) == nil && got == want
}

func initializedCodexServer(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}
