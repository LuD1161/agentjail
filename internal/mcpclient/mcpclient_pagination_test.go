package mcpclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListToolsHTTPFollowsPagination(t *testing.T) {
	var cursors []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var message struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&message); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch message.Method {
		case "initialize":
			if request.Header.Get("Accept") != "application/json, text/event-stream" {
				t.Errorf("initialize Accept = %q", request.Header.Get("Accept"))
			}
			writer.Header().Set("Mcp-Session-Id", "session-1")
			_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`))
		case "notifications/initialized":
			writer.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if request.Header.Get("Mcp-Session-Id") != "session-1" || request.Header.Get("MCP-Protocol-Version") != "2025-06-18" {
				t.Errorf("tools/list protocol headers = %#v", request.Header)
			}
			cursors = append(cursors, message.Params.Cursor)
			if message.Params.Cursor == "" {
				_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"first","description":"one"}],"nextCursor":"page-2"}}`))
				return
			}
			_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"second","description":"two"}]}}`))
		default:
			t.Fatalf("unexpected method %q", message.Method)
		}
	}))
	defer server.Close()

	tools, err := ListTools(context.Background(), MCPServerConfig{Name: "fixture", Type: "http", URL: server.URL})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 2 || tools[0].Name != "first" || tools[1].Name != "second" {
		t.Fatalf("tools = %#v", tools)
	}
	if len(cursors) != 2 || cursors[0] != "" || cursors[1] != "page-2" {
		t.Fatalf("cursors = %#v", cursors)
	}
}

func TestParseSSEJSONRPC(t *testing.T) {
	payload, err := parseSSEJSONRPC([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n"))
	if err != nil || !json.Valid(payload) {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
}

func TestParseToolsPageReturnsCursor(t *testing.T) {
	tools, cursor, err := parseToolsPage(json.RawMessage(`{"result":{"tools":[{"name":"lookup"}],"nextCursor":"next"}}`))
	if err != nil || len(tools) != 1 || tools[0].Name != "lookup" || cursor != "next" {
		t.Fatalf("tools=%#v cursor=%q err=%v", tools, cursor, err)
	}
}
