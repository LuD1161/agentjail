package mcpclient

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReadCodexAuthenticatedCatalogUsesInitializedTools(t *testing.T) {
	responses := strings.Join([]string{
		`{"method":"mcpServer/startupStatus/updated","params":{}}`,
		`{"id":1,"result":{"userAgent":"codex","codexHome":"/tmp","platformFamily":"unix","platformOs":"macos"}}`,
		`{"id":2,"result":{"data":[` +
			`{"name":"linear","serverInfo":{"name":"linear","version":"1"},"tools":{"list_issues":{"name":"list_issues"},"get_issue":{"name":"get_issue"}},"authStatus":"oAuth"},` +
			`{"name":"private","serverInfo":null,"tools":{},"authStatus":"notLoggedIn"},` +
			`{"name":"failed","serverInfo":null,"tools":{},"authStatus":"unsupported"}` +
			`],"nextCursor":null}}`,
	}, "\n") + "\n"
	var requests bytes.Buffer
	got, err := readCodexAuthenticatedCatalog(context.Background(), strings.NewReader(responses), &requests)
	if err != nil {
		t.Fatal(err)
	}
	linear := got["linear"]
	if linear.Status != "connected" || len(linear.Tools) != 2 || linear.Tools[0].Name != "get_issue" || linear.Tools[1].Name != "list_issues" {
		t.Fatalf("linear catalog = %#v", linear)
	}
	if private := got["private"]; private.Status != "auth_required" || len(private.Tools) != 0 {
		t.Fatalf("private catalog = %#v", private)
	}
	if _, exists := got["failed"]; exists {
		t.Fatalf("uninitialized server became authoritative: %#v", got["failed"])
	}
	written := requests.String()
	if !strings.Contains(written, `"method":"initialize"`) || !strings.Contains(written, `"method":"mcpServerStatus/list"`) {
		t.Fatalf("app-server requests = %q", written)
	}
	if strings.Contains(written, "tool/call") || strings.Contains(written, "turn/start") {
		t.Fatalf("catalog requested an executable action: %q", written)
	}
}

func TestReadCodexAuthenticatedCatalogPaginates(t *testing.T) {
	responses := strings.Join([]string{
		`{"id":1,"result":{"userAgent":"codex"}}`,
		`{"id":2,"result":{"data":[{"name":"first","serverInfo":{"name":"first"},"tools":{"one":{}},"authStatus":"unsupported"}],"nextCursor":"next"}}`,
		`{"id":3,"result":{"data":[{"name":"second","serverInfo":{"name":"second"},"tools":{"two":{}},"authStatus":"bearerToken"}],"nextCursor":null}}`,
	}, "\n") + "\n"
	var requests bytes.Buffer
	got, err := readCodexAuthenticatedCatalog(context.Background(), strings.NewReader(responses), &requests)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["first"].Tools[0].Name != "one" || got["second"].Tools[0].Name != "two" {
		t.Fatalf("catalog = %#v", got)
	}
	if !strings.Contains(requests.String(), `"cursor":"next"`) {
		t.Fatalf("pagination request = %q", requests.String())
	}
}

func TestMergeAuthenticatedCatalogOverridesOnlyConfiguredServers(t *testing.T) {
	results := map[string]ServerToolResult{
		"linear": {Status: "auth_required"},
		"local":  {Status: "unreachable"},
	}
	mergeAuthenticatedCatalog(results, map[string]ServerToolResult{
		"linear":     {Status: "connected", Tools: []ToolInfo{{Name: "get_issue"}}},
		"local":      {Status: "unreachable"},
		"codex_apps": {Status: "connected", Tools: []ToolInfo{{Name: "search"}}},
	})
	if got := results["linear"]; got.Status != "connected" || len(got.Tools) != 1 {
		t.Fatalf("linear result = %#v", got)
	}
	if got := results["local"]; got.Status != "unreachable" {
		t.Fatalf("non-authoritative status replaced: %#v", got)
	}
	if _, exists := results["codex_apps"]; exists {
		t.Fatalf("unconfigured connector added to MCP inventory")
	}
}

func TestCodexAuthenticatedCatalogLive(t *testing.T) {
	if os.Getenv("AGENTJAIL_CODEX_CATALOG_LIVE") != "1" {
		t.Skip("set AGENTJAIL_CODEX_CATALOG_LIVE=1 to verify the installed Codex app-server contract")
	}
	ctx, cancel := context.WithTimeout(context.Background(), codexCatalogTimeout)
	defer cancel()
	started := time.Now()
	servers, err := NewCodexAuthenticatedCatalog().ListTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	connected := 0
	tools := 0
	for _, server := range servers {
		if server.Status == "connected" {
			connected++
			tools += len(server.Tools)
		}
	}
	if connected == 0 || tools == 0 {
		t.Fatalf("Codex catalog returned connected=%d tools=%d", connected, tools)
	}
	t.Logf("Codex catalog returned %d connected servers and %d tools in %s", connected, tools, time.Since(started).Round(time.Millisecond))
}
