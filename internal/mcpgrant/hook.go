package mcpgrant

import (
	"encoding/json"
	"errors"
	"strings"
)

var ErrInvalidHookTool = errors.New("invalid MCP hook tool name")

// ParseHookCall translates the canonical hook representation into an MCP
// resource. Hook input contains the tool arguments directly, not a JSON-RPC
// tools/call envelope. _meta is protocol metadata and never gains authority.
func ParseHookCall(toolName string, toolInput map[string]interface{}) (Call, error) {
	server, tool, ok := parseHookToolName(toolName)
	if !ok {
		return Call{}, ErrInvalidHookTool
	}
	arguments := make(map[string]interface{}, len(toolInput))
	for key, value := range toolInput {
		if key == "_meta" {
			if _, ok := value.(map[string]interface{}); !ok {
				return Call{}, ErrInvalidArguments
			}
			continue
		}
		arguments[key] = value
	}
	encoded, err := json.Marshal(arguments)
	if err != nil {
		return Call{}, ErrInvalidArguments
	}
	return NewCall(server, tool, encoded)
}

func parseHookToolName(toolName string) (ServerID, ToolID, bool) {
	if !strings.HasPrefix(toolName, "mcp__") {
		return "", "", false
	}
	server, tool, ok := strings.Cut(strings.TrimPrefix(toolName, "mcp__"), "__")
	if !ok || validateServerID(ServerID(server)) != nil || validateToolID(ToolID(tool)) != nil {
		return "", "", false
	}
	return ServerID(server), ToolID(tool), true
}
