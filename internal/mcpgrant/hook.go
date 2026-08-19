package mcpgrant

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode/utf8"
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
		if !utf8.ValidString(key) || !validHookValue(value, 0) {
			return Call{}, ErrInvalidArguments
		}
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

// validHookValue admits only the JSON graph decoded at the hook boundary.
// See ADR 0141-runtime-grants.
func validHookValue(value interface{}, depth int) bool {
	if depth > 64 {
		return false
	}
	switch typed := value.(type) {
	case nil, bool:
		return true
	case string:
		return utf8.ValidString(typed)
	case float64:
		return !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case []interface{}:
		for _, entry := range typed {
			if !validHookValue(entry, depth+1) {
				return false
			}
		}
		return true
	case map[string]interface{}:
		for key, entry := range typed {
			if !utf8.ValidString(key) || !validHookValue(entry, depth+1) {
				return false
			}
		}
		return true
	default:
		return false
	}
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
