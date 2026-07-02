package netpolicy

import (
	"encoding/binary"
	"strings"
)

// PostgreSQL wire protocol v3 message types (frontend).
const (
	pgMsgSimpleQuery byte = 'Q'
	pgMsgParse       byte = 'P'
	pgMsgTerminate   byte = 'X'
)

// pgStartupVersion is the v3.0 protocol version number (196608 = 3<<16 | 0).
const pgStartupVersion uint32 = 196608

// ParsePostgresMessage parses a PostgreSQL wire protocol message from raw bytes
// and returns a normalized Operation. Returns nil if the data cannot be parsed
// as a recognized PostgreSQL message.
//
// Supported message types:
//   - Startup message (extracts database, user)
//   - SimpleQuery 'Q' (extracts SQL text)
//   - Parse 'P' (extended query protocol, extracts prepared statement SQL)
//   - Terminate 'X'
func ParsePostgresMessage(data []byte) *Operation {
	if len(data) < 4 {
		return nil
	}

	// Try to detect a startup message first. Startup messages have no type
	// byte; they start with a 4-byte length followed by the 4-byte protocol
	// version number.
	if op := tryParseStartup(data); op != nil {
		return op
	}

	// Regular messages: 1-byte type, 4-byte length (includes itself), payload.
	msgType := data[0]
	if len(data) < 5 {
		return nil
	}
	msgLen := int(binary.BigEndian.Uint32(data[1:5]))
	// The length field includes itself (4 bytes), so valid values are >= 4.
	// If msgLen < 4 then 1+msgLen < 5, making data[5 : 1+msgLen] panic.
	if msgLen < 4 || len(data) < 1+msgLen {
		return nil
	}
	payload := data[5 : 1+msgLen]

	switch msgType {
	case pgMsgSimpleQuery:
		return parseSimpleQuery(payload)
	case pgMsgParse:
		return parseParse(payload)
	case pgMsgTerminate:
		return &Operation{
			Protocol: "postgres",
			Service:  "postgresql",
			Verb:     "terminate",
		}
	default:
		return nil
	}
}

// tryParseStartup attempts to parse a PostgreSQL v3 startup message.
// Format: int32 length | int32 version(196608) | key\0value\0 ... \0
func tryParseStartup(data []byte) *Operation {
	if len(data) < 8 {
		return nil
	}
	length := int(binary.BigEndian.Uint32(data[0:4]))
	version := binary.BigEndian.Uint32(data[4:8])

	if version != pgStartupVersion {
		return nil
	}
	if length < 8 || len(data) < length {
		return nil
	}

	// Parse key-value pairs from the parameter block.
	params := parseStartupParams(data[8:length])

	return &Operation{
		Protocol:  "postgres",
		Service:   "postgresql",
		Verb:      "connect",
		Namespace: params["database"],
		Payload: map[string]any{
			"user":     params["user"],
			"database": params["database"],
		},
	}
}

// parseStartupParams extracts null-terminated key-value pairs from the
// startup message parameter block.
func parseStartupParams(data []byte) map[string]string {
	params := make(map[string]string)
	for len(data) > 0 {
		// Find end of key.
		keyEnd := indexOf(data, 0)
		if keyEnd <= 0 {
			break
		}
		key := string(data[:keyEnd])
		data = data[keyEnd+1:]

		// Find end of value.
		valEnd := indexOf(data, 0)
		if valEnd < 0 {
			break
		}
		params[key] = string(data[:valEnd])
		data = data[valEnd+1:]
	}
	return params
}

// parseSimpleQuery parses a SimpleQuery ('Q') message payload.
// Payload is the SQL string followed by a null terminator.
func parseSimpleQuery(payload []byte) *Operation {
	sql := cString(payload)
	return sqlToOperation(sql)
}

// parseParse parses an extended-query Parse ('P') message payload.
// Format: dest\0 query\0 int16 numParams [int32 paramOID ...]
func parseParse(payload []byte) *Operation {
	// Skip destination (prepared statement name).
	destEnd := indexOf(payload, 0)
	if destEnd < 0 {
		return nil
	}
	rest := payload[destEnd+1:]

	sql := cString(rest)
	return sqlToOperation(sql)
}

// sqlToOperation normalizes a SQL query string into an Operation.
func sqlToOperation(sql string) *Operation {
	if sql == "" {
		return nil
	}

	verb := extractSQLVerb(sql)
	resourceType, resourceName := extractSQLTarget(sql, verb)

	return &Operation{
		Protocol:     "postgres",
		Service:      "postgresql",
		Verb:         verb,
		ResourceType: resourceType,
		ResourceName: resourceName,
		RawQuery:     sql,
	}
}

// extractSQLVerb returns the lowercase SQL command from the first token.
func extractSQLVerb(sql string) string {
	trimmed := strings.TrimSpace(sql)
	// Take the first word.
	end := strings.IndexAny(trimmed, " \t\n\r")
	if end < 0 {
		return strings.ToLower(trimmed)
	}
	return strings.ToLower(trimmed[:end])
}

// extractSQLTarget performs best-effort extraction of the resource type and
// table name from a SQL statement.
func extractSQLTarget(sql string, verb string) (resourceType, resourceName string) {
	tokens := tokenizeSQL(sql)

	switch verb {
	case "select":
		resourceType = "tables"
		resourceName = findTokenAfter(tokens, "from")
	case "insert":
		resourceType = "tables"
		resourceName = findTokenAfter(tokens, "into")
	case "update":
		resourceType = "tables"
		// UPDATE <table> SET ...
		if len(tokens) >= 2 {
			resourceName = tokens[1]
		}
	case "delete":
		resourceType = "tables"
		resourceName = findTokenAfter(tokens, "from")
	case "drop":
		resourceType, resourceName = parseDDLTarget(tokens)
	case "alter":
		resourceType, resourceName = parseDDLTarget(tokens)
	case "create":
		resourceType, resourceName = parseDDLTarget(tokens)
	case "truncate":
		resourceType = "tables"
		// TRUNCATE [TABLE] <name>
		resourceName = findTokenAfter(tokens, "table")
		if resourceName == "" && len(tokens) >= 2 {
			resourceName = tokens[1]
		}
	default:
		resourceType = "tables"
	}

	// Strip quotes and trailing punctuation from the identifier.
	resourceName = cleanIdentifier(resourceName)

	return resourceType, resourceName
}

// parseDDLTarget handles DROP/ALTER/CREATE where the second token is the
// object type (TABLE, INDEX, DATABASE, SCHEMA, FUNCTION).
func parseDDLTarget(tokens []string) (resourceType, resourceName string) {
	if len(tokens) < 2 {
		return "tables", ""
	}

	objType := strings.ToLower(tokens[1])
	nameIdx := 2

	switch objType {
	case "table":
		resourceType = "tables"
	case "index":
		resourceType = "indexes"
	case "database":
		resourceType = "databases"
	case "schema":
		resourceType = "schemas"
	case "function":
		resourceType = "functions"
	default:
		resourceType = "tables"
	}

	// Advance past IF [NOT] EXISTS.
	for nameIdx < len(tokens) {
		lower := strings.ToLower(tokens[nameIdx])
		if lower == "if" || lower == "exists" || lower == "not" {
			nameIdx++
		} else {
			break
		}
	}

	if nameIdx < len(tokens) {
		resourceName = tokens[nameIdx]
	}

	return resourceType, resourceName
}

// tokenizeSQL splits SQL into whitespace-separated tokens, lowercasing them.
func tokenizeSQL(sql string) []string {
	fields := strings.Fields(sql)
	result := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimRight(f, ";")
		if f != "" {
			result = append(result, strings.ToLower(f))
		}
	}
	return result
}

// findTokenAfter returns the token immediately following the first occurrence
// of keyword in the token list.
func findTokenAfter(tokens []string, keyword string) string {
	for i, t := range tokens {
		if t == keyword && i+1 < len(tokens) {
			return tokens[i+1]
		}
	}
	return ""
}

// cleanIdentifier strips quotes, backticks, and trailing punctuation from a
// SQL identifier.
func cleanIdentifier(s string) string {
	s = strings.Trim(s, "\"'`")
	s = strings.TrimRight(s, ";,()")
	return s
}

// cString extracts a null-terminated string from bytes.
func cString(data []byte) string {
	idx := indexOf(data, 0)
	if idx < 0 {
		return string(data)
	}
	return string(data[:idx])
}

// indexOf returns the index of the first occurrence of b in data, or -1.
func indexOf(data []byte, b byte) int {
	for i, v := range data {
		if v == b {
			return i
		}
	}
	return -1
}
