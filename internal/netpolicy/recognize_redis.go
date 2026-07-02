package netpolicy

import (
	"bytes"
	"strconv"
	"strings"
)

// redisVerbMap maps uppercase Redis commands to normalized verbs.
var redisVerbMap = map[string]string{
	// Read
	"GET":      "get",
	"MGET":     "get",
	"HGET":     "get",
	"HGETALL":  "get",
	"LRANGE":   "get",
	"SMEMBERS": "get",
	"ZRANGE":   "get",
	"SCAN":     "get",
	"KEYS":     "get",
	"TYPE":     "get",
	"TTL":      "get",
	// Write
	"SET":    "set",
	"MSET":   "set",
	"HSET":   "set",
	"LPUSH":  "set",
	"RPUSH":  "set",
	"SADD":   "set",
	"ZADD":   "set",
	"SETNX":  "set",
	"SETEX":  "set",
	"INCR":   "set",
	"DECR":   "set",
	"APPEND": "set",
	// Delete
	"DEL":      "delete",
	"HDEL":     "delete",
	"LREM":     "delete",
	"SREM":     "delete",
	"ZREM":     "delete",
	"EXPIRE":   "delete",
	"EXPIREAT": "delete",
	"UNLINK":   "delete",
	// Admin
	"FLUSHDB":   "admin",
	"FLUSHALL":  "admin",
	"CONFIG":    "admin",
	"SHUTDOWN":  "admin",
	"DEBUG":     "admin",
	"SLAVEOF":   "admin",
	"REPLICAOF": "admin",
	"CLUSTER":   "admin",
	// Pub/Sub
	"PUBLISH":     "pubsub",
	"SUBSCRIBE":   "pubsub",
	"PSUBSCRIBE":  "pubsub",
	"UNSUBSCRIBE": "pubsub",
	// Script
	"EVAL":    "eval",
	"EVALSHA": "eval",
}

// redisResourceTypeMap maps normalized verbs to resource types.
var redisResourceTypeMap = map[string]string{
	"get":    "keys",
	"set":    "keys",
	"delete": "keys",
	"admin":  "server",
	"pubsub": "channels",
	"eval":   "keys",
}

// ParseRedisCommand parses a raw Redis RESP message (inline or RESP2 array)
// and returns a normalized Operation, or nil if the data cannot be parsed.
func ParseRedisCommand(data []byte) *Operation {
	if len(data) == 0 {
		return nil
	}

	var parts []string
	if data[0] == '*' {
		parts = parseRESPArray(data)
	} else {
		parts = parseInlineCommand(data)
	}

	if len(parts) == 0 {
		return nil
	}

	cmdName := strings.ToUpper(parts[0])
	verb, ok := redisVerbMap[cmdName]
	if !ok {
		verb = strings.ToLower(cmdName)
	}

	resourceType := redisResourceTypeMap[verb]
	if resourceType == "" {
		resourceType = "keys"
	}

	var resourceName string
	if len(parts) > 1 {
		resourceName = parts[1]
	}

	rawQuery := strings.Join(parts, " ")

	return &Operation{
		Protocol:     "redis",
		Service:      "redis",
		Verb:         verb,
		ResourceType: resourceType,
		ResourceName: resourceName,
		RawQuery:     rawQuery,
	}
}

// parseInlineCommand splits an inline Redis command (space-separated, terminated by \r\n).
func parseInlineCommand(data []byte) []string {
	line := data
	if idx := bytes.Index(line, []byte("\r\n")); idx >= 0 {
		line = line[:idx]
	}
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return nil
	}
	return strings.Fields(trimmed)
}

// parseRESPArray parses a RESP2 array starting with *<count>\r\n followed by
// bulk strings ($<len>\r\n<data>\r\n).
func parseRESPArray(data []byte) []string {
	// Read array count: *<count>\r\n
	idx := bytes.Index(data, []byte("\r\n"))
	if idx < 0 || idx < 2 {
		return nil
	}
	count, err := strconv.Atoi(string(data[1:idx]))
	if err != nil || count <= 0 {
		return nil
	}
	// Guard against enormous counts: each element requires at least 4 bytes
	// ($1\r\n), so count > len(data)/4 is unreachable with the data we have.
	// Capping at len(data) prevents a multi-gigabyte make() allocation from a
	// single malformed "*1000000000\r\n" line.
	if count > len(data) {
		return nil
	}

	pos := idx + 2 // skip past first \r\n
	parts := make([]string, 0, count)

	for i := 0; i < count; i++ {
		if pos >= len(data) {
			return nil
		}
		if data[pos] != '$' {
			return nil
		}
		// Read bulk string length: $<len>\r\n
		endOfLen := bytes.Index(data[pos:], []byte("\r\n"))
		if endOfLen < 0 {
			return nil
		}
		strLen, err := strconv.Atoi(string(data[pos+1 : pos+endOfLen]))
		if err != nil || strLen < 0 {
			return nil
		}
		pos += endOfLen + 2 // skip past $<len>\r\n

		// Read the actual string data
		if pos+strLen > len(data) {
			return nil
		}
		parts = append(parts, string(data[pos:pos+strLen]))
		pos += strLen

		// Skip trailing \r\n
		if pos+2 <= len(data) && data[pos] == '\r' && data[pos+1] == '\n' {
			pos += 2
		}
	}

	return parts
}
