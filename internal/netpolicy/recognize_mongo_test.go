package netpolicy

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"testing"
)

// buildBSONDoc builds a minimal BSON document from a list of string key-value pairs
// plus optional int32 and $db fields. This is a test helper only.
func buildBSONDoc(fields []bsonKV) []byte {
	var body []byte
	for _, kv := range fields {
		switch v := kv.val.(type) {
		case string:
			body = append(body, bsonTypeString) // type
			body = append(body, []byte(kv.key)...)
			body = append(body, 0x00) // key null terminator
			strBytes := []byte(v)
			strLen := make([]byte, 4)
			binary.LittleEndian.PutUint32(strLen, uint32(len(strBytes)+1)) // +1 for null
			body = append(body, strLen...)
			body = append(body, strBytes...)
			body = append(body, 0x00) // string null terminator
		case int32:
			body = append(body, bsonTypeInt32)
			body = append(body, []byte(kv.key)...)
			body = append(body, 0x00)
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(v))
			body = append(body, b...)
		case int64:
			body = append(body, bsonTypeInt64)
			body = append(body, []byte(kv.key)...)
			body = append(body, 0x00)
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, uint64(v))
			body = append(body, b...)
		case float64:
			body = append(body, bsonTypeDouble)
			body = append(body, []byte(kv.key)...)
			body = append(body, 0x00)
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, math.Float64bits(v))
			body = append(body, b...)
		}
	}
	body = append(body, 0x00) // document null terminator

	docLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(docLen, uint32(4+len(body)))
	return append(docLen, body...)
}

type bsonKV struct {
	key string
	val any
}

// buildOpMsg builds a complete OP_MSG wire protocol message with a Kind 0 body section.
func buildOpMsg(doc []byte) []byte {
	// Header: messageLength(4) + requestID(4) + responseTo(4) + opCode(4)
	// OP_MSG: flagBits(4) + kind(1) + doc
	totalLen := mongoHeaderSize + 4 + 1 + len(doc)

	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))   // messageLength
	binary.LittleEndian.PutUint32(msg[4:8], 1)                  // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0)                 // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgOpcode)) // opCode
	binary.LittleEndian.PutUint32(msg[16:20], 0)                // flagBits
	msg[20] = 0                                                  // Kind 0
	copy(msg[21:], doc)

	return msg
}

func TestParseMongoMessage_FindCommand(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"find", "users"},
		{"$db", "myapp"},
	})
	msg := buildOpMsg(doc)

	op := ParseMongoMessage(msg)
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Protocol != "mongodb" {
		t.Errorf("Protocol = %q, want %q", op.Protocol, "mongodb")
	}
	if op.Service != "mongodb" {
		t.Errorf("Service = %q, want %q", op.Service, "mongodb")
	}
	if op.Verb != "get" {
		t.Errorf("Verb = %q, want %q", op.Verb, "get")
	}
	if op.ResourceType != "collections" {
		t.Errorf("ResourceType = %q, want %q", op.ResourceType, "collections")
	}
	if op.ResourceName != "users" {
		t.Errorf("ResourceName = %q, want %q", op.ResourceName, "users")
	}
	if op.Namespace != "myapp" {
		t.Errorf("Namespace = %q, want %q", op.Namespace, "myapp")
	}
}

func TestParseMongoMessage_InsertCommand(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"insert", "orders"},
		{"$db", "shop"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "insert" {
		t.Errorf("Verb = %q, want %q", op.Verb, "insert")
	}
	if op.ResourceName != "orders" {
		t.Errorf("ResourceName = %q, want %q", op.ResourceName, "orders")
	}
}

func TestParseMongoMessage_UpdateCommand(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"update", "products"},
		{"$db", "catalog"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "update" {
		t.Errorf("Verb = %q, want %q", op.Verb, "update")
	}
}

func TestParseMongoMessage_DeleteCommand(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"delete", "sessions"},
		{"$db", "auth"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "delete" {
		t.Errorf("Verb = %q, want %q", op.Verb, "delete")
	}
}

func TestParseMongoMessage_DropCommand(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"drop", "temp_data"},
		{"$db", "staging"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "drop" {
		t.Errorf("Verb = %q, want %q", op.Verb, "drop")
	}
	if op.ResourceType != "collections" {
		t.Errorf("ResourceType = %q, want %q", op.ResourceType, "collections")
	}
}

func TestParseMongoMessage_DropDatabase(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"dropDatabase", "1"},
		{"$db", "old_db"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "drop" {
		t.Errorf("Verb = %q, want %q", op.Verb, "drop")
	}
	if op.ResourceType != "databases" {
		t.Errorf("ResourceType = %q, want %q", op.ResourceType, "databases")
	}
	if op.Namespace != "old_db" {
		t.Errorf("Namespace = %q, want %q", op.Namespace, "old_db")
	}
}

func TestParseMongoMessage_CreateIndexes(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"createIndexes", "users"},
		{"$db", "myapp"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "create" {
		t.Errorf("Verb = %q, want %q", op.Verb, "create")
	}
	if op.ResourceType != "indexes" {
		t.Errorf("ResourceType = %q, want %q", op.ResourceType, "indexes")
	}
}

func TestParseMongoMessage_AggregateCommand(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"aggregate", "events"},
		{"$db", "analytics"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "get" {
		t.Errorf("Verb = %q, want %q", op.Verb, "get")
	}
	if op.ResourceName != "events" {
		t.Errorf("ResourceName = %q, want %q", op.ResourceName, "events")
	}
}

func TestParseMongoMessage_AdminCommand(t *testing.T) {
	for _, cmd := range []string{"shutdown", "killOp", "fsync", "validate"} {
		t.Run(cmd, func(t *testing.T) {
			doc := buildBSONDoc([]bsonKV{
				{cmd, "1"},
				{"$db", "admin"},
			})
			op := ParseMongoMessage(buildOpMsg(doc))
			if op == nil {
				t.Fatal("expected non-nil Operation")
			}
			if op.Verb != "admin" {
				t.Errorf("Verb = %q, want %q", op.Verb, "admin")
			}
		})
	}
}

func TestParseMongoMessage_UnknownCommand(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"someNewCommand", "value"},
		{"$db", "test"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	// Unknown commands should default to "admin".
	if op.Verb != "admin" {
		t.Errorf("Verb = %q, want %q", op.Verb, "admin")
	}
}

func TestParseMongoMessage_ListDatabases(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"listDatabases", "1"},
		{"$db", "admin"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "get" {
		t.Errorf("Verb = %q, want %q", op.Verb, "get")
	}
	if op.ResourceType != "databases" {
		t.Errorf("ResourceType = %q, want %q", op.ResourceType, "databases")
	}
}

func TestParseMongoMessage_ListCollections(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"listCollections", "1"},
		{"$db", "myapp"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "get" {
		t.Errorf("Verb = %q, want %q", op.Verb, "get")
	}
	if op.ResourceType != "collections" {
		t.Errorf("ResourceType = %q, want %q", op.ResourceType, "collections")
	}
}

func TestParseMongoMessage_FindAndModify(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"findAndModify", "users"},
		{"$db", "myapp"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "update" {
		t.Errorf("Verb = %q, want %q", op.Verb, "update")
	}
}

func TestParseMongoMessage_Int32Field(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"count", "users"},
		{"$db", "myapp"},
		{"limit", int32(100)},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	if op.Verb != "get" {
		t.Errorf("Verb = %q, want %q", op.Verb, "get")
	}
	// Verify the int32 field appears in RawQuery.
	var raw map[string]any
	if err := json.Unmarshal([]byte(op.RawQuery), &raw); err != nil {
		t.Fatalf("failed to parse RawQuery: %v", err)
	}
	if raw["limit"] == nil {
		t.Error("expected 'limit' in RawQuery")
	}
}

func TestParseMongoMessage_Int64Field(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"find", "logs"},
		{"$db", "ops"},
		{"maxTimeMS", int64(5000)},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(op.RawQuery), &raw); err != nil {
		t.Fatalf("failed to parse RawQuery: %v", err)
	}
	if raw["maxTimeMS"] == nil {
		t.Error("expected 'maxTimeMS' in RawQuery")
	}
}

func TestParseMongoMessage_DoubleField(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"find", "metrics"},
		{"$db", "telemetry"},
		{"threshold", float64(3.14)},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(op.RawQuery), &raw); err != nil {
		t.Fatalf("failed to parse RawQuery: %v", err)
	}
	if raw["threshold"] == nil {
		t.Error("expected 'threshold' in RawQuery")
	}
}

func TestParseMongoMessage_RawQueryJSON(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"find", "users"},
		{"$db", "myapp"},
	})
	op := ParseMongoMessage(buildOpMsg(doc))
	if op == nil {
		t.Fatal("expected non-nil Operation")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(op.RawQuery), &raw); err != nil {
		t.Fatalf("RawQuery is not valid JSON: %v", err)
	}
	if raw["find"] != "users" {
		t.Errorf("RawQuery find = %v, want %q", raw["find"], "users")
	}
	if raw["$db"] != "myapp" {
		t.Errorf("RawQuery $db = %v, want %q", raw["$db"], "myapp")
	}
}

// --- Malformed input tests ---

func TestParseMongoMessage_TooShort(t *testing.T) {
	if op := ParseMongoMessage([]byte{1, 2, 3}); op != nil {
		t.Error("expected nil for data shorter than header")
	}
}

func TestParseMongoMessage_WrongOpcode(t *testing.T) {
	msg := make([]byte, 30)
	binary.LittleEndian.PutUint32(msg[0:4], 30)
	binary.LittleEndian.PutUint32(msg[12:16], 2004) // not OP_MSG
	if op := ParseMongoMessage(msg); op != nil {
		t.Error("expected nil for non-OP_MSG opcode")
	}
}

func TestParseMongoMessage_MessageLengthTooSmall(t *testing.T) {
	msg := make([]byte, 30)
	binary.LittleEndian.PutUint32(msg[0:4], 5) // too small
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgOpcode))
	if op := ParseMongoMessage(msg); op != nil {
		t.Error("expected nil for messageLength too small")
	}
}

func TestParseMongoMessage_MessageLengthExceedsData(t *testing.T) {
	msg := make([]byte, 25)
	binary.LittleEndian.PutUint32(msg[0:4], 1000) // larger than actual data
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgOpcode))
	if op := ParseMongoMessage(msg); op != nil {
		t.Error("expected nil when messageLength > data length")
	}
}

func TestParseMongoMessage_EmptyBSONDoc(t *testing.T) {
	// Build a BSON doc with no fields (just length + terminator = 5 bytes).
	doc := make([]byte, 5)
	binary.LittleEndian.PutUint32(doc[0:4], 5)
	doc[4] = 0x00
	msg := buildOpMsg(doc)

	if op := ParseMongoMessage(msg); op != nil {
		t.Error("expected nil for empty BSON document")
	}
}

func TestParseMongoMessage_NilInput(t *testing.T) {
	if op := ParseMongoMessage(nil); op != nil {
		t.Error("expected nil for nil input")
	}
}

func TestParseMongoMessage_TruncatedBSON(t *testing.T) {
	// Build a valid OP_MSG header but truncate the BSON body.
	totalLen := mongoHeaderSize + 4 + 1 + 3 // 3 bytes is too short for BSON
	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgOpcode))
	binary.LittleEndian.PutUint32(msg[16:20], 0) // flagBits
	msg[20] = 0                                   // Kind 0
	// 3 junk bytes for "doc"
	msg[21] = 0xFF
	msg[22] = 0xFF
	msg[23] = 0xFF

	if op := ParseMongoMessage(msg); op != nil {
		t.Error("expected nil for truncated BSON body")
	}
}

func TestParseMongoMessage_UnknownSectionKind(t *testing.T) {
	doc := buildBSONDoc([]bsonKV{
		{"find", "users"},
		{"$db", "test"},
	})
	totalLen := mongoHeaderSize + 4 + 1 + len(doc)
	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgOpcode))
	binary.LittleEndian.PutUint32(msg[16:20], 0)
	msg[20] = 99 // unknown section kind
	copy(msg[21:], doc)

	if op := ParseMongoMessage(msg); op != nil {
		t.Error("expected nil for unknown section kind")
	}
}

func TestParseMongoMessage_AllVerbMappings(t *testing.T) {
	tests := []struct {
		cmd          string
		wantVerb     string
		wantResType  string
	}{
		{"find", "get", "collections"},
		{"aggregate", "get", "collections"},
		{"count", "get", "collections"},
		{"distinct", "get", "collections"},
		{"listCollections", "get", "collections"},
		{"listDatabases", "get", "databases"},
		{"listIndexes", "get", "indexes"},
		{"insert", "insert", "collections"},
		{"insertMany", "insert", "collections"},
		{"update", "update", "collections"},
		{"updateMany", "update", "collections"},
		{"updateOne", "update", "collections"},
		{"findAndModify", "update", "collections"},
		{"replaceOne", "update", "collections"},
		{"delete", "delete", "collections"},
		{"deleteMany", "delete", "collections"},
		{"deleteOne", "delete", "collections"},
		{"drop", "drop", "collections"},
		{"dropDatabase", "drop", "databases"},
		{"dropIndexes", "drop", "indexes"},
		{"create", "create", "collections"},
		{"createIndexes", "create", "indexes"},
		{"createCollection", "create", "collections"},
		{"shutdown", "admin", "collections"},
		{"killOp", "admin", "collections"},
		{"fsync", "admin", "collections"},
		{"validate", "admin", "collections"},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			doc := buildBSONDoc([]bsonKV{
				{tt.cmd, "testcol"},
				{"$db", "testdb"},
			})
			op := ParseMongoMessage(buildOpMsg(doc))
			if op == nil {
				t.Fatal("expected non-nil Operation")
			}
			if op.Verb != tt.wantVerb {
				t.Errorf("Verb = %q, want %q", op.Verb, tt.wantVerb)
			}
			if op.ResourceType != tt.wantResType {
				t.Errorf("ResourceType = %q, want %q", op.ResourceType, tt.wantResType)
			}
		})
	}
}

// Ensure math import is used.
var _ = math.Float64bits
