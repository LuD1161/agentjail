package netpolicy

import (
	"encoding/binary"
	"testing"
)

// --- helpers for building wire-protocol messages ---

// buildStartupMessage constructs a PostgreSQL v3 startup message with the
// given key-value parameters.
func buildStartupMessage(params map[string]string) []byte {
	var body []byte
	// Version: 3.0
	body = binary.BigEndian.AppendUint32(body, pgStartupVersion)
	for k, v := range params {
		body = append(body, []byte(k)...)
		body = append(body, 0)
		body = append(body, []byte(v)...)
		body = append(body, 0)
	}
	body = append(body, 0) // terminating null

	// Prepend length (int32, includes itself).
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	return append(length, body...)
}

// buildSimpleQuery constructs a SimpleQuery ('Q') message.
func buildSimpleQuery(sql string) []byte {
	payload := append([]byte(sql), 0) // null-terminated SQL
	msg := []byte{'Q'}
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(payload)+4))
	return append(msg, payload...)
}

// buildParseMessage constructs an extended-query Parse ('P') message.
func buildParseMessage(stmtName, sql string) []byte {
	var payload []byte
	payload = append(payload, []byte(stmtName)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(sql)...)
	payload = append(payload, 0)
	// 0 parameter types
	payload = binary.BigEndian.AppendUint16(payload, 0)

	msg := []byte{'P'}
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(payload)+4))
	return append(msg, payload...)
}

// buildTerminate constructs a Terminate ('X') message.
func buildTerminate() []byte {
	msg := []byte{'X'}
	msg = binary.BigEndian.AppendUint32(msg, 4) // length = 4 (just itself)
	return msg
}

// --- Startup message tests ---

func TestParseStartupMessage(t *testing.T) {
	data := buildStartupMessage(map[string]string{
		"user":     "admin",
		"database": "myapp",
	})
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation for startup message")
	}
	assertEqual(t, "protocol", "postgres", op.Protocol)
	assertEqual(t, "service", "postgresql", op.Service)
	assertEqual(t, "verb", "connect", op.Verb)
	assertEqual(t, "namespace", "myapp", op.Namespace)
	if op.Payload == nil {
		t.Fatal("expected non-nil payload")
	}
	if op.Payload["user"] != "admin" {
		t.Errorf("expected user 'admin', got %v", op.Payload["user"])
	}
	if op.Payload["database"] != "myapp" {
		t.Errorf("expected database 'myapp', got %v", op.Payload["database"])
	}
}

// --- SimpleQuery tests ---

func TestSimpleQuerySelect(t *testing.T) {
	data := buildSimpleQuery("SELECT * FROM users WHERE id = 1")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "protocol", "postgres", op.Protocol)
	assertEqual(t, "service", "postgresql", op.Service)
	assertEqual(t, "verb", "select", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "users", op.ResourceName)
	assertEqual(t, "raw_query", "SELECT * FROM users WHERE id = 1", op.RawQuery)
}

func TestSimpleQueryInsert(t *testing.T) {
	data := buildSimpleQuery("INSERT INTO orders (id, amount) VALUES (1, 100)")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "insert", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "orders", op.ResourceName)
}

func TestSimpleQueryUpdate(t *testing.T) {
	data := buildSimpleQuery("UPDATE accounts SET balance = 0 WHERE id = 5")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "update", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "accounts", op.ResourceName)
}

func TestSimpleQueryDelete(t *testing.T) {
	data := buildSimpleQuery("DELETE FROM sessions WHERE expired = true")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "delete", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "sessions", op.ResourceName)
}

func TestSimpleQueryDropTable(t *testing.T) {
	data := buildSimpleQuery("DROP TABLE IF EXISTS temp_data")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "drop", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "temp_data", op.ResourceName)
}

func TestSimpleQueryAlterTable(t *testing.T) {
	data := buildSimpleQuery("ALTER TABLE users ADD COLUMN email TEXT")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "alter", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "users", op.ResourceName)
}

func TestSimpleQueryCreateTable(t *testing.T) {
	data := buildSimpleQuery("CREATE TABLE events (id SERIAL PRIMARY KEY)")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "create", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "events", op.ResourceName)
}

func TestSimpleQueryCreateIndex(t *testing.T) {
	data := buildSimpleQuery("CREATE INDEX idx_users_email ON users (email)")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "create", op.Verb)
	assertEqual(t, "resource_type", "indexes", op.ResourceType)
	assertEqual(t, "resource_name", "idx_users_email", op.ResourceName)
}

func TestSimpleQueryDropDatabase(t *testing.T) {
	data := buildSimpleQuery("DROP DATABASE test_db")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "drop", op.Verb)
	assertEqual(t, "resource_type", "databases", op.ResourceType)
	assertEqual(t, "resource_name", "test_db", op.ResourceName)
}

func TestSimpleQueryCreateSchema(t *testing.T) {
	data := buildSimpleQuery("CREATE SCHEMA analytics")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "create", op.Verb)
	assertEqual(t, "resource_type", "schemas", op.ResourceType)
	assertEqual(t, "resource_name", "analytics", op.ResourceName)
}

func TestSimpleQueryTruncate(t *testing.T) {
	data := buildSimpleQuery("TRUNCATE TABLE logs")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "truncate", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "logs", op.ResourceName)
}

func TestSimpleQueryTruncateWithoutTableKeyword(t *testing.T) {
	data := buildSimpleQuery("TRUNCATE logs")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "truncate", op.Verb)
	assertEqual(t, "resource_name", "logs", op.ResourceName)
}

func TestSimpleQueryDropFunction(t *testing.T) {
	data := buildSimpleQuery("DROP FUNCTION IF EXISTS my_func")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "drop", op.Verb)
	assertEqual(t, "resource_type", "functions", op.ResourceType)
	assertEqual(t, "resource_name", "my_func", op.ResourceName)
}

// --- Parse (extended query protocol) tests ---

func TestParseMessageSelect(t *testing.T) {
	data := buildParseMessage("stmt1", "SELECT name FROM products WHERE price > $1")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "protocol", "postgres", op.Protocol)
	assertEqual(t, "verb", "select", op.Verb)
	assertEqual(t, "resource_type", "tables", op.ResourceType)
	assertEqual(t, "resource_name", "products", op.ResourceName)
	assertEqual(t, "raw_query", "SELECT name FROM products WHERE price > $1", op.RawQuery)
}

func TestParseMessageUnnamedStatement(t *testing.T) {
	data := buildParseMessage("", "INSERT INTO logs (msg) VALUES ($1)")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "insert", op.Verb)
	assertEqual(t, "resource_name", "logs", op.ResourceName)
}

// --- Terminate tests ---

func TestTerminateMessage(t *testing.T) {
	data := buildTerminate()
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation for Terminate")
	}
	assertEqual(t, "protocol", "postgres", op.Protocol)
	assertEqual(t, "service", "postgresql", op.Service)
	assertEqual(t, "verb", "terminate", op.Verb)
}

// --- Edge cases ---

func TestNilData(t *testing.T) {
	op := ParsePostgresMessage(nil)
	if op != nil {
		t.Error("expected nil for nil data")
	}
}

func TestTooShortData(t *testing.T) {
	op := ParsePostgresMessage([]byte{0x01, 0x02})
	if op != nil {
		t.Error("expected nil for short data")
	}
}

func TestUnknownMessageType(t *testing.T) {
	// Build a message with type byte 'Z' (ReadyForQuery is backend, not recognized)
	msg := []byte{'Z'}
	msg = binary.BigEndian.AppendUint32(msg, 5) // length 5
	msg = append(msg, 'I')                      // idle status
	op := ParsePostgresMessage(msg)
	if op != nil {
		t.Error("expected nil for unknown message type")
	}
}

func TestSelectWithSchemaQualifiedTable(t *testing.T) {
	data := buildSimpleQuery("SELECT * FROM public.users")
	op := ParsePostgresMessage(data)
	if op == nil {
		t.Fatal("expected non-nil operation")
	}
	assertEqual(t, "verb", "select", op.Verb)
	assertEqual(t, "resource_name", "public.users", op.ResourceName)
}
