package netpolicy

import (
	"testing"
)

func TestParseRedisCommand_Inline(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantNil      bool
		wantVerb     string
		wantResource string
		wantRaw      string
	}{
		{
			name:         "inline GET",
			input:        "GET mykey\r\n",
			wantVerb:     "get",
			wantResource: "mykey",
			wantRaw:      "GET mykey",
		},
		{
			name:         "inline SET with value",
			input:        "SET mykey myvalue\r\n",
			wantVerb:     "set",
			wantResource: "mykey",
			wantRaw:      "SET mykey myvalue",
		},
		{
			name:         "inline lowercase command",
			input:        "get foo\r\n",
			wantVerb:     "get",
			wantResource: "foo",
			wantRaw:      "get foo",
		},
		{
			name:         "inline DEL",
			input:        "DEL session:123\r\n",
			wantVerb:     "delete",
			wantResource: "session:123",
			wantRaw:      "DEL session:123",
		},
		{
			name:         "inline without CRLF",
			input:        "GET noterm",
			wantVerb:     "get",
			wantResource: "noterm",
			wantRaw:      "GET noterm",
		},
		{
			name:    "empty input",
			input:   "",
			wantNil: true,
		},
		{
			name:    "only whitespace",
			input:   "   \r\n",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := ParseRedisCommand([]byte(tt.input))
			if tt.wantNil {
				if op != nil {
					t.Fatalf("expected nil, got %+v", op)
				}
				return
			}
			if op == nil {
				t.Fatal("expected non-nil Operation")
			}
			if op.Protocol != "redis" {
				t.Errorf("Protocol = %q, want %q", op.Protocol, "redis")
			}
			if op.Service != "redis" {
				t.Errorf("Service = %q, want %q", op.Service, "redis")
			}
			if op.Verb != tt.wantVerb {
				t.Errorf("Verb = %q, want %q", op.Verb, tt.wantVerb)
			}
			if op.ResourceName != tt.wantResource {
				t.Errorf("ResourceName = %q, want %q", op.ResourceName, tt.wantResource)
			}
			if op.RawQuery != tt.wantRaw {
				t.Errorf("RawQuery = %q, want %q", op.RawQuery, tt.wantRaw)
			}
		})
	}
}

func TestParseRedisCommand_RESPArray(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantNil      bool
		wantVerb     string
		wantResource string
		wantResType  string
		wantRaw      string
	}{
		{
			name:         "RESP GET",
			input:        "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n",
			wantVerb:     "get",
			wantResource: "key",
			wantResType:  "keys",
			wantRaw:      "GET key",
		},
		{
			name:         "RESP SET with value",
			input:        "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n",
			wantVerb:     "set",
			wantResource: "mykey",
			wantResType:  "keys",
			wantRaw:      "SET mykey myvalue",
		},
		{
			name:         "RESP HSET",
			input:        "*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n$5\r\nvalue\r\n",
			wantVerb:     "set",
			wantResource: "myhash",
			wantResType:  "keys",
			wantRaw:      "HSET myhash field value",
		},
		{
			name:         "RESP PUBLISH",
			input:        "*3\r\n$7\r\nPUBLISH\r\n$5\r\nnews1\r\n$11\r\nhello world\r\n",
			wantVerb:     "pubsub",
			wantResource: "news1",
			wantResType:  "channels",
			wantRaw:      "PUBLISH news1 hello world",
		},
		{
			name:         "RESP FLUSHALL",
			input:        "*1\r\n$8\r\nFLUSHALL\r\n",
			wantVerb:     "admin",
			wantResource: "",
			wantResType:  "server",
			wantRaw:      "FLUSHALL",
		},
		{
			name:         "RESP EVAL",
			input:        "*3\r\n$4\r\nEVAL\r\n$19\r\nreturn redis.call()\r\n$1\r\n0\r\n",
			wantVerb:     "eval",
			wantResource: "return redis.call()",
			wantResType:  "keys",
			wantRaw:      "EVAL return redis.call() 0",
		},
		{
			name:    "malformed RESP - bad count",
			input:   "*abc\r\n",
			wantNil: true,
		},
		{
			name:    "malformed RESP - zero count",
			input:   "*0\r\n",
			wantNil: true,
		},
		{
			name:    "malformed RESP - truncated bulk string",
			input:   "*1\r\n$10\r\nshort\r\n",
			wantNil: true,
		},
		{
			name:    "malformed RESP - missing dollar sign",
			input:   "*1\r\nGET\r\n",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := ParseRedisCommand([]byte(tt.input))
			if tt.wantNil {
				if op != nil {
					t.Fatalf("expected nil, got %+v", op)
				}
				return
			}
			if op == nil {
				t.Fatal("expected non-nil Operation")
			}
			if op.Verb != tt.wantVerb {
				t.Errorf("Verb = %q, want %q", op.Verb, tt.wantVerb)
			}
			if op.ResourceName != tt.wantResource {
				t.Errorf("ResourceName = %q, want %q", op.ResourceName, tt.wantResource)
			}
			if op.ResourceType != tt.wantResType {
				t.Errorf("ResourceType = %q, want %q", op.ResourceType, tt.wantResType)
			}
			if op.RawQuery != tt.wantRaw {
				t.Errorf("RawQuery = %q, want %q", op.RawQuery, tt.wantRaw)
			}
		})
	}
}

func TestParseRedisCommand_VerbCategories(t *testing.T) {
	// Test one command from each verb category via inline format.
	tests := []struct {
		cmd      string
		wantVerb string
		wantType string
	}{
		{"GET key", "get", "keys"},
		{"MGET k1 k2", "get", "keys"},
		{"HGETALL hash", "get", "keys"},
		{"LRANGE list 0 -1", "get", "keys"},
		{"SMEMBERS set", "get", "keys"},
		{"ZRANGE zs 0 -1", "get", "keys"},
		{"SCAN 0", "get", "keys"},
		{"KEYS *", "get", "keys"},
		{"TYPE key", "get", "keys"},
		{"TTL key", "get", "keys"},

		{"SET key val", "set", "keys"},
		{"MSET k1 v1 k2 v2", "set", "keys"},
		{"HSET h f v", "set", "keys"},
		{"LPUSH list val", "set", "keys"},
		{"RPUSH list val", "set", "keys"},
		{"SADD set m", "set", "keys"},
		{"ZADD zs 1 m", "set", "keys"},
		{"SETNX key val", "set", "keys"},
		{"SETEX key 60 val", "set", "keys"},
		{"INCR counter", "set", "keys"},
		{"DECR counter", "set", "keys"},
		{"APPEND key more", "set", "keys"},

		{"DEL key", "delete", "keys"},
		{"HDEL hash field", "delete", "keys"},
		{"LREM list 0 val", "delete", "keys"},
		{"SREM set member", "delete", "keys"},
		{"ZREM zs member", "delete", "keys"},
		{"EXPIRE key 60", "delete", "keys"},
		{"EXPIREAT key 1234567890", "delete", "keys"},
		{"UNLINK key", "delete", "keys"},

		{"FLUSHDB", "admin", "server"},
		{"FLUSHALL", "admin", "server"},
		{"CONFIG GET maxmemory", "admin", "server"},
		{"SHUTDOWN NOSAVE", "admin", "server"},
		{"DEBUG SLEEP 0", "admin", "server"},
		{"SLAVEOF NO ONE", "admin", "server"},
		{"REPLICAOF NO ONE", "admin", "server"},
		{"CLUSTER INFO", "admin", "server"},

		{"PUBLISH chan msg", "pubsub", "channels"},
		{"SUBSCRIBE chan", "pubsub", "channels"},
		{"PSUBSCRIBE chan*", "pubsub", "channels"},
		{"UNSUBSCRIBE chan", "pubsub", "channels"},

		{"EVAL script 0", "eval", "keys"},
		{"EVALSHA sha1 0", "eval", "keys"},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			op := ParseRedisCommand([]byte(tt.cmd + "\r\n"))
			if op == nil {
				t.Fatal("expected non-nil Operation")
			}
			if op.Verb != tt.wantVerb {
				t.Errorf("Verb = %q, want %q", op.Verb, tt.wantVerb)
			}
			if op.ResourceType != tt.wantType {
				t.Errorf("ResourceType = %q, want %q", op.ResourceType, tt.wantType)
			}
		})
	}
}

func TestParseRedisCommand_UnknownCommand(t *testing.T) {
	op := ParseRedisCommand([]byte("XYZZY foo\r\n"))
	if op == nil {
		t.Fatal("expected non-nil Operation for unknown command")
	}
	if op.Verb != "xyzzy" {
		t.Errorf("Verb = %q, want %q", op.Verb, "xyzzy")
	}
	if op.ResourceType != "keys" {
		t.Errorf("ResourceType = %q, want %q for unknown command", op.ResourceType, "keys")
	}
}

func TestParseRedisCommand_NilInput(t *testing.T) {
	op := ParseRedisCommand(nil)
	if op != nil {
		t.Fatalf("expected nil for nil input, got %+v", op)
	}
}
