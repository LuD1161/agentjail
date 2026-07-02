package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// mustNotPanic wraps a function call in a deferred recover and marks the test
// as failed (rather than crashing) if a panic occurs. Returns true if no panic.
func mustNotPanic(t *testing.T, name string, fn func()) (panicked bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			t.Errorf("ChaosTest %s: unexpected panic: %v", name, r)
		}
	}()
	fn()
	return false
}

// ---------------------------------------------------------------------------
// Helpers to build protocol messages for tests
// ---------------------------------------------------------------------------

// chaosValidPGStartup builds a minimal valid PostgreSQL v3 startup message.
func chaosValidPGStartup() []byte {
	// pgStartupVersion = 196608 = 0x00030000
	const pgVer uint32 = 196608
	var body []byte
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, pgVer)
	body = append(body, v...)
	body = append(body, []byte("user\x00chaos\x00database\x00test\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+4))
	return append(hdr, body...)
}

// chaosValidMongoMsg builds a minimal valid MongoDB OP_MSG message with a
// trivial BSON body (find command).
func chaosValidMongoMsg() []byte {
	// Build BSON document: {find: "col", $db: "test"}
	bsonTypeString := byte(0x02)
	buildBSONStr := func(key, val string) []byte {
		var b []byte
		b = append(b, bsonTypeString)
		b = append(b, []byte(key)...)
		b = append(b, 0x00)
		strBytes := []byte(val)
		lenbuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenbuf, uint32(len(strBytes)+1))
		b = append(b, lenbuf...)
		b = append(b, strBytes...)
		b = append(b, 0x00)
		return b
	}
	var body []byte
	body = append(body, buildBSONStr("find", "col")...)
	body = append(body, buildBSONStr("$db", "test")...)
	body = append(body, 0x00) // BSON document terminator
	docLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(docLen, uint32(4+len(body)))
	bsonDoc := append(docLen, body...)

	// Build OP_MSG: header(16) + flagBits(4) + kind(1) + bsonDoc
	const opMsgOpcode = 2013
	const mongoHeaderSize = 16
	totalLen := mongoHeaderSize + 4 + 1 + len(bsonDoc)
	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[4:8], 1)
	binary.LittleEndian.PutUint32(msg[8:12], 0)
	binary.LittleEndian.PutUint32(msg[12:16], opMsgOpcode)
	binary.LittleEndian.PutUint32(msg[16:20], 0) // flagBits
	msg[20] = 0                                   // Kind 0
	copy(msg[21:], bsonDoc)
	return msg
}

// chaosValidSSHBanner builds a valid SSH-2.0 version banner.
func chaosValidSSHBanner() []byte {
	return []byte("SSH-2.0-OpenSSH_9.6\r\n")
}

// chaosValidRedisREQ builds a valid Redis RESP GET command.
func chaosValidRedisREQ() []byte {
	return []byte("*2\r\n$3\r\nGET\r\n$6\r\nmykey1\r\n")
}

// ---------------------------------------------------------------------------
// Test 1: Known protocol prefix with 1 byte missing (truncated)
// ---------------------------------------------------------------------------

func TestChaos_TruncatedProtocolPrefix(t *testing.T) {
	fullMessages := []struct {
		name string
		port int
		data []byte
	}{
		{"SSH", 22, chaosValidSSHBanner()},
		{"Redis", 6379, chaosValidRedisREQ()},
		{"Postgres", 5432, chaosValidPGStartup()},
		{"Mongo", 27017, chaosValidMongoMsg()},
	}

	for _, tc := range fullMessages {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.data) < 2 {
				t.Skip("message too short to truncate")
			}
			truncated := tc.data[:len(tc.data)-1]
			mustNotPanic(t, tc.name+"_truncated", func() {
				op := netpolicy.RecognizeTCP("host.example.com", tc.port, truncated)
				t.Logf("truncated %s: op=%v", tc.name, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 2: Protocol prefix followed by 10MB of zeros
// ---------------------------------------------------------------------------

func TestChaos_ProtocolPrefix_Followed_By_10MB_Zeros(t *testing.T) {
	zeros := make([]byte, 10*1024*1024)

	cases := []struct {
		name   string
		port   int
		prefix []byte
	}{
		{"SSH+zeros", 22, []byte("SSH-2.0-")},
		{"Redis+zeros", 6379, []byte("*1\r\n")},
		{"Postgres+zeros", 5432, []byte{0x00, 0x00, 0x00, 0x00}},
		{"Mongo+zeros", 27017, []byte{0x00, 0x00, 0x00, 0x00}},
		{"AllZeros_Postgres", 5432, nil},
		{"AllZeros_Redis", 6379, nil},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data := append(tc.prefix, zeros...)
			mustNotPanic(t, tc.name, func() {
				op := netpolicy.RecognizeTCP("host.example.com", tc.port, data)
				t.Logf("%s: op=%v", tc.name, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 3: Empty buffer (0 bytes)
// ---------------------------------------------------------------------------

func TestChaos_EmptyBuffer(t *testing.T) {
	ports := []int{22, 5432, 6379, 27017, 443, 80, 8080}
	for _, port := range ports {
		port := port
		t.Run(fmt.Sprintf("port_%d", port), func(t *testing.T) {
			mustNotPanic(t, fmt.Sprintf("empty_port_%d", port), func() {
				op := netpolicy.RecognizeTCP("host", port, []byte{})
				t.Logf("port %d empty buffer: op=%v", port, op)
			})
		})
	}

	// Also test nil input.
	t.Run("nil_input", func(t *testing.T) {
		for _, port := range ports {
			mustNotPanic(t, "nil", func() {
				netpolicy.RecognizeTCP("host", port, nil)
			})
		}
	})
}

// ---------------------------------------------------------------------------
// Test 4: Single byte for each possible value 0x00–0xFF
// ---------------------------------------------------------------------------

func TestChaos_SingleByteAllValues(t *testing.T) {
	ports := []int{22, 5432, 6379, 27017}
	for _, port := range ports {
		port := port
		for b := 0; b <= 255; b++ {
			b := b
			mustNotPanic(t, fmt.Sprintf("port%d_byte0x%02X", port, b), func() {
				netpolicy.RecognizeTCP("host", port, []byte{byte(b)})
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Test 5: Valid HTTP method followed by null bytes
// ---------------------------------------------------------------------------

func TestChaos_HTTPMethod_NullBytes(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT"}
	ports := []int{22, 5432, 6379, 27017, 80, 443}

	for _, method := range methods {
		for _, port := range ports {
			method, port := method, port
			name := fmt.Sprintf("%s_port%d", method, port)
			t.Run(name, func(t *testing.T) {
				// HTTP method + 256 null bytes
				data := append([]byte(method), make([]byte, 256)...)
				mustNotPanic(t, name, func() {
					op := netpolicy.RecognizeTCP("host", port, data)
					t.Logf("%s: op=%v", name, op)
				})
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Test 6: SSH banner with version string >1000 chars
// ---------------------------------------------------------------------------

func TestChaos_SSH_BannerVersionOver1000Chars(t *testing.T) {
	// SSH version strings longer than 255 bytes without a newline are rejected.
	// But with a newline the line length is unbounded — check that parsing
	// doesn't allocate proportionally to the input size.
	cases := []struct {
		name    string
		banner  []byte
		wantNil bool
	}{
		{
			name:    "1001_chars_no_newline",
			banner:  []byte("SSH-2.0-" + strings.Repeat("X", 993)), // total 1001, no \n
			wantNil: true,                                            // > 255 bytes with no newline
		},
		{
			name:   "1001_chars_with_crlf",
			banner: []byte("SSH-2.0-" + strings.Repeat("X", 993) + "\r\n"),
			// Has newline so line is extracted; should parse successfully.
		},
		{
			name:    "exactly_256_no_newline",
			banner:  []byte("SSH-2.0-" + strings.Repeat("Y", 248)),
			wantNil: true, // exactly 256 bytes > 255
		},
		{
			name:   "exactly_255_no_newline",
			banner: []byte("SSH-2.0-" + strings.Repeat("Z", 247)),
			// Exactly 255 bytes, no newline — should parse successfully.
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mustNotPanic(t, tc.name, func() {
				op := netpolicy.RecognizeTCP("ssh.example.com:22", 22, tc.banner)
				if tc.wantNil && op != nil {
					t.Errorf("expected nil for banner > 255 bytes without newline, got %+v", op)
				}
				t.Logf("%s: op=%v", tc.name, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 7: PostgreSQL startup message with length field claiming 4GB
// ---------------------------------------------------------------------------

func TestChaos_Postgres_4GBLengthClaim(t *testing.T) {
	cases := []struct {
		name    string
		lenVal  uint32
		version uint32
	}{
		// 4GB claim with correct version — must not panic or OOM.
		{"4GB_correct_version", 0xFFFFFFFF, 196608},
		// Zero length with correct version.
		{"zero_len_correct_version", 0, 196608},
		// 4GB claim with wrong version — must not panic.
		{"4GB_wrong_version", 0xFFFFFFFF, 0xDEADBEEF},
		// Minimum plausible large value.
		{"2GB_correct_version", 0x80000000, 196608},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Build an 8-byte header (length + version) with padding.
			buf := make([]byte, 1024)
			binary.BigEndian.PutUint32(buf[0:4], tc.lenVal)
			binary.BigEndian.PutUint32(buf[4:8], tc.version)

			mustNotPanic(t, tc.name, func() {
				op := netpolicy.RecognizeTCP("db.example.com", 5432, buf)
				t.Logf("%s: op=%v", tc.name, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 8: Redis RESP with deeply nested arrays (100 levels)
// ---------------------------------------------------------------------------

func TestChaos_Redis_DeeplyNestedArrays(t *testing.T) {
	const depth = 100

	// Build a RESP with 100 levels of nesting.
	// Each level: *1\r\n<next_level>
	// Innermost: $3\r\nGET\r\n
	var buf bytes.Buffer
	for i := 0; i < depth; i++ {
		buf.WriteString("*1\r\n")
	}
	buf.WriteString("$3\r\nGET\r\n")

	data := buf.Bytes()
	mustNotPanic(t, "nested_arrays_100", func() {
		op := netpolicy.RecognizeTCP("redis.example.com", 6379, data)
		// Parser doesn't handle recursive RESP; nil is expected and acceptable.
		t.Logf("nested arrays (100 levels): op=%v", op)
	})
}

// ---------------------------------------------------------------------------
// Test 8b: Redis RESP with enormous count (OOM attempt)
// ---------------------------------------------------------------------------

func TestChaos_Redis_HugeArrayCount(t *testing.T) {
	cases := []struct {
		name  string
		count string
	}{
		{"count_1GB", "1073741824"},
		{"count_max_int32", "2147483647"},
		{"count_10M", "10000000"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("*" + tc.count + "\r\n$3\r\nGET\r\n")
			mustNotPanic(t, "huge_count_"+tc.count, func() {
				op := netpolicy.RecognizeTCP("redis.example.com", 6379, data)
				// A huge count should result in nil (not OOM).
				t.Logf("huge count %s: op=%v", tc.count, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 9: TLS ClientHello with invalid version bytes
// ---------------------------------------------------------------------------

func TestChaos_TLS_InvalidVersionBytes(t *testing.T) {
	cases := []struct {
		name    string
		port    int
		payload []byte
	}{
		{
			name: "invalid_version_port_443",
			port: 443,
			// TLS record: type=0x16, version=0xFF 0xFF, length=0x00 0x05, ClientHello header.
			payload: []byte{0x16, 0xFF, 0xFF, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
		},
		{
			name:    "invalid_version_port_22",
			port:    22,
			payload: []byte{0x16, 0xFF, 0xFF, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
		},
		{
			name:    "invalid_version_port_5432",
			port:    5432,
			payload: []byte{0x16, 0xFF, 0xFF, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
		},
		{
			name: "all_0xFF",
			port: 443,
			payload: func() []byte {
				b := make([]byte, 256)
				for i := range b {
					b[i] = 0xFF
				}
				return b
			}(),
		},
		{
			name:    "zero_version_bytes",
			port:    443,
			payload: []byte{0x16, 0x00, 0x00, 0x00, 0x01, 0x01},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mustNotPanic(t, tc.name, func() {
				op := netpolicy.RecognizeTCP("host", tc.port, tc.payload)
				t.Logf("%s: op=%v", tc.name, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 10: Mixed protocol bytes (HTTP GET followed by SSH banner)
// ---------------------------------------------------------------------------

func TestChaos_MixedProtocolBytes(t *testing.T) {
	cases := []struct {
		name string
		port int
		data []byte
	}{
		{
			name: "HTTP_then_SSH",
			port: 22,
			data: append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), chaosValidSSHBanner()...),
		},
		{
			name: "SSH_then_HTTP",
			port: 5432,
			data: append(chaosValidSSHBanner(), []byte("GET / HTTP/1.1\r\n")...),
		},
		{
			name: "Redis_then_Postgres",
			port: 5432,
			data: append(chaosValidRedisREQ(), chaosValidPGStartup()...),
		},
		{
			name: "Postgres_then_Redis",
			port: 6379,
			data: append(chaosValidPGStartup(), chaosValidRedisREQ()...),
		},
		{
			name: "Mongo_then_SSH",
			port: 22,
			data: append(chaosValidMongoMsg(), chaosValidSSHBanner()...),
		},
		{
			name: "HTTP_null_then_SSH_port22",
			port: 22,
			data: append([]byte("GET\x00/\x00HTTP\x00"), chaosValidSSHBanner()...),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mustNotPanic(t, tc.name, func() {
				op := netpolicy.RecognizeTCP("host.example.com", tc.port, tc.data)
				t.Logf("%s: op=%v", tc.name, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 11: Concurrent detection calls with shared state
// ---------------------------------------------------------------------------

func TestChaos_ConcurrentDetection(t *testing.T) {
	const goroutines = 50
	const iterations = 100

	payloads := []struct {
		port int
		data []byte
	}{
		{22, chaosValidSSHBanner()},
		{5432, chaosValidPGStartup()},
		{6379, chaosValidRedisREQ()},
		{27017, chaosValidMongoMsg()},
		{22, []byte{}},
		{5432, make([]byte, 1024)}, // all zeros — exercises Postgres panic path
		{6379, []byte("*1073741824\r\n")},
	}

	var wg sync.WaitGroup
	panics := make(chan string, goroutines*len(payloads))

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics <- fmt.Sprintf("goroutine %d: panic: %v", id, r)
				}
			}()
			for iter := 0; iter < iterations; iter++ {
				for _, p := range payloads {
					netpolicy.RecognizeTCP("concurrent.example.com", p.port, p.data)
				}
			}
		}(i)
	}

	wg.Wait()
	close(panics)

	for msg := range panics {
		t.Errorf("concurrent panic: %s", msg)
	}
}

// ---------------------------------------------------------------------------
// Additional edge cases for ParsePostgresMessage msgLen < 4 (regression check)
// ---------------------------------------------------------------------------

func TestChaos_Postgres_SmallMsgLen(t *testing.T) {
	// When msgLen is < 4 (e.g. 0, 1, 2, 3), the code attempts data[5:1+msgLen]
	// where 1+msgLen < 5, causing a slice-bounds panic.
	for msgLen := 0; msgLen <= 3; msgLen++ {
		msgLen := msgLen
		t.Run(fmt.Sprintf("msgLen_%d", msgLen), func(t *testing.T) {
			// First byte: type 'Q' (SimpleQuery, recognized type that reaches payload slicing).
			data := make([]byte, 64)
			data[0] = 'Q'
			binary.BigEndian.PutUint32(data[1:5], uint32(msgLen))

			mustNotPanic(t, fmt.Sprintf("postgres_msgLen_%d", msgLen), func() {
				op := netpolicy.RecognizeTCP("db.host", 5432, data)
				t.Logf("postgres msgLen=%d: op=%v", msgLen, op)
			})
		})
	}
}
