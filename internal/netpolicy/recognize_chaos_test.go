package netpolicy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// chaosMustNotPanic wraps fn in a deferred recover, failing t if a panic occurs.
// Returns true if a panic was caught.
func chaosMustNotPanic(t *testing.T, label string, fn func()) (panicked bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			t.Errorf("PANIC in %s: %v", label, r)
		}
	}()
	fn()
	return false
}

// ---------------------------------------------------------------------------
// Test 12: recognize_ssh.go — adversarial SSH banners
// ---------------------------------------------------------------------------

func TestChaosSSH_BannerNoNewline(t *testing.T) {
	// Valid SSH prefix but no \n anywhere. Under 255 bytes should still parse.
	banners := []struct {
		name    string
		banner  string
		wantNil bool
	}{
		{
			name:    "valid_no_newline_short",
			banner:  "SSH-2.0-OpenSSH_9.6",
			wantNil: false, // should parse OK (partial read accepted)
		},
		{
			name:    "valid_no_newline_254bytes",
			banner:  "SSH-2.0-" + strings.Repeat("A", 246), // 254 bytes total
			wantNil: false,
		},
		{
			name:    "valid_no_newline_255bytes",
			banner:  "SSH-2.0-" + strings.Repeat("B", 247), // 255 bytes total
			wantNil: false,
		},
		{
			name:    "valid_no_newline_256bytes",
			banner:  "SSH-2.0-" + strings.Repeat("C", 248), // 256 bytes total → rejected
			wantNil: true,
		},
		{
			name:    "valid_no_newline_1000bytes",
			banner:  "SSH-2.0-" + strings.Repeat("D", 992), // 1000 bytes, no newline → rejected
			wantNil: true,
		},
	}

	for _, tc := range banners {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.banner)
			chaosMustNotPanic(t, tc.name, func() {
				op := ParseSSHVersion(data, "host:22")
				if tc.wantNil && op != nil {
					t.Errorf("expected nil for %s (len=%d, no newline), got %+v", tc.name, len(data), op)
				}
				if !tc.wantNil && op == nil {
					t.Errorf("expected non-nil for %s (len=%d, no newline), got nil", tc.name, len(data))
				}
			})
		})
	}
}

func TestChaosSSH_BannerOnlyCR(t *testing.T) {
	// Banners ending with \r but no \n. The code searches for \n (not \r),
	// so it falls into the "no newline" path. TrimRight removes the \r.
	cases := []struct {
		name   string
		banner string
	}{
		{"valid_CR_only", "SSH-2.0-OpenSSH_9.6\r"},
		{"valid_CR_only_with_comment", "SSH-2.0-OpenSSH_9.6 Ubuntu-1\r"},
		{"CR_at_position_255", "SSH-2.0-" + strings.Repeat("E", 245) + "\r"}, // 254 bytes
		{"CR_at_position_256", "SSH-2.0-" + strings.Repeat("F", 246) + "\r"}, // 255 bytes
		{"CR_at_position_257", "SSH-2.0-" + strings.Repeat("G", 247) + "\r"}, // 256 bytes → >255 → nil
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.banner)
			chaosMustNotPanic(t, tc.name, func() {
				op := ParseSSHVersion(data, "host:22")
				t.Logf("SSH CR-only %s (len=%d): op=%v", tc.name, len(data), op)
			})
		})
	}
}

func TestChaosSSH_BannerOver255Bytes(t *testing.T) {
	// Banners longer than 255 bytes. Without a newline they should return nil.
	// With a newline before byte 255, the line is extracted and can be long.
	cases := []struct {
		name    string
		banner  []byte
		wantNil bool
	}{
		{
			name:    "256bytes_no_newline",
			banner:  []byte("SSH-2.0-" + strings.Repeat("X", 248)),
			wantNil: true,
		},
		{
			name:    "1024bytes_no_newline",
			banner:  []byte("SSH-2.0-" + strings.Repeat("Y", 1016)),
			wantNil: true,
		},
		{
			// Newline within 255 bytes; line itself is valid.
			name:   "newline_at_byte_20",
			banner: append([]byte("SSH-2.0-OpenSSH_9.6\r\n"), make([]byte, 300)...),
		},
		{
			// Banner starts with SSH- but the segment before \n is >255 bytes.
			// The line should still be extracted normally (only the no-newline path
			// has a 255-byte cap).
			name:   "newline_after_256_bytes",
			banner: []byte("SSH-2.0-" + strings.Repeat("Z", 248) + "\r\n"),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			chaosMustNotPanic(t, tc.name, func() {
				op := ParseSSHVersion(tc.banner, "host:22")
				if tc.wantNil && op != nil {
					t.Errorf("%s: expected nil for >255 bytes without newline, got %+v", tc.name, op)
				}
				t.Logf("SSH >255 %s: op=%v", tc.name, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 13: recognize_postgres.go — startup message with zero/negative length
// ---------------------------------------------------------------------------

func TestChaosPostgres_StartupZeroLength(t *testing.T) {
	// Startup message with length field = 0. The length field includes itself (4
	// bytes), so 0 is invalid. tryParseStartup checks length < 8, which catches
	// this case.
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:4], 0)            // length = 0
	binary.BigEndian.PutUint32(data[4:8], pgStartupVersion) // correct version

	chaosMustNotPanic(t, "startup_zero_length", func() {
		op := ParsePostgresMessage(data)
		// With length=0, tryParseStartup returns nil (length < 8).
		// Then regular message path: msgType=data[0]=0, msgLen=BigEndian(data[1:5]).
		// data[1:5] = [0,0,0,0x03] (high bytes of 0 + low bytes of 196608).
		// This tests the boundary condition.
		t.Logf("startup zero length: op=%v", op)
	})
}

func TestChaosPostgres_StartupNegativeLengthEncoded(t *testing.T) {
	// Encode "negative" lengths as 2's-complement uint32 values.
	// On 64-bit Go, int(uint32) is always positive, but large values may still
	// trigger boundary errors downstream.
	negativeLengths := []uint32{
		0x80000000, // -2147483648 when interpreted as int32
		0xFFFFFFFF, // -1 as int32; 4294967295 as uint32
		0xFFFFFFF0,
	}

	for _, l := range negativeLengths {
		l := l
		t.Run(fmt.Sprintf("len_0x%08X", l), func(t *testing.T) {
			data := make([]byte, 64)
			binary.BigEndian.PutUint32(data[0:4], l)
			binary.BigEndian.PutUint32(data[4:8], pgStartupVersion)

			chaosMustNotPanic(t, fmt.Sprintf("startup_len_0x%08X", l), func() {
				op := ParsePostgresMessage(data)
				t.Logf("startup negative-encoded length 0x%08X: op=%v", l, op)
			})
		})
	}
}

func TestChaosPostgres_RegularMsgSmallLen(t *testing.T) {
	// Regular message (non-startup) with msgLen field set to small values 0–3.
	// The length field encodes (len - 4) bytes of payload, so values < 4 are
	// invalid. data[5 : 1+msgLen] panics when msgLen < 4 because 1+msgLen < 5.
	for msgLen := uint32(0); msgLen <= 3; msgLen++ {
		msgLen := msgLen
		t.Run(fmt.Sprintf("Q_msgLen_%d", msgLen), func(t *testing.T) {
			data := make([]byte, 64)
			data[0] = 'Q' // SimpleQuery — a recognized type that reaches payload slicing.
			binary.BigEndian.PutUint32(data[1:5], msgLen)

			chaosMustNotPanic(t, fmt.Sprintf("postgres_Q_msgLen_%d", msgLen), func() {
				op := ParsePostgresMessage(data)
				t.Logf("Q msgLen=%d: op=%v", msgLen, op)
			})
		})
	}

	// Same for Parse ('P') and Terminate ('X').
	for _, msgType := range []byte{'P', 'X'} {
		for msgLen := uint32(0); msgLen <= 3; msgLen++ {
			msgType, msgLen := msgType, msgLen
			t.Run(fmt.Sprintf("%c_msgLen_%d", msgType, msgLen), func(t *testing.T) {
				data := make([]byte, 64)
				data[0] = msgType
				binary.BigEndian.PutUint32(data[1:5], msgLen)

				chaosMustNotPanic(t, fmt.Sprintf("postgres_%c_msgLen_%d", msgType, msgLen), func() {
					op := ParsePostgresMessage(data)
					t.Logf("%c msgLen=%d: op=%v", msgType, msgLen, op)
				})
			})
		}
	}
}

func TestChaosPostgres_AllZeroData(t *testing.T) {
	sizes := []int{4, 5, 8, 16, 64, 1024, 10 * 1024}
	for _, sz := range sizes {
		sz := sz
		t.Run(fmt.Sprintf("zeros_%d_bytes", sz), func(t *testing.T) {
			data := make([]byte, sz)
			chaosMustNotPanic(t, fmt.Sprintf("postgres_zeros_%d", sz), func() {
				op := ParsePostgresMessage(data)
				t.Logf("zeros %d bytes: op=%v", sz, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 14: recognize_redis.go — RESP with missing CRLF / only LF
// ---------------------------------------------------------------------------

func TestChaosRedis_MissingCRLF(t *testing.T) {
	// RESP array header without \r\n — parseRESPArray requires \r\n to find the count.
	cases := []struct {
		name    string
		input   []byte
		wantNil bool
	}{
		{
			name:    "no_CRLF_at_all",
			input:   []byte("*2"),
			wantNil: true,
		},
		{
			name:    "only_LF_no_CR",
			input:   []byte("*2\n$3\nGET\n$3\nfoo\n"),
			wantNil: true, // parseRESPArray looks for \r\n, not \n alone
		},
		{
			name:    "LF_only_count_line",
			input:   []byte("*2\n$3\r\nGET\r\n$3\r\nfoo\r\n"),
			wantNil: true, // count line lacks \r\n
		},
		{
			name:    "CR_only_count_line",
			input:   []byte("*2\r$3\r\nGET\r\n$3\r\nfoo\r\n"),
			wantNil: true, // \r without \n in count line
		},
		{
			name:  "valid_CRLF_for_comparison",
			input: []byte("*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n"),
			// Should parse successfully.
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			chaosMustNotPanic(t, tc.name, func() {
				op := ParseRedisCommand(tc.input)
				if tc.wantNil && op != nil {
					t.Errorf("%s: expected nil, got %+v", tc.name, op)
				}
				if !tc.wantNil && op == nil {
					t.Errorf("%s: expected non-nil, got nil", tc.name)
				}
				t.Logf("Redis %s: op=%v", tc.name, op)
			})
		})
	}
}

func TestChaosRedis_InlineOnlyLF(t *testing.T) {
	// Inline commands terminated with \n instead of \r\n.
	// parseInlineCommand strips \r\n but falls back to the full line if not found.
	// strings.Fields splits on any whitespace including \n, so "GET foo\n" should work.
	cases := []struct {
		name    string
		input   []byte
		wantNil bool
	}{
		{
			name:    "inline_LF_only",
			input:   []byte("GET foo\n"),
			wantNil: false, // inline parser should handle LF-only lines
		},
		{
			name:    "inline_LF_only_no_args",
			input:   []byte("FLUSHALL\n"),
			wantNil: false,
		},
		{
			name:    "inline_bare_LF",
			input:   []byte("\n"),
			wantNil: true,
		},
		{
			name:    "inline_space_then_LF",
			input:   []byte("   \n"),
			wantNil: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			chaosMustNotPanic(t, tc.name, func() {
				op := ParseRedisCommand(tc.input)
				if tc.wantNil && op != nil {
					t.Errorf("%s: expected nil, got %+v", tc.name, op)
				}
				if !tc.wantNil && op == nil {
					t.Errorf("%s: expected non-nil for %q, got nil", tc.name, tc.input)
				}
			})
		})
	}
}

func TestChaosRedis_HugeArrayCount(t *testing.T) {
	// A RESP count that is astronomically large causes make([]string, 0, count)
	// to attempt a multi-gigabyte allocation. The parser must guard against this.
	cases := []struct {
		name  string
		input []byte
	}{
		{"count_1billion", []byte("*1000000000\r\n$3\r\nGET\r\n")},
		{"count_max_int32", []byte("*2147483647\r\n$3\r\nGET\r\n")},
		{"count_max_uint32", []byte("*4294967295\r\n$3\r\nGET\r\n")},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			chaosMustNotPanic(t, tc.name, func() {
				op := ParseRedisCommand(tc.input)
				// Huge count should not OOM — nil is the expected safe result.
				if op != nil {
					t.Logf("%s: parsed with huge count (op=%+v)", tc.name, op)
				}
			})
		})
	}
}

func TestChaosRedis_BulkStringNegativeLen(t *testing.T) {
	// RESP bulk string with a negative length: $-1 is "null bulk string" in RESP3,
	// but the parser should handle it without panicking.
	cases := []struct {
		name  string
		input []byte
	}{
		{"null_bulk_string", []byte("*1\r\n$-1\r\n")},
		{"negative_len_minus_100", []byte("*1\r\n$-100\r\ndata\r\n")},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			chaosMustNotPanic(t, tc.name, func() {
				op := ParseRedisCommand(tc.input)
				t.Logf("Redis %s: op=%v", tc.name, op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Test 15: recognize_mongo.go — OP_MSG with length < header size
// ---------------------------------------------------------------------------

func TestChaosMongoOPMsg_LengthLessThanHeader(t *testing.T) {
	const opMsgOpcodeVal = 2013
	const mongoHdrSize = 16

	cases := []struct {
		name      string
		msgLen    uint32 // value written into the length field
		totalData int    // total bytes in the buffer
	}{
		{"msgLen_0", 0, mongoHdrSize + 10},
		{"msgLen_1", 1, mongoHdrSize + 10},
		{"msgLen_4", 4, mongoHdrSize + 10},
		{"msgLen_15", 15, mongoHdrSize + 10},        // one less than header size
		{"msgLen_16", 16, mongoHdrSize + 10},        // exactly header — no room for flagBits+section
		{"msgLen_20", 20, mongoHdrSize + 10},        // header + flagBits, no section byte
		{"msgLen_equals_total", uint32(mongoHdrSize + 10), mongoHdrSize + 10}, // msgLen = total, just barely
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.totalData)
			binary.LittleEndian.PutUint32(buf[0:4], tc.msgLen)
			binary.LittleEndian.PutUint32(buf[12:16], uint32(opMsgOpcodeVal))

			chaosMustNotPanic(t, tc.name, func() {
				op := ParseMongoMessage(buf)
				t.Logf("Mongo %s (msgLen=%d, bufLen=%d): op=%v", tc.name, tc.msgLen, tc.totalData, op)
			})
		})
	}
}

func TestChaosMongoOPMsg_TruncatedAtEachByte(t *testing.T) {
	// Build a valid OP_MSG message and then present it truncated at each byte
	// boundary to ensure no panic occurs.
	bsonTypeString := byte(0x02)
	buildStr := func(key, val string) []byte {
		var b []byte
		b = append(b, bsonTypeString)
		b = append(b, []byte(key)...)
		b = append(b, 0x00)
		lenbuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenbuf, uint32(len(val)+1))
		b = append(b, lenbuf...)
		b = append(b, []byte(val)...)
		b = append(b, 0x00)
		return b
	}

	var body []byte
	body = append(body, buildStr("find", "col")...)
	body = append(body, buildStr("$db", "test")...)
	body = append(body, 0x00)
	docLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(docLen, uint32(4+len(body)))
	bsonDoc := append(docLen, body...)

	const opMsgOpcodeConst = 2013
	const hdrSizeConst = 16
	totalLen := hdrSizeConst + 4 + 1 + len(bsonDoc)
	fullMsg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(fullMsg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(fullMsg[4:8], 1)
	binary.LittleEndian.PutUint32(fullMsg[8:12], 0)
	binary.LittleEndian.PutUint32(fullMsg[12:16], opMsgOpcodeConst)
	binary.LittleEndian.PutUint32(fullMsg[16:20], 0)
	fullMsg[20] = 0
	copy(fullMsg[21:], bsonDoc)

	for i := 0; i < len(fullMsg); i++ {
		i := i
		chaosMustNotPanic(t, fmt.Sprintf("mongo_truncated_at_%d", i), func() {
			ParseMongoMessage(fullMsg[:i])
		})
	}
}

func TestChaosMongoOPMsg_AllZeroData(t *testing.T) {
	sizes := []int{0, 1, 4, 8, 15, 16, 17, 20, 21, 64, 1024}
	for _, sz := range sizes {
		sz := sz
		t.Run(fmt.Sprintf("zeros_%d_bytes", sz), func(t *testing.T) {
			data := make([]byte, sz)
			chaosMustNotPanic(t, fmt.Sprintf("mongo_zeros_%d", sz), func() {
				op := ParseMongoMessage(data)
				t.Logf("Mongo zeros %d bytes: op=%v", sz, op)
			})
		})
	}
}

func TestChaosMongoOPMsg_LengthClaimsMoreThanAvailable(t *testing.T) {
	// msgLen field claims 4GB but the actual buffer is only 100 bytes.
	const opMsgOpcodeConst = 2013
	cases := []uint32{
		0xFFFFFFFF,
		0x80000000,
		1000000,
	}

	for _, claimedLen := range cases {
		claimedLen := claimedLen
		t.Run(fmt.Sprintf("claimed_0x%08X", claimedLen), func(t *testing.T) {
			buf := make([]byte, 100)
			binary.LittleEndian.PutUint32(buf[0:4], claimedLen)
			binary.LittleEndian.PutUint32(buf[12:16], uint32(opMsgOpcodeConst))

			chaosMustNotPanic(t, fmt.Sprintf("mongo_claimed_0x%08X", claimedLen), func() {
				op := ParseMongoMessage(buf)
				if op != nil {
					t.Errorf("expected nil when msgLen claims more than available, got %+v", op)
				}
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Additional: SSH garbage / binary data
// ---------------------------------------------------------------------------

func TestChaosSSH_BinaryData(t *testing.T) {
	// Non-SSH binary payloads delivered to the SSH parser.
	payloads := [][]byte{
		make([]byte, 0),
		make([]byte, 1),
		make([]byte, 255),
		make([]byte, 1024),
		{0xFF, 0xFF, 0xFF, 0xFF},
		[]byte("SSH"), // only 3 bytes (too short for "SSH-")
		[]byte("SSH-"), // 4 bytes, prefix matches but no content
		[]byte("SSH-\r\n"),
		[]byte("SSH-2.0\r\n"),   // missing software version dash
		[]byte("SSH-2.0-\r\n"),  // empty software version
		[]byte("SSH--version\r\n"), // empty proto version
	}

	for i, p := range payloads {
		p := p
		label := fmt.Sprintf("payload_%d_len_%d", i, len(p))
		t.Run(label, func(t *testing.T) {
			chaosMustNotPanic(t, label, func() {
				op := ParseSSHVersion(p, "host:22")
				t.Logf("SSH binary payload[%d] len=%d: op=%v", i, len(p), op)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Additional: Postgres binary fuzz data
// ---------------------------------------------------------------------------

func TestChaosPostgres_BinaryFuzz(t *testing.T) {
	// Various byte patterns that might trigger boundary conditions.
	patterns := [][]byte{
		{0x51, 0x00, 0x00, 0x00, 0x00}, // Q + msgLen=0 → panic candidate
		{0x51, 0x00, 0x00, 0x00, 0x01}, // Q + msgLen=1 → panic candidate
		{0x51, 0x00, 0x00, 0x00, 0x02}, // Q + msgLen=2 → panic candidate
		{0x51, 0x00, 0x00, 0x00, 0x03}, // Q + msgLen=3 → panic candidate
		{0x51, 0x00, 0x00, 0x00, 0x04}, // Q + msgLen=4 → boundary (empty payload)
		{0x50, 0x00, 0x00, 0x00, 0x00}, // P + msgLen=0 → panic candidate
		{0x58, 0x00, 0x00, 0x00, 0x00}, // X + msgLen=0 → panic candidate
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		bytes.Repeat([]byte{0xAA}, 32),
		bytes.Repeat([]byte{0x55}, 32),
	}

	for i, p := range patterns {
		p := p
		label := fmt.Sprintf("fuzz_%d", i)
		t.Run(label, func(t *testing.T) {
			// Need at least 5 bytes for the regular message path.
			data := make([]byte, max5(len(p), 64))
			copy(data, p)

			chaosMustNotPanic(t, label, func() {
				op := ParsePostgresMessage(data)
				t.Logf("Postgres fuzz[%d]: input=% x: op=%v", i, p, op)
			})
		})
	}
}

func max5(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Additional: Redis deeply nested arrays (100 levels)
// ---------------------------------------------------------------------------

func TestChaosRedis_DeeplyNestedArrays(t *testing.T) {
	const depth = 100

	// Build 100-deep nested RESP arrays.
	var buf bytes.Buffer
	for i := 0; i < depth; i++ {
		buf.WriteString("*1\r\n")
	}
	// Innermost element.
	buf.WriteString("$3\r\nGET\r\n")

	chaosMustNotPanic(t, "nested_100_levels", func() {
		op := ParseRedisCommand(buf.Bytes())
		// The parser does not handle recursive RESP; nil is expected.
		t.Logf("Redis 100-level nested array: op=%v", op)
	})
}
