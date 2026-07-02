package netpolicy

import (
	"encoding/binary"
	"encoding/json"
	"math"
)

// MongoDB wire protocol constants.
const (
	opMsgOpcode     = 2013
	mongoHeaderSize = 16 // messageLength(4) + requestID(4) + responseTo(4) + opCode(4)

	// BSON element types we handle.
	bsonTypeDouble = 0x01
	bsonTypeString = 0x02
	bsonTypeInt32  = 0x10
	bsonTypeInt64  = 0x12
)

// mongoVerbMap maps MongoDB command names to normalized verbs.
var mongoVerbMap = map[string]string{
	"find":            "get",
	"aggregate":       "get",
	"count":           "get",
	"distinct":        "get",
	"listCollections": "get",
	"listDatabases":   "get",
	"listIndexes":     "get",

	"insert":     "insert",
	"insertMany": "insert",

	"update":        "update",
	"updateMany":    "update",
	"updateOne":     "update",
	"findAndModify": "update",
	"replaceOne":    "update",

	"delete":     "delete",
	"deleteMany": "delete",
	"deleteOne":  "delete",

	"drop":         "drop",
	"dropDatabase": "drop",
	"dropIndexes":  "drop",

	"create":           "create",
	"createIndexes":    "create",
	"createCollection": "create",

	"shutdown": "admin",
	"killOp":   "admin",
	"fsync":    "admin",
	"validate": "admin",
}

// mongoResourceTypeMap maps specific command names to non-default resource types.
var mongoResourceTypeMap = map[string]string{
	"listDatabases": "databases",
	"dropDatabase":  "databases",

	"listIndexes":   "indexes",
	"dropIndexes":   "indexes",
	"createIndexes": "indexes",
}

// ParseMongoMessage parses a MongoDB OP_MSG wire protocol message and returns
// a normalized Operation. Returns nil if the data is too short, malformed,
// or not an OP_MSG (opcode 2013).
func ParseMongoMessage(data []byte) *Operation {
	if len(data) < mongoHeaderSize {
		return nil
	}

	// Parse MsgHeader.
	msgLen := int(binary.LittleEndian.Uint32(data[0:4]))
	opCode := int(binary.LittleEndian.Uint32(data[12:16]))

	if opCode != opMsgOpcode {
		return nil
	}

	// Validate messageLength: must fit header + flagBits + at least one section byte.
	if msgLen < mongoHeaderSize+4+1 || msgLen > len(data) {
		return nil
	}

	// Parse OP_MSG: flagBits (uint32) followed by sections.
	pos := mongoHeaderSize
	if pos+4 > msgLen {
		return nil
	}
	// Skip flagBits.
	pos += 4

	// Walk sections looking for Kind 0 (body).
	var bodyDoc []byte
	for pos < msgLen {
		if pos >= len(data) {
			break
		}
		kind := data[pos]
		pos++

		switch kind {
		case 0: // Kind 0: Body - a single BSON document.
			doc, n := readBSONDocument(data[pos:])
			if doc == nil {
				return nil
			}
			bodyDoc = doc
			pos += n

		case 1: // Kind 1: Document Sequence - int32 size + identifier + documents.
			if pos+4 > len(data) {
				return nil
			}
			sectionSize := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			if sectionSize < 4 || pos+sectionSize > len(data) {
				return nil
			}
			pos += sectionSize

		default:
			// Unknown section kind; stop parsing.
			return nil
		}
	}

	if bodyDoc == nil {
		return nil
	}

	// Extract fields from the BSON body document.
	fields := parseBSONFields(bodyDoc)
	if len(fields) == 0 {
		return nil
	}

	// The command name is the first key in the document.
	cmdName := fields[0].key
	cmdValueStr, _ := fields[0].value.(string)

	// Look up $db.
	db := ""
	for _, f := range fields {
		if f.key == "$db" {
			if s, ok := f.value.(string); ok {
				db = s
			}
			break
		}
	}

	verb, ok := mongoVerbMap[cmdName]
	if !ok {
		verb = "admin"
	}

	resourceType := mongoResourceTypeMap[cmdName]
	if resourceType == "" {
		resourceType = "collections"
	}

	// Build the raw query as JSON from the extracted fields.
	rawMap := make(map[string]any, len(fields))
	for _, f := range fields {
		rawMap[f.key] = f.value
	}
	rawJSON, _ := json.Marshal(rawMap)

	return &Operation{
		Protocol:     "mongodb",
		Service:      "mongodb",
		Verb:         verb,
		ResourceType: resourceType,
		ResourceName: cmdValueStr,
		Namespace:    db,
		RawQuery:     string(rawJSON),
	}
}

// bsonField holds a single key-value pair extracted from a BSON document.
type bsonField struct {
	key   string
	value any
}

// readBSONDocument reads a BSON document from the start of data and returns
// the raw bytes and the number of bytes consumed. Returns nil, 0 on error.
func readBSONDocument(data []byte) ([]byte, int) {
	if len(data) < 5 { // minimum: 4-byte length + 1-byte terminator
		return nil, 0
	}
	docLen := int(binary.LittleEndian.Uint32(data[0:4]))
	if docLen < 5 || docLen > len(data) {
		return nil, 0
	}
	// Verify null terminator.
	if data[docLen-1] != 0x00 {
		return nil, 0
	}
	return data[:docLen], docLen
}

// parseBSONFields extracts key-value pairs from a BSON document.
// Only handles types needed for MongoDB command parsing: string, double, int32, int64.
// Unknown types cause the parser to stop (we already have enough for command identification).
func parseBSONFields(doc []byte) []bsonField {
	if len(doc) < 5 {
		return nil
	}
	docLen := int(binary.LittleEndian.Uint32(doc[0:4]))
	if docLen < 5 || docLen > len(doc) {
		return nil
	}

	var fields []bsonField
	pos := 4 // skip length prefix

	for pos < docLen-1 { // -1 for null terminator
		if pos >= len(doc) {
			break
		}
		elemType := doc[pos]
		pos++

		// Read C-string key (null-terminated).
		key, n := readCString(doc[pos:])
		if n == 0 {
			break
		}
		pos += n

		switch elemType {
		case bsonTypeString: // string: int32 length + bytes + null
			if pos+4 > len(doc) {
				return fields
			}
			strLen := int(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 4
			if strLen < 1 || pos+strLen > len(doc) {
				return fields
			}
			// strLen includes the trailing null byte.
			val := string(doc[pos : pos+strLen-1])
			pos += strLen
			fields = append(fields, bsonField{key: key, value: val})

		case bsonTypeDouble: // double: 8 bytes
			if pos+8 > len(doc) {
				return fields
			}
			bits := binary.LittleEndian.Uint64(doc[pos : pos+8])
			pos += 8
			fields = append(fields, bsonField{key: key, value: math.Float64frombits(bits)})

		case bsonTypeInt32: // int32: 4 bytes
			if pos+4 > len(doc) {
				return fields
			}
			val := int32(binary.LittleEndian.Uint32(doc[pos : pos+4]))
			pos += 4
			fields = append(fields, bsonField{key: key, value: val})

		case bsonTypeInt64: // int64: 8 bytes
			if pos+8 > len(doc) {
				return fields
			}
			val := int64(binary.LittleEndian.Uint64(doc[pos : pos+8]))
			pos += 8
			fields = append(fields, bsonField{key: key, value: val})

		default:
			// Unknown element type; stop parsing. We already have the command
			// name (first field) and possibly $db.
			return fields
		}
	}

	return fields
}

// readCString reads a null-terminated C-string from data.
// Returns the string and the number of bytes consumed (including the null terminator).
// Returns ("", 0) if no null terminator is found.
func readCString(data []byte) (string, int) {
	for i, b := range data {
		if b == 0x00 {
			return string(data[:i]), i + 1
		}
	}
	return "", 0
}
