// Package mcpgrant canonicalizes MCP tool resources and gates their runtime grants.
// See ADR 0141-runtime-grants.
package mcpgrant

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/LuD1161/agentjail/internal/grant"
)

const MaxCallParamsBytes = 64 << 10

var (
	ErrInvalidServerID  = errors.New("invalid MCP server ID")
	ErrInvalidToolID    = errors.New("invalid MCP tool ID")
	ErrInvalidArguments = errors.New("invalid MCP tool arguments")
	ErrInvalidParams    = errors.New("invalid MCP tools/call parameters")
	ErrResourceID       = errors.New("invalid canonical MCP resource ID")
	ErrInputTooLarge    = errors.New("MCP JSON input exceeds limit")
)

type ServerID string
type ToolID string
type ResourceID string
type ArgumentDigest string

type argumentConstraintKind string

const (
	argumentsAny   argumentConstraintKind = "any"
	argumentsExact argumentConstraintKind = "exact"
)

// ArgumentConstraint either admits every argument object or requires one exact
// canonical argument object. It never retains decoded, untyped JSON values.
type ArgumentConstraint struct {
	kind      argumentConstraintKind
	canonical canonicalArguments
	digest    ArgumentDigest
}

func AnyArguments() ArgumentConstraint { return ArgumentConstraint{kind: argumentsAny} }

// StrictArguments creates an exact typed argument constraint from JSON at the
// serialization boundary.
func StrictArguments(arguments []byte) (ArgumentConstraint, error) {
	canonical, err := normalizeArguments(arguments)
	if err != nil {
		return ArgumentConstraint{}, err
	}
	return strictConstraint(canonical), nil
}

func strictConstraint(canonical canonicalArguments) ArgumentConstraint {
	sum := sha256.Sum256([]byte(canonical))
	return ArgumentConstraint{kind: argumentsExact, canonical: canonical, digest: ArgumentDigest(hex.EncodeToString(sum[:]))}
}

func (c ArgumentConstraint) Valid() bool {
	switch c.kind {
	case argumentsAny:
		return c.canonical == "" && c.digest == ""
	case argumentsExact:
		return c.canonical != "" && c.digest != ""
	default:
		return false
	}
}

func (c ArgumentConstraint) Digest() (ArgumentDigest, bool) {
	if c.kind != argumentsExact {
		return "", false
	}
	return c.digest, true
}

// Call is a normalized tools/call request. Its arguments exclude top-level
// protocol metadata such as _meta.
type Call struct {
	server    ServerID
	tool      ToolID
	arguments canonicalArguments
}

func NewCall(server ServerID, tool ToolID, arguments []byte) (Call, error) {
	if err := validateServerID(server); err != nil {
		return Call{}, err
	}
	if err := validateToolID(tool); err != nil {
		return Call{}, err
	}
	canonical, err := normalizeArguments(arguments)
	if err != nil {
		return Call{}, err
	}
	return Call{server: server, tool: tool, arguments: canonical}, nil
}

// ParseCallParams normalizes MCP tools/call parameters. Only name, arguments,
// and the protocol-level _meta extension are accepted in this first release.
func ParseCallParams(server ServerID, params []byte) (Call, error) {
	if len(params) > MaxCallParamsBytes {
		return Call{}, ErrInputTooLarge
	}
	value, err := parseJSON(params)
	if err != nil {
		return Call{}, fmt.Errorf("%w: %v", ErrInvalidParams, err)
	}
	object, ok := value.(jsonObject)
	if !ok {
		return Call{}, fmt.Errorf("%w: parameters must be an object", ErrInvalidParams)
	}
	var name string
	arguments := canonicalArguments("{}")
	hasName := false
	for _, field := range object.fields {
		switch field.name {
		case "name":
			stringValue, ok := field.value.(jsonString)
			if !ok {
				return Call{}, fmt.Errorf("%w: name must be a string", ErrInvalidParams)
			}
			name, hasName = string(stringValue), true
		case "arguments":
			if _, ok := field.value.(jsonObject); !ok {
				return Call{}, fmt.Errorf("%w: arguments must be an object", ErrInvalidArguments)
			}
			arguments = canonicalArguments(field.value.canonical())
		case "_meta":
			// Metadata is validated structurally but excluded from authority.
		default:
			return Call{}, fmt.Errorf("%w: unsupported parameter %q", ErrInvalidParams, field.name)
		}
	}
	if !hasName {
		return Call{}, fmt.Errorf("%w: name is required", ErrInvalidParams)
	}
	return NewCall(server, ToolID(name), []byte(arguments))
}

func (c Call) Server() ServerID                { return c.server }
func (c Call) Tool() ToolID                    { return c.tool }
func (c Call) ArgumentsDigest() ArgumentDigest { return strictConstraint(c.arguments).digest }
func (c Call) Valid() bool {
	return validateServerID(c.server) == nil && validateToolID(c.tool) == nil && c.arguments != ""
}

// Resource creates the exact-resource identity for this live call.
func (c Call) Resource() (grant.Resource, error) {
	return NewResource(c.server, c.tool, strictConstraint(c.arguments))
}

// NewResource creates an MCP tool resource suitable for a runtime grant.
func NewResource(server ServerID, tool ToolID, constraint ArgumentConstraint) (grant.Resource, error) {
	if err := validateServerID(server); err != nil {
		return grant.Resource{}, err
	}
	if err := validateToolID(tool); err != nil {
		return grant.Resource{}, err
	}
	if !constraint.Valid() {
		return grant.Resource{}, ErrInvalidArguments
	}
	return grant.NewResource(grant.ResourceMCPTool, grant.ResourceID(renderResourceID(server, tool, constraint)))
}

// Adapter implements the MCP resource matching contract for runtime grants.
type Adapter struct{}

func (Adapter) Kind() grant.ResourceKind { return grant.ResourceMCPTool }

func (Adapter) Canonicalize(requested grant.Resource) (grant.Resource, error) {
	if requested.Kind() != grant.ResourceMCPTool {
		return grant.Resource{}, grant.ErrAdapterKind
	}
	server, tool, constraint, err := parseResourceID(ResourceID(requested.ID()))
	if err != nil {
		return grant.Resource{}, err
	}
	return NewResource(server, tool, constraint)
}

func (Adapter) Equivalent(left, right grant.Resource) bool {
	leftID, leftOK := canonicalID(left)
	rightID, rightOK := canonicalID(right)
	return leftOK && rightOK && leftID == rightID
}

func (Adapter) Covers(granted, requested grant.Resource) bool {
	grantServer, grantTool, grantConstraint, err := parseGrantResource(granted)
	if err != nil {
		return false
	}
	requestServer, requestTool, requestConstraint, err := parseGrantResource(requested)
	if err != nil || grantServer != requestServer || grantTool != requestTool {
		return false
	}
	if grantConstraint.kind == argumentsAny {
		return true
	}
	return requestConstraint.kind == argumentsExact && grantConstraint.canonical == requestConstraint.canonical
}

func (Adapter) ActivationFor(action grant.Action, resource grant.Resource) (grant.ActivationRequirement, error) {
	if action != grant.ActionMCPCall || resource.Kind() != grant.ResourceMCPTool {
		return "", grant.ErrInvalidAction
	}
	if _, _, _, err := parseGrantResource(resource); err != nil {
		return "", err
	}
	return grant.ActivationNotRequired, nil
}

func canonicalID(resource grant.Resource) (ResourceID, bool) {
	if resource.Kind() != grant.ResourceMCPTool {
		return "", false
	}
	server, tool, constraint, err := parseResourceID(ResourceID(resource.ID()))
	if err != nil {
		return "", false
	}
	return renderResourceID(server, tool, constraint), true
}

func parseGrantResource(resource grant.Resource) (ServerID, ToolID, ArgumentConstraint, error) {
	if resource.Kind() != grant.ResourceMCPTool {
		return "", "", ArgumentConstraint{}, grant.ErrAdapterKind
	}
	return parseResourceID(ResourceID(resource.ID()))
}

func renderResourceID(server ServerID, tool ToolID, constraint ArgumentConstraint) ResourceID {
	serverPart := base64.RawURLEncoding.EncodeToString([]byte(server))
	toolPart := base64.RawURLEncoding.EncodeToString([]byte(tool))
	if constraint.kind == argumentsAny {
		return ResourceID("mcp/v1/" + serverPart + "/" + toolPart + "/any")
	}
	argumentsPart := base64.RawURLEncoding.EncodeToString([]byte(constraint.canonical))
	return ResourceID("mcp/v1/" + serverPart + "/" + toolPart + "/exact/" + string(constraint.digest) + "/" + argumentsPart)
}

func parseResourceID(resourceID ResourceID) (ServerID, ToolID, ArgumentConstraint, error) {
	parts := strings.Split(string(resourceID), "/")
	if len(parts) < 5 || parts[0] != "mcp" || parts[1] != "v1" {
		return "", "", ArgumentConstraint{}, ErrResourceID
	}
	serverBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", ArgumentConstraint{}, ErrResourceID
	}
	toolBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", "", ArgumentConstraint{}, ErrResourceID
	}
	server, tool := ServerID(serverBytes), ToolID(toolBytes)
	if validateServerID(server) != nil || validateToolID(tool) != nil {
		return "", "", ArgumentConstraint{}, ErrResourceID
	}
	switch parts[4] {
	case "any":
		if len(parts) != 5 {
			return "", "", ArgumentConstraint{}, ErrResourceID
		}
		return server, tool, AnyArguments(), nil
	case "exact":
		if len(parts) != 7 {
			return "", "", ArgumentConstraint{}, ErrResourceID
		}
		arguments, err := base64.RawURLEncoding.DecodeString(parts[6])
		if err != nil {
			return "", "", ArgumentConstraint{}, ErrResourceID
		}
		constraint, err := StrictArguments(arguments)
		if err != nil || string(constraint.digest) != parts[5] {
			return "", "", ArgumentConstraint{}, ErrResourceID
		}
		return server, tool, constraint, nil
	default:
		return "", "", ArgumentConstraint{}, ErrResourceID
	}
}

func validateServerID(id ServerID) error {
	if !validName(string(id)) {
		return ErrInvalidServerID
	}
	return nil
}

func validateToolID(id ToolID) error {
	if !validName(string(id)) {
		return ErrInvalidToolID
	}
	return nil
}

func validName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			if index == 0 && (character == '-' || character == '_' || character == '.') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

type canonicalArguments string

func normalizeArguments(arguments []byte) (canonicalArguments, error) {
	if len(arguments) == 0 || len(arguments) > MaxCallParamsBytes {
		if len(arguments) > MaxCallParamsBytes {
			return "", ErrInputTooLarge
		}
		return "", ErrInvalidArguments
	}
	value, err := parseJSON(arguments)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidArguments, err)
	}
	if _, ok := value.(jsonObject); !ok {
		return "", fmt.Errorf("%w: arguments must be an object", ErrInvalidArguments)
	}
	return canonicalArguments(value.canonical()), nil
}

type jsonValue interface{ canonical() string }
type jsonNull struct{}
type jsonBool bool
type jsonNumber string
type jsonString string
type jsonArray struct{ values []jsonValue }
type jsonField struct {
	name  string
	value jsonValue
}
type jsonObject struct{ fields []jsonField }

func (jsonNull) canonical() string { return "null" }
func (value jsonBool) canonical() string {
	if value {
		return "true"
	}
	return "false"
}
func (value jsonNumber) canonical() string { return string(value) }
func (value jsonString) canonical() string {
	encoded, _ := json.Marshal(string(value))
	return string(encoded)
}
func (value jsonArray) canonical() string {
	var builder strings.Builder
	builder.WriteByte('[')
	for index, entry := range value.values {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(entry.canonical())
	}
	builder.WriteByte(']')
	return builder.String()
}
func (value jsonObject) canonical() string {
	fields := append([]jsonField(nil), value.fields...)
	sort.Slice(fields, func(left, right int) bool { return fields[left].name < fields[right].name })
	var builder strings.Builder
	builder.WriteByte('{')
	for index, field := range fields {
		if index > 0 {
			builder.WriteByte(',')
		}
		encoded, _ := json.Marshal(field.name)
		builder.Write(encoded)
		builder.WriteByte(':')
		builder.WriteString(field.value.canonical())
	}
	builder.WriteByte('}')
	return builder.String()
}

func parseJSON(input []byte) (jsonValue, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	value, err := parseValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func parseValue(decoder *json.Decoder) (jsonValue, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			return parseObject(decoder)
		case '[':
			return parseArray(decoder)
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case nil:
		return jsonNull{}, nil
	case bool:
		return jsonBool(value), nil
	case string:
		return jsonString(value), nil
	case json.Number:
		return jsonNumber(value.String()), nil
	default:
		return nil, errors.New("unsupported JSON value")
	}
}

func parseObject(decoder *json.Decoder) (jsonValue, error) {
	fields := make([]jsonField, 0)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("JSON object key is not a string")
		}
		for _, field := range fields {
			if field.name == name {
				return nil, fmt.Errorf("duplicate JSON key %q", name)
			}
		}
		value, err := parseValue(decoder)
		if err != nil {
			return nil, err
		}
		fields = append(fields, jsonField{name: name, value: value})
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("unterminated JSON object")
	}
	return jsonObject{fields: fields}, nil
}

func parseArray(decoder *json.Decoder) (jsonValue, error) {
	values := make([]jsonValue, 0)
	for decoder.More() {
		value, err := parseValue(decoder)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("unterminated JSON array")
	}
	return jsonArray{values: values}, nil
}
