// Package credentialmcp exposes agent credential discovery and exact issuance
// over the MCP stdio transport.
package credentialmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/LuD1161/agentjail/internal/credentialaccess"
	"github.com/LuD1161/agentjail/internal/credentialguidance"
)

const (
	EnvBrokerSocket = "AGENTJAIL_CREDENTIAL_BROKER_SOCKET"
	EnvSessionToken = "AGENTJAIL_CREDENTIAL_SESSION_TOKEN"
	protocolVersion = "2025-06-18"
)

// Broker is the narrow capability consumed by the MCP server.
type Broker interface {
	List(context.Context) ([]credentialaccess.Descriptor, error)
	Request(context.Context, credentialaccess.ID, string) (credentialaccess.Issuance, error)
}

// Run serves newline-delimited MCP JSON-RPC until input closes.
func Run(ctx context.Context, in io.Reader, out io.Writer, broker Broker) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	encoder := json.NewEncoder(out)
	for scanner.Scan() {
		var request rpcRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			if err := encoder.Encode(errorResponse(nil, -32700, "Parse error")); err != nil {
				return err
			}
			continue
		}
		if len(request.ID) == 0 {
			continue
		}
		response := dispatch(ctx, request, broker)
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// RunFromEnvironment connects the stdio MCP server to its shield session.
func RunFromEnvironment(ctx context.Context, in io.Reader, out io.Writer) error {
	socket := os.Getenv(EnvBrokerSocket)
	token := os.Getenv(EnvSessionToken)
	if socket == "" || token == "" {
		return fmt.Errorf("credential MCP is only available inside an AgentJail credential session")
	}
	return Run(ctx, in, out, &unixBroker{socket: socket, token: token})
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  object          `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type object map[string]interface{}

func dispatch(ctx context.Context, request rpcRequest, broker Broker) rpcResponse {
	switch request.Method {
	case "initialize":
		version := protocolVersion
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(request.Params, &params) == nil && supportedProtocolVersion(params.ProtocolVersion) {
			version = params.ProtocolVersion
		}
		return success(request.ID, object{
			"protocolVersion": version,
			"capabilities":    object{"tools": object{}},
			"serverInfo":      object{"name": "agentjail-credentials", "version": "1"},
			"instructions":    credentialguidance.SessionInstructions,
		})
	case "ping":
		return success(request.ID, object{})
	case "tools/list":
		return success(request.ID, object{"tools": toolDefinitions()})
	case "tools/call":
		return callTool(ctx, request, broker)
	default:
		return errorResponse(request.ID, -32601, "Method not found")
	}
}

func supportedProtocolVersion(version string) bool {
	switch version {
	case "2024-11-05", "2025-03-26", "2025-06-18":
		return true
	default:
		return false
	}
}

func toolDefinitions() []object {
	return []object{
		{
			"name":        "list_credentials",
			"description": "List non-secret credential IDs, labels, and tags available to this AgentJail session. Call this before requesting a credential. This never returns credential material.",
			"inputSchema": object{
				"type":                 "object",
				"properties":           object{},
				"additionalProperties": false,
			},
		},
		{
			"name":        "request_credential",
			"description": "Request one exact credential ID returned by list_credentials. AgentJail never infers a provider or purpose from the name, label, or tags. The bootstrap response contains real credential material for the session environment or a private file.",
			"inputSchema": object{
				"type": "object",
				"properties": object{
					"credential_id": object{"type": "string", "minLength": 1, "description": "Exact ID returned by list_credentials."},
					"reason":        object{"type": "string", "maxLength": credentialaccess.MaxReasonBytes, "description": "Optional non-secret audit note."},
				},
				"required":             []string{"credential_id"},
				"additionalProperties": false,
			},
		},
	}
}

func callTool(ctx context.Context, request rpcRequest, broker Broker) rpcResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      json.RawMessage `json:"_meta,omitempty"`
	}
	if err := decodeStrict(request.Params, &params); err != nil {
		return errorResponse(request.ID, -32602, "Invalid tools/call parameters")
	}
	switch params.Name {
	case "list_credentials":
		if len(params.Arguments) != 0 {
			var arguments struct{}
			if err := decodeStrict(params.Arguments, &arguments); err != nil {
				return errorResponse(request.ID, -32602, "Invalid list_credentials arguments")
			}
		}
		items, err := broker.List(ctx)
		if err != nil {
			return toolError(request.ID, err)
		}
		return toolSuccess(request.ID, object{"credentials": items})
	case "request_credential":
		var arguments struct {
			CredentialID string `json:"credential_id"`
			Reason       string `json:"reason"`
		}
		if err := decodeStrict(params.Arguments, &arguments); err != nil {
			return errorResponse(request.ID, -32602, "Invalid request_credential arguments")
		}
		issuance, err := broker.Request(ctx, credentialaccess.ID(arguments.CredentialID), arguments.Reason)
		if err != nil {
			return toolError(request.ID, err)
		}
		return toolSuccess(request.ID, presentIssuance(issuance))
	default:
		return errorResponse(request.ID, -32602, "Unknown tool: "+params.Name)
	}
}

func presentIssuance(issuance credentialaccess.Issuance) object {
	environment := make(map[string]string, len(issuance.Delivery.Env))
	for _, variable := range issuance.Delivery.Env {
		environment[variable.Name] = variable.Value
	}
	files := make([]object, 0, len(issuance.Delivery.Files))
	for _, file := range issuance.Delivery.Files {
		files = append(files, object{
			"environment_variable": file.EnvVar,
			"suggested_name":       file.Name,
			"content":              string(file.Content),
			"mode":                 "0600",
		})
	}
	directories := make([]object, 0, len(issuance.Delivery.Directories))
	for _, directory := range issuance.Delivery.Directories {
		directories = append(directories, object{
			"environment_variable": directory.EnvVar,
			"suggested_name":       directory.Name,
		})
	}
	return object{
		"credential":  issuance.Credential,
		"environment": environment,
		"files":       files,
		"directories": directories,
		"warning":     "Bootstrap mode returns real credential material. Use it only for the requested CLI operation and do not print or persist it outside the session.",
	}
}

func toolSuccess(id json.RawMessage, value object) rpcResponse {
	encoded, _ := json.Marshal(value)
	return success(id, object{
		"content":           []object{{"type": "text", "text": string(encoded)}},
		"structuredContent": value,
		"isError":           false,
	})
}

func toolError(id json.RawMessage, err error) rpcResponse {
	return success(id, object{
		"content": []object{{"type": "text", "text": err.Error()}},
		"isError": true,
	})
}

func success(id json.RawMessage, result object) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errorResponse(id json.RawMessage, code int, message string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}

func decodeStrict(data []byte, target interface{}) error {
	if len(data) == 0 {
		return errors.New("missing JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

type unixBroker struct {
	socket string
	token  string
}

type brokerRequest struct {
	Action       string `json:"action"`
	SessionToken string `json:"session_token"`
	CredentialID string `json:"credential_id,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type brokerResponse struct {
	OK          bool                          `json:"ok"`
	Error       string                        `json:"error,omitempty"`
	Credentials []credentialaccess.Descriptor `json:"credentials,omitempty"`
	Issuance    *credentialaccess.Issuance    `json:"issuance,omitempty"`
}

func (b *unixBroker) List(ctx context.Context) ([]credentialaccess.Descriptor, error) {
	response, err := b.call(ctx, brokerRequest{Action: "credential_list", SessionToken: b.token})
	if err != nil {
		return nil, err
	}
	return response.Credentials, nil
}

func (b *unixBroker) Request(ctx context.Context, id credentialaccess.ID, reason string) (credentialaccess.Issuance, error) {
	response, err := b.call(ctx, brokerRequest{
		Action: "credential_request", SessionToken: b.token, CredentialID: string(id), Reason: reason,
	})
	if err != nil {
		return credentialaccess.Issuance{}, err
	}
	if response.Issuance == nil {
		return credentialaccess.Issuance{}, errors.New("broker returned no credential issuance")
	}
	return *response.Issuance, nil
}

func (b *unixBroker) call(ctx context.Context, request brokerRequest) (brokerResponse, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", b.socket)
	if err != nil {
		return brokerResponse{}, fmt.Errorf("connect to credential broker: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return brokerResponse{}, fmt.Errorf("send credential broker request: %w", err)
	}
	var response brokerResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		return brokerResponse{}, fmt.Errorf("read credential broker response: %w", err)
	}
	if !response.OK {
		return brokerResponse{}, errors.New(response.Error)
	}
	return response, nil
}
