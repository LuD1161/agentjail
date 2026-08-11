// Package credentialaccess owns the agent-visible credential inventory and
// request types. Secret storage and CLI presentation stay in their domains.
package credentialaccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/LuD1161/agentjail/internal/credentialtools"
)

const recordVersion = 1

// ID is the stable broker name an agent must request exactly.
type ID string

// Approval describes the current policy result without exposing material.
type Approval string

const (
	ApprovalAutomatic Approval = "automatic"
)

// Descriptor is the non-secret inventory entry returned to an agent.
type Descriptor struct {
	ID       ID                   `json:"id"`
	Tool     credentialtools.Tool `json:"tool"`
	Kind     string               `json:"kind"`
	Label    string               `json:"label,omitempty"`
	Account  string               `json:"account,omitempty"`
	Context  string               `json:"context,omitempty"`
	Approval Approval             `json:"approval"`
}

// Record is the encrypted-at-rest typed envelope written by the credential
// CLI. Material is deliberately absent from Descriptor.
type Record struct {
	Version  int            `json:"agentjail_credential_version"`
	Metadata recordMetadata `json:"metadata"`
	Material string         `json:"material"`
}

type recordMetadata struct {
	Tool    credentialtools.Tool `json:"tool"`
	Kind    string               `json:"kind"`
	Label   string               `json:"label,omitempty"`
	Account string               `json:"account,omitempty"`
	Context string               `json:"context,omitempty"`
}

// NewRecord validates and builds one typed broker record.
func NewRecord(tool credentialtools.Tool, material, label, account, targetContext string) (Record, error) {
	if _, err := credentialtools.DefaultRegistry().Resolve(tool); err != nil {
		return Record{}, err
	}
	if strings.TrimSpace(material) == "" {
		return Record{}, errors.New("credential material is empty")
	}
	return Record{
		Version: recordVersion,
		Metadata: recordMetadata{
			Tool:    tool,
			Kind:    kindForTool(tool),
			Label:   cleanMetadata(label),
			Account: cleanMetadata(account),
			Context: cleanMetadata(targetContext),
		},
		Material: material,
	}, nil
}

// Encode serializes a typed credential record for encrypted broker storage.
func Encode(record Record) (string, error) {
	if err := validateRecord(record); err != nil {
		return "", err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("encode credential record: %w", err)
	}
	return string(data), nil
}

// Decode recognizes and strictly decodes a typed credential record. Legacy
// values return recognized=false so callers can apply bounded compatibility.
func Decode(raw string) (record Record, recognized bool, err error) {
	var probe struct {
		Version int `json:"agentjail_credential_version"`
	}
	if json.Unmarshal([]byte(raw), &probe) != nil || probe.Version == 0 {
		return Record{}, false, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return Record{}, true, fmt.Errorf("decode credential record: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return Record{}, true, fmt.Errorf("decode credential record: %w", err)
	}
	if err := validateRecord(record); err != nil {
		return Record{}, true, err
	}
	return record, true, nil
}

// Describe returns the non-secret view for a named record.
func Describe(id ID, record Record) Descriptor {
	return Descriptor{
		ID:       id,
		Tool:     record.Metadata.Tool,
		Kind:     record.Metadata.Kind,
		Label:    record.Metadata.Label,
		Account:  record.Metadata.Account,
		Context:  record.Metadata.Context,
		Approval: ApprovalAutomatic,
	}
}

// Legacy recognizes only credential names created by the shipped credential
// CLI. Arbitrary raw broker secrets never enter the agent-visible inventory.
func Legacy(id ID, raw string) (Record, bool, error) {
	name := string(id)
	var tool credentialtools.Tool
	switch {
	case strings.HasPrefix(name, "aws/"):
		tool = credentialtools.ToolAWS
	case strings.HasPrefix(name, "kube/"), strings.HasPrefix(name, "kubernetes/"):
		tool = credentialtools.ToolKubernetes
	case strings.HasPrefix(name, "github/"), strings.HasPrefix(name, "gh/"):
		tool = credentialtools.ToolGitHub
	default:
		return Record{}, false, nil
	}
	if _, err := credentialtools.DecodeStatic(tool, raw); err != nil {
		return Record{}, true, fmt.Errorf("legacy credential %q: %w", id, err)
	}
	record, err := NewRecord(tool, raw, name, "", "")
	return record, true, err
}

func validateRecord(record Record) error {
	if record.Version != recordVersion {
		return fmt.Errorf("unsupported credential record version %d", record.Version)
	}
	if _, err := credentialtools.DefaultRegistry().Resolve(record.Metadata.Tool); err != nil {
		return err
	}
	if record.Metadata.Kind != kindForTool(record.Metadata.Tool) {
		return fmt.Errorf("credential kind %q does not match tool %q", record.Metadata.Kind, record.Metadata.Tool)
	}
	if strings.TrimSpace(record.Material) == "" {
		return errors.New("credential material is empty")
	}
	if _, err := credentialtools.DecodeStatic(record.Metadata.Tool, record.Material); err != nil {
		return err
	}
	return nil
}

func kindForTool(tool credentialtools.Tool) string {
	switch tool {
	case credentialtools.ToolAWS:
		return "access_key"
	case credentialtools.ToolKubernetes:
		return "kubeconfig"
	case credentialtools.ToolGitHub:
		return "token"
	default:
		return "unknown"
	}
}

func cleanMetadata(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > 256 {
		value = value[:256]
	}
	return value
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == nil {
		return errors.New("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
