// Package credentialaccess owns agent-visible credential records and delivery.
package credentialaccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	recordVersion    = 2
	maxLabelBytes    = 256
	maxTagBytes      = 64
	maxTags          = 32
	maxDeliveryItems = 256
)

var envNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ID is the stable broker name an agent must request exactly.
type ID string

// Approval describes the current policy result without exposing material.
type Approval string

// ApprovalAutomatic means the current bootstrap authorizer permits issuance.
const ApprovalAutomatic Approval = "automatic"

// EnvVar is one environment entry delivered to a shielded session.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SessionFile is credential content written into a private session directory.
type SessionFile struct {
	EnvVar  string `json:"env_var"`
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

// SessionDirectory is a private empty directory exposed through one env var.
type SessionDirectory struct {
	EnvVar string `json:"env_var"`
	Name   string `json:"name"`
}

// Delivery is an opaque, provider-neutral credential presentation contract.
type Delivery struct {
	Env         []EnvVar           `json:"env,omitempty"`
	Files       []SessionFile      `json:"files,omitempty"`
	Directories []SessionDirectory `json:"directories,omitempty"`
}

// Descriptor is the non-secret inventory entry returned to an agent.
type Descriptor struct {
	ID       ID       `json:"id"`
	Label    string   `json:"label,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Approval Approval `json:"approval"`
}

// Record is the encrypted-at-rest envelope written by the credential CLI.
// Delivery values are never copied into Descriptor.
type Record struct {
	Version  int            `json:"agentjail_credential_version"`
	Metadata recordMetadata `json:"metadata"`
	Delivery Delivery       `json:"delivery"`
}

type recordMetadata struct {
	Label string   `json:"label,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// NewRecord validates and builds one provider-neutral broker record.
func NewRecord(delivery Delivery, label string, tags []string) (Record, error) {
	if err := ValidateDelivery(delivery); err != nil {
		return Record{}, err
	}
	label, err := cleanMetadata(label, maxLabelBytes, "label")
	if err != nil {
		return Record{}, err
	}
	tags, err = normalizeTags(tags)
	if err != nil {
		return Record{}, err
	}
	return Record{
		Version:  recordVersion,
		Metadata: recordMetadata{Label: label, Tags: tags},
		Delivery: delivery,
	}, nil
}

// Encode serializes a credential record for encrypted broker storage.
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

// Decode recognizes and strictly decodes the current record format. Older
// unreleased typed records and raw broker values remain hidden from inventory.
func Decode(raw string) (record Record, recognized bool, err error) {
	var probe struct {
		Version int `json:"agentjail_credential_version"`
	}
	if json.Unmarshal([]byte(raw), &probe) != nil || probe.Version != recordVersion {
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
		ID: id, Label: record.Metadata.Label,
		Tags: append([]string(nil), record.Metadata.Tags...), Approval: ApprovalAutomatic,
	}
}

// ValidateDelivery rejects empty, ambiguous, or process-control bindings.
func ValidateDelivery(delivery Delivery) error {
	count := len(delivery.Env) + len(delivery.Files) + len(delivery.Directories)
	if count == 0 {
		return errors.New("credential delivery is empty")
	}
	if count > maxDeliveryItems {
		return fmt.Errorf("credential delivery exceeds %d bindings", maxDeliveryItems)
	}
	seen := make(map[string]struct{}, count)
	claim := func(name string) error {
		if err := validateDeliveryEnvName(name); err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("credential delivery repeats environment name %q", name)
		}
		seen[name] = struct{}{}
		return nil
	}
	for _, variable := range delivery.Env {
		if err := claim(variable.Name); err != nil {
			return err
		}
		if variable.Value == "" {
			return fmt.Errorf("credential environment value %q is empty", variable.Name)
		}
	}
	for _, file := range delivery.Files {
		if err := claim(file.EnvVar); err != nil {
			return err
		}
		if err := validateSessionName(file.Name, "filename"); err != nil {
			return err
		}
		if len(file.Content) == 0 {
			return fmt.Errorf("credential session file %q is empty", file.Name)
		}
	}
	for _, directory := range delivery.Directories {
		if err := claim(directory.EnvVar); err != nil {
			return err
		}
		if err := validateSessionName(directory.Name, "directory name"); err != nil {
			return err
		}
	}
	return nil
}

func validateRecord(record Record) error {
	if record.Version != recordVersion {
		return fmt.Errorf("unsupported credential record version %d", record.Version)
	}
	if err := ValidateDelivery(record.Delivery); err != nil {
		return err
	}
	label, err := cleanMetadata(record.Metadata.Label, maxLabelBytes, "label")
	if err != nil {
		return err
	}
	if label != record.Metadata.Label {
		return errors.New("credential label is not canonical")
	}
	tags, err := normalizeTags(record.Metadata.Tags)
	if err != nil {
		return err
	}
	if strings.Join(tags, "\x00") != strings.Join(record.Metadata.Tags, "\x00") {
		return errors.New("credential tags are not canonical")
	}
	return nil
}

func validateDeliveryEnvName(name string) error {
	if !envNamePattern.MatchString(name) {
		return fmt.Errorf("invalid credential environment name %q", name)
	}
	if forbiddenCredentialEnv(name) {
		return fmt.Errorf("credential environment name %q can alter session security", name)
	}
	return nil
}

func forbiddenCredentialEnv(name string) bool {
	for _, prefix := range []string{"AGENTJAIL_", "DYLD_", "LD_"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	switch name {
	case "PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "SHLVL",
		"TMPDIR", "TMP", "TEMP", "BASH_ENV", "ENV", "CDPATH", "NODE_OPTIONS",
		"PYTHONHOME", "PYTHONPATH", "RUBYOPT", "PERL5OPT", "SSH_AUTH_SOCK",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE":
		return true
	default:
		return false
	}
}

func validateSessionName(name, kind string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("invalid credential session %s %q", kind, name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("credential session %s contains a control character", kind)
		}
	}
	return nil
}

func normalizeTags(values []string) ([]string, error) {
	if len(values) > maxTags {
		return nil, fmt.Errorf("credential has more than %d tags", maxTags)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value, err := cleanMetadata(value, maxTagBytes, "tag")
		if err != nil {
			return nil, err
		}
		if value == "" {
			return nil, errors.New("credential tag is empty")
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func cleanMetadata(value string, limit int, field string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("credential %s must be valid UTF-8", field)
	}
	if len(value) > limit {
		return "", fmt.Errorf("credential %s exceeds %d bytes", field, limit)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("credential %s contains a control character", field)
		}
	}
	return value, nil
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
