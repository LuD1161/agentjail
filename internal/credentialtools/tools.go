// Package credentialtools translates issued credential material into the
// environment and session files expected by allowlisted CLI tools.
package credentialtools

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Tool identifies a supported credentialed CLI contract.
type Tool string

const (
	ToolAWS        Tool = "aws"
	ToolKubernetes Tool = "kubectl"
	ToolGitHub     Tool = "gh"
)

// Field is a canonical credential-material field independent of its issuer.
type Field string

const (
	FieldAccessKeyID     Field = "access_key_id"
	FieldSecretAccessKey Field = "secret_access_key"
	FieldSessionToken    Field = "session_token"
	FieldRegion          Field = "region"
	FieldToken           Field = "token"
	FieldKubeconfig      Field = "kubeconfig"
)

// Material is the issuer-independent credential shape consumed by adapters.
// A future JIT, Vault, or OpenBao issuer returns this same type.
type Material struct {
	Fields map[Field]string
}

// EnvVar is one environment entry delivered to the shielded session.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SessionFile is credential content that the shield writes into its private
// session directory before applying the OS sandbox.
type SessionFile struct {
	EnvVar  string `json:"env_var"`
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

// SessionDirectory is an empty private directory that isolates a CLI from its
// ambient host configuration while preserving its standard environment API.
type SessionDirectory struct {
	EnvVar string `json:"env_var"`
	Name   string `json:"name"`
}

// Delivery is the standard CLI-facing presentation of issued material.
type Delivery struct {
	Env         []EnvVar           `json:"env,omitempty"`
	Files       []SessionFile      `json:"files,omitempty"`
	Directories []SessionDirectory `json:"directories,omitempty"`
}

// Adapter owns one CLI's executable and credential-presentation contract.
type Adapter interface {
	Tool() Tool
	Binary() string
	Present(Material) (Delivery, error)
}

// Registry resolves adapters without tool-specific switches in the shield.
type Registry struct {
	adapters map[Tool]Adapter
}

// DefaultRegistry returns the OSS credentialed-tool adapters.
func DefaultRegistry() Registry {
	adapters := []Adapter{awsAdapter{}, kubectlAdapter{}, githubAdapter{}}
	byTool := make(map[Tool]Adapter, len(adapters))
	for _, adapter := range adapters {
		byTool[adapter.Tool()] = adapter
	}
	return Registry{adapters: byTool}
}

// Resolve returns the adapter registered for tool.
func (r Registry) Resolve(tool Tool) (Adapter, error) {
	adapter, ok := r.adapters[tool]
	if !ok {
		return nil, fmt.Errorf("credentialed tool %q is not supported", tool)
	}
	return adapter, nil
}

// ParseTool validates a user-facing tool name.
func ParseTool(value string) (Tool, error) {
	tool := Tool(strings.TrimSpace(value))
	if _, err := DefaultRegistry().Resolve(tool); err != nil {
		return "", err
	}
	return tool, nil
}

// DecodeStatic converts the current encrypted-store representation into the
// issuer-independent material contract. It is intentionally separate from
// Present: JIT issuers can return Material without using this decoder.
func DecodeStatic(tool Tool, raw string) (Material, error) {
	switch tool {
	case ToolAWS:
		var stored struct {
			AccessKeyID     string `json:"access_key_id"`
			AccessKey       string `json:"access_key"`
			SecretAccessKey string `json:"secret_access_key"`
			SecretKey       string `json:"secret_key"`
			SessionToken    string `json:"session_token"`
			Region          string `json:"region"`
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&stored); err != nil {
			return Material{}, fmt.Errorf("decode static AWS credential: %w", err)
		}
		if err := requireJSONEOF(dec); err != nil {
			return Material{}, fmt.Errorf("decode static AWS credential: %w", err)
		}
		accessKey := stored.AccessKeyID
		if accessKey == "" {
			accessKey = stored.AccessKey
		}
		secretKey := stored.SecretAccessKey
		if secretKey == "" {
			secretKey = stored.SecretKey
		}
		return Material{Fields: map[Field]string{
			FieldAccessKeyID:     accessKey,
			FieldSecretAccessKey: secretKey,
			FieldSessionToken:    stored.SessionToken,
			FieldRegion:          stored.Region,
		}}, nil
	case ToolKubernetes:
		if strings.TrimSpace(raw) == "" {
			return Material{}, errors.New("static kubeconfig is empty")
		}
		if err := validateKubeconfig(raw); err != nil {
			return Material{}, err
		}
		return Material{Fields: map[Field]string{FieldKubeconfig: raw}}, nil
	case ToolGitHub:
		token := strings.TrimSpace(raw)
		if token == "" {
			return Material{}, errors.New("static GitHub token is empty")
		}
		return Material{Fields: map[Field]string{FieldToken: token}}, nil
	default:
		return Material{}, fmt.Errorf("static credentials for tool %q are not supported", tool)
	}
}

type kubeconfig struct {
	APIVersion     string               `yaml:"apiVersion"`
	Kind           string               `yaml:"kind"`
	Preferences    kubePreferences      `yaml:"preferences,omitempty"`
	CurrentContext string               `yaml:"current-context"`
	Clusters       []namedKubeCluster   `yaml:"clusters"`
	Contexts       []namedKubeContext   `yaml:"contexts"`
	Users          []namedKubeUser      `yaml:"users"`
	Extensions     []namedKubeExtension `yaml:"extensions,omitempty"`
}

type namedKubeCluster struct {
	Name    string      `yaml:"name"`
	Cluster kubeCluster `yaml:"cluster"`
}

type kubeCluster struct {
	Server                   string               `yaml:"server"`
	TLSServerName            string               `yaml:"tls-server-name,omitempty"`
	InsecureSkipTLSVerify    bool                 `yaml:"insecure-skip-tls-verify,omitempty"`
	CertificateAuthority     string               `yaml:"certificate-authority,omitempty"`
	CertificateAuthorityData string               `yaml:"certificate-authority-data,omitempty"`
	ProxyURL                 string               `yaml:"proxy-url,omitempty"`
	DisableCompression       bool                 `yaml:"disable-compression,omitempty"`
	Extensions               []namedKubeExtension `yaml:"extensions,omitempty"`
}

type namedKubeContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster    string               `yaml:"cluster"`
		User       string               `yaml:"user"`
		Namespace  string               `yaml:"namespace,omitempty"`
		Extensions []namedKubeExtension `yaml:"extensions,omitempty"`
	} `yaml:"context"`
}

type namedKubeUser struct {
	Name string       `yaml:"name"`
	User kubeAuthInfo `yaml:"user"`
}

type kubeAuthInfo struct {
	ClientCertificate     string               `yaml:"client-certificate,omitempty"`
	ClientCertificateData string               `yaml:"client-certificate-data,omitempty"`
	ClientKey             string               `yaml:"client-key,omitempty"`
	ClientKeyData         string               `yaml:"client-key-data,omitempty"`
	Token                 string               `yaml:"token,omitempty"`
	TokenFile             string               `yaml:"tokenFile,omitempty"`
	Impersonate           string               `yaml:"as,omitempty"`
	ImpersonateUID        string               `yaml:"as-uid,omitempty"`
	ImpersonateGroups     []string             `yaml:"as-groups,omitempty"`
	ImpersonateUserExtra  map[string][]string  `yaml:"as-user-extra,omitempty"`
	Username              string               `yaml:"username,omitempty"`
	Password              string               `yaml:"password,omitempty"`
	AuthProvider          *kubeAuthProvider    `yaml:"auth-provider,omitempty"`
	Exec                  *kubeExecConfig      `yaml:"exec,omitempty"`
	Extensions            []namedKubeExtension `yaml:"extensions,omitempty"`
}

type kubeAuthProvider struct {
	Name   string            `yaml:"name"`
	Config map[string]string `yaml:"config"`
}

type kubeExecConfig struct {
	Command            string           `yaml:"command"`
	Args               []string         `yaml:"args,omitempty"`
	Env                []kubeExecEnvVar `yaml:"env,omitempty"`
	APIVersion         string           `yaml:"apiVersion"`
	InstallHint        string           `yaml:"installHint,omitempty"`
	ProvideClusterInfo bool             `yaml:"provideClusterInfo,omitempty"`
	InteractiveMode    string           `yaml:"interactiveMode,omitempty"`
}

type kubeExecEnvVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type kubePreferences struct {
	Colors     bool                 `yaml:"colors,omitempty"`
	Extensions []namedKubeExtension `yaml:"extensions,omitempty"`
}

type namedKubeExtension struct {
	Name      string    `yaml:"name"`
	Extension yaml.Node `yaml:"extension"`
}

func validateKubeconfig(raw string) error {
	var cfg kubeconfig
	dec := yaml.NewDecoder(strings.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("decode static kubeconfig: %w", err)
	}
	if err := requireYAMLEOF(dec); err != nil {
		return fmt.Errorf("decode static kubeconfig: %w", err)
	}
	if cfg.APIVersion != "v1" || cfg.Kind != "Config" {
		return errors.New("static kubeconfig requires apiVersion v1 and kind Config")
	}
	if len(cfg.Clusters) != 1 || len(cfg.Contexts) != 1 || len(cfg.Users) != 1 {
		return errors.New("static kubeconfig must contain exactly one cluster, context, and user")
	}
	context := cfg.Contexts[0]
	if cfg.CurrentContext == "" || context.Name != cfg.CurrentContext {
		return errors.New("static kubeconfig current-context must name its only context")
	}
	if context.Context.Cluster != cfg.Clusters[0].Name || context.Context.User != cfg.Users[0].Name {
		return errors.New("static kubeconfig context must reference its only cluster and user")
	}
	cluster := cfg.Clusters[0].Cluster
	if strings.TrimSpace(cluster.Server) == "" {
		return errors.New("static kubeconfig cluster requires a server")
	}
	if cluster.CertificateAuthority != "" {
		return errors.New("static kubeconfig cannot reference a certificate-authority file; embed certificate-authority-data")
	}
	user := cfg.Users[0].User
	if user.ClientCertificate != "" || user.ClientKey != "" || user.TokenFile != "" {
		return errors.New("static kubeconfig cannot reference credential files; embed credential data")
	}
	if user.Exec != nil || user.AuthProvider != nil {
		return errors.New("static kubeconfig cannot use exec or auth-provider credential plugins")
	}
	if (user.ClientCertificateData == "") != (user.ClientKeyData == "") {
		return errors.New("static kubeconfig client certificate data requires matching client key data")
	}
	if (user.Username == "") != (user.Password == "") {
		return errors.New("static kubeconfig basic authentication requires both username and password")
	}
	if user.Token == "" && user.ClientCertificateData == "" && user.Username == "" {
		return errors.New("static kubeconfig user requires inline token, client certificate data, or basic authentication")
	}
	return nil
}

func requireYAMLEOF(dec *yaml.Decoder) error {
	var extra yaml.Node
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple YAML documents")
	}
	return err
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra json.RawMessage
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

type awsAdapter struct{}

func (awsAdapter) Tool() Tool     { return ToolAWS }
func (awsAdapter) Binary() string { return "aws" }
func (awsAdapter) Present(material Material) (Delivery, error) {
	accessKey := material.Fields[FieldAccessKeyID]
	secretKey := material.Fields[FieldSecretAccessKey]
	if accessKey == "" || secretKey == "" {
		return Delivery{}, errors.New("AWS credential requires access_key_id and secret_access_key")
	}
	env := []EnvVar{
		{Name: "AWS_ACCESS_KEY_ID", Value: accessKey},
		{Name: "AWS_SECRET_ACCESS_KEY", Value: secretKey},
		{Name: "AWS_EC2_METADATA_DISABLED", Value: "true"},
	}
	if value := material.Fields[FieldSessionToken]; value != "" {
		env = append(env, EnvVar{Name: "AWS_SESSION_TOKEN", Value: value})
	}
	if value := material.Fields[FieldRegion]; value != "" {
		env = append(env, EnvVar{Name: "AWS_DEFAULT_REGION", Value: value})
	}
	return Delivery{Env: env}, nil
}

type kubectlAdapter struct{}

func (kubectlAdapter) Tool() Tool     { return ToolKubernetes }
func (kubectlAdapter) Binary() string { return "kubectl" }
func (kubectlAdapter) Present(material Material) (Delivery, error) {
	value := material.Fields[FieldKubeconfig]
	if strings.TrimSpace(value) == "" {
		return Delivery{}, errors.New("kubectl credential requires kubeconfig content")
	}
	return Delivery{Files: []SessionFile{{
		EnvVar:  "KUBECONFIG",
		Name:    "kubeconfig",
		Content: []byte(value),
	}}}, nil
}

type githubAdapter struct{}

func (githubAdapter) Tool() Tool     { return ToolGitHub }
func (githubAdapter) Binary() string { return "gh" }
func (githubAdapter) Present(material Material) (Delivery, error) {
	token := material.Fields[FieldToken]
	if strings.TrimSpace(token) == "" {
		return Delivery{}, errors.New("GitHub credential requires token material")
	}
	return Delivery{
		Env: []EnvVar{
			{Name: "GH_TOKEN", Value: token},
			{Name: "GH_PROMPT_DISABLED", Value: "1"},
		},
		Directories: []SessionDirectory{{EnvVar: "GH_CONFIG_DIR", Name: "gh-config"}},
	}, nil
}
