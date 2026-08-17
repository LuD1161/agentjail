package shieldapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/credentialaccess"
	"github.com/LuD1161/agentjail/internal/credentialguidance"
	"github.com/LuD1161/agentjail/internal/sandbox"
)

type credentialSelection struct {
	Name      string
	Discovery bool
}

func (s credentialSelection) auditEntity() string {
	if s.Name != "" {
		return s.Name
	}
	return "inventory"
}

func (s credentialSelection) deliveryMode() string {
	if s.Name != "" {
		return "eager"
	}
	return "on_request"
}

func reportCredentialSelections(ctx context.Context, selections credentialSelections, emitter audit.Emitter) {
	for _, selection := range selections {
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: credential %s ready (%s)\n", selection.auditEntity(), selection.deliveryMode())
		slog.Info("credential ready", "credential_id", selection.Name, "delivery", selection.deliveryMode())
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.CredentialReady,
			Entity:    selection.auditEntity(),
			Detail:    map[string]string{"delivery": selection.deliveryMode()},
			Actor:     "shield",
		})
	}
}

type credentialSelections []credentialSelection

func (s credentialSelections) hasName(name string) bool {
	for _, selection := range s {
		if selection.Name == name && !selection.Discovery {
			return true
		}
	}
	return false
}

func (s credentialSelections) hasDiscovery() bool {
	for _, selection := range s {
		if selection.Discovery {
			return true
		}
	}
	return false
}

func (s *credentialSelections) String() string {
	values := make([]string, 0, len(*s))
	for _, selection := range *s {
		if !selection.Discovery {
			values = append(values, selection.Name)
		}
	}
	return strings.Join(values, ",")
}

func (s *credentialSelections) Set(value string) error {
	name := strings.TrimSpace(value)
	if name == "" {
		return errors.New("credential ID is empty")
	}
	if s.hasName(name) {
		return fmt.Errorf("credential %q was selected more than once", name)
	}
	*s = append(*s, credentialSelection{Name: name})
	return nil
}

func discoverCredentialSelections(ctlToken string) (credentialSelections, error) {
	if ctlToken == "" {
		return nil, nil
	}
	socketPath := defaultSecretsSocketPath()
	if !sandbox.SecretsBrokerRunning() {
		if err := sandbox.EnsureSecretsBroker(socketPath); err != nil {
			return nil, fmt.Errorf("start AgentJail credential broker: %w", err)
		}
	}
	project, _ := os.Getwd()
	response, err := secretsRPC(socketPath, &secretsRPCRequest{
		Action: "credential_inventory", Token: ctlToken,
		SessionID: fmt.Sprintf("shield-inventory-%d", os.Getpid()), Project: project,
	})
	if err != nil {
		return nil, fmt.Errorf("discover broker credentials: %w", err)
	}
	if !response.OK {
		return nil, fmt.Errorf("discover broker credentials: %s", response.Error)
	}
	if len(response.Credentials) == 0 {
		return nil, nil
	}
	return credentialSelections{{Discovery: true}}, nil
}

func mergeCredentialSelections(explicit, discovered credentialSelections) credentialSelections {
	result := append(credentialSelections(nil), explicit...)
	if discovered.hasDiscovery() && !result.hasDiscovery() {
		result = append(result, credentialSelection{Discovery: true})
	}
	return result
}

func supportsCredentialMCP(agentPath string) bool {
	switch filepath.Base(agentPath) {
	case "codex", "claude":
		return true
	default:
		return false
	}
}

func credentialExecutableUnsafeRoot(path string, roots ...string) (string, bool) {
	path, err := canonicalPath(path)
	if err != nil {
		return "", false
	}
	for _, root := range roots {
		root, err := canonicalPath(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || filepath.IsAbs(rel) {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return root, true
		}
	}
	return "", false
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := abs
	var suffix []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return abs, nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

type credentialSession struct {
	dir          string
	env          []credentialaccess.EnvVar
	grants       []activeGrant
	sessionToken string
	mcpCommand   string
}

func prepareCredentialSession(selections credentialSelections, ctlToken, agentPath string) (*credentialSession, error) {
	if len(selections) == 0 {
		return &credentialSession{}, nil
	}
	if ctlToken == "" {
		return nil, errors.New("credential sessions require the AgentJail control token")
	}
	socketPath := defaultSecretsSocketPath()
	if !sandbox.SecretsBrokerRunning() {
		if err := sandbox.EnsureSecretsBroker(socketPath); err != nil {
			return nil, fmt.Errorf("start AgentJail credential broker: %w", err)
		}
	}
	if err := pruneAbandonedCredentialSessions(os.TempDir(), credentialProcessAlive); err != nil {
		return nil, fmt.Errorf("clean abandoned credential sessions: %w", err)
	}

	dir, err := os.MkdirTemp("", fmt.Sprintf("agentjail-credentials-%d-", os.Getpid()))
	if err != nil {
		return nil, fmt.Errorf("create credential session directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("protect credential session directory: %w", err)
	}
	session := &credentialSession{dir: dir}
	fail := func(err error) (*credentialSession, error) {
		session.cleanup(ctlToken)
		return nil, err
	}
	project, err := os.Getwd()
	if err != nil {
		return fail(fmt.Errorf("resolve credential session project: %w", err))
	}
	sessionID := fmt.Sprintf("shield-%d", os.Getpid())
	agent := filepath.Base(agentPath)

	for _, selection := range selections {
		if selection.Discovery {
			continue
		}

		resp, err := secretsRPC(socketPath, &secretsRPCRequest{
			Action: "credential_grant", Token: ctlToken, Name: selection.Name,
			SessionID: sessionID, Project: project, Agent: agent,
		})
		if err != nil {
			return fail(fmt.Errorf("credential %q: %w", selection.Name, err))
		}
		if !resp.OK {
			return fail(fmt.Errorf("credential %q was rejected: %s", selection.Name, resp.Error))
		}
		if resp.Delivery == nil {
			return fail(fmt.Errorf("credential %q returned no delivery", selection.Name))
		}
		session.grants = append(session.grants, activeGrant{GrantID: resp.GrantID, Name: selection.Name})
		session.env = append(session.env, resp.Delivery.Env...)
		for _, directory := range resp.Delivery.Directories {
			if err := session.writeDirectory(directory); err != nil {
				return fail(fmt.Errorf("credential %q: %w", selection.Name, err))
			}
		}
		for _, file := range resp.Delivery.Files {
			if err := session.writeFile(file); err != nil {
				return fail(fmt.Errorf("credential %q: %w", selection.Name, err))
			}
		}
	}
	if !supportsCredentialMCP(agentPath) {
		return session, nil
	}
	registered, err := secretsRPC(socketPath, &secretsRPCRequest{
		Action:    "session_register",
		Token:     ctlToken,
		SessionID: sessionID,
		Project:   project,
		Agent:     agent,
	})
	if err != nil {
		return fail(fmt.Errorf("register agent credential session: %w", err))
	}
	if !registered.OK || registered.SessionToken == "" {
		return fail(fmt.Errorf("register agent credential session: %s", registered.Error))
	}
	session.sessionToken = registered.SessionToken
	mcpCommand, err := credentialMCPCommand()
	if err != nil {
		return fail(err)
	}
	session.mcpCommand = mcpCommand
	session.env = append(session.env,
		credentialaccess.EnvVar{Name: "AGENTJAIL_CREDENTIAL_BROKER_SOCKET", Value: socketPath},
		credentialaccess.EnvVar{Name: "AGENTJAIL_CREDENTIAL_SESSION_TOKEN", Value: session.sessionToken},
	)
	return session, nil
}

func credentialMCPCommand() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve AgentJail credential MCP command: %w", err)
	}
	candidate := filepath.Join(filepath.Dir(executable), "agentjail")
	if filepath.Base(executable) == "agentjail" {
		candidate = executable
	}
	candidate, err = filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve AgentJail credential MCP command symlinks: %w", err)
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve AgentJail credential MCP command %s: %w", candidate, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("AgentJail credential MCP command is not executable: %s", candidate)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory for credential MCP: %w", err)
	}
	if root, unsafe := credentialExecutableUnsafeRoot(candidate, cwd, os.TempDir()); unsafe {
		return "", fmt.Errorf("AgentJail credential MCP command resolves inside agent-writable path %s", root)
	}
	return candidate, nil
}

func (s *credentialSession) configureAgent(agentPath string, arguments []string) ([]string, error) {
	if s.sessionToken == "" {
		return arguments, nil
	}
	switch filepath.Base(agentPath) {
	case "codex":
		prefix := []string{
			"-c", "mcp_servers.agentjail_credentials.command=" + strconv.Quote(s.mcpCommand),
			"-c", `mcp_servers.agentjail_credentials.args=["credential-mcp"]`,
			"-c", `mcp_servers.agentjail_credentials.env_vars=["AGENTJAIL_CREDENTIAL_BROKER_SOCKET","AGENTJAIL_CREDENTIAL_SESSION_TOKEN"]`,
			"-c", "mcp_servers.agentjail_credentials.required=true",
			"-c", `mcp_servers.agentjail_credentials.enabled_tools=["list_credentials","request_credential"]`,
			"-c", `mcp_servers.agentjail_credentials.default_tools_approval_mode="auto"`,
		}
		return append(prefix, arguments...), nil
	case "claude":
		configPath := filepath.Join(s.dir, "mcp.json")
		config := struct {
			Servers map[string]struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"mcpServers"`
		}{Servers: map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}{"agentjail_credentials": {Command: s.mcpCommand, Args: []string{"credential-mcp"}}}}
		data, err := json.Marshal(config)
		if err != nil {
			return nil, fmt.Errorf("encode Claude credential MCP config: %w", err)
		}
		if err := os.WriteFile(configPath, data, 0o600); err != nil {
			return nil, fmt.Errorf("write Claude credential MCP config: %w", err)
		}
		prefix := []string{"--mcp-config", configPath, "--append-system-prompt", credentialguidance.SessionInstructions}
		return append(prefix, arguments...), nil
	default:
		return nil, fmt.Errorf("agent %s does not support session credential MCP configuration", filepath.Base(agentPath))
	}
}

const credentialSessionPrefix = "agentjail-credentials-"

func pruneAbandonedCredentialSessions(tempDir string, alive func(int) bool) error {
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), credentialSessionPrefix) {
			continue
		}
		rest := strings.TrimPrefix(entry.Name(), credentialSessionPrefix)
		pidText, _, ok := strings.Cut(rest, "-")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(pidText)
		if err != nil || pid <= 0 || alive(pid) {
			continue
		}
		path := filepath.Join(tempDir, entry.Name())
		if filepath.Dir(path) != filepath.Clean(tempDir) {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	return nil
}

func (s *credentialSession) writeDirectory(directory credentialaccess.SessionDirectory) error {
	if err := credentialaccess.ValidateDelivery(credentialaccess.Delivery{Directories: []credentialaccess.SessionDirectory{directory}}); err != nil {
		return err
	}
	path := filepath.Join(s.dir, directory.Name)
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create session directory %s: %w", directory.Name, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect session directory %s: %w", directory.Name, err)
	}
	s.env = append(s.env, credentialaccess.EnvVar{Name: directory.EnvVar, Value: path})
	return nil
}

func (s *credentialSession) writeFile(file credentialaccess.SessionFile) error {
	if err := credentialaccess.ValidateDelivery(credentialaccess.Delivery{Files: []credentialaccess.SessionFile{file}}); err != nil {
		return err
	}
	path := filepath.Join(s.dir, file.Name)
	if err := os.WriteFile(path, file.Content, 0o600); err != nil {
		return fmt.Errorf("write session file %s: %w", file.Name, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect session file %s: %w", file.Name, err)
	}
	s.env = append(s.env, credentialaccess.EnvVar{Name: file.EnvVar, Value: path})
	return nil
}

func (s *credentialSession) applyEnv(base []string) []string {
	keys := make([]string, 0, len(s.env))
	for _, variable := range s.env {
		keys = append(keys, variable.Name)
	}
	base = removeEnvKeys(base, keys...)
	for _, variable := range s.env {
		base = append(base, variable.Name+"="+variable.Value)
	}
	return base
}

func (s *credentialSession) cleanup(ctlToken string) {
	if len(s.grants) > 0 {
		revokeSecretGrants(s.grants, ctlToken)
		s.grants = nil
	}
	if s.sessionToken != "" {
		_, _ = secretsRPC(defaultSecretsSocketPath(), &secretsRPCRequest{
			Action: "session_revoke", Token: ctlToken, SessionToken: s.sessionToken,
		})
		s.sessionToken = ""
	}
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
		s.dir = ""
	}
}

func defaultSecretsSocketPath() string {
	return filepath.Join(filepath.Dir(defaultPolicyPath()), "secrets.sock")
}

func removeEnvKeys(env []string, keys ...string) []string {
	blocked := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		blocked[key] = struct{}{}
	}
	result := env[:0]
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if _, found := blocked[key]; !found {
			result = append(result, entry)
		}
	}
	return result
}
