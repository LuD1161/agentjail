package shieldapp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/LuD1161/agentjail/internal/credentialtools"
	"github.com/LuD1161/agentjail/internal/sandbox"
)

type credentialSelection struct {
	Tool       credentialtools.Tool
	Name       string
	BinaryPath string
	binaryInfo os.FileInfo
}

type credentialSelections []credentialSelection

func (s credentialSelections) binaryPaths() []string {
	paths := make([]string, 0, len(s))
	for _, tool := range s {
		paths = append(paths, tool.BinaryPath)
	}
	return paths
}

func (s *credentialSelections) String() string {
	values := make([]string, 0, len(*s))
	for _, selection := range *s {
		values = append(values, string(selection.Tool)+"="+selection.Name)
	}
	return strings.Join(values, ",")
}

func (s *credentialSelections) Set(value string) error {
	toolValue, name, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(name) == "" {
		return errors.New("credential must be TOOL=NAME (for example aws=aws/default)")
	}
	tool, err := credentialtools.ParseTool(toolValue)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	for _, existing := range *s {
		if existing.Tool == tool {
			return fmt.Errorf("credentialed tool %q was selected more than once", tool)
		}
	}
	*s = append(*s, credentialSelection{Tool: tool, Name: name})
	return nil
}

func resolveCredentialSelections(selections credentialSelections) (credentialSelections, error) {
	registry := credentialtools.DefaultRegistry()
	resolved := make(credentialSelections, 0, len(selections))
	for _, selection := range selections {
		adapter, err := registry.Resolve(selection.Tool)
		if err != nil {
			return nil, err
		}
		path, err := exec.LookPath(adapter.Binary())
		if err != nil {
			return nil, fmt.Errorf("credentialed tool %q requires %s in PATH: %w", selection.Tool, adapter.Binary(), err)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve %s path: %w", adapter.Binary(), err)
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("resolve %s symlinks: %w", adapter.Binary(), err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat credentialed tool %s: %w", adapter.Binary(), err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return nil, fmt.Errorf("credentialed tool %s resolves to unsafe executable %s", adapter.Binary(), path)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve working directory before credential injection: %w", err)
		}
		if root, unsafe := credentialExecutableUnsafeRoot(path, cwd, os.TempDir()); unsafe {
			return nil, fmt.Errorf("credentialed tool %s resolves inside agent-writable path %s", adapter.Binary(), root)
		}
		selection.BinaryPath = path
		selection.binaryInfo = info
		resolved = append(resolved, selection)
	}
	return resolved, nil
}

func credentialExecutableUnsafeRoot(path string, roots ...string) (string, bool) {
	for _, root := range roots {
		root, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(root); err == nil {
			root = resolved
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

type credentialSession struct {
	dir    string
	env    []credentialtools.EnvVar
	grants []activeGrant
}

func prepareCredentialSession(selections credentialSelections, ctlToken string) (*credentialSession, error) {
	if len(selections) == 0 {
		return &credentialSession{}, nil
	}
	if ctlToken == "" {
		return nil, errors.New("credentialed tools require the AgentJail control token")
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

	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		return fail(fmt.Errorf("create credential tool bin directory: %w", err))
	}
	registry := credentialtools.DefaultRegistry()
	for _, selection := range selections {
		adapter, _ := registry.Resolve(selection.Tool)
		current, err := os.Stat(selection.BinaryPath)
		if err != nil || !os.SameFile(selection.binaryInfo, current) || current.Size() != selection.binaryInfo.Size() || !current.ModTime().Equal(selection.binaryInfo.ModTime()) {
			return fail(fmt.Errorf("credentialed tool %s changed after pre-launch resolution", adapter.Binary()))
		}
		if err := os.Symlink(selection.BinaryPath, filepath.Join(binDir, adapter.Binary())); err != nil {
			return fail(fmt.Errorf("pin credentialed tool %s: %w", adapter.Binary(), err))
		}

		resp, err := secretsRPC(socketPath, &secretsRPCRequest{
			Action: "tool_grant",
			Token:  ctlToken,
			Name:   selection.Name,
			Tool:   string(selection.Tool),
		})
		if err != nil {
			return fail(fmt.Errorf("credential %q for %s: %w", selection.Name, selection.Tool, err))
		}
		if !resp.OK {
			return fail(fmt.Errorf("credential %q for %s was rejected: %s", selection.Name, selection.Tool, resp.Error))
		}
		if resp.Delivery == nil {
			return fail(fmt.Errorf("credential %q for %s returned no delivery", selection.Name, selection.Tool))
		}
		session.grants = append(session.grants, activeGrant{GrantID: resp.GrantID, Name: selection.Name})
		session.env = append(session.env, resp.Delivery.Env...)
		for _, directory := range resp.Delivery.Directories {
			if err := session.writeDirectory(directory); err != nil {
				return fail(fmt.Errorf("credential %q for %s: %w", selection.Name, selection.Tool, err))
			}
		}
		for _, file := range resp.Delivery.Files {
			if err := session.writeFile(file); err != nil {
				return fail(fmt.Errorf("credential %q for %s: %w", selection.Name, selection.Tool, err))
			}
		}
	}
	path := binDir
	if inherited := os.Getenv("PATH"); inherited != "" {
		path += string(os.PathListSeparator) + inherited
	}
	session.env = append(session.env, credentialtools.EnvVar{Name: "PATH", Value: path})
	return session, nil
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

var envNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func (s *credentialSession) writeDirectory(directory credentialtools.SessionDirectory) error {
	if !envNamePattern.MatchString(directory.EnvVar) {
		return fmt.Errorf("adapter returned invalid environment name %q", directory.EnvVar)
	}
	if directory.Name == "" || filepath.Base(directory.Name) != directory.Name {
		return fmt.Errorf("adapter returned invalid session directory name %q", directory.Name)
	}
	path := filepath.Join(s.dir, directory.Name)
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create session directory %s: %w", directory.Name, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect session directory %s: %w", directory.Name, err)
	}
	s.env = append(s.env, credentialtools.EnvVar{Name: directory.EnvVar, Value: path})
	return nil
}

func (s *credentialSession) writeFile(file credentialtools.SessionFile) error {
	if !envNamePattern.MatchString(file.EnvVar) {
		return fmt.Errorf("adapter returned invalid environment name %q", file.EnvVar)
	}
	if file.Name == "" || filepath.Base(file.Name) != file.Name {
		return fmt.Errorf("adapter returned invalid session filename %q", file.Name)
	}
	path := filepath.Join(s.dir, file.Name)
	if err := os.WriteFile(path, file.Content, 0o600); err != nil {
		return fmt.Errorf("write session file %s: %w", file.Name, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect session file %s: %w", file.Name, err)
	}
	s.env = append(s.env, credentialtools.EnvVar{Name: file.EnvVar, Value: path})
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
