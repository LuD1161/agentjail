package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	ui "github.com/LuD1161/agentjail/internal/ui"
)

// runSecretSet stores a credential in the vault and writes the credential
// config to policy.yaml.
func runSecretSet(name string) error {
	u := ui.New(os.Stdout)

	// Resolve the credential value.
	value := secretSetValue
	envVar := secretSetFromEnv
	if value == "" && envVar == "" {
		return fmt.Errorf("either --value or --from-env is required")
	}
	if value != "" && envVar != "" {
		return fmt.Errorf("--value and --from-env are mutually exclusive")
	}
	if envVar != "" {
		value = os.Getenv(envVar)
		if value == "" {
			return fmt.Errorf("environment variable %q is empty or not set", envVar)
		}
	} else {
		// When --value is used, infer the env var name.
		envVar = inferEnvVar(name)
	}

	hosts := splitCSV(secretSetHosts)
	if len(hosts) == 0 {
		return fmt.Errorf("--hosts is required")
	}

	// Step 1: Store the value in the encrypted vault via agentjail-secrets.
	if err := callSecretsSet(name, value); err != nil {
		return fmt.Errorf("store credential in vault: %w", err)
	}

	// Step 2: Write the credential config to policy.yaml.
	policyPath, err := policyConfigPath()
	if err != nil {
		return fmt.Errorf("resolve policy path: %w", err)
	}

	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		return fmt.Errorf("load policy config: %w", err)
	}

	// Remove existing credential with the same ID (upsert).
	var filtered []config.CredentialConfig
	for _, c := range cfg.Credentials {
		if c.ID != name {
			filtered = append(filtered, c)
		}
	}

	newCred := config.CredentialConfig{
		ID:             name,
		EnvVar:         envVar,
		Source:          "vault",
		AllowedHosts:   hosts,
		AllowedMethods: splitCSV(secretSetMethods),
		AllowedPaths:   splitCSV(secretSetPaths),
		Injection: config.CredentialInjectionConfig{
			Type:   secretSetType,
			Header: secretSetHeader,
			Scheme: secretSetScheme,
		},
		Violation: secretSetViola,
		TTL:       secretSetTTL,
	}
	cfg.Credentials = append(filtered, newCred)

	if err := config.Save(cfg, policyPath); err != nil {
		return fmt.Errorf("save policy config: %w", err)
	}

	// Step 3: Print confirmation.
	fmt.Fprintln(os.Stdout, u.Badge("ok", "credential stored: "+name))
	fmt.Fprintln(os.Stdout, u.KeyValue("  env_var", envVar, ""))
	fmt.Fprintln(os.Stdout, u.KeyValue("  hosts", strings.Join(hosts, ", "), ""))
	fmt.Fprintln(os.Stdout, u.KeyValue("  injection", formatInjection(secretSetHeader, secretSetScheme), ""))
	if secretSetViola != "" {
		fmt.Fprintln(os.Stdout, u.KeyValue("  violation", secretSetViola, ""))
	}
	if secretSetTTL != "" {
		fmt.Fprintln(os.Stdout, u.KeyValue("  ttl", secretSetTTL, ""))
	}

	return nil
}

// runSecretList shows configured credentials from policy.yaml (no values).
func runSecretList() error {
	u := ui.New(os.Stdout)

	policyPath, err := policyConfigPath()
	if err != nil {
		return fmt.Errorf("resolve policy path: %w", err)
	}

	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		return fmt.Errorf("load policy config: %w", err)
	}

	if len(cfg.Credentials) == 0 {
		fmt.Fprintln(os.Stdout, u.Badge("dim", "no credentials configured"))
		return nil
	}

	fmt.Fprintln(os.Stdout, u.Section("Configured credentials"))
	fmt.Fprintln(os.Stdout)

	for _, c := range cfg.Credentials {
		fmt.Fprintln(os.Stdout, u.Badge("info", c.ID))
		fmt.Fprintln(os.Stdout, u.KeyValue("  env_var", c.EnvVar, ""))
		fmt.Fprintln(os.Stdout, u.KeyValue("  source", c.Source, ""))
		if len(c.AllowedHosts) > 0 {
			fmt.Fprintln(os.Stdout, u.KeyValue("  hosts", strings.Join(c.AllowedHosts, ", "), ""))
		}
		if len(c.AllowedMethods) > 0 {
			fmt.Fprintln(os.Stdout, u.KeyValue("  methods", strings.Join(c.AllowedMethods, ", "), ""))
		}
		if len(c.AllowedPaths) > 0 {
			fmt.Fprintln(os.Stdout, u.KeyValue("  paths", strings.Join(c.AllowedPaths, ", "), ""))
		}
		fmt.Fprintln(os.Stdout, u.KeyValue("  injection", formatInjection(c.Injection.Header, c.Injection.Scheme), ""))
		if c.Violation != "" {
			fmt.Fprintln(os.Stdout, u.KeyValue("  violation", c.Violation, ""))
		}
		if c.TTL != "" {
			fmt.Fprintln(os.Stdout, u.KeyValue("  ttl", c.TTL, ""))
		}
		fmt.Fprintln(os.Stdout)
	}

	return nil
}

// runSecretRemove removes a credential from both the vault and policy.yaml.
func runSecretRemove(name string) error {
	u := ui.New(os.Stdout)

	// Step 1: Remove from the vault via agentjail-secrets.
	if err := callSecretsDelete(name); err != nil {
		// Log but continue -- the policy entry should still be removed.
		fmt.Fprintln(os.Stderr, u.Badge("warn", fmt.Sprintf("vault removal: %v", err)))
	}

	// Step 2: Remove from policy.yaml.
	policyPath, err := policyConfigPath()
	if err != nil {
		return fmt.Errorf("resolve policy path: %w", err)
	}

	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		return fmt.Errorf("load policy config: %w", err)
	}

	found := false
	var filtered []config.CredentialConfig
	for _, c := range cfg.Credentials {
		if c.ID == name {
			found = true
			continue
		}
		filtered = append(filtered, c)
	}

	if !found {
		fmt.Fprintln(os.Stdout, u.Badge("warn", "credential not found in policy: "+name))
		return nil
	}

	cfg.Credentials = filtered
	if err := config.Save(cfg, policyPath); err != nil {
		return fmt.Errorf("save policy config: %w", err)
	}

	fmt.Fprintln(os.Stdout, u.Badge("ok", "credential removed: "+name))
	return nil
}

// callSecretsSet invokes `agentjail-secrets set <name> <value>` to store the
// credential in the encrypted vault.
func callSecretsSet(name, value string) error {
	bin, err := findSecretsBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "set", name, value)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// callSecretsDelete invokes `agentjail-secrets delete <name>`.
func callSecretsDelete(name string) error {
	bin, err := findSecretsBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "delete", name)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// findSecretsBinary locates the agentjail-secrets binary, first checking
// next to the current executable, then falling back to PATH.
func findSecretsBinary() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "agentjail-secrets")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, nil
		}
	}
	if p, err := exec.LookPath("agentjail-secrets"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("agentjail-secrets not found in install dir or PATH")
}
