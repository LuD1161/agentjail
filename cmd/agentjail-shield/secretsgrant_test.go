package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

func TestRequestSecretGrants_NoBroker(t *testing.T) {
	cfg := &config.PolicyConfig{
		Secrets: config.SecretsConfig{
			Grants: []config.SecretGrant{
				{Name: "aws/prod", Scope: "read-only", TTL: "15m"},
			},
		},
	}
	envVars, grants := requestSecretGrants(cfg)
	if envVars != nil {
		t.Errorf("expected nil envVars when broker is not running, got %v", envVars)
	}
	if grants != nil {
		t.Errorf("expected nil grants when broker is not running, got %v", grants)
	}
}

func TestRequestSecretGrants_NoGrantsConfigured(t *testing.T) {
	cfg := &config.PolicyConfig{}
	envVars, grants := requestSecretGrants(cfg)
	if envVars != nil {
		t.Errorf("expected nil envVars with no grants configured, got %v", envVars)
	}
	if grants != nil {
		t.Errorf("expected nil grants with no grants configured, got %v", grants)
	}
}

func TestRequestSecretGrants_NilConfig(t *testing.T) {
	envVars, grants := requestSecretGrants(nil)
	if envVars != nil {
		t.Errorf("expected nil envVars with nil config, got %v", envVars)
	}
	if grants != nil {
		t.Errorf("expected nil grants with nil config, got %v", grants)
	}
}

func TestSecretsRPC_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "secrets.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		dec := json.NewDecoder(conn)
		var req secretsRPCRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		resp := secretsRPCResponse{
			OK:      true,
			GrantID: "test-grant-id",
			EnvVars: map[string]string{
				"AWS_ACCESS_KEY_ID":     "ASIATEST",
				"AWS_SECRET_ACCESS_KEY": "secrettest",
			},
			Expires: "2026-06-19T15:00:00Z",
		}
		data, _ := json.Marshal(resp)
		data = append(data, '\n')
		conn.Write(data)
	}()

	resp, err := secretsRPC(socketPath, &secretsRPCRequest{
		Action: "grant",
		Name:   "aws/prod",
		Scope:  "read-only",
		TTL:    "15m",
	})
	if err != nil {
		t.Fatalf("secretsRPC: %v", err)
	}
	if !resp.OK {
		t.Fatalf("response not OK: %s", resp.Error)
	}
	if resp.GrantID != "test-grant-id" {
		t.Errorf("GrantID = %q, want test-grant-id", resp.GrantID)
	}
	if resp.EnvVars["AWS_ACCESS_KEY_ID"] != "ASIATEST" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want ASIATEST", resp.EnvVars["AWS_ACCESS_KEY_ID"])
	}
}

func TestSecretsRPC_ConnectionFailure(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "nonexistent.sock")
	_, err := secretsRPC(missingPath, &secretsRPCRequest{Action: "grant", Name: "test"})
	if err == nil {
		t.Fatal("expected error for missing socket, got nil")
	}
}

func TestRevokeSecretGrants_Empty(t *testing.T) {
	revokeSecretGrants(nil)
	revokeSecretGrants([]activeGrant{})
}

func TestSecretsBrokerRunning_NoSocket(t *testing.T) {
	oldHome, _ := os.UserHomeDir()
	t.Setenv("HOME", t.TempDir())
	defer t.Setenv("HOME", oldHome)

	if secretsBrokerRunning() {
		t.Error("expected secretsBrokerRunning to return false with no socket")
	}
}
