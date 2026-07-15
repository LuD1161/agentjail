package shieldapp

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/sandbox"
)

type secretsRPCRequest struct {
	Action string `json:"action"`
	// Token authenticates this shield as a caller outside the sandbox (ADR 0067).
	Token   string `json:"token,omitempty"`
	Name    string `json:"name,omitempty"`
	Scope   string `json:"scope,omitempty"`
	TTL     string `json:"ttl,omitempty"`
	GrantID string `json:"grant_id,omitempty"`
}

type secretsRPCResponse struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	EnvVars map[string]string `json:"env_vars,omitempty"`
	GrantID string            `json:"grant_id,omitempty"`
	Expires string            `json:"expires,omitempty"`
}

type activeGrant struct {
	GrantID string
	Name    string
}

func secretsRPC(socketPath string, req *secretsRPCRequest) (*secretsRPCResponse, error) {
	conn, err := net.DialTimeout("unix", socketPath, 300*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("connect to agentjail-secrets: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	buf := make([]byte, 0, 4096)
	deadline := time.Now().Add(10 * time.Second)
	for {
		chunk := make([]byte, 4096)
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			for _, b := range buf {
				if b == '\n' {
					var resp secretsRPCResponse
					if err := json.Unmarshal(buf, &resp); err != nil {
						return nil, fmt.Errorf("parse response: %w", err)
					}
					return &resp, nil
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
	}
}

// requestSecretGrants asks the broker for the grants policy allows this session
// and returns them as env vars for the agent.
//
// ctlToken must be captured BEFORE applyLandlock on Linux -- by the time this
// runs, this process can no longer read the token file (ADR 0067).
func requestSecretGrants(cfg *config.PolicyConfig, ctlToken string) ([]string, []activeGrant) {
	if cfg == nil || len(cfg.Secrets.Grants) == 0 {
		return nil, nil
	}
	socketPath := sandbox.SecretsSocketPath()
	if !sandbox.SecretsBrokerRunning() {
		// On-demand start (ADR 0058): bring the loaded-but-not-running broker up
		// rather than silently dropping the configured grants. Only warn (and
		// continue without grants) if it genuinely cannot be started.
		if err := sandbox.EnsureSecretsBroker(socketPath); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield WARNING: secrets.grants configured but agentjail-secrets broker could not be started: %v\n", err)
			return nil, nil
		}
	}
	var envVars []string
	var grants []activeGrant

	for _, g := range cfg.Secrets.Grants {
		resp, err := secretsRPC(socketPath, &secretsRPCRequest{
			Action: "grant",
			Token:  ctlToken,
			Name:   g.Name,
			Scope:  g.Scope,
			TTL:    g.TTL,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield WARNING: grant %q failed: %v\n", g.Name, err)
			continue
		}
		if !resp.OK {
			fmt.Fprintf(os.Stderr, "agentjail-shield WARNING: grant %q rejected: %s\n", g.Name, resp.Error)
			continue
		}
		for k, v := range resp.EnvVars {
			envVars = append(envVars, k+"="+v)
		}
		grants = append(grants, activeGrant{
			GrantID: resp.GrantID,
			Name:    g.Name,
		})
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: granted %q (scope=%s, expires=%s, grant_id=%s)\n",
			g.Name, g.Scope, resp.Expires, resp.GrantID)
	}

	return envVars, grants
}

// revokeSecretGrants hands the session's grants back at exit. ctlToken has the
// same capture-before-Landlock requirement as requestSecretGrants (ADR 0067);
// without it the grants live until their TTL.
func revokeSecretGrants(grants []activeGrant, ctlToken string) {
	socketPath := sandbox.SecretsSocketPath()
	for _, g := range grants {
		resp, err := secretsRPC(socketPath, &secretsRPCRequest{
			Action:  "revoke",
			Token:   ctlToken,
			GrantID: g.GrantID,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield WARNING: revoke grant %s (%s): %v\n", g.GrantID, g.Name, err)
			continue
		}
		if !resp.OK {
			fmt.Fprintf(os.Stderr, "agentjail-shield WARNING: revoke grant %s (%s): %s\n", g.GrantID, g.Name, resp.Error)
			continue
		}
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: revoked grant %s (%s)\n", g.GrantID, g.Name)
	}
}
