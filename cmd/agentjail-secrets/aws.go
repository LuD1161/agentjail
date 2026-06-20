package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AssumeRoleResponse is the XML response from STS AssumeRole.
type AssumeRoleResponse struct {
	XMLName xml.Name `xml:"AssumeRoleResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleResult"`
	ResponseMetadata struct {
		RequestID string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

// grantAWS issues scoped AWS credentials via STS AssumeRole.
//
// The secret config must contain:
//   - role_arn: the IAM role to assume
//   - access_key / secret_key: base credentials for the AssumeRole call
//
// The scope determines the inline session policy:
//   - read-only: deny all write/delete/terminate operations
//   - read-write: allow create/update but deny delete/terminate
//
// The TTL is the STS session duration (minimum 900 seconds = 15 minutes).
// STS sessions cannot be revoked early — revocation relies on the short TTL.
func grantAWS(cfg *secretConfig, scope string, ttl time.Duration) (*Grant, error) {
	if cfg.RoleARN == "" {
		return nil, fmt.Errorf("aws secret missing role_arn")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("aws secret missing access_key/secret_key")
	}

	durationSeconds := int(ttl.Seconds())
	if durationSeconds < 900 {
		durationSeconds = 900
	}
	if durationSeconds > 43200 {
		durationSeconds = 43200
	}

	policy, ok := scopePolicies[scope]
	if !ok {
		return nil, fmt.Errorf("unknown scope: %q (valid: read-only, read-write)", scope)
	}

	sessionName := fmt.Sprintf("agentjail-%d", time.Now().Unix())
	bodyStr, bodyBytes := buildAssumeRoleBody(cfg.RoleARN, sessionName, durationSeconds, policy)

	req, err := http.NewRequestWithContext(context.Background(),
		"POST", "https://sts.amazonaws.com/", strings.NewReader(bodyStr))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	sigV4Sign(req, bodyBytes, cfg.AccessKey, cfg.SecretKey, "", "us-east-1", "sts")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sts request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read sts response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sts error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var arResp AssumeRoleResponse
	if err := xml.Unmarshal(respBody, &arResp); err != nil {
		return nil, fmt.Errorf("parse sts response: %w", err)
	}

	creds := arResp.Result.Credentials
	if creds.AccessKeyID == "" {
		return nil, fmt.Errorf("sts response missing credentials: %s", string(respBody))
	}

	expiration, err := time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		expiration = time.Now().Add(time.Duration(durationSeconds) * time.Second)
	}

	grant := &Grant{
		ID:         newGrantID(),
		SecretName: cfg.Backend,
		Backend:    "aws",
		Scope:      scope,
		ExpiresAt:  expiration,
		EnvVars: map[string]string{
			"AWS_ACCESS_KEY_ID":     creds.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY": creds.SecretAccessKey,
			"AWS_SESSION_TOKEN":     creds.SessionToken,
		},
		revokeFn: nil,
	}

	slog.Info("aws grant issued",
		"grant_id", grant.ID,
		"role_arn", cfg.RoleARN,
		"scope", scope,
		"expires_at", expiration.Format(time.RFC3339),
	)

	return grant, nil
}
