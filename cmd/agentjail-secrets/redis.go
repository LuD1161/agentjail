package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// grantRedis creates a short-lived Redis ACL user with scoped privileges.
//
// The secret config must contain:
//   - addr: Redis server address (host:port)
//   - password: admin password for ACL SETUSER
//   - keys: allowed key glob (e.g. "prod:*")
//
// The scope determines the allowed commands:
//   - read-only: +@read -@write
//   - read-write: +@read +@write -@dangerous
//
// On revocation, the ACL user is deleted (ACL DELUSER — immediate revocation).
// Redis ACL users don't have a native TTL, so revocation is handled by the
// grant manager on session end or TTL expiry.
func grantRedis(cfg *secretConfig, scope string, ttl time.Duration) (*Grant, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("redis secret missing addr")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("redis secret missing password")
	}

	username := "agentjail_" + randomHex(4)
	password := randomHex(16)
	keys := cfg.Keys
	if keys == "" {
		keys = "*"
	}

	// Build the ACL SETUSER command based on scope.
	cmd := buildRedisACLCommand(username, password, keys, scope)

	// Execute via raw RESP.
	if _, err := redisExec(cfg.Addr, cfg.Password, cmd); err != nil {
		return nil, fmt.Errorf("redis acl setuser: %w", err)
	}

	expiresAt := time.Now().Add(ttl)

	grant := &Grant{
		ID:         newGrantID(),
		SecretName: cfg.Backend,
		Backend:    "redis",
		Scope:      scope,
		ExpiresAt:  expiresAt,
		EnvVars: map[string]string{
			"REDIS_PASSWORD": password,
		},
		revokeFn: func() error {
			delCmd := []string{"ACL", "DELUSER", username}
			if _, err := redisExec(cfg.Addr, cfg.Password, delCmd); err != nil {
				return fmt.Errorf("redis acl deluser: %w", err)
			}
			return nil
		},
	}

	slog.Info("redis grant issued",
		"grant_id", grant.ID,
		"user", username,
		"scope", scope,
		"expires_at", expiresAt.Format(time.RFC3339),
	)

	return grant, nil
}

// buildRedisACLCommand builds the ACL SETUSER command parts for the given scope.
func buildRedisACLCommand(username, password, keys, scope string) []string {
	cmd := []string{"ACL", "SETUSER", username, "on", ">" + password, "~" + keys}

	switch scope {
	case "read-only":
		cmd = append(cmd, "+@read", "-@write", "-@dangerous")
	case "read-write":
		cmd = append(cmd, "+@read", "+@write", "-@dangerous")
	default:
		cmd = append(cmd, "+@read", "-@write", "-@dangerous")
	}

	return cmd
}

// redisExec sends a RESP command to a Redis server and returns the response.
// Uses a raw RESP client (stdlib net + bufio) to avoid a Redis client dep.
func redisExec(addr, authPassword string, cmd []string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial redis: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Authenticate first.
	if authPassword != "" {
		if err := writeRESPCommand(conn, "AUTH", authPassword); err != nil {
			return "", fmt.Errorf("send AUTH: %w", err)
		}
		resp, err := readRESPSimpleString(conn)
		if err != nil {
			return "", fmt.Errorf("read AUTH response: %w", err)
		}
		if resp != "OK" {
			return "", fmt.Errorf("AUTH failed: %s", resp)
		}
	}

	// Send the command.
	if err := writeRESPCommand(conn, cmd...); err != nil {
		return "", fmt.Errorf("send command: %w", err)
	}

	// Read the response.
	resp, err := readRESPResponse(conn)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	return resp, nil
}

// writeRESPCommand writes a RESP array command to the connection.
func writeRESPCommand(conn net.Conn, parts ...string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, p := range parts {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
	}
	_, err := conn.Write([]byte(b.String()))
	return err
}

// readRESPSimpleString reads a RESP simple string response (+OK\r\n).
func readRESPSimpleString(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return "", fmt.Errorf("empty response")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return "", fmt.Errorf("redis error: %s", line[1:])
	default:
		return "", fmt.Errorf("unexpected response type: %c", line[0])
	}
}

// readRESPResponse reads any RESP response and returns it as a string.
func readRESPResponse(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return "", fmt.Errorf("empty response")
	}

	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return "", fmt.Errorf("redis error: %s", line[1:])
	case '$':
		// Bulk string: read the length, then the data.
		var length int
		fmt.Sscanf(line[1:], "%d", &length)
		if length < 0 {
			return "", nil
		}
		data := make([]byte, length+2)
		if _, err := reader.Read(data); err != nil {
			return "", err
		}
		return string(data[:length]), nil
	case ':':
		return line[1:], nil
	case '*':
		// Array: return the count.
		return line[1:], nil
	default:
		return "", fmt.Errorf("unexpected response type: %c", line[0])
	}
}
