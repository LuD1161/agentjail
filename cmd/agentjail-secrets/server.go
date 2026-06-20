package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// RPCRequest is the newline-delimited JSON request sent by CLI clients.
type RPCRequest struct {
	Action  string `json:"action"`
	Name    string `json:"name,omitempty"`
	Value   string `json:"value,omitempty"`
	Scope   string `json:"scope,omitempty"`
	TTL     string `json:"ttl,omitempty"`
	GrantID string `json:"grant_id,omitempty"`
}

// RPCResponse is the newline-delimited JSON response from the server.
type RPCResponse struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	Names   []string          `json:"names,omitempty"`
	EnvVars map[string]string `json:"env_vars,omitempty"`
	GrantID string            `json:"grant_id,omitempty"`
	Expires string            `json:"expires,omitempty"`
}

// defaultSocketPath returns ~/.agentjail/secrets.sock.
func defaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-secrets.sock"
	}
	return filepath.Join(home, ".agentjail", "secrets.sock")
}

// defaultStoreDir returns ~/.agentjail/secrets/.
func defaultStoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-secrets"
	}
	return filepath.Join(home, ".agentjail", "secrets")
}

// defaultKeyPath returns ~/.agentjail/secrets.key.
func defaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-secrets.key"
	}
	return filepath.Join(home, ".agentjail", "secrets.key")
}

// runServer starts the secrets RPC server.
func runServer(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "path to Unix socket")
	storeDir := fs.String("store", defaultStoreDir(), "path to secrets store directory")
	keyPath := fs.String("key", defaultKeyPath(), "path to master key file")
	fs.Parse(args)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	store, err := NewStore(*storeDir, *keyPath)
	if err != nil {
		slog.Error("init store", "err", err)
		os.Exit(1)
	}

	gm := NewGrantManager()

	socketDir := filepath.Dir(*socketPath)
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		slog.Error("create socket dir", "dir", socketDir, "err", err)
		os.Exit(1)
	}

	_ = os.Remove(*socketPath)

	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		slog.Error("listen", "socket", *socketPath, "err", err)
		os.Exit(1)
	}
	if err := os.Chmod(*socketPath, 0o600); err != nil {
		slog.Warn("chmod socket", "err", err)
	}

	slog.Info("agentjail-secrets listening", "socket", *socketPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, store, gm)
		}
	}()

	sig := <-sigCh
	slog.Info("shutdown signal received", "signal", sig)
	gm.RevokeAll()
	_ = ln.Close()
	_ = os.Remove(*socketPath)
}

// handleConn serves one client connection.
func handleConn(conn net.Conn, store *Store, gm *GrantManager) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		var req RPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			_ = enc.Encode(RPCResponse{OK: false, Error: "malformed request: " + err.Error()})
			continue
		}

		resp := handleRPC(&req, store, gm)
		_ = enc.Encode(resp)
	}
}

// handleRPC dispatches an RPC request to the appropriate handler.
func handleRPC(req *RPCRequest, store *Store, gm *GrantManager) RPCResponse {
	switch req.Action {
	case "set":
		if err := store.Set(req.Name, req.Value); err != nil {
			return RPCResponse{OK: false, Error: err.Error()}
		}
		slog.Info("secret stored", "name", req.Name)
		return RPCResponse{OK: true}

	case "list":
		names, err := store.List()
		if err != nil {
			return RPCResponse{OK: false, Error: err.Error()}
		}
		return RPCResponse{OK: true, Names: names}

	case "delete":
		if err := store.Delete(req.Name); err != nil {
			return RPCResponse{OK: false, Error: err.Error()}
		}
		slog.Info("secret deleted", "name", req.Name)
		return RPCResponse{OK: true}

	case "grant":
		return handleGrant(req, store, gm)

	case "revoke":
		if err := gm.Revoke(req.GrantID); err != nil {
			return RPCResponse{OK: false, Error: err.Error()}
		}
		return RPCResponse{OK: true}

	default:
		return RPCResponse{OK: false, Error: "unknown action: " + req.Action}
	}
}

// handleGrant issues scoped credentials for a secret.
func handleGrant(req *RPCRequest, store *Store, gm *GrantManager) RPCResponse {
	cfg, err := store.loadConfig(req.Name)
	if err != nil {
		return RPCResponse{OK: false, Error: fmt.Sprintf("load secret: %v", err)}
	}

	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		ttl = 15 * time.Minute
	}

	scope := req.Scope
	if scope == "" {
		scope = "read-only"
	}

	var grant *Grant
	switch cfg.Backend {
	case "aws":
		grant, err = grantAWS(cfg, scope, ttl)
	case "pg":
		grant, err = grantPostgres(cfg, scope, ttl)
	case "redis":
		grant, err = grantRedis(cfg, scope, ttl)
	case "raw":
		value, gerr := store.Get(req.Name)
		if gerr != nil {
			return RPCResponse{OK: false, Error: gerr.Error()}
		}
		grant = &Grant{
			ID:         newGrantID(),
			SecretName: req.Name,
			Backend:    "raw",
			Scope:      scope,
			ExpiresAt:  time.Now().Add(ttl),
			EnvVars:    map[string]string{req.Name: value},
		}
	default:
		return RPCResponse{OK: false, Error: "unknown backend: " + cfg.Backend}
	}

	if err != nil {
		return RPCResponse{OK: false, Error: err.Error()}
	}

	grant.SecretName = req.Name
	grantID := gm.Register(grant)

	return RPCResponse{
		OK:      true,
		EnvVars: grant.EnvVars,
		GrantID: grantID,
		Expires: grant.ExpiresAt.Format(time.RFC3339),
	}
}

// --- CLI client functions ---

// rpcClient sends a request to the secrets server and returns the response.
func rpcClient(socketPath string, req *RPCRequest) (*RPCResponse, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to secrets server: %w\n  Is agentjail-secrets running? Start it with: agentjail-secrets serve", err)
	}
	defer conn.Close()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	if !scanner.Scan() {
		return nil, fmt.Errorf("read response: %w", scanner.Err())
	}

	var resp RPCResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &resp, nil
}

// runSet is the CLI client for `agentjail-secrets set <name> <value>`.
func runSet(args []string) {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "path to Unix socket")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentjail-secrets set <name> <value>")
		os.Exit(64)
	}

	resp, err := rpcClient(*socketPath, &RPCRequest{Action: "set", Name: rest[0], Value: rest[1]})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %v\n", err)
		os.Exit(1)
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %s\n", resp.Error)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "stored: %s\n", rest[0])
}

// runList is the CLI client for `agentjail-secrets list`.
func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "path to Unix socket")
	fs.Parse(args)

	resp, err := rpcClient(*socketPath, &RPCRequest{Action: "list"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %v\n", err)
		os.Exit(1)
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %s\n", resp.Error)
		os.Exit(1)
	}
	for _, name := range resp.Names {
		fmt.Println(name)
	}
}

// runDelete is the CLI client for `agentjail-secrets delete <name>`.
func runDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "path to Unix socket")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentjail-secrets delete <name>")
		os.Exit(64)
	}

	resp, err := rpcClient(*socketPath, &RPCRequest{Action: "delete", Name: rest[0]})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %v\n", err)
		os.Exit(1)
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %s\n", resp.Error)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "deleted: %s\n", rest[0])
}

// runGrant is the CLI client for `agentjail-secrets grant <name> --scope=<policy> --ttl=<duration>`.
func runGrant(args []string) {
	fs := flag.NewFlagSet("grant", flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "path to Unix socket")
	scope := fs.String("scope", "read-only", "credential scope (read-only, read-write)")
	ttl := fs.String("ttl", "15m", "credential TTL (e.g. 15m, 1h)")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentjail-secrets grant <name> --scope=<policy> --ttl=<duration>")
		os.Exit(64)
	}

	resp, err := rpcClient(*socketPath, &RPCRequest{
		Action: "grant",
		Name:   rest[0],
		Scope:  *scope,
		TTL:    *ttl,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %v\n", err)
		os.Exit(1)
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %s\n", resp.Error)
		os.Exit(1)
	}

	out := map[string]interface{}{
		"grant_id": resp.GrantID,
		"expires":  resp.Expires,
		"env":      resp.EnvVars,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// runRevoke is the CLI client for `agentjail-secrets revoke <grant-id>`.
func runRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "path to Unix socket")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentjail-secrets revoke <grant-id>")
		os.Exit(64)
	}

	resp, err := rpcClient(*socketPath, &RPCRequest{Action: "revoke", GrantID: rest[0]})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %v\n", err)
		os.Exit(1)
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "agentjail-secrets: %s\n", resp.Error)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "revoked: %s\n", rest[0])
}
