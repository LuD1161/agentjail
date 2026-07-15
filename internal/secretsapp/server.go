package secretsapp

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/credentials"
	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/sandbox"
	auditstore "github.com/LuD1161/agentjail/internal/store"
)

// RPCRequest is the newline-delimited JSON request sent by CLI clients.
type RPCRequest struct {
	Action string `json:"action"`
	// Token authenticates the caller as a process outside the sandbox. Required
	// on every action (ADR 0067).
	Token   string `json:"token,omitempty"`
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

// defaultLogPath returns ~/.agentjail/secrets.log, or "" (→ stderr) if the home
// directory cannot be determined.
func defaultLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".agentjail", "secrets.log")
}

// runServer starts the secrets RPC server.
func runServer(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "path to Unix socket")
	storeDir := fs.String("store", defaultStoreDir(), "path to secrets store directory")
	keyPath := fs.String("key", defaultKeyPath(), "path to master key file")
	idleTimeout := fs.Duration("idle-timeout", 0, "self-exit after this idle window with no active grants (0 = never; ADR 0058)")
	logPath := fs.String("log", defaultLogPath(), "structured JSON log file (empty = stderr)")
	fs.Parse(args)

	// Route structured slog to a dedicated file (ADR 0058): under the service
	// manager, stderr is captured to secrets-crash.log (panics/runtime), while
	// secrets.log holds the structured JSON. Every slog site here logs secret
	// NAMES / grant-ids only, never values — keep it that way.
	var logW io.Writer = os.Stderr
	if *logPath != "" {
		if err := os.MkdirAll(filepath.Dir(*logPath), 0o700); err == nil {
			if f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				logW = f
				defer f.Close()
			} else {
				fmt.Fprintf(os.Stderr, "agentjail-secrets: cannot open log %s (%v); logging to stderr\n", *logPath, err)
			}
		}
	}
	logger := slog.New(slog.NewJSONHandler(logW, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	store, err := NewStore(*storeDir, *keyPath)
	if err != nil {
		slog.Error("init store", "err", err)
		os.Exit(1)
	}

	gm := credentials.NewGrantManager()
	stopCleanup := gm.StartCleanup(credentials.DefaultCleanupInterval)
	defer stopCleanup()

	// Open audit emitter (best-effort; fall back to NopEmitter).
	var emitter audit.Emitter = audit.NopEmitter{}
	home, _ := os.UserHomeDir()
	if home != "" {
		dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
		if st, err := auditstore.Open(dbPath); err == nil {
			emitter = st
			defer st.Close()
		}
	}

	// Fail CLOSED: without a token this broker would serve credentials to any
	// caller that connects (ADR 0067).
	ctlToken, err := ctlauth.Ensure()
	if err != nil {
		slog.Error("cannot establish control token; refusing to serve credentials", "err", err)
		os.Exit(1)
	}

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

	// activity tracks the last time a client connected, for the idle watchdog.
	// Seeded to now so a just-started broker is not immediately considered idle.
	var activity idleClock
	activity.touch()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			activity.touch()
			go handleConn(conn, store, gm, emitter, ctlToken)
		}
	}()

	// idleFire closes when the broker has been idle past --idle-timeout AND has
	// zero active grants (ADR 0058 P1: never exit while grants are live, else
	// the in-memory revokeFn state is lost or live sessions are torn down).
	idleFire := make(chan struct{})
	if *idleTimeout > 0 {
		go idleWatchdog(*idleTimeout, &activity, gm, idleFire)
	}

	select {
	case sig := <-sigCh:
		slog.Info("shutdown signal received", "signal", sig)
	case <-idleFire:
		slog.Info("idle timeout reached with no active grants; exiting", "idle_timeout", idleTimeout.String())
	}
	gm.RevokeAll()
	_ = ln.Close()
	_ = os.Remove(*socketPath)
}

// idleClock records the last activity time as unix-nanos for lock-free reads.
type idleClock struct{ last atomic.Int64 }

func (c *idleClock) touch() { c.last.Store(time.Now().UnixNano()) }
func (c *idleClock) idleFor() time.Duration {
	return time.Duration(time.Now().UnixNano() - c.last.Load())
}

// idleWatchdog closes fire once the broker has been idle for at least timeout
// AND the GrantManager reports zero active grants. It polls at a fraction of
// the timeout (min 1s) so the check is cheap and responsive.
func idleWatchdog(timeout time.Duration, clock *idleClock, gm *credentials.GrantManager, fire chan<- struct{}) {
	interval := timeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		if clock.idleFor() >= timeout && gm.Active() == 0 {
			close(fire)
			return
		}
	}
}

// handleConn serves one client connection.
func handleConn(conn net.Conn, store *Store, gm *credentials.GrantManager, emitter audit.Emitter, token string) {
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

		// Every verb here is privileged (grant returns credentials; set/delete
		// mutate the store), so authenticate per request, before dispatch.
		// The token is the boundary -- see ADR 0067.
		if !ctlauth.Valid(req.Token, token) {
			slog.Warn("secrets: rejecting unauthenticated request", "action", req.Action)
			_ = enc.Encode(RPCResponse{OK: false, Error: "unauthorized: control token required"})
			continue
		}

		resp := handleRPC(&req, store, gm, emitter)
		_ = enc.Encode(resp)
	}
}

// handleRPC dispatches an RPC request to the appropriate handler. The caller
// MUST have authenticated req.Token first (see handleConn).
func handleRPC(req *RPCRequest, store *Store, gm *credentials.GrantManager, emitter audit.Emitter) RPCResponse {
	ctx := context.Background()
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
		return handleGrant(req, store, gm, emitter)

	case "revoke":
		if err := gm.Revoke(req.GrantID); err != nil {
			return RPCResponse{OK: false, Error: err.Error()}
		}
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.CredentialRevoked,
			Entity:    req.GrantID,
			Actor:     "secrets",
		})
		return RPCResponse{OK: true}

	default:
		return RPCResponse{OK: false, Error: "unknown action: " + req.Action}
	}
}

// backends maps backend names to their implementations.
var backends = map[string]credentials.Backend{
	"aws":   &credentials.AWSBackend{},
	"pg":    &credentials.PostgresBackend{},
	"redis": &credentials.RedisBackend{},
}

// handleGrant issues scoped credentials for a secret.
func handleGrant(req *RPCRequest, store *Store, gm *credentials.GrantManager, emitter audit.Emitter) RPCResponse {
	cfg, err := store.loadConfig(req.Name)
	if err != nil {
		return RPCResponse{OK: false, Error: fmt.Sprintf("load secret: %v", err)}
	}

	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		ttl = 15 * time.Minute
	}
	ttl = credentials.ClampTTL(ttl)

	scope := req.Scope
	if scope == "" {
		scope = "read-only"
	}

	ctx := context.Background()

	var grant *credentials.Grant
	if backend, ok := backends[cfg.Backend]; ok {
		credCfg := &credentials.Config{
			Backend:    cfg.Backend,
			RoleARN:    cfg.RoleARN,
			AccessKey:  cfg.AccessKey,
			SecretKey:  cfg.SecretKey,
			SessionTTL: cfg.SessionTTL,
			DSN:        cfg.DSN,
			Addr:       cfg.Addr,
			Password:   cfg.Password,
			Keys:       cfg.Keys,
		}
		grant, err = backend.Grant(ctx, credCfg, scope, ttl)
	} else if cfg.Backend == "raw" {
		value, gerr := store.Get(req.Name)
		if gerr != nil {
			return RPCResponse{OK: false, Error: gerr.Error()}
		}
		grant = &credentials.Grant{
			ID:         credentials.NewGrantID(),
			SecretName: req.Name,
			Backend:    "raw",
			Scope:      scope,
			ExpiresAt:  time.Now().Add(ttl),
			EnvVars:    map[string]string{req.Name: value},
		}
	} else {
		return RPCResponse{OK: false, Error: "unknown backend: " + cfg.Backend}
	}

	if err != nil {
		return RPCResponse{OK: false, Error: err.Error()}
	}

	grant.SecretName = req.Name
	grantID := gm.Register(grant)

	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.CredentialIssued,
		Entity:    req.Name,
		Detail:    map[string]string{"type": grant.Backend, "grant_id": grantID},
		Actor:     "secrets",
	})

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
	// Attach the token unless the caller supplied one (the shield passes its
	// own, captured pre-Landlock). A read failure is not fatal: let the server
	// answer "unauthorized" rather than guess locally (ADR 0067).
	if req.Token == "" {
		if tok, terr := ctlauth.Load(); terr == nil {
			req.Token = tok
		}
	}

	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		// On-demand start (ADR 0058): the broker is a loaded-but-not-running
		// launchd/systemd job, so a first client brings it up rather than
		// failing. Falls back to a detached exec where no service manager runs.
		if startErr := sandbox.EnsureSecretsBroker(socketPath); startErr != nil {
			return nil, fmt.Errorf("connect to secrets server: %w\n  Auto-start failed: %v\n  Start it manually with: agentjail-secrets serve", err, startErr)
		}
		conn, err = net.DialTimeout("unix", socketPath, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("connect to secrets server after auto-start: %w", err)
		}
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
