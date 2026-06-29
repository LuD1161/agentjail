// Package main is the agentjail policy evaluation daemon. It listens on a
// Unix socket, accepts newline-delimited JSON requests, evaluates each request
// against the OPA policy engine, and writes back a JSON response. The daemon
// is designed to run as a persistent background process (launchd on macOS)
// so OPA warm-start cost (~50 ms) is paid once; per-decision latency target
// is p95 < 5 ms.
//
// Protocol: one JSON object per line, request and response each terminated by '\n'.
//
// Request:
//
//	{"id":"req-123","hook_event":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s1","cwd":"/tmp"}
//
// Response:
//
//	{"id":"req-123","action":"allow","reason":"default allow","rule_id":"default"}
//
// Signals:
//   - SIGTERM / SIGINT: drain in-flight requests, close socket, exit 0.
//   - SIGHUP: reload policy.yaml AND Rego modules, rebuild engine atomically
//     under RWMutex; in-flight Eval calls complete against the old engine.
//     On reload failure, old config is kept — daemon never goes open.
//
// Architecture note: pattern copied from Firecracker's JSON-over-socket
// control plane — tiny, no framework, no external deps beyond stdlib.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	policy "github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/logrotate"
	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/shellparse"
	"github.com/LuD1161/agentjail/internal/store"
	"github.com/LuD1161/agentjail/internal/telemetry"
)

// version is set via -ldflags at build time (mirrors cmd/agentjail).
var version = ""

// Request is the newline-delimited JSON record sent by callers (agentjail-hook
// or any tool that can write to the socket).
type Request struct {
	ID        string                 `json:"id"`
	HookEvent string                 `json:"hook_event"`
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
	SessionID string                 `json:"session_id"`
	CWD       string                 `json:"cwd"`
	Agent     string                 `json:"agent,omitempty"`
	AgentPID  int                    `json:"agent_pid,omitempty"`
}

// Response is the newline-delimited JSON record written back to the caller.
type Response struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
	RuleID string `json:"rule_id,omitempty"`
	Impact string `json:"impact,omitempty"` // consequence-of-allowing text; forwarded from Decision.Impact
}

// server holds all daemon state. The engine and cache fields are guarded by
// engineMu; readers (per-connection goroutines) take RLock and writers (SIGHUP
// reload) take Lock. This is the zero-downtime hot-reload pattern from
// HashiCorp Vault's provider reloading design.
type server struct {
	engineMu sync.RWMutex
	engine   policy.HookEngine
	cache    policy.Cache
	gen      atomic.Uint64 // bumped on every reload; guards stale cache writes

	// repoRootCache maps canonical cwd → git repo root (or "" for non-git dirs).
	// Populated lazily by resolveRepoRoot; never evicted (repo roots don't move).
	repoRootMu    sync.RWMutex
	repoRootCache map[string]string

	// awsProfiles is a lazily-parsed view of ~/.aws/config (or $AWS_CONFIG_FILE)
	// mapping profile name → account-resolution fields. Populated on first
	// resolveAWSAccount call; invalidated on SIGHUP reload so edits to
	// ~/.aws/config take effect without a daemon restart. See ADR 0017.
	awsCfgMu    sync.Mutex
	awsProfiles map[string]awsProfileInfo

	// sessionAskSeen tracks (sessionID, ruleID) pairs where the daemon already
	// returned "ask". On the SECOND ask for the same pair, the user must have
	// approved the first one (Claude Code does not call the hook again after a
	// denial — "No" means the tool call is not executed at all). So the second
	// ask is promoted to "allow".
	sessionAskMu   sync.RWMutex
	sessionAskSeen map[string]map[string]bool // sessionID → set of ruleID

	// Per-project policy engine cache. Key is repo root path.
	// Each entry holds a compiled OPA engine with the project-merged config.
	projectEngMu   sync.RWMutex
	projectEngines map[string]*projectEngine

	// cfg holds the current global PolicyConfig (under engineMu) so
	// resolveProjectEngine can merge project overlays on top of it.
	cfg     *agentconfig.PolicyConfig
	modules [][2]string

	// wg tracks in-flight connections so graceful shutdown can drain them.
	wg sync.WaitGroup

	// telemetry is nil-safe: a nil recorder records nothing.
	telemetry *telemetry.Recorder

	// eventStore persists decisions/audit/sessions to SQLite (ADR 0018).
	// nil-safe: a nil store means the daemon continues without persistence
	// (fail-open on logging, never on policy). decCh is a bounded buffer
	// drained by a goroutine so a DB write never wedges a decision.
	eventStore store.EventStore
	decCh      chan store.DecisionRecord
	decWg      sync.WaitGroup

	// activeSessions tracks which session IDs have open connections.
	activeSessions *activeTracker
}

// projectEngine holds a compiled OPA engine for a specific project's merged
// config. The configHash allows cheap invalidation when the project's
// policy.yaml changes on disk.
type projectEngine struct {
	eng        policy.HookEngine
	cache      policy.Cache
	configHash string // hex SHA-256 of project policy.yaml content
}

// recordTelemetry feeds one decision to the telemetry recorder (nil-safe).
// toolName and agentID are enum values from the daemon Request struct; they are
// safe to forward to telemetry (not user-controlled argv).
func (s *server) recordTelemetry(action, ruleID, toolName, agentID string, elapsed time.Duration) {
	if s.telemetry != nil {
		s.telemetry.RecordDecisionFull(action, ruleID, toolName, agentID, elapsed)
	}
}

// recordPolicyConfig snapshots the policy configuration into telemetry (nil-safe).
func (s *server) recordPolicyConfig(cfg *agentconfig.PolicyConfig, rulesDir string) {
	if s.telemetry != nil {
		s.telemetry.RecordPolicyConfig(countCustomRuleFiles(rulesDir), cfg.DisabledRules)
	}
}

// enqueueDecision enqueues a decision record for async SQLite persistence
// (ADR 0018). Fail-open: if the store is nil or the buffer is full, the
// record is dropped with a Warn log — the policy decision was already
// returned to the hook and is NOT affected. The buffer is bounded so a slow
// DB cannot cause unbounded memory growth.
func (s *server) enqueueDecision(d store.DecisionRecord) {
	if s.eventStore == nil || s.decCh == nil {
		return
	}
	select {
	case s.decCh <- d:
	default:
		slog.Warn("store buffer full; dropping decision record (fail-open on logging)", "session_id", d.SessionID, "action", d.Action)
	}
}

// drainDecisions consumes the decision channel and writes to the store. It
// runs until ctx is cancelled, then drains any remaining records and exits
// so graceful shutdown flushes pending writes.
func (s *server) drainDecisions(ctx context.Context) {
	defer s.decWg.Done()
	for {
		select {
		case d := <-s.decCh:
			if err := s.eventStore.RecordDecision(ctx, d); err != nil {
				slog.Warn("store write decision failed (fail-open)", "err", err, "session_id", d.SessionID)
			}
		case <-ctx.Done():
			// Flush remaining records before exiting.
			for {
				select {
				case d := <-s.decCh:
					if err := s.eventStore.RecordDecision(context.Background(), d); err != nil {
						slog.Warn("store write decision failed during drain", "err", err)
					}
				default:
					return
				}
			}
		}
	}
}

// countCustomRuleFiles returns how many *.rego files in rulesDir are custom rules
// (stem not in coreFileStems/libraryFileStems). Returns 0 if the dir is empty or
// unreadable. Used only for the telemetry policy_config snapshot.
func countCustomRuleFiles(rulesDir string) int {
	if rulesDir == "" {
		return 0
	}
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
			continue
		}
		stem := strings.TrimSuffix(name, ".rego")
		if !coreFileStems[stem] && !libraryFileStems[stem] {
			n++
		}
	}
	return n
}

// eval evaluates a single request and returns the decision. The cache check
// happens before calling the engine so warm decisions are returned in < 1 ms.
func (s *server) eval(ctx context.Context, req Request) (Response, error) {
	// Normalize cwd and path fields BEFORE eval so all policies see canonical
	// absolute paths.  cwd is canonicalized unconditionally.  file_path / path /
	// old_path in ToolInput are canonicalized when present.
	canonCWD := canonicalizeCWD(req.CWD)
	normalizedInput := normalizeToolInput(req.ToolInput, canonCWD)

	input := policy.HookInput{
		HookEvent: req.HookEvent,
		ToolName:  req.ToolName,
		ToolInput: normalizedInput,
		SessionID: req.SessionID,
		CWD:       canonCWD,
		RepoRoot:  s.resolveRepoRoot(canonCWD),
	}

	// AWS account resolution (ADR 0017): for `aws --profile <name>` CLI
	// commands, resolve the targeted account id from ~/.aws/config and inject
	// it as input.aws_account so aws_policy/posture can apply per-account
	// posture. Empty for non-AWS or unresolvable commands -> default_posture.
	if req.ToolName == "Bash" {
		if cmd, ok := normalizedInput["command"].(string); ok && isAWSCLICommand(cmd) {
			input.AWSAccount = s.resolveAWSAccount(cmd)
		}
	}

	// Shell command parsing (ADR 0025): for Bash tool calls, parse the
	// command string into structured components so Rego rules can check
	// command binaries without regex matching on the raw string.
	if req.ToolName == "Bash" {
		if cmd, ok := normalizedInput["command"].(string); ok {
			parsed := shellparse.Parse(cmd)
			input.CommandBinaries = parsed.Binaries
		}
	}

	// Cache key includes the canonical cwd so a file decision that varies by
	// cwd (ask-in-project vs deny-outside) is never served from the wrong entry.
	// R1/R7: cwd is now part of the static key.
	cacheKey := hookCacheKey(input)

	// Per-project policy: check <RepoRoot>/.agentjail/policy.yaml
	eng, cache := s.resolveProjectEngine(ctx, input.RepoRoot)
	isProjectEng := eng != nil
	var genAtStart uint64
	if !isProjectEng {
		// No project config — use global engine.
		s.engineMu.RLock()
		eng = s.engine
		cache = s.cache
		genAtStart = s.gen.Load()
		s.engineMu.RUnlock()
	}

	if d, ok := cache.Get(cacheKey); ok {
		return Response{
			ID:     req.ID,
			Action: d.Action,
			Reason: d.Reason,
			RuleID: d.RuleID,
			Impact: d.Impact,
		}, nil
	}

	d, err := eng.Eval(ctx, input)
	if err != nil {
		// Fail-safe: on evaluation error, return "ask" rather than silently
		// allowing or denying. The caller should treat "ask" as "escalate to
		// the human." Error is also returned for caller logging.
		return Response{
			ID:     req.ID,
			Action: "ask",
			Reason: "policy evaluation error: " + err.Error(),
		}, err
	}

	// For ask verdicts: if this (session, ruleID) was already asked before,
	// the user approved it (Claude Code doesn't call the hook after a "No").
	// Promote to allow on the second+ occurrence.
	if d.Action == "ask" && s.checkAndRecordAsk(req.SessionID, d.RuleID) {
		return Response{
			ID:     req.ID,
			Action: "allow",
			Reason: "approved earlier in this session",
			RuleID: "session/grant",
		}, nil
	}

	// Only cache non-ask decisions. For the global engine, guard against
	// stale cache writes during reload via the generation counter.
	// Project engines use hash-based invalidation (resolveProjectEngine
	// replaces the cache when the file hash changes), so always cache.
	if d.Action != "ask" {
		if isProjectEng || s.gen.Load() == genAtStart {
			cache.Set(cacheKey, d)
		}
	}

	return Response{
		ID:     req.ID,
		Action: d.Action,
		Reason: d.Reason,
		RuleID: d.RuleID,
		Impact: d.Impact,
	}, nil
}

// checkAndRecordAsk checks whether this (session, ruleID) has been asked before.
// If yes, returns true (the user approved last time — promote to allow).
// If no, records it and returns false (first time — ask the user).
func (s *server) checkAndRecordAsk(sessionID, ruleID string) bool {
	if sessionID == "" || ruleID == "" {
		return false
	}
	s.sessionAskMu.Lock()
	defer s.sessionAskMu.Unlock()
	if s.sessionAskSeen == nil {
		s.sessionAskSeen = make(map[string]map[string]bool)
	}
	if s.sessionAskSeen[sessionID] == nil {
		s.sessionAskSeen[sessionID] = make(map[string]bool)
	}
	if s.sessionAskSeen[sessionID][ruleID] {
		return true // second+ ask → user approved the first
	}
	s.sessionAskSeen[sessionID][ruleID] = true
	return false // first ask → prompt the user
}

// resolveRepoRoot returns the git repo root for the given canonical cwd.
// Results are cached — git repo roots don't move during a daemon's lifetime.
// Returns "" for non-git directories or on any error.
func (s *server) resolveRepoRoot(cwd string) string {
	if cwd == "" {
		return ""
	}

	s.repoRootMu.RLock()
	if root, ok := s.repoRootCache[cwd]; ok {
		s.repoRootMu.RUnlock()
		return root
	}
	s.repoRootMu.RUnlock()

	// Run git rev-parse --show-toplevel with a short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", cwd, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	root := ""
	if err == nil {
		root = strings.TrimSpace(string(out))
		// Canonicalize the git root the same way we canonicalize cwd.
		if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
			root = resolved
		}
	}

	s.repoRootMu.Lock()
	if s.repoRootCache == nil {
		s.repoRootCache = make(map[string]string)
	}
	s.repoRootCache[cwd] = root
	s.repoRootMu.Unlock()

	return root
}

// ─── AWS account resolution (ADR 0017) ────────────────────────────────────

// awsProfileInfo is the per-profile account-resolution data parsed from
// ~/.aws/config. The account id is derived from role_arn (the 12-digit IAM
// account in arn:aws:iam::<acct>:role/...) or sso_account_id. source_profile
// chains to another profile when the profile itself has no role_arn/sso_account_id.
type awsProfileInfo struct {
	roleARN       string
	ssoAccountID  string
	sourceProfile string
}

// reAWSCLI matches a Bash command that invokes the AWS CLI as the first
// significant token (allowing leading env-var assignments and whitespace).
var reAWSCLI = regexp.MustCompile(`(^|[\s;&|(])aws\s+\S+`)

// reAWSProfile captures the --profile argument value (--profile prod or
// --profile=prod). AWS accepts both space- and equals-separated forms.
var reAWSProfile = regexp.MustCompile(`--profile[ =](\S+)`)

// reAWSRoleARNAccount captures the 12-digit account id from an IAM role ARN:
// arn:aws:iam::123456789012:role/MyRole. Also accepts non-AWS partitions
// (aws-cn, aws-us-gov) and any-length numeric account ids.
var reAWSRoleARNAccount = regexp.MustCompile(`arn:aws[a-z-]*:iam::(\d+):`)

// isAWSCLICommand reports whether cmd invokes the AWS CLI.
func isAWSCLICommand(cmd string) bool {
	return reAWSCLI.MatchString(cmd)
}

// extractAWSProfile returns the --profile name from an AWS CLI command, or
// "default" when no --profile is given (the AWS CLI default profile).
func extractAWSProfile(cmd string) string {
	if m := reAWSProfile.FindStringSubmatch(cmd); len(m) == 2 {
		return strings.Trim(m[1], `"'`)
	}
	return "default"
}

// accountFromRoleARN extracts the account id from an IAM role ARN, or "".
func accountFromRoleARN(arn string) string {
	if m := reAWSRoleARNAccount.FindStringSubmatch(arn); len(m) == 2 {
		return m[1]
	}
	return ""
}

// awsConfigPath returns the AWS config file path, honoring AWS_CONFIG_FILE
// (the env var the AWS CLI itself respects) and falling back to ~/.aws/config.
func awsConfigPath() string {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aws", "config")
}

// resolveAWSAccount resolves the AWS account id targeted by an AWS CLI command
// by extracting --profile and looking it up in ~/.aws/config. Returns "" when
// unresolvable (no config, unknown profile, no role_arn/sso_account_id) so
// aws_policy/posture falls back to default_posture.
func (s *server) resolveAWSAccount(cmd string) string {
	profile := extractAWSProfile(cmd)
	if profile == "" {
		return ""
	}
	profiles := s.loadAWSProfiles()
	return accountForProfile(profiles, profile, map[string]bool{})
}

// accountForProfile resolves profile -> account, following source_profile
// chains (with a visited set to avoid cycles). Returns "" if unresolvable.
func accountForProfile(profiles map[string]awsProfileInfo, profile string, visited map[string]bool) string {
	if visited[profile] {
		return ""
	}
	visited[profile] = true
	info, ok := profiles[profile]
	if !ok {
		return ""
	}
	if acct := accountFromRoleARN(info.roleARN); acct != "" {
		return acct
	}
	if info.ssoAccountID != "" {
		return info.ssoAccountID
	}
	if info.sourceProfile != "" {
		return accountForProfile(profiles, info.sourceProfile, visited)
	}
	return ""
}

// loadAWSProfiles returns the cached parsed ~/.aws/config, parsing it lazily
// on first call. Thread-safe; the cache is invalidated on SIGHUP reload.
func (s *server) loadAWSProfiles() map[string]awsProfileInfo {
	s.awsCfgMu.Lock()
	defer s.awsCfgMu.Unlock()
	if s.awsProfiles != nil {
		return s.awsProfiles
	}
	path := awsConfigPath()
	if path == "" {
		s.awsProfiles = map[string]awsProfileInfo{}
		return s.awsProfiles
	}
	b, err := os.ReadFile(path)
	if err != nil {
		slog.Debug("aws config unreadable; AWS posture will use default_posture", "path", path, "err", err)
		s.awsProfiles = map[string]awsProfileInfo{}
		return s.awsProfiles
	}
	s.awsProfiles = parseAWSConfig(string(b))
	return s.awsProfiles
}

// parseAWSConfig parses an AWS config file (INI-like) into a profile->info map.
// Sections are [default] or [profile <name>]; keys are key = value. Comments
// (# or ;) and blank lines are ignored.
func parseAWSConfig(content string) map[string]awsProfileInfo {
	profiles := map[string]awsProfileInfo{}
	current := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inner := strings.TrimSpace(line[1 : len(line)-1])
			if inner == "default" {
				current = "default"
			} else if strings.HasPrefix(inner, "profile ") {
				current = strings.TrimSpace(inner[len("profile "):])
			} else {
				current = "" // non-profile section (e.g. sso-session), skip
			}
			continue
		}
		if current == "" {
			continue
		}
		key, val, ok := splitAWSConfigKV(line)
		if !ok {
			continue
		}
		info := profiles[current]
		switch key {
		case "role_arn":
			info.roleARN = val
		case "sso_account_id":
			info.ssoAccountID = val
		case "source_profile":
			info.sourceProfile = val
		}
		profiles[current] = info
	}
	return profiles
}

// splitAWSConfigKV splits a "key = value" (or "key=value") line, trimming the
// value of surrounding quotes/whitespace. Returns ok=false if no "=" present.
func splitAWSConfigKV(line string) (key, val string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	val = strings.TrimSpace(line[idx+1:])
	val = strings.Trim(val, `"'`)
	return key, val, true
}

// ─── end AWS account resolution ───────────────────────────────────────────

// canonicalizeCWD resolves a working directory to its canonical absolute form:
//  1. If empty, returns "".
//  2. filepath.Clean + makes absolute if not already (using os.Getwd() fallback).
//  3. filepath.EvalSymlinks to resolve symlinks; on error returns cleaned path.
func canonicalizeCWD(cwd string) string {
	if cwd == "" {
		return ""
	}
	// Make absolute if relative (unusual for cwd, but handle it).
	if !filepath.IsAbs(cwd) {
		if wd, err := os.Getwd(); err == nil {
			cwd = filepath.Join(wd, cwd)
		}
	}
	cwd = filepath.Clean(cwd)
	if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
		return resolved
	}
	return cwd
}

// canonicalizePath resolves a file path to its canonical absolute form.
// If the path is relative it is resolved against cwd.  Symlinks are resolved
// on the nearest existing parent; any non-existing suffix is re-appended so
// write targets (files that don't exist yet) still get a canonical prefix.
//
// On ANY resolution error for a path that looks sensitive (contains "..", is
// outside cwd after normalization), the function returns ("", true) signalling
// to the caller to fail closed.
func canonicalizePath(p, cwd string) (canonical string, failClose bool) {
	if p == "" {
		return "", false
	}

	// 1. Make absolute against cwd.
	if !filepath.IsAbs(p) {
		if cwd == "" {
			if wd, err := os.Getwd(); err == nil {
				cwd = wd
			}
		}
		p = filepath.Join(cwd, p)
	}
	// 2. Clean (resolves . and .. lexically).
	p = filepath.Clean(p)

	// 3. EvalSymlinks on the path or nearest existing parent.
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved, false
	}

	// Path doesn't exist — walk up to find the nearest existing parent.
	parent := p
	suffix := ""
	for {
		newParent := filepath.Dir(parent)
		if newParent == parent {
			// Reached root without finding an existing directory — give up.
			break
		}
		suffix = filepath.Join(filepath.Base(parent), suffix)
		parent = newParent
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			// Re-append the non-existing suffix.
			return filepath.Join(resolved, suffix), false
		}
	}

	// Could not resolve any ancestor.  For paths with ".." this is suspicious.
	if strings.Contains(p, "..") {
		return "", true // fail closed
	}
	return p, false
}

// normalizeToolInput returns a copy of toolInput with file_path, path, and
// old_path values canonicalized against cwd.  If a path fails to canonicalize
// and signals fail-close, the field is replaced with a sentinel that will
// match no allow rule so the engine defaults to ask/deny.
//
// For Bash commands, ~ and $HOME tokens are expanded to the real home directory
// so the Rego sensitive-path patterns (which match absolute paths) fire
// consistently regardless of how the agent spelled the path.
func normalizeToolInput(toolInput map[string]interface{}, cwd string) map[string]interface{} {
	if toolInput == nil {
		return nil
	}
	out := make(map[string]interface{}, len(toolInput))
	for k, v := range toolInput {
		out[k] = v
	}
	for _, field := range []string{"file_path", "path", "old_path"} {
		if raw, ok := out[field].(string); ok && raw != "" {
			if canonical, failClose := canonicalizePath(raw, cwd); failClose {
				// Replace with a path guaranteed to match no allow rule.
				// The daemon logs this at Warn level; the policy will see
				// an unrecognised path and fail to its default (ask/deny).
				slog.Warn("path normalization fail-closed",
					"field", field,
					"raw", raw,
					"cwd", cwd,
				)
				out[field] = "/__agentjail_failclosed__"
			} else if canonical != "" {
				out[field] = canonical
			}
		}
	}
	if cmd, ok := out["command"].(string); ok && cmd != "" {
		out["command"] = expandCommandPaths(cmd)
	}
	return out
}

// expandCommandPaths expands ~ and $HOME in a Bash command string to the
// real home directory so Rego sensitive-path patterns match regardless of
// spelling. Expansion happens at token boundaries (start of string or after
// whitespace) to avoid mangling arguments like "--prefix=~other".
func expandCommandPaths(cmd string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "~" {
		return cmd
	}

	// First pass: expand ~/ and bare trailing ~ at token boundaries.
	var b strings.Builder
	b.Grow(len(cmd) + len(home))
	prevWS := true
	i := 0
	for i < len(cmd) {
		if cmd[i] == '~' && prevWS {
			if i+1 < len(cmd) && cmd[i+1] == '/' {
				b.WriteString(home)
				i++
				prevWS = false
				continue
			} else if i+1 == len(cmd) || cmd[i+1] == ' ' || cmd[i+1] == '\t' || cmd[i+1] == '"' || cmd[i+1] == '\'' {
				b.WriteString(home)
				i++
				prevWS = false
				continue
			}
		}
		ch := cmd[i]
		b.WriteByte(ch)
		prevWS = ch == ' ' || ch == '\t'
		i++
	}
	result := b.String()

	// Second pass: expand $HOME to the real path.
	result = strings.ReplaceAll(result, "$HOME", home)

	return result
}

// hookCacheKey derives a CacheKey from a HookInput using only the fields that
// affect the policy decision.  SessionID is excluded (per-invocation noise);
// CWD IS included because decisions are cwd-dependent (a file that is
// ask-in-project vs deny-outside must not share a cache entry across cwds).
// R1/R7 fix: CWD was previously excluded; it is now part of the key.
func hookCacheKey(in policy.HookInput) policy.CacheKey {
	type staticFields struct {
		ToolName  string                 `json:"tool_name"`
		ToolInput map[string]interface{} `json:"tool_input"`
		CWD       string                 `json:"cwd"`
	}
	b, _ := json.Marshal(staticFields{
		ToolName:  in.ToolName,
		ToolInput: in.ToolInput,
		CWD:       in.CWD,
	})
	sum := sha256.Sum256(b)
	return policy.CacheKey{
		ToolName:  in.ToolName,
		InputHash: hex.EncodeToString(sum[:]),
	}
}

// summarizeToolInput returns a short, log-safe identifier for a tool call.
// Bash → the command (truncated). File tools → the file_path. MCP/others →
// fall back to the most informative single string field. Empty if nothing
// useful is available. Truncated to 200 bytes; multi-line collapsed to one.
func summarizeToolInput(tool string, in map[string]interface{}) string {
	if in == nil {
		return ""
	}
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := in[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	var s string
	switch tool {
	case "Bash":
		s = pick("command")
	case "Write", "Edit", "Read", "NotebookEdit":
		s = pick("file_path", "path", "notebook_path")
	default:
		// MCP and anything else: try common single-string fields.
		s = pick("file_path", "path", "command", "query", "url", "pattern")
	}
	if s == "" {
		return ""
	}
	// One line, bounded length — log readability beats fidelity here.
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	const maxLen = 200
	if len(s) > maxLen {
		s = s[:maxLen-1] + "…"
	}
	return s
}

// handleConn serves one client connection. Each connection runs in its own
// goroutine. The function reads newline-delimited JSON requests until the
// connection closes or ctx is cancelled, calling s.eval for each and writing
// the response back.
func (s *server) handleConn(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()


	scanner := bufio.NewScanner(conn)
	// 1 MB line buffer — large enough for realistic tool_input payloads.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			// Write a synthetic error response so the caller doesn't hang.
			_ = enc.Encode(Response{
				ID:     "",
				Action: "ask",
				Reason: "malformed request: " + err.Error(),
			})
			slog.Warn("malformed request", "err", err)
			continue
		}

		if req.SessionID != "" && s.activeSessions != nil && req.AgentPID > 0 {
			s.activeSessions.update(req.SessionID, req.AgentPID)
		}

		start := time.Now()
		resp, err := s.eval(ctx, req)
		elapsed := time.Since(start)

		if err == nil {
			s.recordTelemetry(resp.Action, resp.RuleID, req.ToolName, req.Agent, elapsed)
		}

		// Extract a short identifying summary from tool_input — the command
		// string for Bash, the file_path for file tools, MCP server name for
		// MCP calls. Truncated to keep the log line bounded. This is what the
		// `agentjail logs -v` formatter shows on the same row as the verdict.
		summary := summarizeToolInput(req.ToolName, req.ToolInput)

		// Write the response to the client BEFORE logging. This ensures that
		// log rotation (which holds a mutex and may do file I/O) does not add
		// latency to the hook response. The client is unblocked first; the log
		// write follows. If the client has already disconnected we still log
		// the eval result for forensics (the log is useful even when the hook
		// fell open).
		encErr := enc.Encode(resp)
		if encErr != nil {
			if isClientGone(encErr) {
				// The caller (e.g. agentjail-hook) closed the connection before we
				// finished writing — expected whenever eval exceeds the hook's
				// fail-open deadline (~45 ms). The hook has already fallen open;
				// this is a benign race, not a daemon fault, so keep it out of the
				// Info-level log that `agentjail logs` surfaces.
				slog.Debug("response not delivered: client disconnected", "req_id", req.ID, "err", encErr)
			} else {
				slog.Warn("write response", "req_id", req.ID, "err", encErr)
			}
			// Fall through to log the eval result even when the client is gone.
		}

		// NOTE on `elapsed_us` (see docs/adr/0002-latency-as-engineering-metric.md):
		// This measures cache lookup + (on miss) OPA Rego eval + cache set —
		// internal to s.eval. It is NOT the user-perceived latency. End-to-end
		// wall time = elapsed_us + ~10 ms plumbing (hook fork/exec, socket I/O,
		// JSON marshal). When citing performance externally, use the smoke test's
		// end-to-end wall time, not this field. The field is kept for forensics;
		// the user-facing `agentjail logs` rich view hides it.
		if err != nil {
			slog.Warn("eval error", "req_id", req.ID, "tool", req.ToolName, "session_id", req.SessionID, "agent", req.Agent, "cwd", req.CWD, "summary", summary, "err", err, "elapsed_us", elapsed.Microseconds())
		} else {
			slog.Info("eval", "req_id", req.ID, "tool", req.ToolName, "session_id", req.SessionID, "agent", req.Agent, "cwd", req.CWD, "summary", summary, "action", resp.Action, "rule_id", resp.RuleID, "reason", resp.Reason, "impact", resp.Impact, "elapsed_us", elapsed.Microseconds())
			// Persist the decision to SQLite (async, fail-open). The full
			// tool_input is redacted at the store boundary (ADR 0019).
			s.enqueueDecision(store.DecisionRecord{
				Ts:        time.Now(),
				SessionID: req.SessionID,
				Agent:     req.Agent,
				ToolName:  req.ToolName,
				Summary:   summary,
				Action:    resp.Action,
				RuleID:    resp.RuleID,
				Reason:    resp.Reason,
				Impact:    resp.Impact,
				ElapsedUs: elapsed.Microseconds(),
				CWD:       req.CWD,
				ToolInput: req.ToolInput,
			})
		}

		if encErr != nil && !isClientGone(encErr) {
			return
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("scanner error", "err", err)
	}
}

// isClientGone reports whether err indicates the peer closed the connection
// before the daemon could write its response (broken pipe, connection reset, or
// an already-closed socket). Under the hook's fail-open deadline this is an
// expected race rather than a daemon error, so the caller logs it at Debug.
func isClientGone(err error) bool {
	return errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, net.ErrClosed)
}

// buildTempRoots returns the set of temp-dir roots that the Rego policy should
// treat as scratch space.  os.TempDir() is the primary source; the structural
// fallbacks cover the macOS variant paths that show up when $TMPDIR differs.
func buildTempRoots() []string {
	roots := make([]string, 0, 4)

	tmpDir := os.TempDir()
	if resolved, err := filepath.EvalSymlinks(tmpDir); err == nil {
		tmpDir = resolved
	}
	roots = append(roots, tmpDir)

	// Structural fallbacks always present on macOS regardless of $TMPDIR.
	for _, structural := range []string{"/tmp", "/private/tmp"} {
		if resolved, err := filepath.EvalSymlinks(structural); err == nil {
			structural = resolved
		}
		roots = dedupAppend(roots, structural)
	}

	return roots
}

// dedupAppend appends s to slice only if not already present.
func dedupAppend(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// resolveProjectEngine checks for a per-project policy file at
// <repoRoot>/.agentjail/policy.yaml. If found, it returns a compiled OPA
// engine with the project config merged over the global config, plus a
// per-project LRU cache. Results are cached by repo root and invalidated
// when the file content changes (SHA-256 hash check). Returns (nil, nil)
// when no project policy exists or on any error (fail-open to global).
func (s *server) resolveProjectEngine(ctx context.Context, repoRoot string) (policy.HookEngine, policy.Cache) {
	if repoRoot == "" {
		return nil, nil
	}

	projectPolicyPath := filepath.Join(repoRoot, ".agentjail", "policy.yaml")

	// Quick check: does the file exist?
	content, err := os.ReadFile(projectPolicyPath)
	if err != nil {
		return nil, nil // no project policy
	}

	hash := sha256hex(content)

	// Check cache (read lock — fast path).
	s.projectEngMu.RLock()
	if pe, ok := s.projectEngines[repoRoot]; ok && pe.configHash == hash {
		s.projectEngMu.RUnlock()
		return pe.eng, pe.cache
	}
	s.projectEngMu.RUnlock()

	// Build merged config: global base + project overlay.
	s.engineMu.RLock()
	globalCfg := s.cfg
	mods := s.modules
	s.engineMu.RUnlock()

	if globalCfg == nil {
		return nil, nil // not yet initialized
	}

	projectCfg, err := agentconfig.Load(projectPolicyPath)
	if err != nil {
		slog.Warn("project policy.yaml malformed — falling back to global",
			"path", projectPolicyPath, "err", err)
		return nil, nil
	}

	mergedCfg := agentconfig.Merge(globalCfg, projectCfg)
	mergedCfg.File.TempRoots = buildTempRoots()

	opaData := map[string]interface{}{
		"config": mergedCfg.ToOPAData(),
	}

	eng, err := policy.NewHookOPAEngineWithData(ctx, mods, opaData)
	if err != nil {
		slog.Warn("project policy engine compilation failed — falling back to global",
			"path", projectPolicyPath, "err", err)
		return nil, nil
	}

	newCache := policy.NewLRUCache(1024)

	// Store in cache (write lock).
	s.projectEngMu.Lock()
	if s.projectEngines == nil {
		s.projectEngines = make(map[string]*projectEngine)
	}
	s.projectEngines[repoRoot] = &projectEngine{
		eng:        eng,
		cache:      newCache,
		configHash: hash,
	}
	s.projectEngMu.Unlock()

	return eng, newCache
}

// sha256hex returns the hex-encoded SHA-256 digest of data.
func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// loadConfig loads ~/.agentjail/policy.yaml, merges it over Default(), and
// injects the resolved temp roots.  Returns the merged config.  If the file
// does not exist, Default() is returned with temp roots injected.
func loadConfig(policyPath string) (*agentconfig.PolicyConfig, error) {
	cfg, err := agentconfig.LoadOrDefault(policyPath)
	if err != nil {
		return nil, err
	}
	// Always inject temp roots so Rego never needs env access.
	cfg.File.TempRoots = buildTempRoots()
	return cfg, nil
}

// reload rebuilds the OPA engine from the given Rego modules and atomically
// swaps it in under the write lock. The cache is invalidated so stale
// verdicts from the old rule set cannot leak.
func (s *server) reload(ctx context.Context, modules [][2]string, cfg *agentconfig.PolicyConfig) error {
	// Build the OPA agentjail data document.  Rego rules read
	// data.agentjail.config.mcp.allowed etc, so we wrap ToOPAData() under
	// the "config" key to produce:
	//   { "agentjail": { "config": { "mcp": {...}, "file": {...}, ... } } }
	opaData := map[string]interface{}{
		"config": cfg.ToOPAData(),
	}

	eng, err := policy.NewHookOPAEngineWithData(ctx, modules, opaData)
	if err != nil {
		return fmt.Errorf("compile rego: %w", err)
	}
	s.engineMu.Lock()
	s.engine = eng
	s.cfg = cfg
	s.modules = modules
	s.gen.Add(1)
	// Invalidate the cache on reload so decisions from the old rule set
	// cannot leak into the new one. Borrowed from Linux page cache
	// flush-on-policy-change semantics.
	s.cache.Invalidate()
	s.engineMu.Unlock()
	// Invalidate the AWS profile cache so edits to ~/.aws/config take effect
	// on reload without a daemon restart (ADR 0017).
	s.awsCfgMu.Lock()
	s.awsProfiles = nil
	s.awsCfgMu.Unlock()
	// Invalidate all project engine caches so project policies are
	// re-merged against the new global config on next eval.
	s.projectEngMu.Lock()
	s.projectEngines = nil
	s.projectEngMu.Unlock()
	return nil
}

// coreFileNames is the set of rego file stems that are always-on core rules
// (shipped with the binary, managed by agentjail install, never custom).
// Custom rules are any *.rego in rulesDir whose stem is NOT in this set and
// NOT in the library set.  We use file-stem matching (the same convention as
// installCoreRules in the CLI) rather than package inspection.
//
// NOTE: this list must stay in sync with coreRuleNames() in
// cmd/agentjail/library_embed.go.  If a new core file is added there, add the
// stem here too so the daemon correctly classifies it as non-custom and doesn't
// subject it to staged quarantine.
var coreFileStems = map[string]bool{
	"aws_posture":          true,
	"command_policy":       true,
	"file_policy":          true,
	"internal_tools":       true,
	"mcp_policy":           true,
	"web_policy":           true,
	"no_daemon_kill":       true,
	"no_hook_self_disable": true,
	"resolver":             true,
}

// libraryFileStems is the set of rego file stems that are opt-in library rules.
// Any file in rulesDir with one of these stems is treated as a library rule
// (not custom) and loaded unconditionally as part of the baseline.
//
// NOTE: must match libraryRuleNames() in cmd/agentjail/library_embed.go.
var libraryFileStems = map[string]bool{
	"no_app_binary_write": true,
	"no_aws_destructive":  true,
	"no_destructive_git":  true,
	"no_history_read":     true,
	"no_launchctl":        true,
	"no_shell_eval":       true,
	"no_shell_init_write": true,
}

// loadModules reads all *.rego files from rulesDir (non-recursive, top-level
// only) and returns them as a slice of (filename, source) pairs suitable for
// passing to NewHookOPAEngineWithData.
//
// Staged quarantine (ADR 0014 §5): the function compiles the core+library
// baseline first, then adds custom rule files ONE AT A TIME in sorted
// (deterministic) filename order.  A custom file that breaks the accumulated
// bundle is logged at WARN and skipped — it never prevents the baseline from
// loading.  The daemon therefore NEVER fails startup and NEVER goes open because
// of a bad custom rule.
//
// A file is "custom" if its stem is not in coreFileStems or libraryFileStems.
func loadModules(rulesDir string) ([][2]string, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %s: %w", rulesDir, err)
	}

	type regoFile struct {
		name string // filename (with .rego)
		src  string
	}

	var baselineFiles []regoFile
	var customFiles []regoFile

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".rego") {
			continue
		}
		// Skip OPA test files — only for `opa test`.
		if strings.HasSuffix(name, "_test.rego") {
			continue
		}
		full := filepath.Join(rulesDir, name)
		b, rerr := os.ReadFile(full)
		if rerr != nil {
			return nil, fmt.Errorf("read %s: %w", full, rerr)
		}
		stem := strings.TrimSuffix(name, ".rego")
		rf := regoFile{name: full, src: string(b)}
		if coreFileStems[stem] || libraryFileStems[stem] {
			baselineFiles = append(baselineFiles, rf)
		} else {
			customFiles = append(customFiles, rf)
		}
	}

	// Assemble the baseline module list.
	baseline := make([][2]string, 0, len(baselineFiles))
	for _, f := range baselineFiles {
		baseline = append(baseline, [2]string{f.name, f.src})
	}

	// If there are no custom files, return the baseline unchanged (happy path —
	// identical behaviour to before this change).
	if len(customFiles) == 0 {
		return baseline, nil
	}

	// Sort custom files for deterministic quarantine order.
	sort.Slice(customFiles, func(i, j int) bool {
		return customFiles[i].name < customFiles[j].name
	})

	// Staged accumulation: try to add each custom file to the growing bundle.
	// We probe by compiling; the ctx is background (compile is fast).
	ctx := context.Background()
	accumulated := make([][2]string, len(baseline))
	copy(accumulated, baseline)

	for _, cf := range customFiles {
		candidate := append(accumulated, [2]string{cf.name, cf.src}) //nolint:gocritic
		_, compileErr := policy.NewHookOPAEngine(ctx, candidate)
		if compileErr != nil {
			// Bad custom file — log WARN and skip; do not update accumulated.
			slog.Warn("skipping custom rule: bundle compile error",
				"file", cf.name,
				"err", compileErr,
			)
			continue
		}
		// File is good — keep it in the accumulation.
		accumulated = candidate
	}

	return accumulated, nil
}

// defaultSocketPath returns ~/.agentjail/daemon.sock.
func defaultSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-daemon.sock"
	}
	return filepath.Join(home, ".agentjail", "daemon.sock")
}

// defaultPolicyPath returns ~/.agentjail/policy.yaml.
func defaultPolicyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-policy.yaml"
	}
	return filepath.Join(home, ".agentjail", "policy.yaml")
}

// defaultLogPath returns ~/.agentjail/daemon.log.
func defaultLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-daemon.log"
	}
	return filepath.Join(home, ".agentjail", "daemon.log")
}

// defaultDBPath returns ~/.agentjail/agentjail.db (the SQLite store, ADR 0018).
func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail.db"
	}
	return filepath.Join(home, ".agentjail", "agentjail.db")
}

func main() {
	socketPath := flag.String("socket", defaultSocketPath(), "path to Unix domain socket")
	policyPath := flag.String("policy", defaultPolicyPath(), "path to policy.yaml (data overlay for OPA)")
	rulesDir := flag.String("rules", "", "path to Rego rules directory (default: uses inline default policy)")
	logPath := flag.String("log", defaultLogPath(), "path to structured log file (rotated internally)")
	dbPath := flag.String("db", defaultDBPath(), "path to SQLite event store (~/.agentjail/agentjail.db)")
	retentionDur := flag.Duration("retention", 30*24*time.Hour, "max age to retain decisions/audit events in the store (e.g. 720h)")
	flag.Parse()

	// Open the rotating log writer before setting up slog so all startup
	// messages land in the file. 10 MB per file, 5 rotated backups.
	logWriter, err := logrotate.New(*logPath, 10*1024*1024, 5)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-daemon: open log %s: %v\n", *logPath, err)
		os.Exit(1)
	}
	defer logWriter.Close()

	// Structured JSON logging to the rotating file. slog default level = Info.
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("agentjail-daemon starting",
		"socket", *socketPath,
		"policy", *policyPath,
		"rules_dir", *rulesDir,
	)

	// Ensure the socket directory exists with 0700 so other users cannot
	// enumerate or connect to the daemon socket.
	socketDir := filepath.Dir(*socketPath)
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		slog.Error("create socket dir", "dir", socketDir, "err", err)
		os.Exit(1)
	}

	// Remove a stale socket file from a previous crash. os.Remove is
	// best-effort; if it fails for any reason other than ENOENT the
	// subsequent Listen will fail with a clear error.
	if err := os.Remove(*socketPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("remove stale socket", "path", *socketPath, "err", err)
	}

	// Load initial policy config — merge policy.yaml over Default(), inject temp roots.
	cfg, err := loadConfig(*policyPath)
	if err != nil {
		slog.Error("load policy config", "path", *policyPath, "err", err)
		os.Exit(1)
	}
	if warns := agentconfig.Validate(cfg); len(warns) > 0 {
		for _, w := range warns {
			slog.Warn("policy config warning", "warning", w)
		}
	}
	slog.Info("policy config loaded",
		"mcp_allowed", cfg.MCP.Allowed,
		"mcp_blocked_count", len(cfg.MCP.Blocked),
		"temp_roots", cfg.File.TempRoots,
	)

	// Load initial Rego modules.
	var initModules [][2]string
	if *rulesDir != "" {
		mods, err := loadModules(*rulesDir)
		if err != nil {
			slog.Error("load rego modules", "rules_dir", *rulesDir, "err", err)
			os.Exit(1)
		}
		initModules = mods
		slog.Info("loaded rego modules", "count", len(mods), "rules_dir", *rulesDir)
	} else {
		// No --rules flag: use the inline default policy so the daemon can
		// start and evaluate requests in dev/test. In production, --rules
		// points to the agentpolicy/policies/ directory.
		slog.Info("no --rules dir specified; using inline default policy (deny rm -rf, allow everything else)")
		initModules = [][2]string{
			{"default.rego", defaultInlinePolicy},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build the initial engine with config data injected.
	// Rego reads data.agentjail.config.mcp.allowed etc, so wrap under "config".
	initOPAData := map[string]interface{}{
		"config": cfg.ToOPAData(),
	}
	eng, err := policy.NewHookOPAEngineWithData(ctx, initModules, initOPAData)
	if err != nil {
		slog.Error("compile rego", "err", err)
		os.Exit(1)
	}

	srv := &server{
		engine:         eng,
		cache:          policy.NewLRUCache(policy.DefaultCacheSize),
		activeSessions: newActiveTracker(filepath.Dir(*policyPath)),
	}

	// Open the SQLite event store (ADR 0018). Failure is non-fatal: the daemon
	// continues without persistence (fail-open on logging). On first run, if
	// daemon.log exists and the store is empty, import the historical JSON-lines
	// decisions (best-effort). Then run retention cleanup + start the async
	// drain goroutine.
	if st, serr := store.Open(*dbPath); serr == nil {
		srv.eventStore = st
		srv.decCh = make(chan store.DecisionRecord, 1024)
		migrateDaemonLog(ctx, st, *logPath)
		if cerr := st.Cleanup(ctx, *retentionDur); cerr != nil {
			slog.Warn("store retention cleanup failed (non-fatal)", "err", cerr)
		}
		srv.decWg.Add(1)
		go srv.drainDecisions(ctx)
		slog.Info("sqlite event store opened", "db", *dbPath, "retention", *retentionDur)
	} else {
		slog.Warn("sqlite event store open failed; continuing without persistence (fail-open on logging)", "db", *dbPath, "err", serr)
	}

	// Wire telemetry recorder: nil-safe, failure-tolerant — if init fails, the
	// daemon continues without telemetry. The same ctx is cancelled on
	// SIGTERM/SIGINT, which triggers Recorder.Run's final flush on shutdown.
	if tp, perr := telemetry.DefaultPaths(); perr == nil {
		if rec, rerr := telemetry.New(tp, os.Getenv, version, runtime.GOOS, runtime.GOARCH, telemetry.DefaultClient()); rerr == nil {
			srv.telemetry = rec
			go rec.Run(ctx) // ctx is cancelled on SIGTERM/SIGINT → triggers final flush
			srv.recordPolicyConfig(cfg, *rulesDir)
		} else {
			slog.Warn("telemetry init failed; continuing without telemetry", "err", rerr)
		}
	}

	// Start background update checker (respects AGENTJAIL_NO_UPDATE_CHECK).
	if os.Getenv("AGENTJAIL_NO_UPDATE_CHECK") == "" {
		// InstallDir: the directory containing the running binary.
		// os.Executable() returns e.g. ~/.agentjail/bin/agentjail-daemon.
		autoUpdate := os.Getenv("AGENTJAIL_AUTO_UPDATE") != "false"

		installDir := ""
		if exePath, exeErr := os.Executable(); exeErr == nil {
			installDir = filepath.Dir(exePath)
		}

		// servicePath is passed to RestartDaemon on rollback. On macOS it is
		// the launchd plist path; on Linux it is the systemd user unit name.
		var servicePath string
		if runtime.GOOS == "darwin" {
			homeDir, _ := os.UserHomeDir()
			servicePath = filepath.Join(homeDir, "Library", "LaunchAgents", "com.agentjail.daemon.plist")
		} else if runtime.GOOS == "linux" {
			servicePath = "agentjail-daemon.service"
		}

		checker := &selfupdate.Checker{}
		uc := &UpdateChecker{
			Version:     version,
			BasePath:    filepath.Dir(*socketPath), // ~/.agentjail
			Fetcher:     checker,
			Notifier:    &osNotifier{},
			ExeResolver: selfupdate.ResolveExecutablePath,
			JitterFunc: func(max time.Duration) time.Duration {
				return time.Duration(int64(os.Getpid()) % int64(max))
			},
			AutoUpdate: autoUpdate,
			InstallDir: installDir,
			PlistPath:  servicePath,
			GOOS:       runtime.GOOS,
			GOARCH:     runtime.GOARCH,
		}
		go uc.Run(ctx)
	}

	// Start hook-config watchdog: polls agent settings files every 5 s and
	// re-injects the agentjail-hook entry if it is removed (ADR 0026).
	hookWatchdog := newHookWatcher(logger, func(action, detail string) {
		slog.Info("hookwatch audit", "action", action, "detail", detail)
	})
	go hookWatchdog.Run(ctx)

	// Start listening before installing signal handlers so the socket is
	// ready as soon as we log "listening".
	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		slog.Error("listen", "socket", *socketPath, "err", err)
		os.Exit(1)
	}
	// Restrict socket permissions to the current user — no group or world
	// access. 0600 = read+write for owner only.
	if err := os.Chmod(*socketPath, 0o600); err != nil {
		slog.Warn("chmod socket", "err", err)
	}

	slog.Info("listening", "socket", *socketPath)

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// Accept loop in a separate goroutine so signals can be processed on
	// the main goroutine without blocking.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// When ctx is cancelled we close ln; Accept returns an error.
				if ctx.Err() != nil {
					return
				}
				slog.Warn("accept", "err", err)
				continue
			}
			srv.wg.Add(1)
			go srv.handleConn(ctx, conn)
		}
	}()

	// Block waiting for signals.
	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			slog.Info("SIGHUP received — reloading policy")

			// Reload Rego modules.
			var mods [][2]string
			if *rulesDir != "" {
				var loadErr error
				mods, loadErr = loadModules(*rulesDir)
				if loadErr != nil {
					// Keep old config — do not go open.
					slog.Error("reload: load modules failed — keeping old policy", "err", loadErr)
					continue
				}
			} else {
				mods = [][2]string{{"default.rego", defaultInlinePolicy}}
			}

			// Reload policy.yaml — merge over Default(), inject temp roots.
			newCfg, cfgErr := loadConfig(*policyPath)
			if cfgErr != nil {
				// Keep old config — do not go open.
				slog.Error("reload: load policy config failed — keeping old policy", "path", *policyPath, "err", cfgErr)
				continue
			}

			if reloadErr := srv.reload(ctx, mods, newCfg); reloadErr != nil {
				// Keep old engine — do not go open.
				slog.Error("reload: compile failed — keeping old policy", "err", reloadErr)
				continue
			}
			slog.Info("policy reloaded",
				"rules_dir", *rulesDir,
				"mcp_allowed", newCfg.MCP.Allowed,
				"mcp_blocked_count", len(newCfg.MCP.Blocked),
			)
			srv.recordPolicyConfig(newCfg, *rulesDir)

		case syscall.SIGTERM, syscall.SIGINT:
			slog.Info("shutdown signal received", "signal", sig)
			// Stop accepting new connections.
			cancel()
			_ = ln.Close()
			// Drain in-flight connections with a 5-second deadline.
			done := make(chan struct{})
			go func() {
				srv.wg.Wait()
				close(done)
			}()
			select {
			case <-done:
				slog.Info("all connections drained; exiting")
			case <-time.After(5 * time.Second):
				slog.Warn("drain timeout; forcing exit")
			}
			// Flush the async SQLite writer so pending decisions are persisted
			// before exit. drainDecisions exits after draining the channel on
			// ctx cancellation; wait for it (bounded).
			flushDone := make(chan struct{})
			go func() {
				srv.decWg.Wait()
				close(flushDone)
			}()
			select {
			case <-flushDone:
			case <-time.After(3 * time.Second):
				slog.Warn("store drain timeout; forcing exit")
			}
			if srv.eventStore != nil {
				_ = srv.eventStore.Close()
			}
			// Remove the socket file so a fresh start won't see a stale one.
			_ = os.Remove(*socketPath)
			srv.activeSessions.cleanup()
			return
		}
	}
}

// migrateDaemonLog imports historical decisions from an existing daemon.log
// (slog JSON-lines, msg=="eval") into the SQLite store on first run, iff the
// store is empty. Best-effort: unparseable lines are skipped, failures are
// logged, and startup is never blocked. Migrated records have no tool_input
// (the slog line only carries a summary).
func migrateDaemonLog(ctx context.Context, st store.EventStore, logPath string) {
	n, err := st.DecisionCount(ctx)
	if err != nil || n > 0 {
		return
	}
	f, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	imported := 0
	for sc.Scan() {
		var line struct {
			Time      time.Time `json:"time"`
			Msg       string    `json:"msg"`
			Tool      string    `json:"tool"`
			SessionID string    `json:"session_id"`
			Agent     string    `json:"agent"`
			CWD       string    `json:"cwd"`
			Summary   string    `json:"summary"`
			Action    string    `json:"action"`
			RuleID    string    `json:"rule_id"`
			Reason    string    `json:"reason"`
			Impact    string    `json:"impact"`
			ElapsedUs int64     `json:"elapsed_us"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			continue
		}
		if line.Msg != "eval" || line.Action == "" {
			continue
		}
		sid := line.SessionID
		if sid == "" {
			sid = "migrated"
		}
		if err := st.RecordDecision(ctx, store.DecisionRecord{
			Ts:        line.Time,
			SessionID: sid,
			Agent:     line.Agent,
			ToolName:  line.Tool,
			Summary:   line.Summary,
			Action:    line.Action,
			RuleID:    line.RuleID,
			Reason:    line.Reason,
			Impact:    line.Impact,
			ElapsedUs: line.ElapsedUs,
			CWD:       line.CWD,
		}); err != nil {
			slog.Warn("daemon.log migration: insert failed (continuing)", "err", err)
			continue
		}
		imported++
	}
	if imported > 0 {
		slog.Info("migrated daemon.log decisions into sqlite", "count", imported)
	}
}

// defaultInlinePolicy is a minimal Rego policy used when --rules is not
// specified. It denies rm -rf commands and allows everything else.
// Production deployments pass --rules pointing to agentpolicy/policies/.
//
// Package name is "agentjail" — the namespace queried by NewHookOPAEngine
// (data.agentjail.decision).
const defaultInlinePolicy = `
package agentjail

import future.keywords.if

default decision = {"action": "allow", "reason": "default allow", "rule_id": "default"}

decision = {"action": "deny", "reason": "rm -rf is blocked by default policy", "rule_id": "command_policy/rm_rf"} if {
    input.tool_name == "Bash"
    contains(input.tool_input.command, "rm -rf")
}
`
