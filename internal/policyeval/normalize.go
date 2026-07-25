package policyeval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/LuD1161/agentjail/agentpolicy/policy"
)

// CanonicalizeCWD resolves a working directory to its canonical absolute form:
//  1. If empty, returns "".
//  2. filepath.Clean + makes absolute if not already (using os.Getwd() fallback).
//  3. filepath.EvalSymlinks to resolve symlinks; on error returns cleaned path.
func CanonicalizeCWD(cwd string) string {
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

// CanonicalizePath resolves a file path to its canonical absolute form.
// If the path is relative it is resolved against cwd.  Symlinks are resolved
// on the nearest existing parent; any non-existing suffix is re-appended so
// write targets (files that don't exist yet) still get a canonical prefix.
//
// On ANY resolution error for a path that looks sensitive (contains "..", is
// outside cwd after normalization), the function returns ("", true) signalling
// to the caller to fail closed.
func CanonicalizePath(p, cwd string) (canonical string, failClose bool) {
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

	// Path doesn't exist - walk up to find the nearest existing parent.
	parent := p
	suffix := ""
	for {
		newParent := filepath.Dir(parent)
		if newParent == parent {
			// Reached root without finding an existing directory.
			break
		}
		suffix = filepath.Join(filepath.Base(parent), suffix)
		parent = newParent
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(resolved, suffix), false
		}
	}

	// Could not resolve any ancestor. For paths with ".." this is suspicious.
	if strings.Contains(p, "..") {
		return "", true // fail closed
	}
	return p, false
}

// NormalizeToolCall translates agent-specific tool aliases into the canonical
// policy contract, then canonicalizes their inputs.
func NormalizeToolCall(toolName string, toolInput map[string]interface{}, cwd string) (string, map[string]interface{}) {
	if toolName != "apply_patch" {
		return toolName, NormalizeToolInput(toolInput, cwd)
	}

	out := make(map[string]interface{}, len(toolInput)+1)
	for k, v := range toolInput {
		out[k] = v
	}
	if patch, ok := out["command"].(string); ok {
		out["file_paths"] = ExtractPatchPaths(patch)
	}
	return "Edit", NormalizeToolInput(out, cwd)
}

// ExtractPatchPaths returns every file named by an apply_patch envelope.
func ExtractPatchPaths(patch string) []string {
	prefixes := [...]string{
		"*** Add File: ",
		"*** Delete File: ",
		"*** Update File: ",
		"*** Move to: ",
	}
	seen := make(map[string]struct{})
	var paths []string
	for _, line := range strings.Split(patch, "\n") {
		for _, prefix := range prefixes {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			path := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if path == "" {
				break
			}
			if _, exists := seen[path]; !exists {
				seen[path] = struct{}{}
				paths = append(paths, path)
			}
			break
		}
	}
	return paths
}

// NormalizeToolInput returns a copy of toolInput with file_path, file_paths,
// path, and old_path values canonicalized against cwd. If a path fails to
// canonicalize and signals fail-close, it is replaced with a sentinel that
// will match no allow rule so the engine defaults to ask/deny.
//
// For Bash commands, ~ and $HOME tokens are expanded to the real home directory
// so the Rego sensitive-path patterns (which match absolute paths) fire
// consistently regardless of how the agent spelled the path.
func NormalizeToolInput(toolInput map[string]interface{}, cwd string) map[string]interface{} {
	if toolInput == nil {
		return nil
	}
	out := make(map[string]interface{}, len(toolInput))
	for k, v := range toolInput {
		out[k] = v
	}
	for _, field := range []string{"file_path", "path", "old_path"} {
		if raw, ok := out[field].(string); ok && raw != "" {
			if canonical, failClose := CanonicalizePath(raw, cwd); failClose {
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
	if rawPaths, ok := out["file_paths"].([]string); ok {
		paths := make([]string, 0, len(rawPaths))
		for _, raw := range rawPaths {
			if canonical, failClose := CanonicalizePath(raw, cwd); failClose {
				paths = append(paths, "/__agentjail_failclosed__")
			} else if canonical != "" {
				paths = append(paths, canonical)
			}
		}
		out["file_paths"] = paths
	}
	if cmd, ok := out["command"].(string); ok && cmd != "" {
		out["command"] = ExpandCommandPaths(cmd)
	}
	return out
}

// ExpandCommandPaths expands ~ and $HOME in a Bash command string to the
// real home directory so Rego sensitive-path patterns match regardless of
// spelling. Expansion happens at token boundaries (start of string or after
// whitespace) to avoid mangling arguments like "--prefix=~other".
func ExpandCommandPaths(cmd string) string {
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

// HookCacheKey derives a CacheKey from a HookInput using only the fields that
// affect the policy decision.  SessionID is excluded (per-invocation noise);
// CWD IS included because decisions are cwd-dependent.
func HookCacheKey(in policy.HookInput) policy.CacheKey {
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

// Sha256Hex returns the hex-encoded SHA-256 digest of data.
func Sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
