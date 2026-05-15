package perm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// SessionRef is the minimal projection of a daemon session the adapter
// needs to mint a Principal. Kept as a primitive-shaped value so this
// package does not depend on the root module's internal/session (which
// would violate Go's internal-package rule once perm lives under
// agentpolicy/, and the agentpolicy "no upward imports" hard rule on
// principle).
//
// Callers populate this with one line from their session.Session:
//
//	perm.SessionRef{ID: sess.ID, AgentSlug: sess.AgentSlug, User: sess.User}
type SessionRef struct {
	ID        string
	AgentSlug string
	User      string
}

// FrameInput is the projection of daemon.Frame the adapter actually needs.
// We accept this primitive-shaped struct instead of importing daemon.Frame
// to avoid an import cycle: the daemon depends on perm, not the other way
// round. The daemon's normalize.go is responsible for filling this from a
// concrete Frame.
type FrameInput struct {
	Hook  string
	Op    string
	Track string
	Attrs map[string]any
}

// PrincipalCtx carries the session-scoped, runtime-bound fields that the
// adapter folds into the Principal.Attr map and the Context block.
//
// Kept separate from SessionRef so the adapter does not have to know
// about session lifecycle (file paths, socket paths, etc.) and can be
// driven from a test without touching the filesystem.
type PrincipalCtx struct {
	Home    string
	CwdRepo string
	Enforce bool
}

// FromFrame builds a CheckResourcesRequest from a wire frame plus the
// active session and the principal context snapshot.
//
//   - The principal id is `<agent_slug>:<session_id>` — see PrincipalID.
//   - The action is derived from (hook, op) via NormalizeAction; unknown
//     ops fall through to a hook-default action so a brand new op never
//     silently degrades to an empty string the engine can't match on.
//   - The resource kind is derived from the hook (subprocess / file /
//     http_request / credential / mcp_tool). The resource id is a stable
//     string per resource kind so the cache key downstream is deterministic.
//
// The Context fields are taken from PrincipalCtx — adapter never reads
// $HOME or repo root itself, both to keep the function pure (testable
// without filesystem) and to avoid race conditions if the operator's cwd
// changes mid-session.
func FromFrame(f FrameInput, sess *SessionRef, pctx PrincipalCtx) CheckResourcesRequest {
	req := CheckResourcesRequest{
		Principal: BuildPrincipal(sess, pctx),
		Action:    NormalizeAction(f.Hook, f.Op),
		Resource:  BuildResource(f),
		Context:   Context{Home: pctx.Home, CwdRepo: pctx.CwdRepo},
	}
	req.RequestID = requestIDFor(req)
	return req
}

// BuildPrincipal projects a SessionRef + PrincipalCtx into a Principal.
// Roles are left empty at this layer — Phase 1 has no role assignment
// story (the wrapper does not yet know whether it was launched from CI
// vs interactive); rules that need roles can read `principal.attr.agent`.
func BuildPrincipal(sess *SessionRef, pctx PrincipalCtx) Principal {
	attr := map[string]any{}
	var slug, sid string
	if sess != nil {
		slug = sess.AgentSlug
		sid = sess.ID
		if sess.User != "" {
			attr["user"] = sess.User
		}
	}
	if slug != "" {
		attr["agent"] = slug
	}
	if pctx.Home != "" {
		attr["home"] = pctx.Home
	}
	if pctx.CwdRepo != "" {
		attr["cwd_repo"] = pctx.CwdRepo
	}
	attr["enforce"] = pctx.Enforce
	return Principal{
		ID:   PrincipalID(slug, sid),
		Attr: attr,
	}
}

// PrincipalID is the canonical `<agent_slug>:<session_id>` formatter. When
// no agent slug is bound, "unknown" is used so the id stays parseable and
// downstream audit queries can still group by session.
func PrincipalID(agentSlug, sid string) string {
	if agentSlug == "" {
		agentSlug = "unknown"
	}
	return agentSlug + ":" + sid
}

// NormalizeAction implements the action mapping table from the plan
// (Stream B.1 / Phase 1 §"Action normalization table"). The table is
// closed: an unknown op for a known hook still produces a valid Action
// (the hook default) so rules can match on the broad category.
//
//	exec   spawn|spawnSync|Bun.spawn|Bun.spawnSync|shim                   -> exec
//	file   writeFile|writeFileSync|appendFile|mkdir|rename|unlink|chmod|truncate -> write
//	file   open|readFile|readFileSync                                     -> read
//	file   writeFd|appendFd                                               -> write
//	http   request|response|fetch|https.request                           -> fetch
//	cred   issue                                                          -> cred_use
func NormalizeAction(hook, op string) Action {
	switch hook {
	case "exec":
		// Every recognised exec op (and the empty/default) collapses to
		// the same action; the table is shown as an enumeration only to
		// make audit + rule authoring explicit.
		switch op {
		case "spawn", "spawnSync", "Bun.spawn", "Bun.spawnSync", "shim", "":
			return ActionExec
		}
		return ActionExec
	case "file":
		switch op {
		case "writeFile", "writeFileSync",
			"appendFile", "appendFileSync",
			"mkdir", "mkdirSync",
			"rename", "renameSync",
			"unlink", "unlinkSync",
			"chmod", "chmodSync",
			"truncate", "truncateSync",
			"writeFd", "appendFd",
			"open_write", "write":
			return ActionWrite
		case "open", "openSync", "readFile", "readFileSync":
			return ActionRead
		}
		// Default unknown file ops to write — the safer side: a new write
		// op silently falling through as "read" would skip ASK rules.
		return ActionWrite
	case "http":
		switch op {
		case "request", "response", "fetch", "https.request", "":
			return ActionFetch
		}
		return ActionFetch
	case "cred":
		switch op {
		case "issue", "":
			return ActionCredUse
		}
		return ActionCredUse
	case "mcp":
		return ActionMCPCall
	}
	return ""
}

// BuildResource derives the Resource{Kind, ID, Attr} for a frame. The
// resource id is a stable string per kind:
//
//   - subprocess:   "subprocess:<program-basename>:<argv-hash-8>"
//   - file:         "file:<resolved-path>"
//   - http_request: "http:<METHOD>:<host><path>"
//   - credential:   "credential:<name>"
//   - mcp_tool:     "mcp:<server>.<tool>"
//
// Stability matters for the cache key split (see internal/policy) so
// re-issuing the same logical request hits the same bucket.
func BuildResource(f FrameInput) Resource {
	switch f.Hook {
	case "exec":
		return buildSubprocessResource(f.Attrs)
	case "file":
		return buildFileResource(f.Attrs)
	case "http":
		return buildHTTPResource(f.Attrs)
	case "cred":
		return buildCredentialResource(f.Attrs)
	case "mcp":
		return buildMCPResource(f.Attrs)
	}
	return Resource{Kind: f.Hook}
}

func buildSubprocessResource(attrs map[string]any) Resource {
	argv := asStringSlice(attrs["argv"])
	program, _ := attrs["program"].(string)
	if program == "" && len(argv) > 0 {
		program = argv[0]
	}
	base := filepath.Base(program)
	r := Resource{
		Kind: "subprocess",
		Attr: map[string]any{
			"program": base,
		},
	}
	if program != "" {
		r.Attr["program_path"] = program
	}
	if cwd, ok := attrs["cwd"].(string); ok && cwd != "" {
		r.Attr["cwd"] = cwd
	}
	if len(argv) > 0 {
		r.Attr["argv_raw"] = argv
	}
	r.ID = "subprocess:" + base + ":" + shortHash(argv)
	return r
}

func buildFileResource(attrs map[string]any) Resource {
	path, _ := attrs["path"].(string)
	r := Resource{
		Kind: "file",
		ID:   "file:" + path,
		Attr: map[string]any{},
	}
	if path != "" {
		r.Attr["path"] = path
	}
	if op, ok := attrs["op"].(string); ok && op != "" {
		r.Attr["op"] = op
	}
	return r
}

func buildHTTPResource(attrs map[string]any) Resource {
	host, _ := attrs["host"].(string)
	method, _ := attrs["method"].(string)
	path, _ := attrs["path"].(string)
	r := Resource{
		Kind: "http_request",
		ID:   "http:" + strings.ToUpper(method) + ":" + host + path,
		Attr: map[string]any{},
	}
	if host != "" {
		r.Attr["host"] = host
	}
	if method != "" {
		r.Attr["method"] = method
	}
	if path != "" {
		r.Attr["path"] = path
	}
	switch v := attrs["port"].(type) {
	case float64:
		r.Attr["port"] = int(v)
	case int:
		r.Attr["port"] = v
	}
	return r
}

func buildCredentialResource(attrs map[string]any) Resource {
	name, _ := attrs["name"].(string)
	r := Resource{
		Kind: "credential",
		ID:   "credential:" + name,
		Attr: map[string]any{},
	}
	if name != "" {
		r.Attr["name"] = name
	}
	if kind, ok := attrs["kind"].(string); ok && kind != "" {
		r.Attr["kind"] = kind
	}
	if scope, ok := attrs["scope"].(string); ok && scope != "" {
		r.Attr["scope"] = scope
	}
	return r
}

func buildMCPResource(attrs map[string]any) Resource {
	server, _ := attrs["server"].(string)
	tool, _ := attrs["tool"].(string)
	id := "mcp:" + server
	if tool != "" {
		id = id + "." + tool
	}
	r := Resource{
		Kind: "mcp_tool",
		ID:   id,
		Attr: map[string]any{},
	}
	if server != "" {
		r.Attr["server"] = server
	}
	if tool != "" {
		r.Attr["tool"] = tool
	}
	return r
}

func asStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// shortHash returns the first 8 hex chars of sha256(strings joined). Used
// purely for resource-id stability — never for security.
func shortHash(parts []string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:4])
}

// requestIDFor synthesizes a deterministic request id when the caller did
// not supply one. The id is a sha256 over the principal id, resource id,
// and action so identical requests share an id (which lets audit
// correlation across hosts dedupe), while distinct requests don't collide
// even within the same session.
func requestIDFor(req CheckResourcesRequest) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s", req.Principal.ID, req.Resource.ID, req.Action)
	if len(req.Resource.Attr) > 0 {
		keys := make([]string, 0, len(req.Resource.Attr))
		for k := range req.Resource.Attr {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = fmt.Fprintf(h, "|%s=%v", k, req.Resource.Attr[k])
		}
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:12])
}
