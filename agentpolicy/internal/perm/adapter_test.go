package perm

import (
	"strings"
	"testing"
)

// TestNormalizeActionTable is the source-of-truth table coverage for the
// action mapping. Every entry in the plan's normalization table must
// appear here; adding a new op without a row is a regression.
func TestNormalizeActionTable(t *testing.T) {
	cases := []struct {
		hook string
		op   string
		want Action
	}{
		// exec — every recognized verb collapses to ActionExec.
		{"exec", "spawn", ActionExec},
		{"exec", "spawnSync", ActionExec},
		{"exec", "Bun.spawn", ActionExec},
		{"exec", "Bun.spawnSync", ActionExec},
		{"exec", "shim", ActionExec},
		{"exec", "", ActionExec},
		{"exec", "unknown-verb", ActionExec}, // hook-default

		// file writes (codex's blocker — every mutating op must land on write)
		{"file", "writeFile", ActionWrite},
		{"file", "writeFileSync", ActionWrite},
		{"file", "appendFile", ActionWrite},
		{"file", "appendFileSync", ActionWrite},
		{"file", "mkdir", ActionWrite},
		{"file", "mkdirSync", ActionWrite},
		{"file", "rename", ActionWrite},
		{"file", "renameSync", ActionWrite},
		{"file", "unlink", ActionWrite},
		{"file", "unlinkSync", ActionWrite},
		{"file", "chmod", ActionWrite},
		{"file", "chmodSync", ActionWrite},
		{"file", "truncate", ActionWrite},
		{"file", "truncateSync", ActionWrite},
		{"file", "writeFd", ActionWrite},
		{"file", "appendFd", ActionWrite},
		{"file", "open_write", ActionWrite},
		{"file", "write", ActionWrite},
		{"file", "unknown-mutator", ActionWrite}, // safe default

		// file reads
		{"file", "open", ActionRead},
		{"file", "openSync", ActionRead},
		{"file", "readFile", ActionRead},
		{"file", "readFileSync", ActionRead},

		// http
		{"http", "request", ActionFetch},
		{"http", "response", ActionFetch},
		{"http", "fetch", ActionFetch},
		{"http", "https.request", ActionFetch},
		{"http", "", ActionFetch},
		{"http", "unknown", ActionFetch},

		// cred
		{"cred", "issue", ActionCredUse},
		{"cred", "", ActionCredUse},
		{"cred", "unknown", ActionCredUse},

		// mcp
		{"mcp", "any", ActionMCPCall},

		// unknown hook — empty action, the engine treats this as "rule
		// not applicable".
		{"ping", "anything", ""},
		{"", "anything", ""},
	}
	for _, c := range cases {
		got := NormalizeAction(c.hook, c.op)
		if got != c.want {
			t.Errorf("NormalizeAction(%q, %q) = %q, want %q", c.hook, c.op, got, c.want)
		}
	}
}

// TestPrincipalIDConstruction covers the four permutations of slug/sid
// (both set, slug missing, sid missing, both missing). The "unknown:"
// prefix is load-bearing: audit queries split on the colon and rely on
// the field always being present.
func TestPrincipalIDConstruction(t *testing.T) {
	cases := []struct {
		slug string
		sid  string
		want string
	}{
		{"claude-code-mbp", "01J", "claude-code-mbp:01J"},
		{"", "01J", "unknown:01J"},
		{"comp-intel", "", "comp-intel:"},
		{"", "", "unknown:"},
	}
	for _, c := range cases {
		got := PrincipalID(c.slug, c.sid)
		if got != c.want {
			t.Errorf("PrincipalID(%q, %q) = %q, want %q", c.slug, c.sid, got, c.want)
		}
	}
}

// TestBuildPrincipalAttrs pins the principal.attr map: every populated
// session field flows through, enforce is always present (even when
// false), and missing fields don't materialize as empty strings.
func TestBuildPrincipalAttrs(t *testing.T) {
	sess := &SessionRef{ID: "sid-123", AgentSlug: "comp-intel", User: "alice"}
	pctx := PrincipalCtx{Home: "/Users/alice", CwdRepo: "/Users/alice/work/foo", Enforce: true}
	p := BuildPrincipal(sess, pctx)
	if p.ID != "comp-intel:sid-123" {
		t.Errorf("id: %q", p.ID)
	}
	if p.Attr["agent"] != "comp-intel" {
		t.Errorf("attr.agent: %v", p.Attr["agent"])
	}
	if p.Attr["user"] != "alice" {
		t.Errorf("attr.user: %v", p.Attr["user"])
	}
	if p.Attr["home"] != "/Users/alice" {
		t.Errorf("attr.home: %v", p.Attr["home"])
	}
	if p.Attr["cwd_repo"] != "/Users/alice/work/foo" {
		t.Errorf("attr.cwd_repo: %v", p.Attr["cwd_repo"])
	}
	if p.Attr["enforce"] != true {
		t.Errorf("attr.enforce: %v", p.Attr["enforce"])
	}

	// enforce=false still surfaces as the literal false (so rules can
	// match on it; absence would silently be treated as nil).
	p2 := BuildPrincipal(&SessionRef{ID: "s2"}, PrincipalCtx{})
	if p2.Attr["enforce"] != false {
		t.Errorf("enforce default: %v", p2.Attr["enforce"])
	}
	if p2.ID != "unknown:s2" {
		t.Errorf("missing slug id: %q", p2.ID)
	}
}

// TestBuildResourceSubprocess covers the exec→subprocess mapping
// including basename-of-program and argv-hash id stability.
func TestBuildResourceSubprocess(t *testing.T) {
	f := FrameInput{Hook: "exec", Op: "spawn", Attrs: map[string]any{
		"argv":    []any{"/usr/bin/rm", "-rf", "/tmp/x"},
		"program": "/usr/bin/rm",
		"cwd":     "/tmp",
	}}
	r := BuildResource(f)
	if r.Kind != "subprocess" {
		t.Errorf("kind: %q", r.Kind)
	}
	if !strings.HasPrefix(r.ID, "subprocess:rm:") {
		t.Errorf("id: %q (want subprocess:rm:<hash>)", r.ID)
	}
	if r.Attr["program"] != "rm" {
		t.Errorf("program (basename): %v", r.Attr["program"])
	}
	if r.Attr["program_path"] != "/usr/bin/rm" {
		t.Errorf("program_path: %v", r.Attr["program_path"])
	}

	// Identical argv → identical id (cache-key stability).
	r2 := BuildResource(f)
	if r.ID != r2.ID {
		t.Errorf("subprocess id should be deterministic: %q vs %q", r.ID, r2.ID)
	}

	// Different argv → different id.
	f3 := f
	f3.Attrs = map[string]any{
		"argv":    []any{"/usr/bin/rm", "-rf", "/different/path"},
		"program": "/usr/bin/rm",
	}
	r3 := BuildResource(f3)
	if r.ID == r3.ID {
		t.Errorf("different argv should produce different id; both: %q", r.ID)
	}
}

func TestBuildResourceFile(t *testing.T) {
	r := BuildResource(FrameInput{Hook: "file", Op: "writeFile", Attrs: map[string]any{
		"path": "/Users/me/app/.env",
		"op":   "writeFile",
	}})
	if r.Kind != "file" || r.ID != "file:/Users/me/app/.env" {
		t.Errorf("file: %+v", r)
	}
	if r.Attr["op"] != "writeFile" {
		t.Errorf("op attr: %v", r.Attr["op"])
	}
}

func TestBuildResourceHTTP(t *testing.T) {
	r := BuildResource(FrameInput{Hook: "http", Op: "request", Attrs: map[string]any{
		"host":   "api.anthropic.com",
		"method": "post",
		"path":   "/v1/messages",
		"port":   float64(443),
	}})
	if r.Kind != "http_request" {
		t.Errorf("kind: %q", r.Kind)
	}
	if r.ID != "http:POST:api.anthropic.com/v1/messages" {
		t.Errorf("id (note method must be uppercased for stable cache keys): %q", r.ID)
	}
	if r.Attr["port"] != 443 {
		t.Errorf("port (must be int, not float64): %v (%T)", r.Attr["port"], r.Attr["port"])
	}
}

func TestBuildResourceCredential(t *testing.T) {
	r := BuildResource(FrameInput{Hook: "cred", Op: "issue", Attrs: map[string]any{
		"name":  "mongo_prod_ro",
		"kind":  "mongodb-url",
		"scope": "read-only",
	}})
	if r.Kind != "credential" || r.ID != "credential:mongo_prod_ro" {
		t.Errorf("credential: %+v", r)
	}
}

func TestBuildResourceMCP(t *testing.T) {
	r := BuildResource(FrameInput{Hook: "mcp", Op: "call", Attrs: map[string]any{
		"server": "mongo",
		"tool":   "query",
	}})
	if r.Kind != "mcp_tool" || r.ID != "mcp:mongo.query" {
		t.Errorf("mcp: %+v", r)
	}
}

// TestFromFrameEndToEnd ensures the adapter assembles a complete request
// — principal id, resource, action, context — without dropping any field.
func TestFromFrameEndToEnd(t *testing.T) {
	sess := &SessionRef{ID: "sid-xyz", AgentSlug: "comp-intel", User: "alice"}
	pctx := PrincipalCtx{Home: "/Users/alice", CwdRepo: "/Users/alice/repo", Enforce: true}
	f := FrameInput{Hook: "file", Op: "writeFile", Track: "node", Attrs: map[string]any{
		"path": "/Users/alice/.env",
	}}
	req := FromFrame(f, sess, pctx)

	if req.Principal.ID != "comp-intel:sid-xyz" {
		t.Errorf("principal id: %q", req.Principal.ID)
	}
	if req.Action != ActionWrite {
		t.Errorf("action: %q (writeFile must map to write)", req.Action)
	}
	if req.Resource.Kind != "file" {
		t.Errorf("resource kind: %q", req.Resource.Kind)
	}
	if req.Context.Home != "/Users/alice" {
		t.Errorf("context.home: %q", req.Context.Home)
	}
	if req.Context.CwdRepo != "/Users/alice/repo" {
		t.Errorf("context.cwd_repo: %q", req.Context.CwdRepo)
	}
	if req.RequestID == "" {
		t.Errorf("request id should be auto-populated")
	}

	// Idempotent: same inputs → same request id.
	req2 := FromFrame(f, sess, pctx)
	if req.RequestID != req2.RequestID {
		t.Errorf("request id should be deterministic: %q vs %q", req.RequestID, req2.RequestID)
	}
}

// TestFromFrameNilSession exercises the cold-start / failure path where
// the wrapper has not yet bound a session (e.g. internal test harness).
func TestFromFrameNilSession(t *testing.T) {
	req := FromFrame(FrameInput{Hook: "exec", Attrs: map[string]any{"argv": []any{"ls"}}}, nil, PrincipalCtx{})
	if req.Principal.ID != "unknown:" {
		t.Errorf("nil sess principal id: %q (want unknown:)", req.Principal.ID)
	}
}
