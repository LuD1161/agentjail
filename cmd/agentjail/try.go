package main

// try.go — `agentjail try` hands-on policy evaluator.
//
// Evaluates a single command (one-shot) or an interactive loop (REPL) against
// the live daemon. Nothing is ever executed; the daemon only decides. The seam
// for evaluation is the evalOne function field, which tests replace with a stub
// to avoid a real daemon.
//
// No os/exec import — by design (enforced by TestTry_NoExecImport).

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/LuD1161/agentjail/internal/ui"
	"github.com/LuD1161/agentjail/internal/wire"
)

// tryRunner holds the stateful bits for a single try invocation.
// Tests construct a tryRunner with bytes buffers + a stub evalOne — NO swapping
// of global os.Stdout.
type tryRunner struct {
	in    io.Reader
	out   io.Writer
	errw  io.Writer
	// evalOne is the per-request evaluation seam. Production code calls
	// wire.EvalOne; tests inject a stub so no real socket is needed.
	evalOne func(wire.Request) (wire.Response, error)
	home    string
	cwd     string
	// isTTY is true when in is an interactive terminal. Controls whether the
	// REPL banner and try> prompt are printed.
	isTTY bool
}

// tryJSONRow is the JSON output shape for --json mode.
type tryJSONRow struct {
	Tool   string `json:"tool"`
	Input  string `json:"input"`
	Action string `json:"action"`
	RuleID string `json:"rule_id,omitempty"`
	Reason string `json:"reason,omitempty"`
	Impact string `json:"impact,omitempty"`
	Error  string `json:"error,omitempty"`
}

// runTry is the entry point for `agentjail try`. It returns the exit code.
func runTry(args []string) int {
	fs := flag.NewFlagSet("try", flag.ContinueOnError)
	readPath := fs.String("read", "", "evaluate a Read tool event on this path")
	writePath := fs.String("write", "", "evaluate a Write tool event on this path")
	jsonMode := fs.Bool("json", false, "emit JSON to stdout (object for one-shot, JSONL for REPL)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: agentjail try [--read <path>] [--write <path>] [--json] [command...]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Evaluates an action against the live daemon and prints the verdict.")
		fmt.Fprintln(os.Stderr, "Nothing is executed — these are policy decisions only.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  ~ in paths and commands is expanded to the real home directory.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  agentjail try \"cat ~/.ssh/id_rsa\"")
		fmt.Fprintln(os.Stderr, "  agentjail try \"git status\"")
		fmt.Fprintln(os.Stderr, "  agentjail try --read ~/.aws/credentials")
		fmt.Fprintln(os.Stderr, "  agentjail try --write /etc/hosts")
		fmt.Fprintln(os.Stderr, "  agentjail try                          # interactive REPL")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}

	switch err := fs.Parse(args); err {
	case nil:
		// ok
	case flag.ErrHelp:
		return 0
	default:
		return 2
	}

	// Mutual exclusion: --read / --write / positional command.
	positional := fs.Args()
	hasRead := *readPath != ""
	hasWrite := *writePath != ""
	hasCmd := len(positional) > 0

	conflicts := 0
	if hasRead {
		conflicts++
	}
	if hasWrite {
		conflicts++
	}
	if hasCmd {
		conflicts++
	}
	if conflicts > 1 {
		fmt.Fprintln(os.Stderr, "agentjail try: --read, --write, and a positional command are mutually exclusive")
		return 2
	}

	sockPath := os.Getenv("AGENTJAIL_SOCKET")
	if sockPath == "" {
		sockPath = wire.DefaultSocketPath()
	}

	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/tmp"
	}
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "/tmp"
	}

	isTTY := term.IsTerminal(int(os.Stdin.Fd()))

	runner := &tryRunner{
		in:   os.Stdin,
		out:  os.Stdout,
		errw: os.Stderr,
		evalOne: func(req wire.Request) (wire.Response, error) {
			return wire.EvalOne(sockPath, time.Second, req)
		},
		home:  home,
		cwd:   cwd,
		isTTY: isTTY,
	}

	// One-shot mode.
	if hasRead || hasWrite || hasCmd {
		var req wire.Request
		if hasRead {
			req = runner.buildRequest("", *readPath, "")
		} else if hasWrite {
			req = runner.buildRequest("", "", *writePath)
		} else {
			req = runner.buildRequest(strings.Join(positional, " "), "", "")
		}
		return runner.evalAndRender(req, 1, *jsonMode)
	}

	// REPL mode.
	return runner.repl(*jsonMode)
}

// buildRequest constructs a wire.Request from the given inputs.
// Exactly one of cmd, readPath, writePath should be non-empty.
// The sequence number n is used to construct the request ID.
func (r *tryRunner) buildRequest(cmd, readPath, writePath string) wire.Request {
	return r.buildRequestN(cmd, readPath, writePath, 1)
}

// buildRequestN constructs a wire.Request with a given sequence number n.
func (r *tryRunner) buildRequestN(cmd, readPath, writePath string, n int) wire.Request {
	req := wire.Request{
		ID:        fmt.Sprintf("try-%d", n),
		HookEvent: "PreToolUse",
		SessionID: "agentjail-try",
		CWD:       r.cwd,
		Agent:     "try",
	}

	switch {
	case readPath != "":
		abs := r.expandAndAbs(readPath)
		req.ToolName = "Read"
		req.ToolInput = map[string]interface{}{"file_path": abs}
	case writePath != "":
		abs := r.expandAndAbs(writePath)
		req.ToolName = "Write"
		req.ToolInput = map[string]interface{}{"file_path": abs, "content": ""}
	default:
		// Bash command: expand ~ token-aware (at string start or preceded by whitespace).
		expanded := r.expandTilde(cmd)
		req.ToolName = "Bash"
		req.ToolInput = map[string]interface{}{"command": expanded}
	}

	return req
}

// expandTilde expands `~/` and bare leading `~` in s to the actual home directory.
// Expansion happens at two positions: string start, or immediately after whitespace.
// This matches the shell convention used in the rego sensitive-path rules.
func (r *tryRunner) expandTilde(s string) string {
	if r.home == "" || r.home == "~" {
		return s
	}

	// We walk rune-by-rune building the result.
	var b strings.Builder
	b.Grow(len(s) + len(r.home))

	prevWS := true // treat start-of-string as "preceded by whitespace"
	i := 0
	for i < len(s) {
		if s[i] == '~' && prevWS {
			// Check what follows the tilde.
			if i+1 < len(s) && s[i+1] == '/' {
				b.WriteString(r.home)
				// don't advance past the '/' — let the loop pick it up
				i++
				prevWS = false
				continue
			} else if i+1 == len(s) {
				// bare trailing ~: expand to home
				b.WriteString(r.home)
				i++
				prevWS = false
				continue
			}
		}
		ch := s[i]
		b.WriteByte(ch)
		prevWS = ch == ' ' || ch == '\t'
		i++
	}

	return b.String()
}

// expandAndAbs expands ~ and resolves p to an absolute path relative to r.cwd.
func (r *tryRunner) expandAndAbs(p string) string {
	if r.home != "" {
		if p == "~" {
			p = r.home
		} else if strings.HasPrefix(p, "~/") {
			p = r.home + p[1:]
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(r.cwd, p)
	}
	return p
}

// evalAndRender evaluates req and renders the result. Returns exit code.
func (r *tryRunner) evalAndRender(req wire.Request, n int, jsonMode bool) int {
	req.ID = fmt.Sprintf("try-%d", n)

	resp, err := r.evalOne(req)

	inputSummary := inputSummaryFor(req)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "daemon not reachable") || strings.Contains(errStr, "agentjail status") {
			fmt.Fprintln(r.errw, "daemon not reachable — run `agentjail status`")
		} else {
			fmt.Fprintf(r.errw, "agentjail try: eval error: %s\n", errStr)
		}
		if jsonMode {
			row := tryJSONRow{
				Tool:   req.ToolName,
				Input:  inputSummary,
				Action: "error",
				Error:  errStr,
			}
			enc := json.NewEncoder(r.out)
			_ = enc.Encode(row)
		}
		return 1
	}

	// Response validation: action must be one of allow/ask/deny.
	if resp.Action != "allow" && resp.Action != "ask" && resp.Action != "deny" {
		errStr := fmt.Sprintf("unexpected action %q from daemon", resp.Action)
		fmt.Fprintf(r.errw, "agentjail try: %s\n", errStr)
		if jsonMode {
			row := tryJSONRow{
				Tool:   req.ToolName,
				Input:  inputSummary,
				Action: "error",
				Error:  errStr,
			}
			enc := json.NewEncoder(r.out)
			_ = enc.Encode(row)
		}
		return 1
	}

	if jsonMode {
		row := tryJSONRow{
			Tool:   req.ToolName,
			Input:  inputSummary,
			Action: resp.Action,
			RuleID: resp.RuleID,
			Reason: resp.Reason,
			Impact: resp.Impact,
		}
		enc := json.NewEncoder(r.out)
		_ = enc.Encode(row)
		return 0
	}

	renderVerdict(r.out, req.ToolName, inputSummary, resp)
	return 0
}

// repl runs the interactive REPL loop, reading lines from r.in.
// Returns exit code: non-zero if any eval errored AND input is not a TTY.
func (r *tryRunner) repl(jsonMode bool) int {
	u := ui.New(r.errw)

	if !jsonMode && r.isTTY {
		fmt.Fprintln(r.errw, u.Badge("info", "agentjail try — nothing is executed — policy decisions only; type a command, Ctrl-D to quit"))
		fmt.Fprintln(r.errw)
	}

	scanner := bufio.NewScanner(r.in)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var anyError bool
	n := 0

	for {
		if !jsonMode && r.isTTY {
			fmt.Fprint(r.errw, "try> ")
		}

		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}

		n++
		req := r.buildRequestN(line, "", "", n)
		code := r.evalAndRender(req, n, jsonMode)
		if code != 0 {
			anyError = true
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(r.errw, "agentjail try: read error: %s\n", err)
		anyError = true
	}

	// Interactive TTY: always exit 0 (user session).
	// Piped / non-TTY: exit non-zero if any line errored.
	if r.isTTY {
		return 0
	}
	if anyError {
		return 1
	}
	return 0
}

// inputSummaryFor returns a short display string for the request's tool_input.
func inputSummaryFor(req wire.Request) string {
	switch req.ToolName {
	case "Bash":
		if cmd, ok := req.ToolInput["command"].(string); ok {
			return truncate(cmd, 60)
		}
	case "Read", "Write", "Edit":
		if fp, ok := req.ToolInput["file_path"].(string); ok {
			return truncate(fp, 60)
		}
	}
	return truncate(fmt.Sprintf("%v", req.ToolInput), 60)
}

// renderVerdict prints a human-readable verdict line to w.
func renderVerdict(w io.Writer, toolName, inputSummary string, resp wire.Response) {
	u := ui.New(w)

	var badge string
	switch resp.Action {
	case "allow":
		badge = u.Badge("ok", "allow")
	case "ask":
		badge = u.Badge("warn", "ask")
	case "deny":
		badge = u.Badge("fail", "deny")
	default:
		badge = u.Badge("dim", resp.Action)
	}

	ruleID := resp.RuleID
	if ruleID == "" {
		ruleID = "-"
	}

	detail := resp.Reason
	if resp.Impact != "" {
		detail = resp.Impact
	}

	fmt.Fprintf(w, "  %-8s  %-60s  %s  %s  %s\n",
		toolName,
		inputSummary,
		badge,
		u.Badge("dim", ruleID),
		u.Badge("dim", truncate(detail, 50)),
	)
}
