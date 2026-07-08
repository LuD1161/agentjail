// Package shellparse parses shell command strings and extracts binary names.
// It is a best-effort parser for the 95% case — not a full POSIX shell parser.
package shellparse

import (
	"path/filepath"
	"strings"
)

// maxSubstitutionDepth bounds recursion into interpreter scripts (sh -c
// '...') and command substitutions ($(...), `...`) so pathological or
// self-referential input (e.g. "bash -c 'bash -c \"bash -c ...\"'") cannot
// cause unbounded recursion.
const maxSubstitutionDepth = 8

// interpreters are shells that, when invoked as "<shell> -c <script>",
// execute an arbitrary command string. The -c argument is parsed
// recursively so any binaries named inside the script are also surfaced.
var interpreters = map[string]bool{
	"sh":   true,
	"bash": true,
	"zsh":  true,
	"dash": true,
}

// wrappers are commands that execute another program on the caller's
// behalf, more or less transparently. The wrapper's own name is still
// reported, but the parser also looks past its flags / env-assignments to
// find — and recursively parse — the real command being wrapped.
var wrappers = map[string]bool{
	"env":     true,
	"nohup":   true,
	"timeout": true,
	"xargs":   true,
	"sudo":    true,
	"command": true,
	"nice":    true,
	"stdbuf":  true,
	"setsid":  true,
}

// scriptInterpreters maps a non-shell scripting-language interpreter to the
// flag(s) it accepts for an inline "run this code" argument (as opposed to a
// script file path). Unlike the shell interpreters above, the argument that
// follows is NOT shell syntax, so it is not parsed as a shell command.
// Instead — best-effort, not a Python/JS/Perl/Ruby/PHP parser — quoted
// string literals inside the code are extracted and each is recursively
// parsed as a shell command. This catches the common evasion of shelling
// out via a string argument (os.system(...), execSync(...), system(...),
// shell_exec(...)), e.g.
// python -c 'import os; os.system("agentjail policy disable no-sudo")'.
var scriptInterpreters = map[string][]string{
	"python":  {"-c"},
	"python3": {"-c"},
	"perl":    {"-e"},
	"ruby":    {"-e"},
	"node":    {"-e", "--eval"},
	"nodejs":  {"-e", "--eval"},
	"php":     {"-r"},
}

// Result holds the parsed components of a shell command string.
type Result struct {
	// Binaries contains the base name of every command binary found in the
	// pipeline/chain, including binaries reachable only through newline /
	// ';' / '&&' / '||' / '|' separated commands, interpreter wrappers
	// (sh -c, bash -c, ...), process wrappers (sudo, env, nohup, timeout,
	// xargs, command, nice, stdbuf, setsid), and command substitutions
	// ($(...) and `...`). For "git status && /usr/local/bin/agentjail
	// policy list | grep foo", Binaries is ["git", "agentjail", "grep"].
	Binaries []string
}

// Parse extracts binary names from a shell command string.
// It splits on pipes (|), chains (&&, ||), semicolons (;), and newlines,
// and for each segment extracts the command binary (first non-assignment
// word). Paths are reduced to basenames (/usr/local/bin/agentjail →
// agentjail). Quoted paths are handled ("$HOME/.agentjail/bin/agentjail" →
// agentjail). Interpreter wrappers (sh/bash/zsh/dash -c '<script>') are
// parsed recursively, as are command substitutions ($(...), `...`).
// Returns an empty Result (not nil) if parsing finds no binaries.
func Parse(cmd string) Result {
	binaries := parseBinaries(cmd, 0)
	if binaries == nil {
		binaries = []string{}
	}
	return Result{Binaries: binaries}
}

// parseBinaries is the recursive core of Parse. depth bounds recursion into
// interpreter scripts / command substitutions (see maxSubstitutionDepth).
func parseBinaries(cmd string, depth int) []string {
	if depth > maxSubstitutionDepth {
		return nil
	}
	segments := splitSegments(cmd)
	var binaries []string
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		binaries = append(binaries, extractBinaries(seg, depth)...)
	}
	return binaries
}

// splitSegments splits a shell command string on |, &&, ||, ;, and newline
// operators without splitting inside quoted strings, $(...) command
// substitutions, or `...` command substitutions.
func splitSegments(cmd string) []string {
	var segments []string
	var current strings.Builder
	i := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	depth := 0 // depth for $( ... ) substitutions

	for i < len(cmd) {
		ch := cmd[i]

		switch {
		case inSingle:
			if ch == '\'' {
				inSingle = false
			}
			current.WriteByte(ch)
			i++

		case inDouble:
			if ch == '"' {
				inDouble = false
			} else if ch == '\\' && i+1 < len(cmd) {
				current.WriteByte(ch)
				i++
				current.WriteByte(cmd[i])
				i++
				continue
			}
			current.WriteByte(ch)
			i++

		case inBacktick:
			if ch == '`' {
				inBacktick = false
			}
			current.WriteByte(ch)
			i++

		case depth > 0:
			// inside $( ... )
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
			} else if ch == '\'' {
				inSingle = true
			} else if ch == '"' {
				inDouble = true
			}
			current.WriteByte(ch)
			i++

		case ch == '\'':
			inSingle = true
			current.WriteByte(ch)
			i++

		case ch == '"':
			inDouble = true
			current.WriteByte(ch)
			i++

		case ch == '`':
			inBacktick = true
			current.WriteByte(ch)
			i++

		case ch == '$' && i+1 < len(cmd) && cmd[i+1] == '(':
			depth++
			current.WriteByte(ch)
			i++
			current.WriteByte(cmd[i])
			i++

		case ch == '&' && i+1 < len(cmd) && cmd[i+1] == '&':
			segments = append(segments, current.String())
			current.Reset()
			i += 2

		case ch == '|' && i+1 < len(cmd) && cmd[i+1] == '|':
			segments = append(segments, current.String())
			current.Reset()
			i += 2

		case ch == '|':
			segments = append(segments, current.String())
			current.Reset()
			i++

		case ch == ';':
			segments = append(segments, current.String())
			current.Reset()
			i++

		case ch == '\n':
			segments = append(segments, current.String())
			current.Reset()
			i++

		default:
			current.WriteByte(ch)
			i++
		}
	}

	if s := current.String(); strings.TrimSpace(s) != "" {
		segments = append(segments, s)
	}

	return segments
}

// extractBinaries extracts the binary name(s) from a single command segment.
// It resolves the primary command word — unwrapping process wrappers
// (sudo, env, nohup, timeout, xargs, command, nice, stdbuf, setsid) and
// interpreter -c scripts (sh/bash/zsh/dash) recursively — and separately
// scans the remaining argument tokens for embedded command substitutions
// ($(...) / `...`), which execute regardless of how their result is used.
func extractBinaries(seg string, depth int) []string {
	seg = strings.TrimSpace(seg)

	// Strip leading subshell parens: (cmd arg) → cmd arg
	for strings.HasPrefix(seg, "(") {
		seg = strings.TrimPrefix(seg, "(")
		seg = strings.TrimSpace(seg)
	}
	if seg == "" {
		return nil
	}

	tokens := tokenize(seg)
	if len(tokens) == 0 {
		return nil
	}

	var result []string
	// [skipFrom, skipTo) marks tokens already fully resolved (recursively
	// parsed) by the primary-command logic below, so the trailing
	// substitution scan doesn't double-count them.
	skipFrom, skipTo := 0, 0

	i := 0
	for i < len(tokens) {
		tok := tokens[i]

		// Skip redirection operators and their targets: >, >>, 2>, <
		if tok == ">" || tok == ">>" || tok == "2>" || tok == "<" || tok == "2>>" {
			i += 2
			continue
		}

		// Skip variable assignments: KEY=value
		if isAssignment(tok) {
			i++
			continue
		}

		// The whole token is a command substitution, e.g. "$(agentjail x)"
		// or "`agentjail x`" used as the command itself.
		if inner, ok := wholeSubstitutionInner(tok); ok {
			result = append(result, resolveSubstitutionInner(inner, depth)...)
			skipFrom, skipTo = i, i+1
			break
		}

		binary := cleanBinary(tok)
		if binary == "" {
			i++
			continue
		}
		result = append(result, binary)
		i++

		switch {
		case interpreters[binary]:
			// sh/bash/zsh/dash -c '<script>' — the script argument is
			// itself a full command string; parse it recursively.
			if scriptIdx, script, ok := findDashCScript(tokens, i); ok {
				result = append(result, parseBinaries(script, depth+1)...)
				skipFrom, skipTo = scriptIdx, scriptIdx+1
			}

		case scriptInterpreters[binary] != nil:
			// python/python3 -c, perl/ruby -e, node/nodejs -e|--eval,
			// php -r — the code argument is NOT shell syntax, so it is not
			// parsed as a command string. Instead, best-effort scan its
			// quoted string literals for embedded shell commands (the
			// os.system("...")/execSync("...")/system("...") pattern).
			if codeIdx, code, ok := findInlineCodeArg(tokens, i, scriptInterpreters[binary]); ok {
				result = append(result, extractInlineCodeBinaries(code, depth+1)...)
				skipFrom, skipTo = codeIdx, codeIdx+1
			}

		case wrappers[binary]:
			j := i
			introspectionOnly := false
			for j < len(tokens) {
				next := tokens[j]
				if next == "--" {
					j++
					continue
				}
				if strings.HasPrefix(next, "-") {
					// "command -v"/"command -V" only look up a command,
					// they don't execute it.
					if binary == "command" && (next == "-v" || next == "-V") {
						introspectionOnly = true
					}
					if wrapperFlagTakesValue(binary, next) && j+1 < len(tokens) {
						j += 2
					} else {
						j++
					}
					continue
				}
				if isAssignment(next) {
					j++
					continue
				}
				if binary == "timeout" && startsWithDigit(next) {
					// duration argument, e.g. "timeout 5 agentjail ..."
					j++
					continue
				}
				break
			}
			if !introspectionOnly && j < len(tokens) && depth < maxSubstitutionDepth {
				rest := strings.Join(tokens[j:], " ")
				result = append(result, extractBinaries(rest, depth+1)...)
				skipFrom, skipTo = j, len(tokens)
			} else {
				// Nothing recursively parsed beyond the wrapper's own
				// flags — still scan the remaining tokens below for
				// embedded substitutions (the shell evaluates those
				// regardless of what consumes the result).
				skipFrom, skipTo = j, j
			}
		}
		break
	}

	// Command substitutions embedded in argument tokens execute
	// unconditionally as part of shell word-expansion, independent of the
	// primary command resolved above.
	for idx, tok := range tokens {
		if idx >= skipFrom && idx < skipTo {
			continue
		}
		for _, inner := range findSubstitutions(tok) {
			result = append(result, resolveSubstitutionInner(inner, depth)...)
		}
	}

	return result
}

// tokenize splits a shell segment into tokens respecting single/double
// quotes, backtick command substitutions, and $(...) command substitutions.
// It does NOT split on shell operators (those were already consumed by
// splitSegments).
func tokenize(s string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	inBacktick := false
	depth := 0 // depth for $( ... ) substitutions
	i := 0

	for i < len(s) {
		ch := s[i]
		switch {
		case inSingle:
			if ch == '\'' {
				inSingle = false
				cur.WriteByte(ch)
			} else {
				cur.WriteByte(ch)
			}
			i++
		case inDouble:
			if ch == '"' {
				inDouble = false
				cur.WriteByte(ch)
			} else if ch == '\\' && i+1 < len(s) {
				cur.WriteByte(s[i+1])
				i += 2
				continue
			} else {
				cur.WriteByte(ch)
			}
			i++
		case inBacktick:
			if ch == '`' {
				inBacktick = false
			}
			cur.WriteByte(ch)
			i++
		case depth > 0:
			// inside $( ... ) — keep everything as part of the current token
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
			} else if ch == '\'' {
				inSingle = true
			} else if ch == '"' {
				inDouble = true
			}
			cur.WriteByte(ch)
			i++
		case ch == '$' && i+1 < len(s) && s[i+1] == '(':
			depth++
			cur.WriteByte(ch)
			i++
			cur.WriteByte(s[i])
			i++
		case ch == '\'':
			inSingle = true
			cur.WriteByte(ch)
			i++
		case ch == '"':
			inDouble = true
			cur.WriteByte(ch)
			i++
		case ch == '`':
			inBacktick = true
			cur.WriteByte(ch)
			i++
		case ch == ' ' || ch == '\t' || ch == '\n':
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			i++
		default:
			cur.WriteByte(ch)
			i++
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// isAssignment returns true if the token looks like KEY=value or KEY=.
func isAssignment(tok string) bool {
	// Must contain '=' and the part before '=' must be a valid identifier
	idx := strings.Index(tok, "=")
	if idx <= 0 {
		return false
	}
	key := tok[:idx]
	for _, ch := range key {
		if !isIdentChar(ch) {
			return false
		}
	}
	return true
}

func isIdentChar(ch rune) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
		(ch >= '0' && ch <= '9') || ch == '_'
}

func startsWithDigit(tok string) bool {
	return tok != "" && tok[0] >= '0' && tok[0] <= '9'
}

// cleanBinary strips quotes, takes the basename, and returns the binary name.
func cleanBinary(tok string) string {
	// Strip outer single quotes
	if strings.HasPrefix(tok, "'") && strings.HasSuffix(tok, "'") && len(tok) >= 2 {
		tok = tok[1 : len(tok)-1]
	}
	// Strip outer double quotes
	if strings.HasPrefix(tok, `"`) && strings.HasSuffix(tok, `"`) && len(tok) >= 2 {
		tok = tok[1 : len(tok)-1]
	}

	// Expand simple $HOME-style prefix — we only need the basename so just take it
	tok = filepath.Base(tok)

	// Remove trailing special chars like ) that might have been left
	tok = strings.TrimRight(tok, ")")

	return tok
}

// unquoteToken strips a single layer of matching outer quotes from a token,
// without basename-ing it (unlike cleanBinary, this is used for full
// command strings such as a "-c" script argument).
func unquoteToken(tok string) string {
	if len(tok) >= 2 {
		if tok[0] == '\'' && tok[len(tok)-1] == '\'' {
			return tok[1 : len(tok)-1]
		}
		if tok[0] == '"' && tok[len(tok)-1] == '"' {
			s := tok[1 : len(tok)-1]
			s = strings.ReplaceAll(s, `\"`, `"`)
			return s
		}
	}
	return tok
}

// findDashCScript scans tokens starting at start for a "-c" flag (allowing
// other leading dash-flags before it, e.g. "bash --norc -c '...'") and
// returns the index and unquoted text of the script argument that follows.
// If a non-flag token is seen before "-c" (e.g. "bash script.sh"), it stops
// looking — that invocation runs a script file, which this parser does not
// read.
func findDashCScript(tokens []string, start int) (idx int, script string, ok bool) {
	for k := start; k < len(tokens); k++ {
		t := tokens[k]
		if t == "-c" {
			if k+1 < len(tokens) {
				return k + 1, unquoteToken(tokens[k+1]), true
			}
			return 0, "", false
		}
		if !strings.HasPrefix(t, "-") {
			break
		}
	}
	return 0, "", false
}

// findInlineCodeArg scans tokens starting at start for one of the given
// inline-code flags (e.g. "-c", "-e", "--eval") — allowing other leading
// dash-flags before it — and returns the index and unquoted text of the
// code argument that follows. It also accepts the "--eval=<code>" long-flag
// form. If a non-flag token is seen first (e.g. "python script.py"), it
// stops looking — that invocation runs a script file, which this parser
// does not read.
func findInlineCodeArg(tokens []string, start int, flags []string) (idx int, code string, ok bool) {
	for k := start; k < len(tokens); k++ {
		t := tokens[k]
		for _, f := range flags {
			if t == f {
				if k+1 < len(tokens) {
					return k + 1, unquoteToken(tokens[k+1]), true
				}
				return 0, "", false
			}
			if strings.HasPrefix(f, "--") && strings.HasPrefix(t, f+"=") {
				return k, unquoteToken(t[len(f)+1:]), true
			}
		}
		if !strings.HasPrefix(t, "-") {
			break
		}
	}
	return 0, "", false
}

// extractInlineCodeBinaries best-effort scans a non-shell scripting
// language's inline code string (e.g. a python -c or node -e argument) for
// quoted string literals and recursively parses each as a shell command.
// This is NOT a Python/JavaScript/Perl/Ruby/PHP parser — it does not
// understand variables, string concatenation, or encoding (base64, etc).
// It only catches the common "shell out with a string literal" pattern
// (os.system("..."), execSync("..."), system("..."), shell_exec("...")) by
// surfacing any binaries named in string literals within the code.
// Depth-bounded like the rest of this package's recursive parsing.
func extractInlineCodeBinaries(code string, depth int) []string {
	if depth >= maxSubstitutionDepth {
		return nil
	}
	var result []string
	for _, s := range findQuotedStrings(code) {
		result = append(result, parseBinaries(s, depth+1)...)
	}
	return result
}

// findQuotedStrings scans raw text for single- and double-quoted string
// literals and returns their (best-effort unescaped) contents. It is a
// lightweight scan, not a lexer for the host language's full quoting/escaping
// rules.
func findQuotedStrings(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		ch := s[i]
		if ch == '\'' || ch == '"' {
			quote := ch
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != quote {
				if s[j] == '\\' && j+1 < len(s) {
					b.WriteByte(s[j+1])
					j += 2
					continue
				}
				b.WriteByte(s[j])
				j++
			}
			out = append(out, b.String())
			if j < len(s) {
				j++ // consume closing quote
			}
			i = j
			continue
		}
		i++
	}
	return out
}

// wrapperFlagTakesValue reports whether flag is a known value-taking option
// for the given wrapper binary, so its argument can be skipped along with it.
func wrapperFlagTakesValue(binary, flag string) bool {
	switch binary {
	case "sudo":
		switch flag {
		case "-u", "-g", "-C", "-c", "-h", "-p", "-r", "-t", "-U":
			return true
		}
	case "env":
		switch flag {
		case "-u", "-C", "-S":
			return true
		}
	case "nice":
		return flag == "-n"
	case "xargs":
		switch flag {
		case "-I", "-i", "-L", "-l", "-n", "-P", "-s", "-a", "-d", "-E":
			return true
		}
	case "stdbuf":
		switch flag {
		case "-i", "-o", "-e":
			return true
		}
	case "timeout":
		switch flag {
		case "-s", "-k", "--signal", "--kill-after":
			return true
		}
	}
	return false
}

// wholeSubstitutionInner returns the inner command text if tok is entirely
// a command substitution — "$(...)" or "`...`" — with nothing before or
// after it.
func wholeSubstitutionInner(tok string) (string, bool) {
	if strings.HasPrefix(tok, "$(") && strings.HasSuffix(tok, ")") && len(tok) >= 3 {
		return strings.TrimSpace(tok[2 : len(tok)-1]), true
	}
	if strings.HasPrefix(tok, "`") && strings.HasSuffix(tok, "`") && len(tok) >= 2 && tok != "`" {
		return strings.TrimSpace(tok[1 : len(tok)-1]), true
	}
	return "", false
}

// resolveWhichOrCommandV special-cases "$(which cmd)" and
// "$(command -v cmd)" / "$(command -V cmd)" substitutions, which resolve to
// the path of cmd (and cmd is what actually ends up invoked by the
// surrounding command line), rather than "which"/"command" themselves.
func resolveWhichOrCommandV(inner string) (string, bool) {
	inner = strings.TrimSpace(inner)

	if strings.HasPrefix(inner, "which ") {
		parts := strings.Fields(inner)
		if len(parts) >= 2 {
			return filepath.Base(parts[len(parts)-1]), true
		}
	}

	if strings.HasPrefix(inner, "command ") {
		parts := strings.Fields(inner)
		for i := 1; i < len(parts); i++ {
			if !strings.HasPrefix(parts[i], "-") {
				return filepath.Base(parts[i]), true
			}
		}
	}

	return "", false
}

// resolveSubstitutionInner resolves the binaries invoked by the inner text
// of a command substitution: the which/command-v shortcut if it matches,
// otherwise a full recursive parse of the inner text as a command string.
func resolveSubstitutionInner(inner string, depth int) []string {
	if resolved, ok := resolveWhichOrCommandV(inner); ok {
		return []string{resolved}
	}
	if depth >= maxSubstitutionDepth {
		return nil
	}
	return parseBinaries(inner, depth+1)
}

// findSubstitutions scans raw token text for $(...) and `...` command
// substitutions and returns their inner command text. Content inside
// single quotes is skipped (the shell does not expand substitutions there).
func findSubstitutions(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		ch := s[i]

		if ch == '\'' {
			j := i + 1
			for j < len(s) && s[j] != '\'' {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}

		if ch == '$' && i+1 < len(s) && s[i+1] == '(' {
			depth := 1
			j := i + 2
			for j < len(s) && depth > 0 {
				if s[j] == '(' {
					depth++
				} else if s[j] == ')' {
					depth--
				}
				j++
			}
			inner := s[i+2:]
			if depth == 0 {
				inner = s[i+2 : j-1]
			}
			out = append(out, strings.TrimSpace(inner))
			i = j
			continue
		}

		if ch == '`' {
			j := i + 1
			for j < len(s) && s[j] != '`' {
				j++
			}
			out = append(out, strings.TrimSpace(s[i+1:j]))
			if j < len(s) {
				j++
			}
			i = j
			continue
		}

		i++
	}
	return out
}
