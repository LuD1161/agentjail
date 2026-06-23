// Package shellparse parses shell command strings and extracts binary names.
// It is a best-effort parser for the 95% case — not a full POSIX shell parser.
package shellparse

import (
	"path/filepath"
	"strings"
)

// Result holds the parsed components of a shell command string.
type Result struct {
	// Binaries contains the base name of every command binary in the
	// pipeline/chain. For "git status && /usr/local/bin/agentjail policy list | grep foo",
	// Binaries is ["git", "agentjail", "grep"].
	Binaries []string
}

// Parse extracts binary names from a shell command string.
// It splits on pipes (|), chains (&&, ||), semicolons (;),
// and for each segment extracts the command binary (first non-assignment word).
// Paths are reduced to basenames (/usr/local/bin/agentjail → agentjail).
// Quoted paths are handled ("$HOME/.agentjail/bin/agentjail" → agentjail).
// Returns an empty Result (not nil) if parsing finds no binaries.
func Parse(cmd string) Result {
	segments := splitSegments(cmd)
	var binaries []string
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		bins := extractBinaries(seg)
		binaries = append(binaries, bins...)
	}
	if binaries == nil {
		binaries = []string{}
	}
	return Result{Binaries: binaries}
}

// splitSegments splits a shell command string on |, &&, ||, ; operators
// without splitting inside quoted strings or $(...) command substitutions.
func splitSegments(cmd string) []string {
	var segments []string
	var current strings.Builder
	i := 0
	inSingle := false
	inDouble := false
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
// It handles env prefixes (KEY=val), sudo, env, subshell parens, and
// $(which cmd) / $(command -v cmd) substitutions.
func extractBinaries(seg string) []string {
	seg = strings.TrimSpace(seg)

	// Strip leading subshell parens: (cmd arg) → cmd arg
	for strings.HasPrefix(seg, "(") {
		seg = strings.TrimPrefix(seg, "(")
		seg = strings.TrimSpace(seg)
	}

	// Tokenize the segment respecting quotes (but not splitting on operators
	// since we already did that).
	tokens := tokenize(seg)
	if len(tokens) == 0 {
		return nil
	}

	var result []string
	i := 0
	for i < len(tokens) {
		tok := tokens[i]

		// Skip redirection operators and their targets: >, >>, 2>, <
		if tok == ">" || tok == ">>" || tok == "2>" || tok == "<" || tok == "2>>" {
			i += 2 // skip operator and filename
			continue
		}

		// Skip variable assignments: KEY=value
		if isAssignment(tok) {
			i++
			continue
		}

		// Handle $(which cmd) or $(command -v cmd) substitution as the binary
		if binary, ok := parseSubstitution(tok); ok {
			result = append(result, binary)
			return result
		}

		// Found the binary token
		binary := cleanBinary(tok)
		if binary == "" {
			i++
			continue
		}
		result = append(result, binary)

		// Special case: sudo or env — also capture the actual command after flags/assignments
		if binary == "sudo" || binary == "env" {
			i++
			// skip sudo flags (-u user, -E, etc.) and env assignments
			for i < len(tokens) {
				next := tokens[i]
				if strings.HasPrefix(next, "-") {
					// sudo flag: might consume a value, simple heuristic — skip flag
					// For -u/-g we skip one more token (the user/group)
					if (next == "-u" || next == "-g" || next == "-C" || next == "-c") && i+1 < len(tokens) {
						i += 2
					} else {
						i++
					}
					continue
				}
				if isAssignment(next) {
					i++
					continue
				}
				// next non-flag, non-assignment token is the real command
				if sub, ok := parseSubstitution(next); ok {
					result = append(result, sub)
				} else {
					cmd := cleanBinary(next)
					if cmd != "" {
						result = append(result, cmd)
					}
				}
				break
			}
		}
		return result
	}
	return result
}

// tokenize splits a shell segment into tokens respecting single/double quotes
// and $(...) command substitutions. It does NOT split on shell operators
// (those were already consumed by splitSegments).
func tokenize(s string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
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
		case ch == ' ' || ch == '\t':
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

// parseSubstitution checks if a token is $(which cmd) or $(command -v cmd)
// and returns the extracted command name.
func parseSubstitution(tok string) (string, bool) {
	tok = strings.TrimSpace(tok)
	if !strings.HasPrefix(tok, "$(") || !strings.HasSuffix(tok, ")") {
		return "", false
	}
	inner := tok[2 : len(tok)-1]
	inner = strings.TrimSpace(inner)

	// $(which cmd)
	if strings.HasPrefix(inner, "which ") {
		parts := strings.Fields(inner)
		if len(parts) >= 2 {
			return filepath.Base(parts[len(parts)-1]), true
		}
	}

	// $(command -v cmd)
	if strings.HasPrefix(inner, "command ") {
		parts := strings.Fields(inner)
		// skip "command" and any flags like -v
		for i := 1; i < len(parts); i++ {
			if !strings.HasPrefix(parts[i], "-") {
				return filepath.Base(parts[i]), true
			}
		}
	}

	return "", false
}
