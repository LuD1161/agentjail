package shellparse

import "strings"

// Invocation is one executable command recovered from a shell expression.
// Arguments are unquoted shell words; shell expansions are not evaluated.
type Invocation struct {
	Binary    string
	Arguments []string
}

func parseInvocations(cmd string, depth int) []Invocation {
	if depth > maxSubstitutionDepth {
		return nil
	}
	var out []Invocation
	for _, segment := range splitSegments(cmd) {
		out = append(out, extractInvocations(strings.TrimSpace(segment), depth)...)
	}
	return out
}

func extractInvocations(segment string, depth int) []Invocation {
	for strings.HasPrefix(segment, "(") {
		segment = strings.TrimSpace(strings.TrimPrefix(segment, "("))
	}
	if segment == "" {
		return nil
	}

	tokens := tokenize(segment)
	if len(tokens) == 0 {
		return nil
	}

	commandIndex := invocationCommandIndex(tokens)
	if commandIndex < 0 {
		return nil
	}

	commandToken := tokens[commandIndex]
	if inner, ok := wholeSubstitutionInner(commandToken); ok {
		if binary, resolved := resolveWhichOrCommandV(inner); resolved {
			invocation := Invocation{
				Binary:    binary,
				Arguments: invocationArguments(tokens[commandIndex+1:]),
			}
			return append([]Invocation{invocation}, invocationSubstitutions(tokens, commandIndex+1, depth)...)
		}
		return parseInvocations(inner, depth+1)
	}

	binary := cleanBinary(commandToken)
	if binary == "" {
		return nil
	}
	invocation := Invocation{
		Binary:    binary,
		Arguments: invocationArguments(tokens[commandIndex+1:]),
	}
	out := []Invocation{invocation}

	switch {
	case interpreters[binary]:
		if _, script, ok := findDashCScript(tokens, commandIndex+1); ok {
			out = append(out, parseInvocations(script, depth+1)...)
		}
	case scriptInterpreters[binary] != nil:
		if _, code, ok := findInlineCodeArg(tokens, commandIndex+1, scriptInterpreters[binary]); ok {
			for _, literal := range findQuotedStrings(code) {
				out = append(out, parseInvocations(literal, depth+1)...)
			}
		}
	case wrappers[binary]:
		if innerIndex := wrappedCommandIndex(binary, tokens, commandIndex+1); innerIndex >= 0 {
			out = append(out, extractInvocations(strings.Join(tokens[innerIndex:], " "), depth+1)...)
		}
	}

	out = append(out, invocationSubstitutions(tokens, commandIndex+1, depth)...)
	return out
}

func invocationCommandIndex(tokens []string) int {
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case ">", ">>", "2>", "2>>", "<":
			i++
			continue
		}
		if isAssignment(tokens[i]) {
			continue
		}
		return i
	}
	return -1
}

func invocationArguments(tokens []string) []string {
	args := make([]string, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case ">", ">>", "2>", "2>>", "<":
			i++
			continue
		}
		args = append(args, unquoteToken(tokens[i]))
	}
	return args
}

func wrappedCommandIndex(binary string, tokens []string, start int) int {
	introspectionOnly := false
	for i := start; i < len(tokens); {
		token := tokens[i]
		if token == "--" {
			i++
			if i < len(tokens) {
				return i
			}
			return -1
		}
		if strings.HasPrefix(token, "-") {
			if binary == "command" && (token == "-v" || token == "-V") {
				introspectionOnly = true
			}
			if wrapperFlagTakesValue(binary, token) && i+1 < len(tokens) {
				i += 2
			} else {
				i++
			}
			continue
		}
		if isAssignment(token) {
			i++
			continue
		}
		if binary == "timeout" && startsWithDigit(token) {
			i++
			continue
		}
		if introspectionOnly {
			return -1
		}
		return i
	}
	return -1
}

func invocationSubstitutions(tokens []string, start, depth int) []Invocation {
	if depth >= maxSubstitutionDepth {
		return nil
	}
	var out []Invocation
	for _, token := range tokens[start:] {
		for _, inner := range findSubstitutions(token) {
			if binary, resolved := resolveWhichOrCommandV(inner); resolved {
				out = append(out, Invocation{Binary: binary, Arguments: []string{}})
				continue
			}
			out = append(out, parseInvocations(inner, depth+1)...)
		}
	}
	return out
}
