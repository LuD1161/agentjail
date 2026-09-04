package hostproxy

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrCommandShape = errors.New("host proxy requires one direct agentjail proxy command")
var ErrReasonRequired = errors.New("host proxy requires --reason with a concise explanation")
var ErrReasonInvalid = fmt.Errorf("host proxy --reason must be valid UTF-8, single-line, and at most %d bytes", MaxReasonBytes)

// ParseCommand accepts only one direct shell command. Expansion and shell
// operators are refused so the approved string has one exact argv meaning.
// See ADR 0134-host-proxy-mvp.
func ParseCommand(command string) ([]string, error) {
	words, err := strictWords(command)
	if err != nil || len(words) < 2 || filepath.Base(words[0]) != "agentjail" || words[1] != "proxy" {
		return nil, ErrCommandShape
	}
	intent, err := ParseArgs(words[2:])
	if err != nil {
		return nil, err
	}
	return intent.Argv, nil
}

func ParseIntent(command string) (Intent, error) {
	words, err := strictWords(command)
	if err != nil || len(words) < 2 || filepath.Base(words[0]) != "agentjail" || words[1] != "proxy" {
		return Intent{}, ErrCommandShape
	}
	return ParseArgs(words[2:])
}

func ParseArgs(args []string) (Intent, error) {
	if len(args) < 1 || args[0] != "--reason" {
		return Intent{}, ErrReasonRequired
	}
	if len(args) < 2 || args[1] == "" {
		return Intent{}, ErrReasonRequired
	}
	reason := Reason(args[1])
	if !validReason(reason) {
		return Intent{}, ErrReasonInvalid
	}
	if len(args) < 4 || args[2] != "--" || args[3] == "" {
		return Intent{}, ErrCommandShape
	}
	return Intent{Reason: reason, Argv: append([]string(nil), args[3:]...)}, nil
}

func validReason(reason Reason) bool {
	value := string(reason)
	if !utf8.ValidString(value) || len(value) > MaxReasonBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return value != ""
}

type quoteState uint8

const (
	quoteNone quoteState = iota
	quoteSingle
	quoteDouble
)

func strictWords(input string) ([]string, error) {
	var words []string
	var word strings.Builder
	state := quoteNone
	started := false
	flush := func() {
		if started {
			words = append(words, word.String())
			word.Reset()
			started = false
		}
	}
	for i := 0; i < len(input); i++ {
		c := input[i]
		switch state {
		case quoteSingle:
			if c == '\'' {
				state = quoteNone
			} else {
				word.WriteByte(c)
			}
			started = true
		case quoteDouble:
			switch c {
			case '"':
				state = quoteNone
			case '$', '`', '\n', '\r':
				return nil, ErrCommandShape
			case '\\':
				if i+1 >= len(input) {
					return nil, ErrCommandShape
				}
				next := input[i+1]
				if next == '"' || next == '\\' {
					word.WriteByte(next)
					i++
				} else {
					word.WriteByte(c)
				}
			default:
				word.WriteByte(c)
			}
			started = true
		default:
			switch {
			case unicode.IsControl(rune(c)):
				return nil, ErrCommandShape
			case c == '\n' || c == '\r':
				return nil, ErrCommandShape
			case unicode.IsSpace(rune(c)):
				flush()
			case c == '\'':
				state = quoteSingle
				started = true
			case c == '"':
				state = quoteDouble
				started = true
			case c == '\\':
				if i+1 >= len(input) || input[i+1] == '\n' || input[i+1] == '\r' {
					return nil, ErrCommandShape
				}
				i++
				word.WriteByte(input[i])
				started = true
			case strings.ContainsRune(";&|<>$`(){}*?[]#", rune(c)):
				return nil, ErrCommandShape
			default:
				word.WriteByte(c)
				started = true
			}
		}
	}
	if state != quoteNone {
		return nil, fmt.Errorf("%w: unterminated quote", ErrCommandShape)
	}
	flush()
	return words, nil
}
