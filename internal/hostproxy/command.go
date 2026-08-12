package hostproxy

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

var ErrCommandShape = errors.New("host proxy requires one direct agentjail proxy command")

// ParseCommand accepts only one direct shell command. Expansion and shell
// operators are refused so the approved string has one exact argv meaning.
// See ADR 0132-host-proxy-mvp.
func ParseCommand(command string) ([]string, error) {
	words, err := strictWords(command)
	if err != nil || len(words) < 4 || filepath.Base(words[0]) != "agentjail" || words[1] != "proxy" || words[2] != "--" {
		return nil, ErrCommandShape
	}
	argv := append([]string(nil), words[3:]...)
	if argv[0] == "" {
		return nil, ErrCommandShape
	}
	return argv, nil
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
