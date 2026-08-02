package costanalytics

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

var errTranscriptFileLimit = errors.New("cost transcript file limit reached")

const (
	maxTranscriptLineBytes = 16 << 20
	maxTranscriptFiles     = 10_000
	maxSessionCosts        = 50_000
	maxCostPeriod          = 90 * 24 * time.Hour
)

// MaxProjectFilterBytes bounds a caller-controlled project filter before it
// is compared against locally discovered project metadata.
const MaxProjectFilterBytes = 4096

// ParsePeriod accepts the documented compact day form or a Go duration and
// rejects values that would turn a report into an unbounded historical scan.
func ParsePeriod(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseInt(strings.TrimSuffix(value, "d"), 10, 64)
		if err != nil || days <= 0 || days > int64(maxCostPeriod/(24*time.Hour)) {
			return 0, fmt.Errorf("invalid period %q", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > maxCostPeriod {
		return 0, fmt.Errorf("invalid period %q", value)
	}
	return duration, nil
}

type transcriptScanner struct {
	reader *bufio.Reader
	line   []byte
	err    error
	done   bool
}

func newTranscriptScanner(r io.Reader) *transcriptScanner {
	return &transcriptScanner{reader: bufio.NewReaderSize(r, 64*1024)}
}

func (s *transcriptScanner) Scan() bool {
	if s.done {
		return false
	}

	line := make([]byte, 0, 64*1024)
	oversized := false
	for {
		fragment, err := s.reader.ReadSlice('\n')
		if !oversized {
			contentLen := len(fragment)
			if err == nil && contentLen > 0 {
				contentLen--
			}
			if len(line)+contentLen > maxTranscriptLineBytes {
				line = nil
				oversized = true
			} else {
				line = append(line, fragment...)
			}
		}

		switch {
		case err == nil:
			s.line = bytesTrimLineEnding(line)
			return true
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			s.done = true
			if len(line) == 0 && !oversized {
				return false
			}
			s.line = bytesTrimLineEnding(line)
			return true
		default:
			s.err = err
			s.done = true
			return false
		}
	}
}

func (s *transcriptScanner) Bytes() []byte { return s.line }

func (s *transcriptScanner) Err() error { return s.err }

func bytesTrimLineEnding(line []byte) []byte {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	return bytes.TrimSuffix(line, []byte{'\r'})
}

func appendSessionCosts(existing, added []SessionCost) ([]SessionCost, error) {
	remaining := maxSessionCosts - len(existing)
	if remaining <= 0 {
		return existing, fmt.Errorf("cost session limit of %d reached", maxSessionCosts)
	}
	if len(added) <= remaining {
		return append(existing, added...), nil
	}
	return append(existing, added[:remaining]...), fmt.Errorf("cost session limit of %d reached", maxSessionCosts)
}
