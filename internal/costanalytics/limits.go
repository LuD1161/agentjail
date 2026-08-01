package costanalytics

import (
	"bufio"
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

func newTranscriptScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	// Scanner refuses an oversized token before exposing it to JSON decoding.
	scanner.Buffer(make([]byte, 64*1024), maxTranscriptLineBytes+1)
	return scanner
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
