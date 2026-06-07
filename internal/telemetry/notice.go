package telemetry

import (
	"fmt"
	"io"
)

const notice = `agentjail sends anonymous usage stats (counts, OS, which rules fired — never
paths, commands, or repo names), tied to a random ID.
  See everything it sends:  agentjail telemetry view
  Off anytime:              agentjail telemetry disable   ·   docs: agentjail.io/docs/reference/telemetry`

// MaybePrintNotice prints the one-time telemetry notice to w, then records
// notice_shown so it never prints again. Silent if telemetry is disabled or the
// notice was already shown. Best-effort; never errors out the caller.
func MaybePrintNotice(p Paths, getenv func(string) string, w io.Writer) {
	c, err := LoadConsent(p)
	if err != nil {
		return
	}
	if on, _ := Resolve(c, getenv); !on {
		return
	}
	if c.NoticeShown {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, notice)
	fmt.Fprintln(w)
	c.NoticeShown = true
	_ = SaveConsent(p, c)
}
