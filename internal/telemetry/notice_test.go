package telemetry

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaybePrintNotice_PrintsOnceThenSuppresses(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	var buf bytes.Buffer
	MaybePrintNotice(p, func(string) string { return "" }, &buf)
	out := buf.String()
	if !strings.Contains(out, "anonymous usage stats") || !strings.Contains(out, "telemetry disable") {
		t.Fatalf("notice missing expected text: %q", out)
	}
	if strings.Contains(strings.ToLower(out), "posthog") {
		t.Fatalf("notice must NOT name the vendor: %q", out)
	}
	// Second call prints nothing (notice_shown persisted).
	buf.Reset()
	MaybePrintNotice(p, func(string) string { return "" }, &buf)
	if buf.Len() != 0 {
		t.Fatalf("notice printed twice: %q", buf.String())
	}
}

func TestMaybePrintNotice_SilentWhenDisabled(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	var buf bytes.Buffer
	MaybePrintNotice(p, func(k string) string {
		if k == EnvVar {
			return "false"
		}
		return ""
	}, &buf)
	if buf.Len() != 0 {
		t.Fatalf("notice printed while disabled: %q", buf.String())
	}
}
