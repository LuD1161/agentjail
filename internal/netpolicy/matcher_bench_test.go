package netpolicy

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkMatcherEvaluate(b *testing.B) {
	for _, size := range []int{128, 1 << 20} {
		for _, rules := range []int{1, 8} {
			b.Run(fmt.Sprintf("bytes=%d/rules=%d", size, rules), func(b *testing.B) {
				var yaml strings.Builder
				for i := 0; i < rules; i++ {
					fmt.Fprintf(&yaml, `---
id: rule-%d
match:
  path: ["re:^/v1/messages$"]
action: deny
reason: "Blocked {{.Verb}}: {{range .ScanHits}}{{.RuleName}} {{end}}"
impact: "To {{.Host}}"
scan:
  payload:
    - type: contains
      patterns: [marker]
      name: marker
`, i)
				}
				ts, err := parseTemplates([]byte(yaml.String()))
				if err != nil {
					b.Fatal(err)
				}
				m := &Matcher{templates: ts}
				op := &Operation{Path: "/v1/messages", Verb: "create", Host: "example.test", Payload: map[string]any{"text": strings.Repeat("a", size) + "marker"}}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if m.Evaluate(op) == nil {
						b.Fatal("missing match")
					}
				}
			})
		}
	}
}
