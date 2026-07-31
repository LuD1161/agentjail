package daemonapp

import (
	"strings"
	"testing"
)

func TestApprovalDisplayCommand(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]interface{}
		want        string
		contains    string
		notContains string
	}{
		{
			name:  "exact command",
			input: map[string]interface{}{"command": "git -C /tmp/work push origin HEAD:refs/heads/topic"},
			want:  "git -C /tmp/work push origin HEAD:refs/heads/topic",
		},
		{
			name:        "URL credential",
			input:       map[string]interface{}{"command": "git push https://user:supersecretpassword@example.com/repo.git"},
			contains:    "https://user:[redacted:url-credential]@example.com/repo.git",
			notContains: "supersecretpassword",
		},
		{
			name:        "control characters",
			input:       map[string]interface{}{"command": "git push origin main\nprintf evil\targ\x1b"},
			contains:    "git push origin main ↵ printf evil arg",
			notContains: "\n",
		},
		{
			name:  "missing command",
			input: map[string]interface{}{"path": "/tmp/work"},
			want:  "git push (command unavailable)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := approvalDisplayCommand(tt.input)
			if tt.want != "" && got != tt.want {
				t.Fatalf("approvalDisplayCommand() = %q, want %q", got, tt.want)
			}
			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Fatalf("approvalDisplayCommand() = %q, want substring %q", got, tt.contains)
			}
			if tt.notContains != "" && strings.Contains(got, tt.notContains) {
				t.Fatalf("approvalDisplayCommand() = %q, contains forbidden substring %q", got, tt.notContains)
			}
		})
	}
}

func TestApprovalDisplayCommandCapsLength(t *testing.T) {
	command := "git push origin " + strings.Repeat("a", maxApprovalDisplayRunes+100)
	got := approvalDisplayCommand(map[string]interface{}{"command": command})
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("approvalDisplayCommand() missing ellipsis: %q", got)
	}
	if count := len([]rune(strings.TrimSuffix(got, "…"))); count != maxApprovalDisplayRunes {
		t.Fatalf("approvalDisplayCommand() has %d runes before ellipsis, want %d", count, maxApprovalDisplayRunes)
	}
}
