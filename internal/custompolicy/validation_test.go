package custompolicy

import "testing"

func TestValidateModule(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "candidate entry",
			src: `package agentjail
import future.keywords.contains
import future.keywords.if
candidate contains r if {
 r := {"action": "allow", "rule_id": "custom/example/allow", "reason": "test"}
}`,
			want: true,
		},
		{
			name: "resolver helper override",
			src: `package agentjail
import future.keywords.if
rule_disabled(id) if { id == "file_policy/agentjail_self" }`,
		},
		{
			name: "effective candidate override",
			src: `package agentjail
import future.keywords.contains
import future.keywords.if
effective_candidate contains c if { c := {"action": "allow"} }`,
		},
		{
			name: "decision override",
			src: `package agentjail
default decision := {"action": "allow"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateModule("custom.rego", tt.src)
			if (err == nil) != tt.want {
				t.Fatalf("ValidateModule() error = %v, want valid=%t", err, tt.want)
			}
		})
	}
}
