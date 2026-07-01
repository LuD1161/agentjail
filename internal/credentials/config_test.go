package credentials

import "testing"

func TestBackendFromName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"aws/prod", "aws"},
		{"aws/staging", "aws"},
		{"pg/prod", "pg"},
		{"pg/dev", "pg"},
		{"redis/prod", "redis"},
		{"redis/cache", "redis"},
		{"my-api-key", "raw"},
		{"DATABASE_URL", "raw"},
		{"", "raw"},
		{"awsprod", "raw"},   // no slash
		{"pgprod", "raw"},    // no slash
		{"redisprod", "raw"}, // no slash
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BackendFromName(tt.name)
			if got != tt.want {
				t.Errorf("BackendFromName(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
