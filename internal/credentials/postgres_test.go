package credentials

import "testing"

func TestParsePGDSN(t *testing.T) {
	tests := []struct {
		dsn      string
		wantHost string
		wantPort string
		wantDB   string
	}{
		{"postgresql://admin:pass@localhost:5432/mydb", "localhost", "5432", "mydb"},
		{"postgres://user:pass@db.example.com:6543/prod", "db.example.com", "6543", "prod"},
		{"host=db port=5432 dbname=test", "db", "5432", "test"},
		{"postgresql://user:pass@host:5432/db?sslmode=require", "host", "5432", "db"},
	}
	for _, tc := range tests {
		host, port, db := parsePGDSN(tc.dsn)
		if host != tc.wantHost || port != tc.wantPort || db != tc.wantDB {
			t.Errorf("parsePGDSN(%q) = (%q, %q, %q); want (%q, %q, %q)",
				tc.dsn, host, port, db, tc.wantHost, tc.wantPort, tc.wantDB)
		}
	}
}

func TestBuildPGCreateRoleSQL(t *testing.T) {
	sql := buildPGCreateRoleSQL("test_role", "secret", "2026-01-01 00:00:00", "read-only")
	if sql == "" {
		t.Fatal("buildPGCreateRoleSQL returned empty string")
	}
	// Should contain the role name and SELECT grant.
	if !contains(sql, "test_role") {
		t.Error("SQL should contain the role name")
	}
	if !contains(sql, "GRANT SELECT") {
		t.Error("read-only scope should grant SELECT")
	}
}

func TestQuoteIdent(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", `"simple"`},
		{`has"quote`, `"has""quote"`},
	}
	for _, tc := range tests {
		got := quoteIdent(tc.input)
		if got != tc.want {
			t.Errorf("quoteIdent(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
