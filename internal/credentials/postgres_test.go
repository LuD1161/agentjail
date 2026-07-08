package credentials

import (
	"io"
	"strings"
	"testing"
)

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

func TestStripPGDSNPassword(t *testing.T) {
	tests := []struct {
		dsn      string
		wantDSN  string
		wantPass string
	}{
		{
			"postgresql://admin:supersecret@localhost:5432/mydb",
			"postgresql://admin@localhost:5432/mydb",
			"supersecret",
		},
		{
			"postgres://user:pass@db.example.com:6543/prod",
			"postgres://user@db.example.com:6543/prod",
			"pass",
		},
		{
			"postgresql://admin@localhost:5432/mydb",
			"postgresql://admin@localhost:5432/mydb",
			"",
		},
		{
			"host=db port=5432 dbname=test password=hunter2",
			"host=db port=5432 dbname=test",
			"hunter2",
		},
		{
			"host=db port=5432 dbname=test",
			"host=db port=5432 dbname=test",
			"",
		},
	}
	for _, tc := range tests {
		gotDSN, gotPass := stripPGDSNPassword(tc.dsn)
		if gotDSN != tc.wantDSN || gotPass != tc.wantPass {
			t.Errorf("stripPGDSNPassword(%q) = (%q, %q); want (%q, %q)",
				tc.dsn, gotDSN, gotPass, tc.wantDSN, tc.wantPass)
		}
	}
}

func TestBuildPsqlCmd_NoPasswordInArgv(t *testing.T) {
	dsn := "postgresql://admin:supersecret@localhost:5432/mydb"
	sql := "CREATE ROLE agentjail_abcd WITH LOGIN PASSWORD 'rolepassword123' VALID UNTIL '2026-01-01 00:00:00';"

	cmd := buildPsqlCmd(dsn, sql)

	for _, arg := range cmd.Args {
		if strings.Contains(arg, "supersecret") {
			t.Fatalf("admin password leaked into argv: %q", arg)
		}
		if strings.Contains(arg, "rolepassword123") {
			t.Fatalf("SQL (containing the new role password) leaked into argv: %q", arg)
		}
	}

	foundPGPassword := false
	for _, e := range cmd.Env {
		if e == "PGPASSWORD=supersecret" {
			foundPGPassword = true
		}
		if strings.Contains(e, "rolepassword123") {
			t.Fatalf("SQL leaked into Env: %q", e)
		}
	}
	if !foundPGPassword {
		t.Fatalf("expected PGPASSWORD=supersecret in cmd.Env, got %v", cmd.Env)
	}

	// The SQL must travel via stdin, not argv or env.
	stdinReader, ok := cmd.Stdin.(io.Reader)
	if !ok {
		t.Fatal("expected cmd.Stdin to be set")
	}
	got, err := io.ReadAll(stdinReader)
	if err != nil {
		t.Fatalf("read stdin: %v", err)
	}
	if string(got) != sql {
		t.Fatalf("stdin = %q; want %q", got, sql)
	}
}

func TestBuildPsqlCmd_NoPasswordNoEnvOverride(t *testing.T) {
	dsn := "postgresql://admin@localhost:5432/mydb" // no password
	cmd := buildPsqlCmd(dsn, "SELECT 1;")

	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "PGPASSWORD=") {
			t.Fatalf("did not expect PGPASSWORD to be set when DSN has no password, got %q", e)
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
