package credentials

import "testing"

func TestBuildRedisACLCommand(t *testing.T) {
	cmd := buildRedisACLCommand("user", "pass", "prod:*", "read-only")
	if cmd[0] != "ACL" || cmd[1] != "SETUSER" || cmd[2] != "user" {
		t.Errorf("unexpected command prefix: %v", cmd)
	}
	foundRead := false
	foundNoWrite := false
	for _, c := range cmd {
		if c == "+@read" {
			foundRead = true
		}
		if c == "-@write" {
			foundNoWrite = true
		}
	}
	if !foundRead {
		t.Error("read-only scope should include +@read")
	}
	if !foundNoWrite {
		t.Error("read-only scope should include -@write")
	}
}

func TestBuildRedisACLCommand_ReadWrite(t *testing.T) {
	cmd := buildRedisACLCommand("user", "pass", "*", "read-write")
	foundWrite := false
	for _, c := range cmd {
		if c == "+@write" {
			foundWrite = true
		}
	}
	if !foundWrite {
		t.Error("read-write scope should include +@write")
	}
}
