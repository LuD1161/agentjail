package grantctl

import "testing"

func TestActivitySnapshotValidationBoundsAndRequiresSelectedSession(t *testing.T) {
	network := NetworkSnapshotV1{
		ProtocolVersion: NetworkProtocolVersion,
		Events:          []NetworkEventV1{{ID: 1, TimestampUnixMs: 1, Host: "api.example.com"}},
	}
	if err := validateNetworkSnapshotV1(network); err != nil {
		t.Fatal(err)
	}
	network.Events[0].Path = string(make([]byte, MaxActivityTextBytes+1))
	if err := validateNetworkSnapshotV1(network); err == nil {
		t.Fatal("oversized network text accepted")
	}

	logs := SessionLogSnapshotV1{
		ProtocolVersion:   SessionLogProtocolVersion,
		SelectedSessionID: "session-1",
		Sessions:          []ActivitySessionV1{{SessionID: "session-1", Agent: "codex", Project: "repo"}},
		Entries:           []SessionActionV1{{ID: 1, TimestampUnixMs: 1, ToolName: "Bash", Action: "allow"}},
	}
	if err := validateSessionLogSnapshotV1(logs); err != nil {
		t.Fatal(err)
	}
	logs.SelectedSessionID = "missing"
	if err := validateSessionLogSnapshotV1(logs); err == nil {
		t.Fatal("unknown selected session accepted")
	}
}
