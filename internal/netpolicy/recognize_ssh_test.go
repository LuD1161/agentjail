package netpolicy

import (
	"strings"
	"testing"
)

func TestParseSSHVersion(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		host              string
		wantNil           bool
		wantVerb          string
		wantHost          string
		wantProtoVer      string
		wantVersion       string // full software version string (e.g. "OpenSSH_9.6")
		wantSoftware      string // software name (e.g. "OpenSSH")
		wantSoftwareVer   string // software version number (e.g. "9.6")
		wantOSComment     string // optional OS comment (empty if absent)
	}{
		{
			name:            "OpenSSH 2.0 with CRLF",
			input:           "SSH-2.0-OpenSSH_9.6\r\n",
			host:            "bastion.example.com:22",
			wantVerb:        "connect",
			wantHost:        "bastion.example.com:22",
			wantProtoVer:    "2.0",
			wantVersion:     "OpenSSH_9.6",
			wantSoftware:    "OpenSSH",
			wantSoftwareVer: "9.6",
		},
		{
			name:            "OpenSSH 2.0 with LF only",
			input:           "SSH-2.0-OpenSSH_9.6\n",
			host:            "dev-box:22",
			wantVerb:        "connect",
			wantHost:        "dev-box:22",
			wantProtoVer:    "2.0",
			wantVersion:     "OpenSSH_9.6",
			wantSoftware:    "OpenSSH",
			wantSoftwareVer: "9.6",
		},
		{
			name:            "OpenSSH 2.0 without newline (partial read)",
			input:           "SSH-2.0-OpenSSH_9.6",
			host:            "server:22",
			wantVerb:        "connect",
			wantHost:        "server:22",
			wantProtoVer:    "2.0",
			wantVersion:     "OpenSSH_9.6",
			wantSoftware:    "OpenSSH",
			wantSoftwareVer: "9.6",
		},
		{
			name:            "SSH 1.99 compatibility version",
			input:           "SSH-1.99-OpenSSH_3.9p1\r\n",
			host:            "legacy.internal:22",
			wantVerb:        "connect",
			wantHost:        "legacy.internal:22",
			wantProtoVer:    "1.99",
			wantVersion:     "OpenSSH_3.9p1",
			wantSoftware:    "OpenSSH",
			wantSoftwareVer: "3.9p1",
		},
		{
			name:            "SSH 1.5 legacy version (no underscore in software)",
			input:           "SSH-1.5-1.2.27\r\n",
			host:            "ancient.host:22",
			wantVerb:        "connect",
			wantHost:        "ancient.host:22",
			wantProtoVer:    "1.5",
			wantVersion:     "1.2.27",
			wantSoftware:    "",    // no underscore separator → name unknown
			wantSoftwareVer: "1.2.27",
		},
		{
			name:            "version with OS comment",
			input:           "SSH-2.0-libssh_0.10.6 Linux\r\n",
			host:            "host:22",
			wantVerb:        "connect",
			wantHost:        "host:22",
			wantProtoVer:    "2.0",
			wantVersion:     "libssh_0.10.6",
			wantSoftware:    "libssh",
			wantSoftwareVer: "0.10.6",
			wantOSComment:   "Linux",
		},
		{
			name:            "OpenSSH with Ubuntu distro comment",
			input:           "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
			host:            "ubuntu-box:22",
			wantVerb:        "connect",
			wantHost:        "ubuntu-box:22",
			wantProtoVer:    "2.0",
			wantVersion:     "OpenSSH_8.9p1",
			wantSoftware:    "OpenSSH",
			wantSoftwareVer: "8.9p1",
			wantOSComment:   "Ubuntu-3ubuntu0.10",
		},
		{
			name:            "Dropbear server",
			input:           "SSH-2.0-dropbear_2022.83\r\n",
			host:            "router.local:22",
			wantVerb:        "connect",
			wantHost:        "router.local:22",
			wantProtoVer:    "2.0",
			wantVersion:     "dropbear_2022.83",
			wantSoftware:    "dropbear",
			wantSoftwareVer: "2022.83",
		},
		{
			name:            "libssh2 with numeric suffix in name",
			input:           "SSH-2.0-libssh2_1.11.0\r\n",
			host:            "host:22",
			wantVerb:        "connect",
			wantHost:        "host:22",
			wantProtoVer:    "2.0",
			wantVersion:     "libssh2_1.11.0",
			wantSoftware:    "libssh2",
			wantSoftwareVer: "1.11.0",
		},
		{
			name:    "empty input",
			input:   "",
			host:    "host:22",
			wantNil: true,
		},
		{
			name:    "too short",
			input:   "SSH",
			host:    "host:22",
			wantNil: true,
		},
		{
			name:    "not SSH prefix",
			input:   "HTTP/1.1 200 OK\r\n",
			host:    "host:80",
			wantNil: true,
		},
		{
			name:    "SSH prefix but malformed (no second dash)",
			input:   "SSH-2.0\r\n",
			host:    "host:22",
			wantNil: true,
		},
		{
			name:    "SSH prefix but empty software version",
			input:   "SSH-2.0-\r\n",
			host:    "host:22",
			wantNil: true,
		},
		{
			name:    "partial read exceeding 255 bytes without newline",
			input:   "SSH-2.0-" + strings.Repeat("x", 250),
			host:    "host:22",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := ParseSSHVersion([]byte(tt.input), tt.host)
			if tt.wantNil {
				if op != nil {
					t.Fatalf("expected nil, got %+v", op)
				}
				return
			}
			if op == nil {
				t.Fatal("expected non-nil Operation, got nil")
			}

			if op.Protocol != "ssh" {
				t.Errorf("Protocol = %q, want %q", op.Protocol, "ssh")
			}
			if op.Service != "ssh" {
				t.Errorf("Service = %q, want %q", op.Service, "ssh")
			}
			if op.Verb != tt.wantVerb {
				t.Errorf("Verb = %q, want %q", op.Verb, tt.wantVerb)
			}
			if op.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", op.Host, tt.wantHost)
			}

			protoVer, _ := op.Payload["proto_version"].(string)
			if protoVer != tt.wantProtoVer {
				t.Errorf("proto_version = %q, want %q", protoVer, tt.wantProtoVer)
			}
			version, _ := op.Payload["version"].(string)
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			software, _ := op.Payload["software"].(string)
			if software != tt.wantSoftware {
				t.Errorf("software = %q, want %q", software, tt.wantSoftware)
			}
			softwareVer, _ := op.Payload["software_version"].(string)
			if softwareVer != tt.wantSoftwareVer {
				t.Errorf("software_version = %q, want %q", softwareVer, tt.wantSoftwareVer)
			}

			osComment, _ := op.Payload["os_comment"].(string)
			if osComment != tt.wantOSComment {
				t.Errorf("os_comment = %q, want %q", osComment, tt.wantOSComment)
			}
		})
	}
}

func TestSplitSSHSoftware(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		version string
	}{
		{"OpenSSH_9.6", "OpenSSH", "9.6"},
		{"OpenSSH_8.9p1", "OpenSSH", "8.9p1"},
		{"OpenSSH_3.9p1", "OpenSSH", "3.9p1"},
		{"dropbear_2022.83", "dropbear", "2022.83"},
		{"libssh_0.10.6", "libssh", "0.10.6"},
		{"libssh2_1.11.0", "libssh2", "1.11.0"},
		{"1.2.27", "", "1.2.27"},           // legacy numeric-only version
		{"putty_0.81", "putty", "0.81"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := splitSSHSoftware(tt.input)
			if name != tt.name {
				t.Errorf("name = %q, want %q", name, tt.name)
			}
			if version != tt.version {
				t.Errorf("version = %q, want %q", version, tt.version)
			}
		})
	}
}
