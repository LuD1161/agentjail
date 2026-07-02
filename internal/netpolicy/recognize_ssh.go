package netpolicy

import (
	"bytes"
	"strings"
)

// SSH protocol recognition.
//
// ENCRYPTION BOUNDARY: SSH is end-to-end encrypted. Unlike HTTPS where a
// MITM CA certificate lets a proxy see plaintext, SSH key exchange happens
// directly between client and server. After the version exchange, all
// traffic is encrypted and we CANNOT inspect command content (exec, shell,
// subsystem, port-forward, etc.).
//
// What we CAN do:
//   - Parse the plaintext SSH version string from the initial handshake
//     (e.g. "SSH-2.0-OpenSSH_9.6").
//   - Extract the destination host:port from the SOCKS5/VIP routing layer
//     (not from SSH itself — the caller supplies it).
//   - Extract the software name and version from the version string
//     (e.g. software="OpenSSH", software_version="9.6").
//   - Extract the optional OS/platform comment if present
//     (e.g. "SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu0.10" → os_comment="Ubuntu-3ubuntu0.10").
//   - Allow or deny SSH connections by host pattern or software version in policy.
//
// What we CANNOT do:
//   - Detect exec commands (e.g. "ssh host ls /etc")
//   - Detect subsystem requests (sftp, rsync)
//   - Detect channel types (shell, direct-tcpip, x11)
//   - Inspect any traffic after the key exchange completes
//
// The Operation produced has verb="connect", protocol="ssh", and the host
// set by the caller. Policy can match on host patterns and software version
// fields, but cannot match on command content, subsystem names, or channel types.

// sshVersionPrefix is the required prefix for SSH version strings (RFC 4253 §4.2).
var sshVersionPrefix = []byte("SSH-")

// ParseSSHVersion parses the SSH version string from the first bytes of a
// new TCP connection on port 22. The version string has the format:
//
//	SSH-protoversion-softwareversion[ SP comment]\r\n
//
// Returns a normalized Operation with verb="connect" and the parsed version
// metadata in Payload, or nil if the data does not look like an SSH version
// exchange.
//
// Payload fields:
//   - proto_version:    SSH protocol version (e.g. "2.0", "1.99")
//   - version:          full software version string (e.g. "OpenSSH_9.6")
//   - software:         software name parsed from version (e.g. "OpenSSH", "dropbear", "libssh")
//   - software_version: software version number (e.g. "9.6", "2022.83", "0.10.6")
//   - os_comment:       optional comment field, typically OS/distro info (e.g. "Ubuntu-3ubuntu0.10")
func ParseSSHVersion(data []byte, host string) *Operation {
	if len(data) < 4 {
		return nil
	}

	// SSH version strings must start with "SSH-".
	if !bytes.HasPrefix(data, sshVersionPrefix) {
		return nil
	}

	// Find the line terminator. SSH version strings end with \r\n, but
	// some implementations use just \n.
	lineEnd := bytes.IndexByte(data, '\n')
	var line string
	if lineEnd < 0 {
		// No newline yet — could be a truncated read. Accept up to 255
		// bytes (RFC 4253 max version string length) as the line.
		if len(data) > 255 {
			return nil
		}
		line = string(data)
	} else {
		line = string(data[:lineEnd])
	}

	// Strip trailing \r if present.
	line = strings.TrimRight(line, "\r")

	// Minimum valid version string: "SSH-2.0-x" (9 chars).
	if len(line) < 8 {
		return nil
	}

	protoVersion, softwareVersion, osComment := parseSSHVersionLine(line)
	if protoVersion == "" {
		return nil
	}

	softwareName, softwareVersionNum := splitSSHSoftware(softwareVersion)

	payload := map[string]any{
		"proto_version":    protoVersion,
		"version":          softwareVersion,
		"software":         softwareName,
		"software_version": softwareVersionNum,
	}
	if osComment != "" {
		payload["os_comment"] = osComment
	}

	return &Operation{
		Protocol: "ssh",
		Service:  "ssh",
		Verb:     "connect",
		Host:     host,
		Payload:  payload,
	}
}

// parseSSHVersionLine splits "SSH-protoversion-softwareversion[ comment]"
// into the protocol version (e.g. "2.0"), software version (e.g.
// "OpenSSH_9.6"), and optional comment (e.g. "Ubuntu-3ubuntu0.10").
// Returns empty strings if the format is invalid.
func parseSSHVersionLine(line string) (protoVersion, softwareVersion, comment string) {
	// Strip the "SSH-" prefix.
	rest := line[4:]

	// Split on the first '-' to get protoversion and the remainder.
	dashIdx := strings.IndexByte(rest, '-')
	if dashIdx < 0 {
		return "", "", ""
	}

	protoVersion = rest[:dashIdx]
	remainder := rest[dashIdx+1:]

	// The software version extends to the first space; anything after
	// the space is the optional comment field (RFC 4253 §4.2).
	if spaceIdx := strings.IndexByte(remainder, ' '); spaceIdx >= 0 {
		softwareVersion = remainder[:spaceIdx]
		comment = strings.TrimSpace(remainder[spaceIdx+1:])
	} else {
		softwareVersion = remainder
	}

	if protoVersion == "" || softwareVersion == "" {
		return "", "", ""
	}

	return protoVersion, softwareVersion, comment
}

// splitSSHSoftware splits an SSH software version string into name and version
// components. SSH clients conventionally use an underscore to separate the
// software name from its version number (e.g. "OpenSSH_9.6", "dropbear_2022.83",
// "libssh_0.10.6"). If no underscore is present (e.g. legacy "1.2.27"), the
// entire string is treated as the version and the name is left empty.
func splitSSHSoftware(softwareVersion string) (name, version string) {
	// Split on the last underscore so names like "libssh2_1.11.0" parse
	// correctly as name="libssh2", version="1.11.0".
	idx := strings.LastIndexByte(softwareVersion, '_')
	if idx < 0 {
		// No underscore — could be a legacy numeric-only version like "1.2.27".
		return "", softwareVersion
	}
	return softwareVersion[:idx], softwareVersion[idx+1:]
}
