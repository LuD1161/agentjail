import Foundation
import XCTest
@testable import AgentjailApprovalCore

final class MCPInventoryTests: XCTestCase {
    func testClaudeAdapterNormalizesLocalAndRemoteServersWithoutExposingSecrets() throws {
        let secret = "sk-super-secret-value"
        let data = try XCTUnwrap("""
        {
          "mcpServers": {
            "filesystem": {
              "command": "/opt/homebrew/bin/npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "--token", "\(secret)"],
              "env": {"API_KEY": "\(secret)"}
            },
            "private-api": {
              "type": "http",
              "url": "https://user:\(secret)@Example.COM/private/\(secret)?api_key=\(secret)",
              "headers": {"Authorization": "Bearer \(secret)"}
            }
          }
        }
        """.data(using: .utf8))

        let items = ClaudeMCPConfigAdapter().parse(data)

        XCTAssertEqual(items.count, 2)
        let filesystem = try XCTUnwrap(items.first { $0.name == "filesystem" })
        XCTAssertEqual(filesystem.sourceClient, .claudeCode)
        XCTAssertEqual(filesystem.adapterVersion, "claude-code-json-v1")
        XCTAssertEqual(filesystem.kind, .local)
        XCTAssertEqual(filesystem.target, "npx • 4 arguments hidden")
        XCTAssertEqual(filesystem.status, .configured)
        let remote = try XCTUnwrap(items.first { $0.name == "private-api" })
        XCTAssertEqual(remote.kind, .remote)
        XCTAssertEqual(remote.target, "https://example.com")
        XCTAssertFalse(publicText(items).contains(secret))
    }

    func testCursorAdapterReportsMalformedAndUnknownEntriesWithoutDroppingValidOnes() throws {
        let data = try XCTUnwrap("""
        {
          "mcpServers": {
            "valid": {"command": "uvx", "args": ["safe-package"]},
            "wrong-shape": "npx server",
            "unknown": {"type": "websocket", "url": "https://example.invalid/mcp"},
            "missing": {"env": {"TOKEN": "must-not-escape"}}
          }
        }
        """.data(using: .utf8))

        let items = CursorMCPConfigAdapter().parse(data)

        XCTAssertEqual(items.count, 4)
        XCTAssertEqual(items.first { $0.name == "valid" }?.status, .configured)
        XCTAssertEqual(items.first { $0.name == "wrong-shape" }?.status, .issue("This server entry must be an object."))
        XCTAssertEqual(items.first { $0.name == "unknown" }?.status, .issue("The server transport is unknown."))
        XCTAssertEqual(items.first { $0.name == "missing" }?.status, .issue("The server is missing a command or URL."))
        XCTAssertFalse(publicText(items).contains("must-not-escape"))
    }

    func testJSONAdapterRejectsMalformedKnownFieldTypesWithoutLeakingValues() throws {
        let secret = "sk-field-secret"
        let data = try XCTUnwrap("""
        {
          "mcpServers": {
            "bad-args": {"command": "npx", "args": ["safe", {"token": "\(secret)"}]},
            "bad-env": {"command": "uvx", "env": "\(secret)"},
            "bad-enabled": {"command": "node", "enabled": "\(secret)"}
          }
        }
        """.data(using: .utf8))

        let items = CursorMCPConfigAdapter().parse(data)

        XCTAssertEqual(items.first { $0.name == "bad-args" }?.status, .issue("The server arguments must be an array of strings."))
        XCTAssertEqual(items.first { $0.name == "bad-env" }?.status, .issue("The server environment must be an object."))
        XCTAssertEqual(items.first { $0.name == "bad-enabled" }?.status, .issue("The enabled value must be true or false."))
        XCTAssertFalse(publicText(items).contains(secret))
    }

    func testJSONAdaptersReportMalformedDocumentsAsNonfatalSourceIssues() throws {
        let malformed = try XCTUnwrap("{not-json".data(using: .utf8))

        for items in [ClaudeMCPConfigAdapter().parse(malformed), CursorMCPConfigAdapter().parse(malformed)] {
            XCTAssertEqual(items.count, 1)
            XCTAssertEqual(items[0].name, "Configuration issue")
            XCTAssertEqual(items[0].kind, .unknown)
            XCTAssertEqual(items[0].status, .issue("The configuration is malformed JSON."))
        }
    }

    func testCodexAdapterParsesCurrentStdioHTTPAndDisabledShapes() throws {
        let data = try XCTUnwrap("""
        [mcp_servers.filesystem]
        command = "/usr/local/bin/npx"
        args = ["-y", "@modelcontextprotocol/server-filesystem"]

        [mcp_servers."Remote API"]
        url = "https://Example.COM:443/mcp?token=must-not-escape"
        bearer_token_env_var = "PRIVATE_TOKEN"
        enabled = false

        [mcp_servers.filesystem.env]
        API_KEY = "must-not-escape"
        """.data(using: .utf8))

        let items = CodexMCPConfigAdapter().parse(data)

        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(items.first { $0.name == "filesystem" }?.kind, .local)
        XCTAssertEqual(items.first { $0.name == "filesystem" }?.target, "npx")
        XCTAssertEqual(items.first { $0.name == "filesystem" }?.status, .configured)
        XCTAssertEqual(items.first { $0.name == "Remote API" }?.kind, .remote)
        XCTAssertEqual(items.first { $0.name == "Remote API" }?.target, "https://example.com")
        XCTAssertEqual(items.first { $0.name == "Remote API" }?.status, .disabled)
        XCTAssertFalse(publicText(items).contains("must-not-escape"))
    }

    func testCodexAdapterKeepsMalformedServersVisibleAndContinuesParsing() throws {
        let data = try XCTUnwrap("""
        [mcp_servers.broken]
        command = 42

        [mcp_servers.valid]
        url = "https://valid.example/mcp"

        [mcp_servers.unknown
        command = "must-not-run"
        """.data(using: .utf8))

        let items = CodexMCPConfigAdapter().parse(data)

        XCTAssertEqual(items.count, 3)
        XCTAssertEqual(items.first { $0.name == "broken" }?.status, .issue("The local command is malformed."))
        XCTAssertEqual(items.first { $0.name == "valid" }?.status, .configured)
        XCTAssertTrue(items.contains { $0.name == "Configuration issue" })
    }

    func testDiscoveryReadsOnlyDocumentedGlobalConfigsAndMarksCrossClientDuplicates() throws {
        let home = "/Users/fixture"
        let reader = FixtureMCPConfigReader(files: [
            "\(home)/.claude.json": .data(try jsonData(name: "shared", command: "npx")),
            "\(home)/.codex/config.toml": .data(try XCTUnwrap("""
            [mcp_servers.shared]
            command = "uvx"
            """.data(using: .utf8))),
            "\(home)/.cursor/mcp.json": .data(try jsonData(name: "cursor-only", command: "node")),
        ])

        let snapshot = MCPInventoryDiscovery(reader: reader).discover(homeDirectory: home)

        XCTAssertEqual(Set(reader.requestedPaths), Set([
            "\(home)/.claude.json",
            "\(home)/.codex/config.toml",
            "\(home)/.cursor/mcp.json",
        ]))
        XCTAssertEqual(snapshot.items.count, 3)
        XCTAssertEqual(snapshot.items.filter { $0.name == "shared" }.map(\.duplicateCount), [2, 2])
        XCTAssertEqual(snapshot.duplicateCount, 1)
        XCTAssertEqual(snapshot.configuredCount, 3)
        XCTAssertEqual(snapshot.issueCount, 0)
    }

    func testUnreadableConfigIsHonestAndMissingConfigIsQuiet() {
        let home = "/Users/fixture"
        let reader = FixtureMCPConfigReader(files: [
            "\(home)/.claude.json": .unreadable,
            "\(home)/.codex/config.toml": .missing,
            "\(home)/.cursor/mcp.json": .missing,
        ])

        let snapshot = MCPInventoryDiscovery(reader: reader).discover(homeDirectory: home)

        XCTAssertEqual(snapshot.items.count, 1)
        XCTAssertEqual(snapshot.issueCount, 1)
        XCTAssertEqual(snapshot.items[0].sourceClient, .claudeCode)
        XCTAssertEqual(snapshot.items[0].status, .issue("AgentJail could not safely read this configuration file."))
    }

    func testSystemReaderBoundsInputAndNeverTreatsDirectoriesAsConfig() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let oversized = root.appendingPathComponent("oversized.json")
        try Data(repeating: 0x61, count: SystemMCPConfigFileReader.maximumBytes + 1).write(to: oversized)

        let reader = SystemMCPConfigFileReader()

        XCTAssertEqual(reader.readFile(at: root.path), .unreadable)
        XCTAssertEqual(reader.readFile(at: oversized.path), .unreadable)
        XCTAssertEqual(reader.readFile(at: root.appendingPathComponent("missing").path), .missing)
    }

    func testSecretLookingServerAndCommandNamesAreRedacted() throws {
        let secret = "github_pat_abcdefghijklmnopqrstuvwxyz"
        let data = try XCTUnwrap("""
        {"mcpServers":{"\(secret)":{"command":"\(secret)","args":[]}}}
        """.data(using: .utf8))

        let items = ClaudeMCPConfigAdapter().parse(data)

        XCTAssertEqual(items[0].name, "[redacted server name]")
        XCTAssertEqual(items[0].target, "[redacted command]")
        XCTAssertFalse(publicText(items).contains(secret))
    }

    func testRedactedNamesAreNotCollapsedIntoFalseDuplicates() throws {
        let home = "/Users/fixture"
        let reader = FixtureMCPConfigReader(files: [
            "\(home)/.claude.json": .data(try jsonData(name: "token-alpha", command: "npx")),
            "\(home)/.cursor/mcp.json": .data(try jsonData(name: "secret-beta", command: "node")),
        ])

        let snapshot = MCPInventoryDiscovery(reader: reader).discover(homeDirectory: home)

        XCTAssertEqual(snapshot.items.map(\.name), ["[redacted server name]", "[redacted server name]"])
        XCTAssertEqual(snapshot.items.map(\.duplicateCount), [1, 1])
        XCTAssertEqual(snapshot.duplicateCount, 0)
    }

    func testDisplayTextRemovesControlsAndBidirectionalOverrides() throws {
        let data = try XCTUnwrap("""
        {"mcpServers":{"safe\\u202Ename":{"command":"node\\u001b","args":[]}}}
        """.data(using: .utf8))

        let item = try XCTUnwrap(ClaudeMCPConfigAdapter().parse(data).first)

        XCTAssertEqual(item.name, "safename")
        XCTAssertEqual(item.target, "node")
    }

    private func jsonData(name: String, command: String) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "mcpServers": [name: ["command": command]],
        ])
    }

    private func publicText(_ items: [MCPInventoryItem]) -> String {
        items.map { item in
            [
                item.id,
                item.name,
                item.sourceClient.displayName,
                item.sourceLabel,
                item.adapterVersion,
                item.kind.displayName,
                item.target,
                item.status.displayName,
                item.status.detail ?? "",
            ].joined(separator: " ")
        }.joined(separator: " ")
    }
}

private final class FixtureMCPConfigReader: MCPConfigFileReading {
    private let files: [String: MCPConfigFileReadResult]
    private(set) var requestedPaths: [String] = []

    init(files: [String: MCPConfigFileReadResult]) {
        self.files = files
    }

    func readFile(at path: String) -> MCPConfigFileReadResult {
        requestedPaths.append(path)
        return files[path] ?? .missing
    }
}
