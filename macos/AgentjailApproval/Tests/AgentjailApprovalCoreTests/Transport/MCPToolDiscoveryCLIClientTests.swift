import AgentjailApprovalCore
import Foundation
import Testing

@Suite("MCP tool discovery CLI client")
struct MCPToolDiscoveryCLIClientTests {
    @Test("decodes the CLI versioned JSON projection")
    func decodesProjection() async throws {
        let runner = StubMCPToolDiscoveryCommandRunner(data: Data(#"{"protocol_version":1,"servers":[{"server":"linear","status":"connected","tools":["get_issue"]}]}"#.utf8))
        let result = try await MCPToolDiscoveryCLIClient(runner: runner).discoverTools()
        #expect(result.protocolVersion == 1)
        #expect(result.servers.first?.server == "linear")
        #expect(result.servers.first?.tools == ["get_issue"])
    }

    @Test("rejects malformed CLI output")
    func rejectsMalformedOutput() async {
        let runner = StubMCPToolDiscoveryCommandRunner(data: Data(#"{"protocol_version":1,"servers":[{"server":"linear","status":"new-secret-status","tools":[]}]}"#.utf8))
        await #expect(throws: ApprovalControlError.self) {
            _ = try await MCPToolDiscoveryCLIClient(runner: runner).discoverTools()
        }
    }
}

private struct StubMCPToolDiscoveryCommandRunner: MCPToolDiscoveryCommandRunning {
    let data: Data

    func discoverToolsJSON() async throws -> Data { data }
}
