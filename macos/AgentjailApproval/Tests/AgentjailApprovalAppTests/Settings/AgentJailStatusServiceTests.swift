import Foundation
import Testing
@testable import AgentjailApprovalApp

struct AgentJailStatusServiceTests {
    @Test func decodesVersionedCLIProjection() async throws {
        let service = BundledAgentJailStatusService(runner: StatusRunner(data: Self.validJSON))

        let snapshot = try await service.status()

        #expect(snapshot.protocolVersion == 1)
        #expect(snapshot.infrastructure.cliInstalled)
        #expect(snapshot.policies.activeRules == 12)
        #expect(snapshot.agents.map(\.id) == ["claude-code", "cursor", "codex"])
        #expect(snapshot.agents.allSatisfy { $0.hookInstalled })
    }

    @Test func rejectsUnsupportedProtocol() async {
        let data = Self.validJSON.replacingOccurrences(of: "\"protocol_version\": 1", with: "\"protocol_version\": 2")
        let service = BundledAgentJailStatusService(runner: StatusRunner(data: data))

        await #expect(throws: AgentJailStatusError.unsupportedProtocol) {
            _ = try await service.status()
        }
    }

    @Test func rejectsMalformedProjection() async {
        let service = BundledAgentJailStatusService(runner: StatusRunner(data: "{}"))

        await #expect(throws: AgentJailStatusError.malformedReply) {
            _ = try await service.status()
        }
    }

    private static let validJSON = """
    {
      "protocol_version": 1,
      "version": "1.6.0",
      "infrastructure": {
        "cli_installed": true,
        "hook_binary_installed": true,
        "daemon_binary_installed": true,
        "service_definition_present": true,
        "daemon_running": true
      },
      "policies": { "configured": true, "readable": true, "active_rules": 12 },
      "agents": [
        { "id": "claude-code", "display_name": "Claude Code", "detected": true, "hook_installed": true },
        { "id": "cursor", "display_name": "Cursor", "detected": true, "hook_installed": true },
        { "id": "codex", "display_name": "Codex", "detected": true, "hook_installed": true }
      ]
    }
    """
}

private struct StatusRunner: AgentJailStatusCommandRunning {
    let data: Data

    init(data: String) {
        self.data = Data(data.utf8)
    }

    func statusJSON() async throws -> Data { data }
}
