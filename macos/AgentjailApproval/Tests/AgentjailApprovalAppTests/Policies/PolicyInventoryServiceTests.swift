import Foundation
import Testing
@testable import AgentjailApprovalApp

struct PolicyInventoryServiceTests {
    @Test func decodesActivePolicyProjectionAndSource() async throws {
        let service = BundledPolicyInventoryService(runner: PolicyRunner(data: Self.validJSON))

        let snapshot = try await service.inventory()

        #expect(snapshot.protocolVersion == 1)
        #expect(snapshot.historyAvailable)
        #expect(snapshot.policies.count == 1)
        #expect(snapshot.policies[0].matchedCount == 7)
        #expect(snapshot.policies[0].evaluations[0].sessionFolder == "…/agentjail")
        #expect(snapshot.rego(for: snapshot.policies[0]) == "package agentjail\n")
    }

    @Test func rejectsPolicyWhoseSourceIsMissing() async {
        let invalid = Self.validJSON.replacingOccurrences(
            of: "\"source_file\": \"command_policy.rego\"",
            with: "\"source_file\": \"missing.rego\""
        )
        let service = BundledPolicyInventoryService(runner: PolicyRunner(data: invalid))

        await #expect(throws: PolicyInventoryError.invalidProjection) {
            _ = try await service.inventory()
        }
    }

    @Test func rejectsUnsupportedProtocol() async {
        let data = Self.validJSON.replacingOccurrences(of: "\"protocol_version\": 1", with: "\"protocol_version\": 2")
        let service = BundledPolicyInventoryService(runner: PolicyRunner(data: data))

        await #expect(throws: PolicyInventoryError.unsupportedProtocol) {
            _ = try await service.inventory()
        }
    }

    private static let validJSON = """
    {
      "protocol_version": 1,
      "history_available": true,
      "breakdown_limited": false,
      "sources": [
        { "filename": "command_policy.rego", "rego": "package agentjail\\n" }
      ],
      "policies": [
        {
          "id": "command_policy/no-sudo",
          "name": "No Sudo",
          "description": "Block sudo invocations",
          "source": "core",
          "source_file": "command_policy.rego",
          "locked": false,
          "matched_count": 7,
          "agent_count": 1,
          "session_count": 1,
          "breakdown_limited": false,
          "examples": [
            { "action": "deny", "reason": "No privilege escalation", "impact": "Would escalate to root" }
          ],
          "evaluations": [
            { "agent": "codex", "session_id": "session-123", "session_folder": "…/agentjail", "matched_count": 7 }
          ]
        }
      ]
    }
    """
}

private struct PolicyRunner: PolicyInventoryCommandRunning {
    let data: Data

    init(data: String) {
        self.data = Data(data.utf8)
    }

    func policyInventoryJSON() async throws -> Data { data }
}
