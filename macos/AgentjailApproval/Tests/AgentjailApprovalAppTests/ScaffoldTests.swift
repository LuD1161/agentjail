import XCTest
@testable import AgentjailApprovalApp

@MainActor
final class ScaffoldTests: XCTestCase {
    func testProductionAppEntryIsAvailable() {
        _ = AgentjailApprovalApp()
    }
}
