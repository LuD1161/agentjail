import XCTest
@testable import AgentjailApprovalApp

@MainActor
final class ScaffoldTests: XCTestCase {
    func testProductionAppEntryIsAvailable() {
        _ = AgentJailApp()
    }

    func testTunnelCommandSurfaceIsExplicit() {
        let executable = "/Applications/AgentJail.app/Contents/MacOS/AgentJail"
        for command in ["install-extension", "start", "stop", "run", "wipe"] {
            XCTAssertTrue(AgentJailTunnelCommand.handles(arguments: [executable, command]))
        }
        XCTAssertFalse(AgentJailTunnelCommand.handles(arguments: [executable]))
        XCTAssertFalse(AgentJailTunnelCommand.handles(arguments: [executable, "install"]))
        XCTAssertFalse(AgentJailTunnelCommand.handles(arguments: [executable, "arbitrary-command"]))
    }
}
