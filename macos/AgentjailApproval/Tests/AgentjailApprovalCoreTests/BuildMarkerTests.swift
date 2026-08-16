import XCTest
@testable import AgentjailApprovalCore

final class BuildMarkerTests: XCTestCase {
    func testVersionMatchesLocalMVP() {
        XCTAssertEqual(BuildMarker.version, "0.1.0")
    }
}
