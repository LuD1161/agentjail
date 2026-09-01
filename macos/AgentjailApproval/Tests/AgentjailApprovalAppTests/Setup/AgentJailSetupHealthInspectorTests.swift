import Foundation
import XCTest
@testable import AgentjailApprovalApp

final class AgentJailSetupHealthInspectorTests: XCTestCase {
    func testInstalledExecutableAvailabilityDoesNotDependOnBuildBytes() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentjail-health-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let installed = root.appendingPathComponent("installed")

        XCTAssertFalse(installedExecutableIsAvailable(at: installed, fileManager: .default))

        try Data("old".utf8).write(to: installed)
        XCTAssertFalse(installedExecutableIsAvailable(at: installed, fileManager: .default))

        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installed.path)
        XCTAssertTrue(installedExecutableIsAvailable(at: installed, fileManager: .default))
    }
}
