import Foundation
import XCTest
@testable import AgentjailApprovalApp

final class AgentJailSetupHealthInspectorTests: XCTestCase {
    func testInstalledExecutableMustMatchBundledBuild() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentjail-health-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let installed = root.appendingPathComponent("installed")
        let bundled = root.appendingPathComponent("bundled")
        try Data("current".utf8).write(to: bundled)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bundled.path)

        XCTAssertFalse(installedExecutableMatchesBundled(installedURL: installed, bundledURL: bundled, fileManager: .default))

        try Data("old".utf8).write(to: installed)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installed.path)
        XCTAssertFalse(installedExecutableMatchesBundled(installedURL: installed, bundledURL: bundled, fileManager: .default))

        try Data("current".utf8).write(to: installed)
        XCTAssertTrue(installedExecutableMatchesBundled(installedURL: installed, bundledURL: bundled, fileManager: .default))
    }
}
