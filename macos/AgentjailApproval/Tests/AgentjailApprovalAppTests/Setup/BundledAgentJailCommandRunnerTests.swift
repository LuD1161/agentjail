import Foundation
import Testing
@testable import AgentjailApprovalApp

struct BundledAgentJailCommandRunnerTests {
    @Test func repairUsesCanonicalCLIWhileFreshSetupUsesBundledCLI() throws {
        let bundled = URL(fileURLWithPath: "/fixture/AgentJail.app/Contents/Resources/bin/agentjail")
        let installed = URL(fileURLWithPath: "/fixture/home/.agentjail/bin/agentjail")
        let runner = BundledAgentJailCommandRunner(cliURL: bundled, appExecutableURL: nil, installedCLIURL: installed)
        let fresh = try #require(runner.invocation(for: .installComponents))
        let repair = try #require(runner.invocation(for: .repairInstalledComponents))
        #expect(fresh.executableURL == bundled)
        #expect(repair.executableURL == installed)
        #expect(fresh.arguments == ["--no-color", "install", "--all", "--yes", "--with-cli-path"])
        #expect(repair.arguments == fresh.arguments)
        #expect(!fresh.arguments.contains("--with-path-shim"))
    }
}
