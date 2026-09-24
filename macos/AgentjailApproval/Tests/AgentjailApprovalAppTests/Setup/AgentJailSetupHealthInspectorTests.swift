import Foundation
import Testing
@testable import AgentjailApprovalApp

struct AgentJailSetupHealthInspectorTests {
    @Test(arguments: ["matching", "newer"])
    func adoptsHealthyCanonicalCLIWithoutNetwork(_ state: String) throws {
        let installation = try snapshot(state: state)
        let health = setupHealthForInstallation(appInApplications: true, installation: installation, reviewAvailable: true, tunnelProfile: .absent)
        #expect(health.localComponentsReady)
        #expect(health.isReady == false)
        #expect(health.canInstallComponents == (state == "matching"))
    }

    @Test(arguments: ["older", "different", "unknown"])
    func doesNotCallMismatchedPayloadCurrent(_ state: String) throws {
        let health = setupHealthForInstallation(appInApplications: true, installation: try snapshot(state: state), reviewAvailable: true, tunnelProfile: .absent)
        #expect(health.localComponentsReady == false)
        #expect(health.localComponentsNeedUpdate)
        #expect(health.canInstallComponents == (state != "unknown"))
    }

    @Test func matchingFilesDoNotAttestAnOldRunningDaemon() throws {
        let health = setupHealthForInstallation(appInApplications: true, installation: try snapshot(daemonMatches: false), reviewAvailable: true, tunnelProfile: .absent)
        #expect(health.cliInstalled)
        #expect(health.daemonReachable == false)
        #expect(health.localComponentsReady == false)
    }

    @Test func absentProjectionCannotAuthorizeAutomaticInstall() {
        let health = setupHealthForInstallation(appInApplications: true, installation: nil, reviewAvailable: false, tunnelProfile: .absent)
        #expect(health.canInstallComponents == false)
        #expect(health.localComponentsReady == false)
    }

    @Test func projectsExplicitUninstallIndependentlyOfDaemonFailure() throws {
        let health = setupHealthForInstallation(appInApplications: true, installation: try snapshot(state: "missing", explicitlyUninstalled: true), reviewAvailable: false, tunnelProfile: .absent)
        #expect(health.explicitlyUninstalled)
        #expect(health.canInstallComponents)
        #expect(health.cliPresent == false)
    }

    @Test(arguments: ["matching", "newer"])
    func missingSetupPrerequisitesRequireRepair(_ state: String) throws {
        for missing in ["policy", "rules"] {
            let installation = try snapshot(state: state, policyReady: missing != "policy", coreRulesReady: missing != "rules")
            let health = setupHealthForInstallation(appInApplications: true, installation: installation, reviewAvailable: true, tunnelProfile: .absent)
            #expect(health.localComponentsReady == false)
            #expect(health.canInstallComponents == (state == "matching"))
            #expect(health.canRepairInstalledComponents == (state == "newer"))
        }
    }

    @Test func unsupportedNewerCLIIsNeitherAdoptedNorGivenAFutileRepair() throws {
        let installation = try snapshot(state: "newer", installedStatusSupported: false)
        let health = setupHealthForInstallation(appInApplications: true, installation: installation, reviewAvailable: true, tunnelProfile: .absent)
        #expect(health.localComponentsReady == false)
        #expect(health.canInstallComponents == false)
        #expect(health.canRepairInstalledComponents == false)
    }

    @Test func futureInstallationContractDoesNotAuthorizeSetup() throws {
        let installation = try snapshot(protocolVersion: 2)
        #expect(installation.componentsCompatible == false)
        #expect(installation.canInstallBundledComponents == false)
        #expect(installation.canRepairInstalledComponents == false)
    }

    private func snapshot(state: String = "matching", daemonMatches: Bool = true, explicitlyUninstalled: Bool = false, policyReady: Bool = true, coreRulesReady: Bool = true, installedStatusSupported: Bool = true, protocolVersion: UInt32 = 1) throws -> AgentJailInstallationSnapshot {
        try JSONDecoder().decode(AgentJailInstallationSnapshot.self, from: Data("""
        {"protocol_version":\(protocolVersion),"payload_state":"\(state)","candidate_version":"v1.8.2","installed_version":"v1.8.2","daemon_version":"v1.8.2",
        "cli_present":\(state != "missing"),"cli_payload_matches":\(state == "matching"),"hook_payload_matches":\(state == "matching"),
        "policy_ready":\(policyReady),"core_rules_ready":\(coreRulesReady),"installed_status_supported":\(installedStatusSupported),
        "roles_ready":true,"service_ready":true,"daemon_matches_install":\(daemonMatches),"explicitly_uninstalled":\(explicitlyUninstalled)}
        """.utf8))
    }
}
