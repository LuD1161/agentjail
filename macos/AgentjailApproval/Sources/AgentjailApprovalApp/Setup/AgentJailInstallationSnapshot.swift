import Foundation

struct AgentJailInstallationSnapshot: Decodable, Equatable, Sendable {
    enum PayloadState: String, Decodable, Sendable {
        case missing, matching, older, newer, different, unknown
    }

    let protocolVersion: UInt32
    let payloadState: PayloadState
    let candidateVersion: String
    let installedVersion: String?
    let daemonVersion: String?
    let cliPresent: Bool
    let cliPayloadMatches: Bool
    let hookPayloadMatches: Bool
    let rolesReady: Bool
    let serviceReady: Bool
    let policyReady: Bool
    let coreRulesReady: Bool
    let installedStatusSupported: Bool
    let daemonMatchesInstall: Bool
    let explicitlyUninstalled: Bool

    var componentsCompatible: Bool {
        protocolVersion == 1 && installedStatusSupported &&
            (payloadState == .matching || payloadState == .newer) &&
            rolesReady && serviceReady && policyReady && coreRulesReady
    }

    var canInstallBundledComponents: Bool {
        guard protocolVersion == 1 else { return false }
        switch payloadState {
        case .missing, .matching, .older, .different: return true
        case .newer, .unknown: return false
        }
    }

    var canRepairInstalledComponents: Bool {
        protocolVersion == 1 && payloadState == .newer && installedStatusSupported
    }

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case payloadState = "payload_state"
        case candidateVersion = "candidate_version"
        case installedVersion = "installed_version"
        case daemonVersion = "daemon_version"
        case cliPresent = "cli_present"
        case cliPayloadMatches = "cli_payload_matches"
        case hookPayloadMatches = "hook_payload_matches"
        case rolesReady = "roles_ready"
        case serviceReady = "service_ready"
        case policyReady = "policy_ready"
        case coreRulesReady = "core_rules_ready"
        case installedStatusSupported = "installed_status_supported"
        case daemonMatchesInstall = "daemon_matches_install"
        case explicitlyUninstalled = "explicitly_uninstalled"
    }
}
