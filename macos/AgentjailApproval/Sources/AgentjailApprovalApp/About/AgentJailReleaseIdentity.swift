import Foundation

struct AgentJailReleaseIdentity: Equatable, Sendable {
    let version: String?
    let build: String?

    static var current: AgentJailReleaseIdentity {
        AgentJailReleaseIdentity(
            version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
            build: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        )
    }

    var displayText: String {
        ["AgentJail", version, build].compactMap { $0 }.joined(separator: " · ")
    }

    var versionLabel: String {
        version.map { "v\($0)" } ?? "release"
    }

    var releaseURL: URL? {
        guard let version, isSemanticVersion(version) else { return nil }
        return URL(string: "https://github.com/LuD1161/agentjail/releases/tag/v\(version)")
    }

    private func isSemanticVersion(_ value: String) -> Bool {
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        return components.count == 3 && components.allSatisfy { component in
            !component.isEmpty && component.allSatisfy(\.isNumber)
        }
    }
}
