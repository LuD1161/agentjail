import Foundation
import Testing
@testable import AgentjailApprovalApp

struct AgentJailReleaseIdentityTests {
    @Test func linksSemanticAppVersionToItsExactGitHubRelease() {
        let identity = AgentJailReleaseIdentity(version: "1.6.0", build: "1264")

        #expect(identity.displayText == "AgentJail · 1.6.0 · 1264")
        #expect(identity.versionLabel == "v1.6.0")
        #expect(identity.releaseURL?.absoluteString == "https://github.com/LuD1161/agentjail/releases/tag/v1.6.0")
    }

    @Test func doesNotCreateAReleaseLinkForAnUnversionedDevelopmentBuild() {
        #expect(AgentJailReleaseIdentity(version: nil, build: "1264").releaseURL == nil)
        #expect(AgentJailReleaseIdentity(version: "development", build: "1264").releaseURL == nil)
    }

    @Test func aboutLinksUseCanonicalProjectAndAuthorDestinations() {
        #expect(AgentJailAboutLinks.source.absoluteString == "https://github.com/LuD1161/agentjail")
        #expect(AgentJailAboutLinks.feedback.absoluteString == "https://github.com/LuD1161/agentjail/issues/new")
        #expect(AgentJailAboutLinks.authorX.absoluteString == "https://x.com/AseemShrey")
    }
}
