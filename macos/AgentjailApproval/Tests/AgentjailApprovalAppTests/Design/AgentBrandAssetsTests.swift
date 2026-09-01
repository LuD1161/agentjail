import SwiftUI
import Testing
@testable import AgentjailApprovalApp

struct AgentBrandAssetsTests {
    @Test func cursorUsesContrastingAssetForEachTheme() {
        #expect(AgentBrandAssets.name(for: "cursor", colorScheme: .light) == "agent-cursor")
        #expect(AgentBrandAssets.name(for: "cursor", colorScheme: .dark) == "agent-cursor-light")
    }

    @Test func knownThemePairsShareTheSameResolver() {
        #expect(AgentBrandAssets.name(for: "codex", colorScheme: .dark) == "agent-codex-light")
        #expect(AgentBrandAssets.name(for: "opencode", colorScheme: .dark) == "agent-opencode-light")
        #expect(AgentBrandAssets.name(for: "claude-code", colorScheme: .dark) == "agent-claude")
    }
}
