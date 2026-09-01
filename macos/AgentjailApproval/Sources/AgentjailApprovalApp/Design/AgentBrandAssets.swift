import SwiftUI

enum AgentBrandAssets {
    static func themedName(for baseName: String, colorScheme: ColorScheme) -> String {
        guard colorScheme == .dark else { return baseName }
        switch baseName {
        case "agent-codex", "agent-opencode", "agent-cursor":
            return "\(baseName)-light"
        default:
            return baseName
        }
    }

    static func name(for agent: String, colorScheme: ColorScheme) -> String? {
        let baseName: String
        switch agent {
        case "claude-code": baseName = "agent-claude"
        case "codex": baseName = "agent-codex"
        case "opencode": baseName = "agent-opencode"
        case "cursor": baseName = "agent-cursor"
        default: return nil
        }
        return themedName(for: baseName, colorScheme: colorScheme)
    }
}
