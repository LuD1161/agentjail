import SwiftUI

enum AgentJailAboutLinks {
    static let source = URL(string: "https://github.com/LuD1161/agentjail")!
    static let feedback = URL(string: "https://github.com/LuD1161/agentjail/issues/new")!
    static let authorX = URL(string: "https://x.com/AseemShrey")!
}

struct AgentJailAboutView: View {
    private let identity = AgentJailReleaseIdentity.current

    var body: some View {
        AgentJailPage {
            VStack(spacing: 34) {
                AgentJailAboutHero(identity: identity)
                AgentJailAboutCredit()
            }
            .frame(maxWidth: 820)
            .frame(maxWidth: .infinity)
            .padding(.top, 42)
            .padding(.bottom, 36)
        }
    }
}

private struct AgentJailAboutHero: View {
    let identity: AgentJailReleaseIdentity

    var body: some View {
        VStack(spacing: 30) {
            AgentJailAboutMark()

            VStack(spacing: 7) {
                Text("AgentJail")
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                Text("Open-source guardrails for agents")
                    .font(.title3.weight(.medium))
                    .foregroundStyle(.secondary)
            }

            Text("Give coding agents enforceable boundaries for files, shell commands, MCP tools, credentials, and network access—without changing the agents themselves.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 590)

            HStack(spacing: 10) {
                AgentJailAboutTrait(title: "Local-first", systemImage: "house.fill")
                AgentJailAboutTrait(title: "Policy-enforced", systemImage: "checkmark.shield.fill")
                AgentJailAboutTrait(title: "Agent-agnostic", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("AgentJail principles")

            HStack(spacing: 10) {
                if let releaseURL = identity.releaseURL {
                    Link(destination: releaseURL) {
                        Label(identity.versionLabel, systemImage: "tag")
                    }
                    .focusable(false)
                    .agentJailInteractiveHover()
                    .help("Open release notes for \(identity.versionLabel)")
                }

                Link(destination: AgentJailAboutLinks.source) {
                    Label("View on GitHub", systemImage: "arrow.up.right.square")
                }
                .focusable(false)
                .agentJailInteractiveHover()
                .help("Open the AgentJail source repository")

                Link(destination: AgentJailAboutLinks.feedback) {
                    Label("Feedback & issues", systemImage: "exclamationmark.bubble")
                }
                .focusable(false)
                .agentJailInteractiveHover()
                .help("Request a feature, share feedback, or report a bug")
            }
            .buttonStyle(.bordered)
            .controlSize(.large)

            HStack(spacing: 8) {
                Image(systemName: "shippingbox")
                    .accessibilityHidden(true)
                Text(identity.displayText)
                    .textSelection(.enabled)
            }
            .font(.caption.monospacedDigit())
            .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 48)
        .padding(.vertical, 28)
        .frame(maxWidth: .infinity)
    }
}

private struct AgentJailAboutMark: View {
    var body: some View {
        ZStack {
            Circle()
                .fill(Color.accentColor.opacity(0.09))
                .frame(width: 174, height: 174)

            Circle()
                .stroke(Color.accentColor.opacity(0.13), lineWidth: 1)
                .frame(width: 146, height: 146)

            AgentJailAppMark(size: 112)
                .shadow(color: .black.opacity(0.13), radius: 16, y: 8)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("AgentJail app icon")
    }
}

private struct AgentJailAboutTrait: View {
    let title: String
    let systemImage: String

    var body: some View {
        Label(title, systemImage: systemImage)
            .font(.callout.weight(.medium))
            .foregroundStyle(.primary)
            .padding(.horizontal, 13)
            .padding(.vertical, 7)
            .background(Color.accentColor.opacity(0.08), in: Capsule())
    }
}

private struct AgentJailAboutCredit: View {
    var body: some View {
        Link(destination: AgentJailAboutLinks.authorX) {
            HStack(spacing: 0) {
                Text("Made with ❤️ by ")
                    .foregroundStyle(.secondary)
                Text("@AseemShrey")
                    .foregroundStyle(.secondary)
                    .fontWeight(.semibold)
                Image(systemName: "arrow.up.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.leading, 4)
                    .accessibilityHidden(true)
            }
        }
        .font(.callout)
        .buttonStyle(.plain)
        .focusable(false)
        .agentJailPointingCursor()
        .help("Open @AseemShrey on X")
        .accessibilityLabel("Made with love by Aseem Shrey on X")
    }
}
