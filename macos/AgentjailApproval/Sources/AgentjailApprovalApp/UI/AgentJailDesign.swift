import AppKit
import SwiftUI

private struct AgentJailInteractiveHoverModifier: ViewModifier {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.colorScheme) private var colorScheme
    @State private var isHovering = false

    func body(content: Content) -> some View {
        content
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .fill(hoverOverlayColor)
                    .allowsHitTesting(false)
            }
            .shadow(
                color: Color.black.opacity(isHovering && isEnabled ? 0.12 : 0),
                radius: 3,
                y: 1
            )
            .animation(.easeOut(duration: 0.12), value: isHovering)
            .onHover { hovering in
                isHovering = hovering
            }
            .agentJailPointingCursor()
    }

    private var hoverOverlayColor: Color {
        guard isHovering && isEnabled else { return .clear }
        return colorScheme == .dark
            ? Color.white.opacity(0.07)
            : Color.black.opacity(0.055)
    }
}

private struct AgentJailPointingCursorModifier: ViewModifier {
    @Environment(\.isEnabled) private var isEnabled
    @State private var cursorIsPushed = false

    func body(content: Content) -> some View {
        content
            .onHover { hovering in
                updateCursor(hovering: hovering)
            }
            .onChange(of: isEnabled) { enabled in
                if !enabled { popCursorIfNeeded() }
            }
            .onDisappear {
                popCursorIfNeeded()
            }
    }

    private func updateCursor(hovering: Bool) {
        if hovering && isEnabled && !cursorIsPushed {
            NSCursor.pointingHand.push()
            cursorIsPushed = true
        } else if (!hovering || !isEnabled) && cursorIsPushed {
            NSCursor.pop()
            cursorIsPushed = false
        }
    }

    private func popCursorIfNeeded() {
        guard cursorIsPushed else { return }
        NSCursor.pop()
        cursorIsPushed = false
    }
}

extension View {
    func agentJailInteractiveHover() -> some View {
        modifier(AgentJailInteractiveHoverModifier())
    }

    func agentJailPointingCursor() -> some View {
        modifier(AgentJailPointingCursorModifier())
    }

    func agentJailCardSurface(cornerRadius: CGFloat = AgentJailPageMetrics.cardCornerRadius) -> some View {
        modifier(AgentJailCardSurfaceModifier(cornerRadius: cornerRadius))
    }

    func agentJailTableSectionBackground(_ color: Color) -> some View {
        background {
            Rectangle().fill(color)
        }
    }
}

struct AgentJailCopyButton: View {
    let title: String
    let text: String

    @State private var copied = false
    @State private var feedbackTask: Task<Void, Never>?

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            if NSPasteboard.general.setString(text, forType: .string) {
                showFeedback()
            }
        } label: {
            Label(copied ? "Copied" : title, systemImage: copied ? "checkmark" : "doc.on.doc")
        }
        .foregroundStyle(copied ? Color.green : Color.primary)
        .focusable(false)
        .agentJailInteractiveHover()
        .accessibilityLabel(copied ? "Copied to clipboard" : title)
        .onDisappear { feedbackTask?.cancel() }
    }

    private func showFeedback() {
        feedbackTask?.cancel()
        copied = true
        feedbackTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_600_000_000)
            guard !Task.isCancelled else { return }
            copied = false
        }
    }
}

enum AgentJailPageMetrics {
    static let maxContentWidth: CGFloat = 1180
    static let horizontalPadding: CGFloat = 32
    static let topPadding: CGFloat = 20
    static let bottomPadding: CGFloat = 32
    static let sectionSpacing: CGFloat = 24
    static let cardSpacing: CGFloat = 16
    static let cardCornerRadius: CGFloat = 16
    static let settingsColumnMinimumWidth: CGFloat = 360
    static let settingsPrimaryColumnCount = 2
}

struct AgentJailPage<Content: View>: View {
    @ViewBuilder let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: AgentJailPageMetrics.sectionSpacing) {
                content
            }
            .frame(maxWidth: AgentJailPageMetrics.maxContentWidth)
            .padding(.horizontal, AgentJailPageMetrics.horizontalPadding)
            .padding(.top, AgentJailPageMetrics.topPadding)
            .padding(.bottom, AgentJailPageMetrics.bottomPadding)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct AgentJailCardSurface<Content: View>: View {
    let padding: CGFloat
    @ViewBuilder let content: Content

    init(padding: CGFloat = 18, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .agentJailCardSurface()
    }
}

private struct AgentJailCardSurfaceModifier: ViewModifier {
    let cornerRadius: CGFloat

    func body(content: Content) -> some View {
        content
            .background(
                Color(nsColor: .controlBackgroundColor),
                in: RoundedRectangle(cornerRadius: cornerRadius)
            )
            .overlay {
                RoundedRectangle(cornerRadius: cornerRadius)
                    .stroke(Color.primary.opacity(0.08))
            }
    }
}

struct AgentJailPageHeader<Trailing: View>: View {
    let eyebrow: String
    let title: String
    let detail: String
    @ViewBuilder let trailing: Trailing

    var body: some View {
        HStack(alignment: .center, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                if !eyebrow.isEmpty {
                    Text(eyebrow.uppercased())
                        .font(.caption2.weight(.bold))
                        .tracking(1.2)
                        .foregroundStyle(.tint)
                }
                Text(title)
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 16)
            trailing
        }
    }
}

struct AgentJailSurface<Content: View>: View {
    let padding: CGFloat
    @ViewBuilder let content: Content

    init(padding: CGFloat = 18, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .agentJailGlass(cornerRadius: 16)
            .overlay {
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color.white.opacity(0.12), lineWidth: 1)
            }
    }
}

private extension View {
    @ViewBuilder
    func agentJailGlass(cornerRadius: CGFloat) -> some View {
        if #available(macOS 26.0, *) {
            glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
        } else {
            background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius))
                .background(Color(nsColor: .controlBackgroundColor).opacity(0.42), in: RoundedRectangle(cornerRadius: cornerRadius))
        }
    }
}

struct AgentJailIconTile: View {
    let systemImage: String
    let color: Color

    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(color)
            .frame(width: 34, height: 34)
            .background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
            .accessibilityHidden(true)
    }
}

struct AgentJailStatusPill: View {
    let title: String
    let color: Color

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(title).font(.caption.weight(.semibold))
        }
            .foregroundStyle(color)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
        .background(.ultraThinMaterial, in: Capsule())
        .overlay { Capsule().fill(color.opacity(0.08)) }
    }
}
