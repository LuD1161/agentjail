import AgentjailApprovalCore
import SwiftUI

enum ApprovalPanelLayout {
    static let width: CGFloat = 400
    static let emptyHeight: CGFloat = 304
    static let reviewHeight: CGFloat = 520

    static func height(hasPendingReviews: Bool) -> CGFloat {
        hasPendingReviews ? reviewHeight : emptyHeight
    }
}

struct ApprovalPanelView: View {
    let presentation: PanelPresentation
    let onApprove: (ReviewID) -> Void
    let onDeny: (ReviewID) -> Void
    let onRetry: () -> Void
    let onOpenAgentJail: () -> Void
    let onMCPInventory: () -> Void
    let onSettings: () -> Void
    let onQuit: () -> Void
    let onFocusConsumed: (ReviewFocusRequest) -> Void

    @State private var consumedThroughFocusGeneration: UInt64?
    @FocusState private var keyboardFocusedReviewID: ReviewID?
    @AccessibilityFocusState private var focusedReviewID: ReviewID?
    @AccessibilityFocusState private var isFocusFeedbackFocused: Bool

    init(
        presentation: PanelPresentation,
        onApprove: @escaping (ReviewID) -> Void,
        onDeny: @escaping (ReviewID) -> Void,
        onRetry: @escaping () -> Void,
        onOpenAgentJail: @escaping () -> Void,
        onMCPInventory: @escaping () -> Void,
        onSettings: @escaping () -> Void,
        onQuit: @escaping () -> Void,
        onFocusConsumed: @escaping (ReviewFocusRequest) -> Void = { _ in }
    ) {
        self.presentation = presentation
        self.onApprove = onApprove
        self.onDeny = onDeny
        self.onRetry = onRetry
        self.onOpenAgentJail = onOpenAgentJail
        self.onMCPInventory = onMCPInventory
        self.onSettings = onSettings
        self.onQuit = onQuit
        self.onFocusConsumed = onFocusConsumed
        _consumedThroughFocusGeneration = State(initialValue: nil)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if showsStatusBanner {
                StatusBanner(presentation: presentation.status, onRetry: onRetry)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                Divider()
            }

            content
            Divider()
            footer
        }
        .frame(
            width: ApprovalPanelLayout.width,
            height: ApprovalPanelLayout.height(hasPendingReviews: hasPendingReviews)
        )
        .background(Color(nsColor: .windowBackgroundColor))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("AgentJail approval review")
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            AgentJailAppMark(size: 34)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("AgentJail")
                    .font(.headline)
                Text("Approval center")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            PanelStatusBadge(
                status: presentation.status,
                pendingCount: presentation.totalPending
            )
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 13)
    }

    private var content: some View {
        ScrollViewReader { proxy in
            Group {
                if let empty = presentation.empty {
                    VStack(alignment: .leading, spacing: 12) {
                        focusFeedback
                        EmptyApprovalView(
                            presentation: empty,
                            status: presentation.status,
                            onRetry: onRetry
                        )
                    }
                    .padding(16)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 12) {
                            focusFeedback

                            ForEach(presentation.cards) { card in
                                ReviewCardView(
                                    presentation: card,
                                    isFocusTarget: focusTargetReviewID == card.id,
                                    onApprove: onApprove,
                                    onDeny: onDeny
                                )
                                .id(card.id)
                                .focusable()
                                .focused($keyboardFocusedReviewID, equals: card.id)
                                .accessibilityFocused($focusedReviewID, equals: card.id)
                            }

                            if let truncationText = presentation.truncationText {
                                Label(truncationText, systemImage: "ellipsis.circle")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .accessibilityLabel(truncationText)
                            }
                        }
                        .padding(16)
                    }
                }
            }
            .onAppear {
                applyFocus(using: proxy)
            }
            .onChange(of: presentation.focus) { _ in
                applyFocus(using: proxy)
            }
        }
    }

    private var hasPendingReviews: Bool {
        !presentation.cards.isEmpty
    }

    private var showsStatusBanner: Bool {
        hasPendingReviews && presentation.status.kind != .ready
    }

    @ViewBuilder
    private var focusFeedback: some View {
        if case let .unavailable(_, reason) = presentation.focus {
            Label(reason.message, systemImage: "info.circle")
                .font(.callout)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                .accessibilityLabel(reason.message)
                .accessibilityFocused($isFocusFeedbackFocused)
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            PanelFooterAction(
                title: "Open AgentJail",
                systemImage: "macwindow",
                prominence: .primary,
                accessibilityHint: "Opens AgentJail setup and health status.",
                action: onOpenAgentJail
            )

            Spacer(minLength: 4)

            PanelFooterAction(
                title: "Settings",
                systemImage: "gearshape",
                accessibilityHint: "Opens AgentJail settings.",
                action: onSettings
            )

            PanelFooterAction(
                title: "MCP inventory",
                systemImage: "point.3.connected.trianglepath.dotted",
                accessibilityHint: "Opens the read-only MCP inventory.",
                action: onMCPInventory
            )

            Divider()
                .frame(height: 22)
                .padding(.horizontal, 2)

            PanelFooterAction(
                title: "Quit AgentJail",
                systemImage: "power",
                prominence: .destructive,
                accessibilityHint: "Stops this menu-bar app. The AgentJail daemon remains authoritative.",
                action: onQuit
            )
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private var focusTargetReviewID: ReviewID? {
        guard case let .target(request) = presentation.focus else { return nil }
        return request.reviewID
    }

    private func applyFocus(using proxy: ScrollViewProxy) {
        switch presentation.focus {
        case .none:
            isFocusFeedbackFocused = false
        case let .target(request):
            isFocusFeedbackFocused = false
            proxy.scrollTo(request.reviewID, anchor: .center)
            keyboardFocusedReviewID = request.reviewID
            focusedReviewID = request.reviewID
        case .unavailable:
            keyboardFocusedReviewID = nil
            focusedReviewID = nil
            isFocusFeedbackFocused = true
        }
        consumeFocusIfNeeded()
    }

    private func consumeFocusIfNeeded() {
        guard let request = presentation.focus.consumableRequest,
              consumedThroughFocusGeneration.map({ request.generation > $0 }) ?? true
        else {
            return
        }
        consumedThroughFocusGeneration = request.generation
        onFocusConsumed(request)
    }
}

private struct PanelStatusBadge: View {
    let status: ApprovalPanelStatusPresentation
    let pendingCount: Int

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
            Text(title)
                .font(.caption.weight(.semibold))
                .monospacedDigit()
        }
        .foregroundStyle(color)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(color.opacity(0.11), in: Capsule())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityLabel)
    }

    private var title: String {
        if pendingCount > 0 {
            return "\(pendingCount) pending"
        }
        return status.kind == .ready ? "All clear" : status.title
    }

    private var accessibilityLabel: String {
        pendingCount > 0 ? "\(pendingCount) pending approvals" : status.accessibilityText
    }

    private var color: Color {
        switch status.kind {
        case .starting, .connecting:
            .secondary
        case .ready:
            .green
        case .disconnected, .unauthorized, .unsupportedProtocol:
            .orange
        }
    }
}

private struct StatusBanner: View {
    let presentation: ApprovalPanelStatusPresentation
    let onRetry: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: presentation.systemImage)
                .foregroundStyle(statusColor)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(presentation.title)
                    .font(.callout.weight(.semibold))
                Text(presentation.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if presentation.canRetry {
                Button("Retry", action: onRetry)
                    .buttonStyle(.borderless)
                    .focusable(false)
                    .accessibilityHint("Refreshes approval state from the local AgentJail daemon.")
                    .agentJailInteractiveHover()
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(presentation.accessibilityText)
    }

    private var statusColor: Color {
        switch presentation.kind {
        case .starting, .connecting:
            .secondary
        case .ready:
            .green
        case .disconnected, .unauthorized, .unsupportedProtocol:
            .orange
        }
    }
}

private struct EmptyApprovalView: View {
    let presentation: ApprovalEmptyPresentation
    let status: ApprovalPanelStatusPresentation
    let onRetry: () -> Void

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: presentation.systemImage)
                .font(.title2.weight(.medium))
                .foregroundStyle(statusColor)
                .frame(width: 44, height: 44)
                .background(statusColor.opacity(0.11), in: RoundedRectangle(cornerRadius: 12))
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(presentation.title)
                    .font(.headline)
                Text(presentation.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)

            if status.canRetry {
                Button("Retry", action: onRetry)
                    .buttonStyle(.borderless)
                    .focusable(false)
                    .accessibilityHint("Refreshes approval state from the local AgentJail daemon.")
                    .agentJailInteractiveHover()
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.primary.opacity(0.08), lineWidth: 1)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(presentation.title). \(presentation.detail)")
    }

    private var statusColor: Color {
        switch status.kind {
        case .starting, .connecting:
            .secondary
        case .ready:
            .green
        case .disconnected, .unauthorized, .unsupportedProtocol:
            .orange
        }
    }
}

private enum PanelFooterActionProminence {
    case primary
    case standard
    case destructive
}

private struct PanelFooterAction: View {
    let title: String
    let systemImage: String
    var prominence: PanelFooterActionProminence = .standard
    let accessibilityHint: String
    let action: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 7) {
                Image(systemName: systemImage)
                    .font(.system(size: 14, weight: .medium))
                if prominence == .primary {
                    Text(title)
                        .font(.callout.weight(.semibold))
                }
            }
            .padding(.horizontal, prominence == .primary ? 11 : 9)
            .frame(minHeight: 34)
            .contentShape(RoundedRectangle(cornerRadius: 9))
        }
        .buttonStyle(.plain)
        .focusable(false)
        .foregroundStyle(foregroundColor)
        .background(backgroundColor, in: RoundedRectangle(cornerRadius: 9))
        .onHover { isHovering = $0 }
        .animation(.easeOut(duration: 0.12), value: isHovering)
        .agentJailPointingCursor()
        .help(title)
        .accessibilityLabel(title)
        .accessibilityHint(accessibilityHint)
    }

    private var foregroundColor: Color {
        if prominence == .destructive && isHovering {
            return .red
        }
        if prominence == .primary {
            return .accentColor
        }
        return .primary
    }

    private var backgroundColor: Color {
        switch prominence {
        case .primary:
            Color.accentColor.opacity(isHovering ? 0.17 : 0.10)
        case .standard:
            Color.primary.opacity(isHovering ? 0.09 : 0.045)
        case .destructive:
            Color.red.opacity(isHovering ? 0.12 : 0)
        }
    }
}
