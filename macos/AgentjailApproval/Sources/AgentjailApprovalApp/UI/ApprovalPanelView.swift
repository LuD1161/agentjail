import AgentjailApprovalCore
import SwiftUI

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

            StatusBanner(presentation: presentation.status, onRetry: onRetry)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)

            Divider()
            content
            Divider()
            footer
        }
        .frame(width: 420, height: 520)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("AgentJail approval review")
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: "shield")
                .font(.title2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("AgentJail")
                    .font(.headline)
                Text("Project host approvals")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(presentation.pendingCountText)
                .font(.callout.weight(.semibold))
                .monospacedDigit()
                .accessibilityLabel("Pending approvals")
                .accessibilityValue(String(presentation.totalPending))
        }
        .padding(16)
    }

    private var content: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    focusFeedback

                    if let empty = presentation.empty {
                        EmptyApprovalView(presentation: empty)
                    } else {
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
            .onAppear {
                applyFocus(using: proxy)
            }
            .onChange(of: presentation.focus) { _ in
                applyFocus(using: proxy)
            }
        }
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
        HStack(spacing: 10) {
            Button(action: onOpenAgentJail) {
                Label("AgentJail", systemImage: "shield")
            }
            .accessibilityHint("Opens AgentJail setup and health status.")

            Button(action: onSettings) {
                Label("Settings", systemImage: "gearshape")
            }
            .accessibilityHint("Opens AgentJail settings.")

            Button(action: onMCPInventory) {
                Label("MCPs", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .accessibilityHint("Opens the read-only MCP inventory.")

            Spacer()

            Button(action: onQuit) {
                Text("Quit")
            }
            .accessibilityLabel("Quit AgentJail")
            .accessibilityHint("Stops this menu-bar app. The AgentJail daemon remains authoritative.")
        }
        .padding(12)
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
                    .accessibilityHint("Refreshes approval state from the local AgentJail daemon.")
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

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: presentation.systemImage)
                .font(.largeTitle)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(presentation.title)
                .font(.headline)
            Text(presentation.detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 220)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(presentation.title). \(presentation.detail)")
    }
}
