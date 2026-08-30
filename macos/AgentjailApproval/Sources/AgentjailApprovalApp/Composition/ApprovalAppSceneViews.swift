import AgentjailApprovalCore
import SwiftUI

enum ApprovalAppSceneID {
    static let main = "agentjail-main"
    static let review = "approval-review"
    static let settings = "approval-settings"
    static let setup = "agentjail-setup"
    static let mcpInventory = "agentjail-mcp-inventory"
}

struct ApprovalPanelHostView: View {
    @ObservedObject private var store: ApprovalStore
    let composition: ApprovalAppComposition
    let refreshOnAppear: Bool
    let receivesReviewFocus: Bool

    init(composition: ApprovalAppComposition, refreshOnAppear: Bool, receivesReviewFocus: Bool) {
        self.composition = composition
        self.refreshOnAppear = refreshOnAppear
        self.receivesReviewFocus = receivesReviewFocus
        _store = ObservedObject(wrappedValue: composition.store)
    }

    var body: some View {
        ApprovalPanelView(
            presentation: composition.panelPresentation(
                focusRequest: receivesReviewFocus ? composition.focusRequest : nil
            ),
            onApprove: composition.approve,
            onDeny: composition.deny,
            onRetry: composition.refreshFromMenuOpening,
            onOpenAgentJail: composition.requestSetup,
            onMCPInventory: composition.requestMCPInventory,
            onSettings: composition.requestSettings,
            onQuit: composition.quit,
            onFocusConsumed: { request in
                guard receivesReviewFocus else { return }
                composition.consumeFocus(request)
            }
        )
        .task {
            guard refreshOnAppear else { return }
            composition.refreshFromMenuOpening()
        }
    }
}

struct ApprovalMenuBarLabelHost: View {
    @ObservedObject private var store: ApprovalStore
    let composition: ApprovalAppComposition
    @Binding var isInserted: Bool

    init(composition: ApprovalAppComposition, isInserted: Binding<Bool>) {
        self.composition = composition
        _store = ObservedObject(wrappedValue: composition.store)
        _isInserted = isInserted
    }

    var body: some View {
        ApprovalMenuBarLabelView(presentation: ApprovalMenuLabelPresentation(state: store.state))
            .background(ReviewRouteBridge(composition: composition))
            .background(SettingsRouteBridge(composition: composition))
            .background(SetupRouteBridge(composition: composition))
            .background(MCPInventoryRouteBridge(composition: composition))
            .onAppear {
                composition.start()
            }
    }
}

private struct MCPInventoryRouteBridge: View {
    @ObservedObject private var composition: ApprovalAppComposition
    @Environment(\.openWindow) private var openWindow
    @State private var openedGeneration: UInt64 = 0

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
    }

    var body: some View {
        Color.clear
            .frame(width: 0, height: 0)
            .onAppear { openIfNeeded(composition.mcpInventoryRouteGeneration) }
            .onChange(of: composition.mcpInventoryRouteGeneration) { generation in
                openIfNeeded(generation)
            }
    }

    private func openIfNeeded(_ generation: UInt64) {
        guard generation > openedGeneration else { return }
        openedGeneration = generation
        openWindow(id: ApprovalAppSceneID.main)
    }
}

private struct SetupRouteBridge: View {
    @ObservedObject private var composition: ApprovalAppComposition
    @Environment(\.openWindow) private var openWindow
    @State private var openedGeneration: UInt64 = 0

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
    }

    var body: some View {
        Color.clear
            .frame(width: 0, height: 0)
            .onAppear { openIfNeeded(composition.setupRouteGeneration) }
            .onChange(of: composition.setupRouteGeneration) { generation in
                openIfNeeded(generation)
            }
    }

    private func openIfNeeded(_ generation: UInt64) {
        guard generation > openedGeneration else { return }
        openedGeneration = generation
        openWindow(id: ApprovalAppSceneID.main)
    }
}

private struct ReviewRouteBridge: View {
    @ObservedObject private var composition: ApprovalAppComposition
    @Environment(\.openWindow) private var openWindow

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
    }

    var body: some View {
        Color.clear
            .frame(width: 0, height: 0)
            .onAppear {
                process(composition.reviewRoute)
            }
            .onChange(of: composition.reviewRoute) { route in
                process(route)
            }
    }

    private func process(_ route: ApprovalNotificationReviewRoute?) {
        guard let route else { return }
        Task {
            await composition.dispatchReviewRoute(route) {
                openWindow(id: ApprovalAppSceneID.review)
            }
        }
    }
}

private struct SettingsRouteBridge: View {
    @ObservedObject private var composition: ApprovalAppComposition
    @Environment(\.openWindow) private var openWindow

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
    }

    var body: some View {
        Color.clear
            .frame(width: 0, height: 0)
            .onChange(of: composition.settingsRouteGeneration) { _ in
                openWindow(id: ApprovalAppSceneID.main)
            }
    }
}
