import Foundation
import SwiftUI

@main
@MainActor
enum AgentJailEntrypoint {
    static func main() {
        let arguments = CommandLine.arguments
        if AgentJailTunnelCommand.handles(arguments: arguments) {
            AgentJailTunnelCommand.run(arguments: arguments)
        }
        AgentJailApp.main()
    }
}

struct AgentJailApp: App {
    @NSApplicationDelegateAdaptor(ApprovalApplicationDelegate.self) private var applicationDelegate
    @State private var isMenuBarExtraInserted = true

    var body: some Scene {
        MenuBarExtra(isInserted: menuBarExtraInsertion) {
            ApprovalPanelHostView(
                composition: applicationDelegate.composition,
                refreshOnAppear: true,
                receivesReviewFocus: false
            )
        } label: {
            ApprovalMenuBarLabelHost(
                composition: applicationDelegate.composition,
                isInserted: $isMenuBarExtraInserted
            )
        }
        .menuBarExtraStyle(.window)

        Window("AgentJail Review", id: ApprovalAppSceneID.review) {
            ApprovalPanelHostView(
                composition: applicationDelegate.composition,
                refreshOnAppear: false,
                receivesReviewFocus: true
            )
        }

        Window("AgentJail", id: ApprovalAppSceneID.setup) {
            AgentJailSetupView(
                coordinator: applicationDelegate.composition.setupCoordinator,
                onOpenExtensionSettings: applicationDelegate.composition.openExtensionApprovalSettings,
                onOpenSettings: applicationDelegate.composition.requestSettings,
                onOpenMCPInventory: applicationDelegate.composition.requestMCPInventory
            )
        }
        .defaultSize(width: 700, height: 640)

        Window("AgentJail MCP Inventory", id: ApprovalAppSceneID.mcpInventory) {
            MCPInventoryView(store: applicationDelegate.composition.mcpInventoryStore)
        }
        .defaultSize(width: 760, height: 620)

        Settings {
            ApprovalSettingsView(composition: applicationDelegate.composition)
        }

        Window("AgentJail Settings", id: ApprovalAppSceneID.settings) {
            ApprovalSettingsView(composition: applicationDelegate.composition)
        }
    }

    private var menuBarExtraInsertion: Binding<Bool> {
        Binding(
            get: { isMenuBarExtraInserted },
            set: { inserted in
                isMenuBarExtraInserted = inserted
                applicationDelegate.composition.menuBarExtraInsertionChanged(inserted)
            }
        )
    }
}
