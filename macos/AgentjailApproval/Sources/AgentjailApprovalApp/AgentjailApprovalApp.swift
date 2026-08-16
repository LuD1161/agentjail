import SwiftUI

@main
struct AgentjailApprovalApp: App {
    var body: some Scene {
        MenuBarExtra("AgentJail", systemImage: "shield") {
            PlaceholderView()
        }
        .menuBarExtraStyle(.window)
    }
}
