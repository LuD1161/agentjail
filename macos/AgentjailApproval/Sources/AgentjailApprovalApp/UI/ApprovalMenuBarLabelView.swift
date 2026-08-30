import AgentjailApprovalCore
import AppKit
import SwiftUI

struct ApprovalMenuBarLabelView: View {
    let presentation: ApprovalMenuLabelPresentation

    var body: some View {
        HStack(spacing: 4) {
            menuBarAppIcon
            if let badgeText = presentation.badgeText {
                Text(badgeText)
                    .monospacedDigit()
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(presentation.accessibilityLabel)
        .accessibilityValue(presentation.accessibilityValue)
        .help(presentation.accessibilityValue)
    }

    @ViewBuilder
    private var menuBarAppIcon: some View {
        if let iconURL = Bundle.main.url(forResource: "AgentJail", withExtension: "icns"),
           let icon = NSImage(contentsOf: iconURL) {
            Image(nsImage: icon)
                .resizable()
                .interpolation(.high)
                .scaledToFit()
                .frame(width: 18, height: 18)
                .accessibilityHidden(true)
        } else {
            Image(systemName: "shield.lefthalf.filled")
                .accessibilityHidden(true)
        }
    }
}
