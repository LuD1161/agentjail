import AgentjailApprovalCore
import SwiftUI

struct ApprovalMenuBarLabelView: View {
    let presentation: ApprovalMenuLabelPresentation

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: presentation.systemImage)
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
}
