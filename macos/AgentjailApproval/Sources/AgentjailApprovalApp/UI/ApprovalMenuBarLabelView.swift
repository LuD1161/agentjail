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
        if let icon = renderedMenuBarIcon {
            Image(nsImage: icon)
                .accessibilityHidden(true)
        } else {
            Image(systemName: "shield.lefthalf.filled")
                .accessibilityHidden(true)
        }
    }

    private var renderedMenuBarIcon: NSImage? {
        guard let iconURL = Bundle.main.url(forResource: "AgentJail", withExtension: "icns"),
              let sourceIcon = NSImage(contentsOf: iconURL) else {
            return nil
        }
        let icon = NSImage(size: NSSize(width: 18, height: 18))
        icon.lockFocus()
        NSGraphicsContext.current?.imageInterpolation = .high
        sourceIcon.draw(
            in: NSRect(x: 0, y: 0, width: 18, height: 18),
            from: .zero,
            operation: .sourceOver,
            fraction: 1
        )
        icon.unlockFocus()
        icon.isTemplate = false
        return icon
    }
}
