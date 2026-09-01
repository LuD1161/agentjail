import AppKit
import SwiftUI

struct AgentBrandMark: View {
    let agent: String
    var size: CGFloat = 25
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Group {
            if let imageName, let image = Self.load(imageName) {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
            } else {
                Text("<>")
                    .font(.system(size: max(size * 0.42, 9), weight: .bold, design: .monospaced))
                    .foregroundStyle(.purple)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    private var imageName: String? {
        AgentBrandAssets.name(for: agent, colorScheme: colorScheme)
    }

    private static func load(_ name: String) -> NSImage? {
        guard let url = Bundle.main.url(forResource: name, withExtension: "svg") else { return nil }
        return NSImage(contentsOf: url)
    }
}
