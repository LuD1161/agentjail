import AgentjailApprovalCore
import SwiftUI

struct TokenUsageHoverLabel: View {
    let day: String
    let totalTokens: Int64

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(day)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(compactTotal + " tokens")
                .font(.headline)
                .monospacedDigit()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }

    private var compactTotal: String {
        TokenChartScale.fitting(maximum: totalTokens).label(for: Double(totalTokens))
    }
}
