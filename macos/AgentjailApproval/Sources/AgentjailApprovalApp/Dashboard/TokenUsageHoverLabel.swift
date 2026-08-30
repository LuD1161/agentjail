import AgentjailApprovalCore
import SwiftUI

struct TokenUsageHoverLabel: View {
    let point: DashboardTokenDay

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(point.day)
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
        TokenChartScale.fitting(maximum: point.totalTokens).label(for: Double(point.totalTokens))
    }
}
