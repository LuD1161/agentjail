import AgentjailApprovalCore
import Charts
import SwiftUI

struct TokenUsageChart: View {
    let points: [DashboardTokenDay]
    @State private var hoveredDay: String?

    private var scale: TokenChartScale {
        .fitting(maximum: points.map(\.totalTokens).max() ?? 0)
    }

    private var hoveredPoint: DashboardTokenDay? {
        points.first { $0.day == hoveredDay }
    }

    private var domainMaximum: Double {
        let maximum = Double(points.map(\.totalTokens).max() ?? 0)
        return max(maximum * 1.15, 1)
    }

    var body: some View {
        Chart(points) { point in
            AreaMark(x: .value("Day", point.day), y: .value("Tokens", point.totalTokens))
                .foregroundStyle(.blue.opacity(0.16))
            LineMark(x: .value("Day", point.day), y: .value("Tokens", point.totalTokens))
                .foregroundStyle(.blue)
                .interpolationMethod(.catmullRom)
            if point.day == hoveredDay {
                RuleMark(x: .value("Selected day", point.day))
                    .foregroundStyle(.secondary)
                    .annotation(position: .top, spacing: 8) {
                        TokenUsageHoverLabel(point: point)
                    }
            }
        }
        .chartYScale(domain: 0...domainMaximum)
        .chartXAxis(.hidden)
        .chartYAxis {
            AxisMarks(position: .trailing) { value in
                AxisGridLine()
                AxisValueLabel {
                    if let tokens = value.as(Double.self) {
                        Text(scale.label(for: tokens))
                    }
                }
            }
        }
        .chartOverlay { proxy in
            GeometryReader { geometry in
                Rectangle()
                    .fill(.clear)
                    .contentShape(Rectangle())
                    .onContinuousHover { phase in
                        updateHover(phase, proxy: proxy, geometry: geometry)
                    }
            }
        }
        .frame(height: 130)
        .accessibilityLabel("Token usage over time")
        .accessibilityValue(hoveredPoint.map { TokenChartScale.fitting(maximum: $0.totalTokens).label(for: Double($0.totalTokens)) + " tokens on " + $0.day } ?? "Hover over the chart to inspect daily usage")
    }

    private func updateHover(_ phase: HoverPhase, proxy: ChartProxy, geometry: GeometryProxy) {
        switch phase {
        case let .active(location):
            let plotFrame = geometry[proxy.plotAreaFrame]
            guard plotFrame.contains(location) else {
                hoveredDay = nil
                return
            }
            hoveredDay = proxy.value(atX: location.x - plotFrame.origin.x, as: String.self)
        case .ended:
            hoveredDay = nil
        }
    }
}
