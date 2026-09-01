import Testing
@testable import AgentjailApprovalApp

struct TokenChartTooltipPlacementTests {
    @Test func keepsEdgeTooltipsInsideTheChart() {
        #expect(TokenChartTooltipPlacement.resolve(index: 0, count: 35) == .leading)
        #expect(TokenChartTooltipPlacement.resolve(index: 17, count: 35) == .center)
        #expect(TokenChartTooltipPlacement.resolve(index: 34, count: 35) == .trailing)
    }

    @Test func centersSinglePointCharts() {
        #expect(TokenChartTooltipPlacement.resolve(index: 0, count: 1) == .center)
    }
}
