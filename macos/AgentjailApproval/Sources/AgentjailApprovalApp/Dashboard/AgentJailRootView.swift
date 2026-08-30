import AgentjailApprovalCore
import Charts
import SwiftUI

enum AgentJailTab: Hashable {
    case overview
    case mcp
    case settings
}

struct AgentJailRootView: View {
    @ObservedObject private var composition: ApprovalAppComposition

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
    }

    var body: some View {
        TabView(selection: $composition.selectedTab) {
            DashboardOverviewView(composition: composition)
                .tabItem { Label("Overview", systemImage: "chart.xyaxis.line") }
                .tag(AgentJailTab.overview)
            MCPInventoryView(store: composition.mcpInventoryStore)
                .tabItem { Label("MCP", systemImage: "point.3.connected.trianglepath.dotted") }
                .tag(AgentJailTab.mcp)
            ApprovalSettingsView(composition: composition)
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(AgentJailTab.settings)
        }
        .frame(minWidth: 820, minHeight: 650)
    }
}

private struct DashboardOverviewView: View {
    @ObservedObject private var composition: ApprovalAppComposition
    @ObservedObject private var dashboard: DashboardStore
    @ObservedObject private var setup: AgentJailSetupCoordinator

    init(composition: ApprovalAppComposition) {
        self.composition = composition
        _composition = ObservedObject(wrappedValue: composition)
        _dashboard = ObservedObject(wrappedValue: composition.dashboardStore)
        _setup = ObservedObject(wrappedValue: composition.setupCoordinator)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Overview").font(.largeTitle.bold())
                        Text("Local protection activity from the last 35 days").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button { Task { await refresh() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                        .disabled(dashboard.isRefreshing)
                }
                if !setup.health.isReady { setupCard }
                if let snapshot = dashboard.snapshot {
                    metrics(snapshot)
                    HStack(alignment: .top, spacing: 16) {
                        activityCard(snapshot).frame(maxWidth: .infinity)
                        tokenCard(snapshot).frame(maxWidth: .infinity)
                    }
                    sessionsCard(snapshot)
                } else { emptyDashboard }
            }
            .padding(24)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task { await refresh() }
    }

    private func refresh() async {
        _ = await setup.refresh()
        await dashboard.refresh()
    }

    private var setupCard: some View {
        HStack(spacing: 16) {
            Image(systemName: setupIcon).font(.title2).foregroundStyle(setupColor)
            VStack(alignment: .leading, spacing: 4) {
                Text(setupTitle).font(.headline)
                Text(setupDetail).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if setup.phase == .awaitingApproval {
                Button("Open System Settings", action: composition.openExtensionApprovalSettings)
            } else if !setup.phase.isWorking {
                Button(setup.phase == .readyToInstall ? "Install AgentJail" : "Try Again") {
                    if setup.phase == .readyToInstall { setup.beginSetup() } else { setup.retry() }
                }
                .buttonStyle(.borderedProminent)
            } else { ProgressView().controlSize(.small) }
        }
        .padding(16)
        .background(setupColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 14))
        .overlay { RoundedRectangle(cornerRadius: 14).stroke(setupColor.opacity(0.2)) }
    }

    private func metrics(_ snapshot: DashboardSnapshotV1) -> some View {
        HStack(spacing: 12) {
            MetricCard(title: "Audited calls", value: snapshot.totalCalls, icon: "checkmark.shield")
            MetricCard(title: "Active sessions", value: Int64(snapshot.activeSessions), icon: "bolt.horizontal.circle")
            MetricCard(title: "Recent sessions", value: snapshot.totalSessions, icon: "terminal")
            MetricCard(title: "Denied", value: snapshot.deniedCalls, icon: "hand.raised")
        }
    }

    private func activityCard(_ snapshot: DashboardSnapshotV1) -> some View {
        DashboardCard(title: "Audited activity", subtitle: "Calls per day", icon: "square.grid.3x3.fill") {
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 5), count: 7), spacing: 5) {
                ForEach(activityCells(snapshot)) { point in
                    RoundedRectangle(cornerRadius: 3)
                        .fill(activityColor(point.count, maximum: point.maximum))
                        .aspectRatio(1, contentMode: .fit)
                        .help("\(point.day): \(point.count) audited calls")
                }
            }
        }
    }

    private func tokenCard(_ snapshot: DashboardSnapshotV1) -> some View {
        DashboardCard(title: "Tokens over time", subtitle: snapshot.tokenCoverage.joined(separator: ", "), icon: "waveform.path.ecg") {
            if snapshot.tokens.isEmpty {
                DashboardEmptyState(title: "No token usage yet", icon: "chart.line.downtrend.xyaxis", detail: "Usage appears after supported agent transcripts are available.")
                    .frame(height: 130)
            } else {
                Chart(snapshot.tokens) { point in
                    AreaMark(x: .value("Day", point.day), y: .value("Tokens", point.totalTokens))
                        .foregroundStyle(.blue.opacity(0.16))
                    LineMark(x: .value("Day", point.day), y: .value("Tokens", point.totalTokens))
                        .foregroundStyle(.blue).interpolationMethod(.catmullRom)
                }
                .chartXAxis(.hidden)
                .frame(height: 130)
            }
        }
    }

    private func sessionsCard(_ snapshot: DashboardSnapshotV1) -> some View {
        DashboardCard(title: "Agent sessions", subtitle: "Active now and recently audited", icon: "terminal.fill") {
            if snapshot.recentSessions.isEmpty {
                Text("No audited agent sessions yet.").foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 80)
            } else {
                VStack(spacing: 0) {
                    ForEach(snapshot.recentSessions) { session in
                        HStack(spacing: 12) {
                            Circle().fill(session.active ? Color.green : Color.secondary.opacity(0.3)).frame(width: 8, height: 8)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(session.project).font(.headline)
                                Text(session.agent).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text("\(session.auditedCalls) calls").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 10)
                        if session.id != snapshot.recentSessions.last?.id { Divider() }
                    }
                }
            }
        }
    }

    private var emptyDashboard: some View {
        DashboardEmptyState(
            title: emptyDashboardTitle,
            icon: emptyDashboardIcon,
            detail: emptyDashboardDetail
        ).frame(maxWidth: .infinity, minHeight: 280)
    }

    private var emptyDashboardTitle: String {
        if !setup.health.isReady { return "Activity starts after setup" }
        return dashboard.unavailable ? "Dashboard unavailable" : "Loading local activity"
    }

    private var emptyDashboardIcon: String {
        if !setup.health.isReady { return "chart.xyaxis.line" }
        return dashboard.unavailable ? "exclamationmark.triangle" : "hourglass"
    }

    private var emptyDashboardDetail: String {
        if !setup.health.isReady { return "Finish setup above, then AgentJail will show audited sessions, calls, and token usage here." }
        return dashboard.unavailable ? "Start or retry the local daemon, then refresh." : "Reading the local AgentJail daemon."
    }

    private var setupTitle: String {
        switch setup.phase {
        case .readyToInstall: "Finish setting up AgentJail"
        case .awaitingApproval: "Approve the Network Extension"
        case .failed: "Setup needs attention"
        case .moveToApplications: "Move AgentJail to Applications"
        default: "Setting up AgentJail"
        }
    }

    private var setupDetail: String {
        switch setup.phase {
        case .awaitingApproval: "AgentJail stays open while System Settings handles Apple’s one-time approval. Return here when finished."
        case .moveToApplications: "The Network Extension requires the app to run from /Applications."
        case .readyToInstall: "Install the local CLI and daemon, then request macOS network approval."
        case .failed: "No protection was weakened. Retry after reviewing the current status."
        default: "Checking the CLI, daemon, and Network Extension."
        }
    }

    private var setupIcon: String { setup.phase == .awaitingApproval ? "hand.raised.fill" : "shield.lefthalf.filled" }
    private var setupColor: Color {
        switch setup.phase {
        case .failed: .red
        case .awaitingApproval: .orange
        default: .blue
        }
    }

    private func activityCells(_ snapshot: DashboardSnapshotV1) -> [ActivityCell] {
        let counts = Dictionary(uniqueKeysWithValues: snapshot.activity.map { ($0.day, $0.count) })
        let maximum = max(counts.values.max() ?? 0, 1)
        let formatter = DateFormatter(); formatter.calendar = Calendar(identifier: .iso8601); formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.dateFormat = "yyyy-MM-dd"
        let calendar = Calendar(identifier: .iso8601)
        let today = calendar.startOfDay(for: Date())
        return (0..<35).compactMap { offset in
            guard let date = calendar.date(byAdding: .day, value: offset - 34, to: today) else { return nil }
            let day = formatter.string(from: date)
            return ActivityCell(day: day, count: counts[day] ?? 0, maximum: maximum)
        }
    }

    private func activityColor(_ count: Int64, maximum: Int64) -> Color {
        guard count > 0 else { return Color.secondary.opacity(0.1) }
        return Color.green.opacity(0.25 + 0.75 * Double(count) / Double(maximum))
    }
}

private struct ActivityCell: Identifiable { let day: String; let count: Int64; let maximum: Int64; var id: String { day } }

private struct DashboardEmptyState: View {
    let title: String; let icon: String; let detail: String
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon).font(.largeTitle).foregroundStyle(.secondary)
            Text(title).font(.headline)
            Text(detail).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
    }
}

private struct MetricCard: View {
    let title: String; let value: Int64; let icon: String
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: icon).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            Text(value.formatted()).font(.title2.bold()).monospacedDigit()
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))
    }
}

private struct DashboardCard<Content: View>: View {
    let title: String; let subtitle: String; let icon: String; @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Image(systemName: icon).foregroundStyle(.tint); VStack(alignment: .leading) { Text(title).font(.headline); Text(subtitle).font(.caption).foregroundStyle(.secondary) }; Spacer() }
            content
        }
        .padding(18).background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 14))
        .overlay { RoundedRectangle(cornerRadius: 14).stroke(Color.secondary.opacity(0.12)) }
    }
}
