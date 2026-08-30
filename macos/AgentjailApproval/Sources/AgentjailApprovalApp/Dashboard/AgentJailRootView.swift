import AgentjailApprovalCore
import SwiftUI

enum AgentJailTab: Hashable {
    case overview
    case mcp
    case settings
}

struct AgentJailRootView: View {
    @ObservedObject private var composition: ApprovalAppComposition
    @ObservedObject private var setup: AgentJailSetupCoordinator

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
        _setup = ObservedObject(wrappedValue: composition.setupCoordinator)
    }

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                brand
                List(selection: $composition.selectedTab) {
                    Section("Workspace") {
                        sidebarItem("Overview", icon: "chart.xyaxis.line", tab: .overview)
                        sidebarItem("MCP inventory", icon: "point.3.connected.trianglepath.dotted", tab: .mcp)
                    }
                    Section("AgentJail") {
                        sidebarItem("Settings", icon: "gearshape", tab: .settings)
                    }
                }
                .listStyle(.sidebar)
                sidebarStatus
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 220, max: 260)
        } detail: {
            detail
        }
        .navigationSplitViewStyle(.balanced)
        .frame(minWidth: 900, minHeight: 650)
    }

    private var brand: some View {
        HStack(spacing: 11) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 36, height: 36)
                .background(Color.accentColor.gradient, in: RoundedRectangle(cornerRadius: 11))
            VStack(alignment: .leading, spacing: 1) {
                Text("AgentJail").font(.headline)
                Text("Local security").font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.top, 18)
        .padding(.bottom, 12)
    }

    private func sidebarItem(_ title: String, icon: String, tab: AgentJailTab) -> some View {
        Label(title, systemImage: icon)
            .font(.callout.weight(.medium))
            .tag(tab)
    }

    private var sidebarStatus: some View {
        AgentJailSurface(padding: 12) {
            HStack(spacing: 10) {
                Circle()
                    .fill(sidebarStatusColor)
                    .frame(width: 8, height: 8)
                    .shadow(color: sidebarStatusColor.opacity(0.45), radius: 4)
                VStack(alignment: .leading, spacing: 1) {
                    Text(sidebarStatusTitle)
                        .font(.caption.weight(.semibold))
                    Text(sidebarStatusDetail)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(12)
    }

    private var sidebarStatusColor: Color {
        setup.health.isReady ? .green : (setup.health.localComponentsReady ? .orange : .red)
    }

    private var sidebarStatusTitle: String {
        setup.health.isReady ? "Protection ready" : (setup.health.localComponentsReady ? "Network monitoring off" : "Setup required")
    }

    private var sidebarStatusDetail: String {
        setup.health.isReady ? "Local services online" : (setup.health.localComponentsReady ? "Enable anytime in Settings" : "Finish on Overview")
    }

    @ViewBuilder
    private var detail: some View {
        switch composition.selectedTab {
        case .overview:
            DashboardOverviewView(composition: composition)
        case .mcp:
            MCPInventoryView(store: composition.mcpInventoryStore)
        case .settings:
            ApprovalSettingsView(composition: composition)
        }
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
            VStack(alignment: .leading, spacing: 24) {
                AgentJailPageHeader(eyebrow: "Local security", title: "Overview", detail: "Protection activity from the last 35 days") {
                    Button { Task { await refresh() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                        .disabled(dashboard.isRefreshing)
                }
                if !setup.health.isReady { setupCard }
                if let snapshot = dashboard.snapshot {
                    metrics(snapshot)
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .top, spacing: 16) {
                            activityCard(snapshot).frame(maxWidth: .infinity)
                            tokenCard(snapshot).frame(maxWidth: .infinity)
                        }
                        VStack(spacing: 16) {
                            activityCard(snapshot)
                            tokenCard(snapshot)
                        }
                    }
                    sessionsCard(snapshot)
                } else { emptyDashboard }
            }
            .frame(maxWidth: 1180)
            .padding(32)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task { await refresh() }
    }

    private func refresh() async {
        _ = await setup.refresh()
        await dashboard.refresh()
    }

    private var setupCard: some View {
        HStack(alignment: .top, spacing: 14) {
            AgentJailIconTile(systemImage: setupIcon, color: setupColor)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(setupTitle).font(.headline)
                    AgentJailStatusPill(title: setupStatusTitle, color: setupColor)
                }
                Text(setupDetail).font(.callout).foregroundStyle(.secondary)
                if setup.phase == .awaitingApproval {
                    Text("General → Login Items & Extensions → Network Extensions → AgentJail")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .padding(.top, 4)
                }
            }
            Spacer()
            if setup.phase == .awaitingApproval {
                Button("Open System Settings", action: composition.openExtensionApprovalSettings)
                    .buttonStyle(.borderedProminent)
            } else if !setup.phase.isWorking {
                Button(setupActionTitle) {
                    if setup.phase == .readyToInstall { setup.beginSetup() } else { setup.retry() }
                }
                .buttonStyle(.borderedProminent)
            } else { ProgressView().controlSize(.small) }
        }
        .padding(18)
        .background(setupColor.opacity(0.07), in: RoundedRectangle(cornerRadius: 16))
        .overlay { RoundedRectangle(cornerRadius: 16).stroke(setupColor.opacity(0.22)) }
    }

    private func metrics(_ snapshot: DashboardSnapshotV1) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 155), spacing: 12)], spacing: 12) {
            MetricCard(title: "Audited calls", value: snapshot.totalCalls, icon: "checkmark.shield")
            MetricCard(title: "Active sessions", value: Int64(snapshot.activeSessions), icon: "bolt.horizontal.circle")
            MetricCard(title: "Recent sessions", value: snapshot.totalSessions, icon: "terminal")
            MetricCard(title: "Denied", value: snapshot.deniedCalls, icon: "hand.raised")
        }
    }

    private func activityCard(_ snapshot: DashboardSnapshotV1) -> some View {
        let total = snapshot.activity.reduce(Int64(0)) { $0 + $1.count }
        return DashboardCard(title: "Audited activity", subtitle: "\(total.formatted()) activities in the last 35 days", icon: "square.grid.3x3.fill") {
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 5), count: 7), spacing: 5) {
                ForEach(activityCells(snapshot)) { point in
                    ActivityCellView(point: point)
                }
            }
        }
    }

    private func tokenCard(_ snapshot: DashboardSnapshotV1) -> some View {
        DashboardCard(title: "Tokens over time", subtitle: snapshot.tokenCoverage.joined(separator: ", "), icon: "waveform.path.ecg") {
            if snapshot.tokenStatus == .loading && snapshot.tokens.isEmpty {
                VStack(spacing: 10) {
                    ProgressView()
                    Text("Loading local token usage…")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 130)
            } else if snapshot.tokens.isEmpty {
                DashboardEmptyState(title: "No token usage yet", icon: "chart.line.downtrend.xyaxis", detail: "Usage appears after supported agent transcripts are available.")
                    .frame(height: 130)
            } else {
                TokenUsageChart(points: snapshot.tokens)
                .overlay(alignment: .topTrailing) {
                    if snapshot.tokenStatus == .loading {
                        Label("Updating", systemImage: "arrow.triangle.2.circlepath")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityLabel("Updating token usage")
                    }
                }
                if !snapshot.tokenAgents.isEmpty { tokenAgentLegend(snapshot) }
            }
        }
    }

    private func tokenAgentLegend(_ snapshot: DashboardSnapshotV1) -> some View {
        let total = max(snapshot.tokenAgents.reduce(Int64(0)) { $0 + $1.totalTokens }, 1)
        return VStack(alignment: .leading, spacing: 8) {
            Text("By agent").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            HStack(spacing: 14) {
                ForEach(snapshot.tokenAgents) { agent in
                    Label {
                        Text("\(agentDisplayName(agent.agent)) \(Int((Double(agent.totalTokens) / Double(total) * 100).rounded()))%")
                            .font(.caption.monospacedDigit())
                    } icon: {
                        Image(systemName: agentIcon(agent.agent)).foregroundStyle(agentColor(agent.agent))
                    }
                    .help("\(agentDisplayName(agent.agent)): \(TokenChartScale.fitting(maximum: total).label(for: Double(agent.totalTokens))) tokens")
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Token usage by agent")
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

    private func agentDisplayName(_ value: String) -> String {
        switch value { case "claude-code": "Claude Code"; case "codex": "Codex"; case "opencode": "OpenCode"; default: value }
    }

    private func agentIcon(_ value: String) -> String {
        switch value { case "claude-code": "bubble.left.and.bubble.right.fill"; case "codex": "sparkles"; case "opencode": "chevron.left.forwardslash.chevron.right"; default: "cpu" }
    }

    private func agentColor(_ value: String) -> Color {
        switch value { case "claude-code": .orange; case "codex": .blue; case "opencode": .purple; default: .secondary }
    }

    private var emptyDashboard: some View {
        AgentJailSurface {
            DashboardEmptyState(
                title: emptyDashboardTitle,
                icon: emptyDashboardIcon,
                detail: emptyDashboardDetail
            ).frame(maxWidth: .infinity, minHeight: 220)
        }
    }

    private var emptyDashboardTitle: String {
        if !setup.health.localComponentsReady { return "Activity starts after local setup" }
        return dashboard.unavailable ? "Dashboard unavailable" : "Loading local activity"
    }

    private var emptyDashboardIcon: String {
        if !setup.health.localComponentsReady { return "chart.xyaxis.line" }
        return dashboard.unavailable ? "exclamationmark.triangle" : "hourglass"
    }

    private var emptyDashboardDetail: String {
        if !setup.health.localComponentsReady { return "Install the local CLI and daemon above, then AgentJail will show audited sessions, calls, and token usage here." }
        return dashboard.unavailable ? "Start or retry the local daemon, then refresh." : "Reading the local AgentJail daemon."
    }

    private var setupTitle: String {
        switch setup.phase {
        case .readyToInstall: setup.health.localComponentsReady ? "Network monitoring is off" : "Set up AgentJail"
        case .awaitingApproval: "Network approval required"
        case .failed: "Setup needs attention"
        case .moveToApplications: "Move AgentJail to Applications"
        default: "Setting up AgentJail"
        }
    }

    private var setupDetail: String {
        switch setup.phase {
        case .awaitingApproval: "Click Open System Settings, enable AgentJail at the path below, then return here. Apple’s OK button only dismisses its notice."
        case .moveToApplications: "The Network Extension requires the app to run from /Applications."
        case .readyToInstall: setup.health.localComponentsReady
            ? "Optional. Enable traffic auditing now, or continue using AgentJail and turn it on later from Settings."
            : "Install the local CLI, daemon, and hooks. Network monitoring is a separate optional step."
        case .failed: "No protection was weakened. Retry after reviewing the current status."
        default: "Checking the CLI, daemon, and Network Extension."
        }
    }

    private var setupActionTitle: String {
        setup.phase == .readyToInstall
            ? (setup.health.localComponentsReady ? "Enable Network Monitoring" : "Install Local Components")
            : "Try Again"
    }

    private var setupStatusTitle: String {
        if setup.phase == .awaitingApproval { return "Action required" }
        if setup.health.localComponentsReady { return "Optional" }
        return "Setup required"
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
        var calendar = Calendar(identifier: .iso8601)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let formatter = DateFormatter(); formatter.calendar = calendar; formatter.timeZone = calendar.timeZone; formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.dateFormat = "yyyy-MM-dd"
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

private struct ActivityCellView: View {
    let point: ActivityCell
    @State private var hovering = false

    var body: some View {
        RoundedRectangle(cornerRadius: 3)
            .fill(activityColor)
            .aspectRatio(1, contentMode: .fit)
            .overlay {
                if hovering {
                    Text("\(point.day) · \(point.count.formatted()) audited")
                        .font(.caption2.weight(.medium))
                        .fixedSize()
                        .padding(.horizontal, 7)
                        .padding(.vertical, 5)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 6))
                        .shadow(radius: 4)
                        .zIndex(2)
                }
            }
            .onHover { hovering = $0 }
            .help("\(point.day): \(point.count.formatted()) audited activities")
            .accessibilityLabel("\(point.day), \(point.count.formatted()) audited activities")
    }

    private var activityColor: Color {
        guard point.count > 0 else { return Color.secondary.opacity(0.12) }
        let intensity = Double(point.count) / Double(max(point.maximum, 1))
        return Color.green.opacity(0.18 + 0.82 * intensity)
    }
}

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
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14))
        .overlay { RoundedRectangle(cornerRadius: 14).stroke(Color.primary.opacity(0.08)) }
    }
}

private struct DashboardCard<Content: View>: View {
    let title: String; let subtitle: String; let icon: String; @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Image(systemName: icon).foregroundStyle(.tint); VStack(alignment: .leading) { Text(title).font(.headline); Text(subtitle).font(.caption).foregroundStyle(.secondary) }; Spacer() }
            content
        }
        .padding(18).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
        .overlay { RoundedRectangle(cornerRadius: 16).stroke(Color.primary.opacity(0.08)) }
    }
}
