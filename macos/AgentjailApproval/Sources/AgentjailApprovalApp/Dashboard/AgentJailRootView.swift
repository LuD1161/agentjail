import AgentjailApprovalCore
import AppKit
import SwiftUI

enum AgentJailTab: Hashable {
    case overview
    case policies
    case mcp
    case settings
    case about
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
                    sidebarItem("Overview", icon: "chart.xyaxis.line", tab: .overview)
                    sidebarItem("Policies", icon: "checkmark.shield", tab: .policies)
                    sidebarItem("MCP inventory", icon: "point.3.connected.trianglepath.dotted", tab: .mcp)
                    Divider()
                    sidebarItem("Settings", icon: "gearshape", tab: .settings)
                    sidebarItem("About", icon: "info.circle", tab: .about)
                }
                .listStyle(.sidebar)
                sidebarGitHubLink
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
            AgentJailAppMark()
            VStack(alignment: .leading, spacing: 1) {
                Text("AgentJail").font(.headline)
                Text("Open-source guardrails for agents")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.top, 18)
        .padding(.bottom, 12)
    }

    private func sidebarItem(_ title: String, icon: String, tab: AgentJailTab) -> some View {
        SidebarNavigationItem(
            title: title,
            icon: icon
        )
            .padding(.vertical, 1)
            .tag(tab)
    }

    private var sidebarGitHubLink: some View {
        SidebarGitHubLink()
        .padding(.horizontal, 12)
        .padding(.bottom, 4)
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
        setup.health.isReady ? .green : (setup.health.localComponentsReady || setup.health.localComponentsNeedUpdate ? .orange : .red)
    }

    private var sidebarStatusTitle: String {
        if setup.health.isReady { return "All services operational" }
        if setup.health.localComponentsReady { return "Local services operational" }
        if setup.health.localComponentsNeedUpdate { return "Update available" }
        return "Setup required"
    }

    private var sidebarStatusDetail: String {
        if setup.health.isReady { return "Daemon · Network · Policy engine" }
        if setup.health.localComponentsReady { return "Daemon · Policy engine · Network off" }
        if setup.health.localComponentsNeedUpdate { return "Refresh local components" }
        return "Finish on Overview"
    }

    @ViewBuilder
    private var detail: some View {
        switch composition.selectedTab {
        case .overview:
            DashboardOverviewView(composition: composition)
        case .policies:
            PoliciesView(store: composition.policyInventoryStore)
        case .mcp:
            MCPInventoryView(store: composition.mcpInventoryStore)
        case .settings:
            ApprovalSettingsView(composition: composition)
        case .about:
            AgentJailAboutView()
        }
    }
}

private struct SidebarNavigationItem: View {
    let title: String
    let icon: String

    var body: some View {
        HStack(spacing: 8) {
            Label(title, systemImage: icon)
                .font(.system(size: 14, weight: .medium))
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
        .contentShape(Rectangle())
        .agentJailPointingCursor()
    }
}

struct AgentJailAppMark: View {
    let size: CGFloat

    init(size: CGFloat = 46) {
        self.size = size
    }

    var body: some View {
        Group {
            if let url = Bundle.main.url(forResource: "AgentJail", withExtension: "icns"), let icon = NSImage(contentsOf: url) {
                Image(nsImage: icon).resizable().interpolation(.high).scaledToFit()
            } else {
                Image(systemName: "shield.lefthalf.filled").foregroundStyle(.white)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color.accentColor.gradient, in: RoundedRectangle(cornerRadius: 11))
            }
        }
        .frame(width: size, height: size)
        .accessibilityLabel("AgentJail")
    }
}

private struct SidebarGitHubLink: View {
    @Environment(\.colorScheme) private var colorScheme
    @State private var isHovering = false

    var body: some View {
        Link(destination: URL(string: "https://github.com/LuD1161/agentjail")!) {
            HStack(spacing: 8) {
                GitHubBrandMark()
                Text("Star on GitHub")
                    .font(.callout.weight(.semibold))
                Spacer(minLength: 4)
                GitHubStarMark()
            }
            .padding(.horizontal, 11)
            .frame(maxWidth: .infinity, minHeight: 38)
        }
        .buttonStyle(SidebarGitHubButtonStyle(isHovering: isHovering, colorScheme: colorScheme))
        .onHover { isHovering = $0 }
        .agentJailPointingCursor()
        .accessibilityLabel("Star AgentJail on GitHub")
        .accessibilityHint("Opens AgentJail's GitHub repository in your default browser")
    }
}

private struct GitHubStarMark: View {
    var body: some View {
        Group {
            if let url = Bundle.main.url(forResource: "github-star", withExtension: "svg"),
               let image = NSImage(contentsOf: url) {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
            } else {
                Image(systemName: "star.fill")
                    .foregroundStyle(.yellow)
            }
        }
        .frame(width: 18, height: 18)
        .accessibilityHidden(true)
    }
}

private struct SidebarGitHubButtonStyle: ButtonStyle {
    let isHovering: Bool
    let colorScheme: ColorScheme

    func makeBody(configuration: Configuration) -> some View {
        let shape = RoundedRectangle(cornerRadius: 10)
        configuration.label
            .foregroundStyle(.primary)
            .background {
                shape.fill(backgroundColor)
            }
            .overlay {
                shape.strokeBorder(borderColor, lineWidth: isHovering ? 1.25 : 1)
            }
            .shadow(color: .black.opacity(isHovering ? 0.10 : 0.04), radius: isHovering ? 6 : 2, y: 2)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(.easeOut(duration: 0.14), value: configuration.isPressed)
            .animation(.easeOut(duration: 0.14), value: isHovering)
    }

    private var backgroundColor: Color {
        if isHovering { return Color.accentColor.opacity(colorScheme == .dark ? 0.18 : 0.10) }
        return Color.primary.opacity(colorScheme == .dark ? 0.08 : 0.035)
    }

    private var borderColor: Color {
        isHovering ? Color.accentColor.opacity(0.55) : Color.primary.opacity(0.12)
    }
}

private struct GitHubBrandMark: View {
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Group {
            if let image {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
            } else {
                Image(systemName: "chevron.left.forwardslash.chevron.right")
            }
        }
        .frame(width: 17, height: 17)
        .accessibilityHidden(true)
    }

    private var image: NSImage? {
        let name = colorScheme == .dark ? "github-light" : "github"
        guard let url = Bundle.main.url(forResource: name, withExtension: "svg") else { return nil }
        return NSImage(contentsOf: url)
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
        let report = dashboard.snapshot.map {
            DashboardActivityReport(activity: $0.activity, referenceDate: Date())
        }
        AgentJailPage {
            AgentJailPageHeader(
                eyebrow: "",
                title: "Overview",
                detail: report?.headerDetail ?? "Loading local protection activity"
            ) {
                Button { Task { await refresh() } } label: {
                    if dashboard.isRefreshing {
                        Label("Refreshing", systemImage: "arrow.triangle.2.circlepath")
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                .buttonStyle(.bordered)
                .dashboardRefreshFocusStyle()
                .disabled(dashboard.isRefreshing)
                .agentJailInteractiveHover()
            }
            if !setup.health.isReady { setupCard }
            if let snapshot = dashboard.snapshot, let report {
                metrics(snapshot)
                ViewThatFits(in: .horizontal) {
                    Grid(horizontalSpacing: AgentJailPageMetrics.cardSpacing) {
                        GridRow(alignment: .top) {
                            activityCard(snapshot, report: report)
                            tokenCard(dashboard.tokenSnapshot ?? snapshot)
                        }
                    }
                    VStack(spacing: AgentJailPageMetrics.cardSpacing) {
                        activityCard(snapshot, report: report)
                        tokenCard(dashboard.tokenSnapshot ?? snapshot)
                    }
                }
                sessionsCard(snapshot)
            } else { emptyDashboard }
        }
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
                    .agentJailInteractiveHover()
            } else if !setup.phase.isWorking {
                Button(setupActionTitle) {
                    if setup.phase == .readyToInstall { setup.beginSetup() } else { setup.retry() }
                }
                .buttonStyle(.borderedProminent)
                .agentJailInteractiveHover()
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

    private func activityCard(_ snapshot: DashboardSnapshotV1, report: DashboardActivityReport) -> some View {
        DashboardCard(title: "Audited activity", subtitle: report.cardDetail, icon: "square.grid.3x3.fill") {
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 5), count: 7), spacing: 5) {
                ForEach(activityCells(snapshot)) { point in
                    ActivityCellView(point: point)
                }
            }
        }
    }

    private func tokenCard(_ snapshot: DashboardSnapshotV1) -> some View {
        let totalTokens = TokenChartScale.total(of: snapshot.tokens.lazy.map(\.totalTokens))
        let totalLabel = TokenChartScale.fitting(maximum: totalTokens).label(for: Double(totalTokens))
        return DashboardCard(
            title: "Agent token usage",
            subtitle: "Local agent history · not audit coverage",
            icon: "waveform.path.ecg",
            trailingMetric: DashboardCardMetric(value: totalLabel, label: "total tokens")
        ) {
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
                        AgentBrandMark(agent: agent.agent)
                    }
                    .help("\(agentDisplayName(agent.agent)): \(TokenChartScale.fitting(maximum: total).label(for: Double(agent.totalTokens))) tokens")
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Token usage by agent")
    }

    private func sessionsCard(_ snapshot: DashboardSnapshotV1) -> some View {
        let sessions = DashboardSessionOrdering.liveFirst(snapshot.recentSessions)
        let visibleAuditedCalls = snapshot.recentSessions.reduce(0) { $0 + $1.auditedCalls }
        return DashboardCard(
            title: "Agent sessions",
            subtitle: "\(snapshot.activeSessions) active · \(visibleAuditedCalls.formatted()) calls in recent sessions",
            icon: "terminal.fill"
        ) {
            if sessions.isEmpty {
                Text("No audited agent sessions yet.").foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 80)
            } else {
                VStack(spacing: 0) {
                    ForEach(sessions) { session in
                        DashboardSessionRow(session: session, generatedAtUnixMs: snapshot.generatedAtUnixMs)
                        if session.id != sessions.last?.id { Divider() }
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
        case .readyToInstall:
            if setup.health.localComponentsReady { return "Network monitoring is off" }
            if setup.health.localComponentsNeedUpdate { return "AgentJail update available" }
            return "Set up AgentJail"
        case .awaitingApproval: return "Network approval required"
        case .failed: return "Setup needs attention"
        case .moveToApplications: return "Move AgentJail to Applications"
        default: return "Setting up AgentJail"
        }
    }

    private var setupDetail: String {
        switch setup.phase {
        case .awaitingApproval: return "Click Open System Settings, enable AgentJail at the path below, then return here. Apple’s OK button only dismisses its notice."
        case .moveToApplications: return "The Network Extension requires the app to run from /Applications."
        case .readyToInstall:
            if setup.health.localComponentsReady {
                return "Optional. Enable traffic auditing now, or continue using AgentJail and turn it on later from Settings."
            }
            if setup.health.localComponentsNeedUpdate {
                return "The app includes newer local components. Update them without changing policy configuration or audit history."
            }
            return "Install the local CLI, daemon, and hooks. Network monitoring is a separate optional step."
        case .failed: return "No protection was weakened. Retry after reviewing the current status."
        default: return "Checking the CLI, daemon, and Network Extension."
        }
    }

    private var setupActionTitle: String {
        guard setup.phase == .readyToInstall else { return "Try Again" }
        if setup.health.localComponentsReady { return "Enable Network Monitoring" }
        if setup.health.localComponentsNeedUpdate { return "Update Local Components" }
        return "Install Local Components"
    }

    private var setupStatusTitle: String {
        if setup.phase == .awaitingApproval { return "Action required" }
        if setup.health.localComponentsReady { return "Optional" }
        if setup.health.localComponentsNeedUpdate { return "Update available" }
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
            return ActivityCell(day: day, count: counts[day] ?? 0, maximum: maximum, column: offset % 7)
        }
    }

    private func activityColor(_ count: Int64, maximum: Int64) -> Color {
        guard count > 0 else { return Color.secondary.opacity(0.1) }
        return Color.green.opacity(0.25 + 0.75 * Double(count) / Double(maximum))
    }
}

private struct DashboardSessionRow: View {
    let session: DashboardSession
    let generatedAtUnixMs: Int64

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                Text(session.project)
                    .font(.headline)
                    .lineLimit(1)
                HStack(spacing: 7) {
                    HStack(spacing: 5) {
                        Circle()
                            .fill(session.active ? Color.green : Color.secondary.opacity(0.55))
                            .frame(width: 7, height: 7)
                        Text(session.active ? "Live" : "Recent")
                    }
                    .foregroundStyle(session.active ? Color.green : Color.secondary)
                    Text("·").foregroundStyle(.tertiary)
                    HStack(spacing: 5) {
                        AgentBrandMark(agent: session.agent, size: 14)
                        Text(agentDisplayName)
                    }
                    Text("·").foregroundStyle(.tertiary)
                    Label(timingText, systemImage: "clock")
                }
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }

            Spacer(minLength: 18)

            VStack(alignment: .trailing, spacing: 2) {
                Text(session.auditedCalls.formatted())
                    .font(.title3.bold())
                    .monospacedDigit()
                Text("audited calls")
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 13)
        .background(
            session.active ? Color.green.opacity(0.035) : Color.clear,
            in: RoundedRectangle(cornerRadius: 12)
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(session.project), \(agentDisplayName), \(session.active ? "active" : "recent") session")
        .accessibilityValue("\(session.auditedCalls.formatted()) audited calls, \(timingText)")
    }

    private var agentDisplayName: String {
        switch session.agent {
        case "claude-code": "Claude Code"
        case "codex": "Codex"
        case "opencode": "OpenCode"
        default: session.agent
        }
    }

    private var timingText: String {
        let endUnixMs = session.active ? generatedAtUnixMs : (session.endedAtUnixMs ?? generatedAtUnixMs)
        let duration = compactDuration(milliseconds: max(endUnixMs - session.startedAtUnixMs, 0))
        if session.active { return "Running \(duration)" }
        guard let endedAtUnixMs = session.endedAtUnixMs else { return "Ran \(duration)" }
        let endedAt = Date(timeIntervalSince1970: Double(endedAtUnixMs) / 1_000)
        return "Ran \(duration) · ended \(endedAt.formatted(.relative(presentation: .numeric)))"
    }

    private func compactDuration(milliseconds: Int64) -> String {
        let totalMinutes = max(milliseconds / 60_000, 0)
        let hours = totalMinutes / 60
        let minutes = totalMinutes % 60
        if hours > 0 { return minutes > 0 ? "\(hours)h \(minutes)m" : "\(hours)h" }
        return totalMinutes > 0 ? "\(totalMinutes)m" : "<1m"
    }
}

private extension View {
    @ViewBuilder
    func dashboardRefreshFocusStyle() -> some View {
        if #available(macOS 14.0, *) {
            focusEffectDisabled()
        } else {
            self
        }
    }
}

private struct ActivityCell: Identifiable {
    let day: String
    let count: Int64
    let maximum: Int64
    let column: Int

    var id: String { day }
}

private struct ActivityCellView: View {
    let point: ActivityCell
    @State private var hovering = false

    var body: some View {
        RoundedRectangle(cornerRadius: 3)
            .fill(activityColor)
            .aspectRatio(1, contentMode: .fit)
            .overlay(alignment: tooltipAlignment) {
                if hovering {
                    Text("\(point.day) · \(point.count.formatted()) audited")
                        .font(.caption2.weight(.medium))
                        .lineLimit(1)
                        .fixedSize()
                        .padding(.horizontal, 7)
                        .padding(.vertical, 5)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 6))
                        .shadow(radius: 4)
                }
            }
            .zIndex(hovering ? 1 : 0)
            .onHover { hovering = $0 }
            .help("\(point.day): \(point.count.formatted()) audited activities")
            .accessibilityLabel("\(point.day), \(point.count.formatted()) audited activities")
    }

    private var activityColor: Color {
        guard point.count > 0 else { return Color.secondary.opacity(0.12) }
        let intensity = Double(point.count) / Double(max(point.maximum, 1))
        return Color.green.opacity(0.18 + 0.82 * intensity)
    }

    private var tooltipAlignment: Alignment {
        switch point.column {
        case 0, 1:
            .leading
        case 5, 6:
            .trailing
        default:
            .center
        }
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

private struct DashboardCardMetric {
    let value: String
    let label: String
}

private struct DashboardCard<Content: View>: View {
    let title: String
    let subtitle: String
    let icon: String
    let trailingMetric: DashboardCardMetric?
    @ViewBuilder let content: Content

    init(
        title: String,
        subtitle: String,
        icon: String,
        trailingMetric: DashboardCardMetric? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.icon = icon
        self.trailingMetric = trailingMetric
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: icon).foregroundStyle(.tint)
                VStack(alignment: .leading) {
                    Text(title).font(.headline)
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: 12)
                if let trailingMetric {
                    VStack(alignment: .trailing, spacing: 1) {
                        Text(trailingMetric.value)
                            .font(.title3.bold())
                            .monospacedDigit()
                        Text(trailingMetric.label)
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(trailingMetric.value) \(trailingMetric.label)")
                }
            }
            content
        }
        .padding(18)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .agentJailCardSurface()
    }
}
