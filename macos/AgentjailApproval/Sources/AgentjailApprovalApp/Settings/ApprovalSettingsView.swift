import AppKit
import AgentjailApprovalCore
import SwiftUI

struct ApprovalSettingsView: View {
    @ObservedObject private var composition: ApprovalAppComposition
    @ObservedObject private var setup: AgentJailSetupCoordinator
    @ObservedObject private var mcpInventory: MCPInventoryStore
    @ObservedObject private var status: AgentJailStatusStore

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
        _setup = ObservedObject(wrappedValue: composition.setupCoordinator)
        _mcpInventory = ObservedObject(wrappedValue: composition.mcpInventoryStore)
        _status = ObservedObject(wrappedValue: composition.settingsStatusStore)
    }

    var body: some View {
        AgentJailPage {
            AgentJailPageHeader(
                eyebrow: "",
                title: "Settings",
                detail: "Local protection, app behavior, and privacy"
            ) {
                appVersionLink
            }

            HStack(alignment: .top, spacing: AgentJailPageMetrics.cardSpacing) {
                servicesGroup
                privacyAndTrustGroup
            }

            agentIntegrationsGroup
            diagnosticsGroup

            if let settingsError = composition.settingsError {
                AgentJailSurface {
                    Label(settingsError, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                }
            }
        }
        .task {
            await composition.refreshSettingsStatus()
            await mcpInventory.refresh()
            await status.refresh()
        }
    }

    private var servicesGroup: some View {
        SettingsGroup(title: "Services & app") {
            SettingsRow(icon: "network", color: setup.health.isReady ? .green : .orange, title: "Network monitoring", detail: networkMonitoringDetail) {
                networkMonitoringAction
            }
            Divider()
            SettingsRow(icon: "server.rack", color: daemonColor, title: "Local daemon", detail: daemonDetail) {
                daemonAction
            }
            Divider()
            SettingsRow(icon: "bell.badge", color: notificationColor, title: "Notifications", detail: notificationDetail) {
                notificationAction
            }
            Divider()
            SettingsRow(icon: "arrow.clockwise.circle", color: loginColor, title: "Launch at login", detail: loginDetail) {
                loginAction
            }
        }
    }

    private var privacyAndTrustGroup: some View {
        SettingsGroup(title: "Privacy & trust") {
            SettingsRow(
                icon: "chart.bar.xaxis",
                color: telemetryColor,
                title: "Anonymous product metrics",
                detail: telemetryDetail,
                titleInfo: .anonymousProductMetrics
            ) {
                telemetryAction
            }
            Divider()
            SettingsRow(
                icon: "person.badge.shield.checkmark",
                color: .blue,
                title: "Approval scope",
                detail: "Updates verified project policy"
            ) { EmptyView() }
            Divider()
            SettingsRow(
                icon: "lock.shield",
                color: .green,
                title: "Local authority",
                detail: "Authenticated local daemon"
            ) { EmptyView() }
            Divider()
            SettingsRow(
                icon: "point.3.connected.trianglepath.dotted",
                color: .purple,
                title: "MCP inventory",
                detail: mcpInventoryDetail
            ) {
                Button("Open") { composition.requestMCPInventory() }
                    .agentJailInteractiveHover()
            }
        }
    }

    private var agentIntegrationsGroup: some View {
        SettingsGroup(title: "Agent integrations") {
            HStack(spacing: 10) {
                ForEach(agentPresentations) { agent in
                    SettingsAgentCard(agent: agent)
                }
            }
        }
    }

    private var diagnosticsGroup: some View {
        SettingsGroup(title: "Installation & diagnostics") {
            VStack(spacing: 12) {
                HStack(spacing: 0) {
                    DiagnosticMetric(title: "CLI", value: cliStatus.title, color: cliStatus.color)
                    Divider().frame(height: 32)
                    DiagnosticMetric(title: "Daemon", value: daemonStatus.title, color: daemonStatus.color)
                    Divider().frame(height: 32)
                    DiagnosticMetric(title: "Network", value: networkStatus.title, color: networkStatus.color)
                    Divider().frame(height: 32)
                    DiagnosticMetric(title: "Policies", value: policyStatus.title, color: policyStatus.color)
                }
                Divider()
                HStack(spacing: 8) {
                    Button {
                        Task { await refreshDiagnostics() }
                    } label: {
                        Label(status.isRefreshing ? "Checking" : "Check now", systemImage: "checkmark.circle")
                    }
                    .disabled(status.isRefreshing)
                    .agentJailInteractiveHover()
                Button("Open logs", action: openLogs)
                    .agentJailInteractiveHover()
                AgentJailCopyButton(title: "Copy status", text: statusSummary)
                Button("Reveal CLI", action: revealCLI)
                    .disabled(status.snapshot?.infrastructure.cliInstalled != true)
                    .agentJailInteractiveHover()
                    Spacer(minLength: 0)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        }
    }

    private var agentPresentations: [SettingsAgentPresentation] {
        let supported = [
            (id: "claude-code", name: "Claude Code"),
            (id: "cursor", name: "Cursor"),
            (id: "codex", name: "Codex"),
        ]
        return supported.map { supportedAgent in
            guard let agent = status.snapshot?.agents.first(where: { $0.id == supportedAgent.id }) else {
                return SettingsAgentPresentation(id: supportedAgent.id, name: supportedAgent.name, state: .checking)
            }
            let state: SettingsAgentState
            if agent.hookInstalled {
                state = .protected
            } else if agent.detected {
                state = .detected
            } else {
                state = .notFound
            }
            return SettingsAgentPresentation(id: agent.id, name: agent.displayName, state: state)
        }
    }

    private var cliStatus: SettingsDiagnosticStatus {
        guard let snapshot = status.snapshot else { return .checking }
        return snapshot.infrastructure.cliInstalled ? .healthy("Installed") : .warning("Missing")
    }

    private var daemonStatus: SettingsDiagnosticStatus {
        guard let snapshot = status.snapshot else { return .checking }
        return snapshot.infrastructure.daemonRunning ? .healthy("Running") : .warning("Stopped")
    }

    private var networkStatus: SettingsDiagnosticStatus {
        if setup.health.isReady { return .healthy("Enabled") }
        if setup.phase == .awaitingApproval { return .warning("Approval needed") }
        return .neutral("Optional · Off")
    }

    private var policyStatus: SettingsDiagnosticStatus {
        guard let policies = status.snapshot?.policies else { return .checking }
        guard policies.configured else { return .warning("Not installed") }
        guard policies.readable else { return .warning("Needs review") }
        return .healthy("\(policies.activeRules) active")
    }

    @ViewBuilder
    private var appVersionLink: some View {
        let identity = AgentJailReleaseIdentity.current
        if let releaseURL = identity.releaseURL {
            Link(destination: releaseURL) {
                HStack(spacing: 5) {
                    Text(identity.displayText)
                    Image(systemName: "arrow.up.right")
                        .font(.caption2)
                }
            }
            .font(.caption.monospacedDigit())
            .foregroundStyle(.secondary)
            .buttonStyle(.plain)
            .focusable(false)
            .agentJailInteractiveHover()
            .help("Open AgentJail \(identity.versionLabel) release notes")
            .accessibilityLabel("Open AgentJail \(identity.versionLabel) release notes")
        } else {
            Text(identity.displayText)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var mcpInventoryDetail: String {
        let serverCount = mcpInventory.snapshot.items.count
        let toolCount = mcpInventory.observedToolsByServer.values.reduce(0) { $0 + $1.count }
        return "\(serverCount) servers · \(toolCount) tools"
    }

    private var daemonPresentation: ApprovalPanelStatusPresentation {
        PanelPresentation(
            state: composition.store.state,
            actionStates: composition.store.actionStates,
            now: SystemApprovalClock().now()
        ).status
    }

    private var daemonDetail: String {
        switch daemonPresentation.kind {
        case .ready:
            "Ready for approval requests"
        case .starting:
            "Starting local service"
        case .connecting:
            "Connecting to local service"
        case .disconnected:
            "Local service unavailable"
        case .unauthorized:
            "Authentication required"
        case .unsupportedProtocol:
            "App update required"
        }
    }

    private var daemonColor: Color {
        switch daemonPresentation.kind {
        case .ready:
            .green
        case .starting, .connecting:
            .blue
        case .disconnected, .unauthorized, .unsupportedProtocol:
            .orange
        }
    }

    @ViewBuilder
    private var daemonAction: some View {
        if daemonPresentation.kind == .ready {
            AgentJailStatusPill(title: "Running", color: .green)
        } else if daemonPresentation.canRetry {
            Button("Retry") { composition.refreshFromMenuOpening() }
                .agentJailInteractiveHover()
        } else {
            AgentJailStatusPill(title: daemonPresentation.title, color: daemonColor)
        }
    }

    private var networkMonitoringDetail: String {
        if setup.health.isReady { return "Protected traffic auditing" }
        if setup.phase == .awaitingApproval { return "Approval required in Settings" }
        return "Optional traffic visibility"
    }

    @ViewBuilder
    private var networkMonitoringAction: some View {
        if setup.health.isReady {
            AgentJailStatusPill(title: "Enabled", color: .green)
        } else if setup.phase == .awaitingApproval {
            Button("Open System Settings", action: composition.openExtensionApprovalSettings)
                .agentJailInteractiveHover()
        } else if setup.health.localComponentsReady {
            Button("Enable") { setup.beginSetup() }
                .agentJailInteractiveHover()
        } else {
            Button("Set Up") { composition.requestSetup() }
                .agentJailInteractiveHover()
        }
    }

    private var loginItemEnabled: Binding<Bool> {
        Binding(
            get: { composition.loginStatus == .enabled },
            set: { enabled in
                Task {
                    await composition.setLoginItemEnabledFromUserAction(enabled)
                }
            }
        )
    }

    private var notificationColor: Color {
        switch composition.notificationAuthorization {
        case .authorized:
            .green
        case .denied:
            .orange
        case .notDetermined:
            .blue
        }
    }

    @ViewBuilder
    private var notificationAction: some View {
        switch composition.notificationAuthorization {
        case .authorized:
            AgentJailStatusPill(title: "Enabled", color: .green)
        case .denied:
            Button("Open Settings", action: openNotificationSettings)
                .agentJailInteractiveHover()
        case .notDetermined:
            Button("Enable") {
                Task { await composition.enableNotificationsFromUserAction() }
            }
            .agentJailInteractiveHover()
        }
    }

    private var loginColor: Color {
        switch composition.loginStatus {
        case .enabled:
            .green
        case .notRegistered:
            .blue
        case .requiresApproval, .notFound, .unknown:
            .orange
        }
    }

    @ViewBuilder
    private var loginAction: some View {
        switch composition.loginStatus {
        case .enabled, .notRegistered:
            Toggle("Launch AgentJail at login", isOn: loginItemEnabled)
                .labelsHidden()
                .accessibilityLabel("Launch AgentJail at login")
        case .requiresApproval:
            Button("Open Settings") { composition.openLoginItemsSettings() }
                .agentJailInteractiveHover()
        case .notFound, .unknown:
            Button("Try Again") {
                Task { await composition.setLoginItemEnabledFromUserAction(true) }
            }
            .agentJailInteractiveHover()
        }
    }

    private var telemetryEnabled: Binding<Bool> {
        Binding(
            get: { composition.telemetryStatus.isEnabled },
            set: { enabled in
                Task {
                    await composition.setTelemetryEnabledFromUserAction(enabled)
                }
            }
        )
    }

    private var telemetryColor: Color {
        switch composition.telemetryStatus {
        case .enabled:
            .green
        case .disabled:
            .secondary
        case .unknown, .updating:
            .blue
        case .unavailable:
            .orange
        }
    }

    @ViewBuilder
    private var telemetryAction: some View {
        switch composition.telemetryStatus {
        case .enabled(.config), .disabled(.config):
            Toggle("Send anonymous product metrics", isOn: telemetryEnabled)
                .labelsHidden()
                .accessibilityLabel("Send anonymous product metrics")
        case .updating:
            AgentJailStatusPill(title: "Saving", color: .blue)
        case .enabled:
            AgentJailStatusPill(title: "On · Managed", color: .green)
        case .disabled:
            AgentJailStatusPill(title: "Off · Managed", color: .secondary)
        case .unknown:
            AgentJailStatusPill(title: "Checking", color: .blue)
        case .unavailable:
            AgentJailStatusPill(title: "Unavailable", color: .orange)
        }
    }

    private var notificationDetail: String {
        switch composition.notificationAuthorization {
        case .authorized:
            "Alerts for approval requests"
        case .denied:
            "Approvals stay in the menu bar"
        case .notDetermined:
            "Alerts for approval requests"
        }
    }

    private var loginDetail: String {
        switch composition.loginStatus {
        case .enabled:
            "Starts AgentJail automatically"
        case .notRegistered:
            "Start AgentJail automatically"
        case .requiresApproval:
            "Approval required in Settings"
        case .notFound:
            "Login item needs repair"
        case .unknown:
            "Login item status unavailable"
        }
    }

    private var telemetryDetail: String {
        switch composition.telemetryStatus {
        case .unknown:
            "Checking product metrics"
        case .enabled(.config), .disabled(.config):
            "Anonymous product signals"
        case .enabled(.environment), .disabled(.environment):
            "Managed by the environment"
        case .enabled(.continuousIntegration), .disabled(.continuousIntegration):
            "Disabled in continuous integration"
        case .enabled(.unknown), .disabled(.unknown):
            "Managed outside this app"
        case .updating:
            "Saving product metrics"
        case .unavailable:
            "Product metrics unavailable"
        }
    }

    private func openNotificationSettings() {
        if let applicationURL = NotificationSettingsDestination.applicationURL(
            bundleIdentifier: Bundle.main.bundleIdentifier
        ), NSWorkspace.shared.open(applicationURL) {
            return
        }

        NSWorkspace.shared.open(NotificationSettingsDestination.paneURL)
    }

    private func refreshDiagnostics() async {
        async let statusRefresh: Void = status.refresh()
        async let setupRefresh: AgentJailSetupHealth = setup.refresh()
        _ = await (statusRefresh, setupRefresh)
    }

    private func openLogs() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let directory = home.appendingPathComponent(".agentjail", isDirectory: true)
        let candidates = ["daemon.log", "crash.log"].map { directory.appendingPathComponent($0) }
        let existing = candidates.filter { FileManager.default.fileExists(atPath: $0.path) }
        if existing.isEmpty {
            NSWorkspace.shared.open(directory)
        } else {
            NSWorkspace.shared.activateFileViewerSelecting(existing)
        }
    }

    private func revealCLI() {
        let cli = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".agentjail/bin/agentjail")
        NSWorkspace.shared.activateFileViewerSelecting([cli])
    }

    private var statusSummary: String {
        let snapshot = status.snapshot
        let integrations = agentPresentations.map { "\($0.name): \($0.state.title)" }.joined(separator: "\n")
        return """
        AgentJail \(snapshot?.version ?? "status unavailable")
        CLI: \(cliStatus.title)
        Daemon: \(daemonStatus.title)
        Network: \(networkStatus.title)
        Policies: \(policyStatus.title)
        \(integrations)
        """
    }
}

private struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
                .padding(.leading, 2)
            AgentJailCardSurface(padding: 14) {
                VStack(spacing: 0) { content }
            }
        }
        .frame(
            minWidth: AgentJailPageMetrics.settingsColumnMinimumWidth,
            maxWidth: .infinity,
            alignment: .topLeading
        )
    }
}

private struct SettingsRow<Trailing: View>: View {
    let icon: String
    let color: Color
    let title: String
    let detail: String
    let titleInfo: SettingsTitleInfo?
    @ViewBuilder let trailing: Trailing

    init(
        icon: String,
        color: Color,
        title: String,
        detail: String,
        titleInfo: SettingsTitleInfo? = nil,
        @ViewBuilder trailing: () -> Trailing
    ) {
        self.icon = icon
        self.color = color
        self.title = title
        self.detail = detail
        self.titleInfo = titleInfo
        self.trailing = trailing()
    }

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            AgentJailIconTile(systemImage: icon, color: color)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 5) {
                    Text(title)
                        .font(.callout.weight(.semibold))
                        .lineLimit(1)
                    if let titleInfo {
                        SettingsInfoButton(info: titleInfo)
                    }
                }
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(detail)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .layoutPriority(1)
            Spacer(minLength: 16)
            trailing
                .controlSize(.small)
                .frame(width: 112, alignment: .trailing)
        }
        .padding(.vertical, 8)
        .frame(minHeight: 52)
    }
}

private struct SettingsTitleInfo {
    let title: String
    let summary: String
    let collected: [String]
    let note: String
    let excluded: String
    let helpText: String

    static let anonymousProductMetrics = SettingsTitleInfo(
        title: "What AgentJail collects",
        summary: "A random installation ID plus these product signals:",
        collected: [
            "Version, OS, architecture, and install method",
            "Install, update, setup, agent, and CLI feature enums",
            "Aggregated action, tool, agent, and rule counts",
            "Custom-rule counts, disabled rule IDs, and latency",
            "Fixed failure reasons and update availability"
        ],
        note: "Custom rule IDs can appear in aggregated counts.",
        excluded: "Never file paths, command text, repositories, MCP server names, policy contents, credentials, hostnames, usernames, or IP addresses.",
        helpText: "Show exactly which anonymous product metrics AgentJail collects"
    )
}

private struct SettingsInfoButton: View {
    let info: SettingsTitleInfo
    @State private var isPresented = false

    var body: some View {
        Button {
            isPresented.toggle()
        } label: {
            Image(systemName: "info.circle")
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
                .frame(width: 18, height: 18)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .agentJailPointingCursor()
        .help(info.helpText)
        .accessibilityLabel("About anonymous product metrics")
        .accessibilityHint("Shows what AgentJail collects and excludes")
        .popover(isPresented: $isPresented, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 12) {
                Text(info.title)
                    .font(.headline)
                Text(info.summary)
                    .font(.callout)

                VStack(alignment: .leading, spacing: 7) {
                    ForEach(info.collected, id: \.self) { item in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Circle()
                                .fill(Color.accentColor)
                                .frame(width: 5, height: 5)
                            Text(item)
                                .font(.callout)
                        }
                    }
                }

                Label(info.note, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)

                Divider()

                Label {
                    Text(info.excluded)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } icon: {
                    Image(systemName: "hand.raised.fill")
                        .foregroundStyle(.green)
                }

                Text("See the exact queued JSON with `agentjail telemetry view`.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            .padding(16)
            .frame(width: 360, alignment: .leading)
        }
    }
}

private struct SettingsAgentPresentation: Identifiable {
    let id: String
    let name: String
    let state: SettingsAgentState
}

private enum SettingsAgentState {
    case protected
    case detected
    case notFound
    case checking

    var title: String {
        switch self {
        case .protected: "Protected"
        case .detected: "Needs setup"
        case .notFound: "Not found"
        case .checking: "Checking"
        }
    }

    var color: Color {
        switch self {
        case .protected: .green
        case .detected: .orange
        case .notFound: .secondary
        case .checking: .blue
        }
    }
}

private struct SettingsAgentCard: View {
    let agent: SettingsAgentPresentation

    var body: some View {
        HStack(spacing: 10) {
            AgentBrandMark(agent: agent.id, size: 28)
            VStack(alignment: .leading, spacing: 4) {
                Text(agent.name)
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                HStack(spacing: 5) {
                    Circle().fill(agent.state.color).frame(width: 6, height: 6)
                    Text(agent.state.title)
                }
                .font(.caption)
                .foregroundStyle(agent.state.color)
                .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(maxWidth: .infinity, minHeight: 58, alignment: .leading)
        .background(agent.state.color.opacity(0.07), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .accessibilityElement(children: .combine)
    }
}

private struct SettingsDiagnosticStatus {
    let title: String
    let color: Color

    static let checking = SettingsDiagnosticStatus(title: "Checking", color: .blue)
    static func healthy(_ title: String) -> SettingsDiagnosticStatus { .init(title: title, color: .green) }
    static func warning(_ title: String) -> SettingsDiagnosticStatus { .init(title: title, color: .orange) }
    static func neutral(_ title: String) -> SettingsDiagnosticStatus { .init(title: title, color: .secondary) }
}

private struct DiagnosticMetric: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            HStack(spacing: 5) {
                Circle().fill(color).frame(width: 6, height: 6)
                Text(value)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .font(.caption.weight(.medium))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12)
        .accessibilityElement(children: .combine)
    }
}
