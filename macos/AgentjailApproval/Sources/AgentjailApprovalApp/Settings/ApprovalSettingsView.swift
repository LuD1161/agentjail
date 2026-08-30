import AgentjailApprovalCore
import SwiftUI

struct ApprovalSettingsView: View {
    @ObservedObject private var composition: ApprovalAppComposition
    @ObservedObject private var setup: AgentJailSetupCoordinator

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
        _setup = ObservedObject(wrappedValue: composition.setupCoordinator)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                AgentJailPageHeader(
                    eyebrow: "AgentJail",
                    title: "Settings",
                    detail: "Manage local services, notifications, and privacy"
                ) { EmptyView() }

                SettingsGroup(title: "General") {
                    SettingsRow(icon: "network", color: setup.health.isReady ? .green : .orange, title: "Network monitoring", detail: networkMonitoringDetail) {
                        networkMonitoringAction
                    }
                    Divider()
                    SettingsRow(icon: "server.rack", color: .blue, title: "Local daemon", detail: daemonDetail) {
                        Button("Retry") { composition.refreshFromMenuOpening() }
                    }
                    Divider()
                    SettingsRow(icon: "bell.badge", color: .orange, title: "Notifications", detail: notificationDetail) {
                        if composition.notificationAuthorization == .authorized {
                            AgentJailStatusPill(title: "Enabled", color: .green)
                        } else {
                            Button("Enable") {
                                Task { await composition.enableNotificationsFromUserAction() }
                            }
                        }
                    }
                    if composition.notificationAuthorization == .denied {
                        Text("Notification permission is disabled in System Settings.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.leading, 46)
                    }
                    Divider()
                    SettingsRow(icon: "arrow.clockwise.circle", color: .purple, title: "Launch at login", detail: loginDetail) {
                        Toggle("", isOn: loginItemEnabled).labelsHidden()
                    }
                    if composition.loginStatus == .requiresApproval {
                        Button("Open Login Items Settings") { composition.openLoginItemsSettings() }
                            .padding(.leading, 46)
                    }
                }

                SettingsGroup(title: "Privacy") {
                    SettingsRow(icon: "chart.bar.xaxis", color: .green, title: "Anonymous product metrics", detail: telemetryDetail) {
                        Toggle("", isOn: telemetryEnabled)
                            .labelsHidden()
                            .disabled(!composition.telemetryStatus.canChange)
                    }
                    Text("Includes only app version and fixed setup stage/outcome values. Never includes hosts, paths, commands, traffic, credentials, or error text.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.leading, 46)
                }

                SettingsGroup(title: "Security model") {
                    SettingsRow(
                        icon: "person.badge.shield.checkmark",
                        color: .blue,
                        title: "Approval scope",
                        detail: "Approvals add the displayed host to the verified project policy for future sessions. The current session is unchanged."
                    ) { EmptyView() }
                    Divider()
                    SettingsRow(
                        icon: "lock.shield",
                        color: .green,
                        title: "Local authority",
                        detail: "This app communicates with the authenticated local daemon. It never stores the control token or opens the AgentJail database."
                    ) { EmptyView() }
                    Divider()
                    SettingsRow(
                        icon: "point.3.connected.trianglepath.dotted",
                        color: .purple,
                        title: "MCP inventory",
                        detail: "Review observe-only discovery for Claude Code, Codex, and Cursor."
                    ) {
                        Button("Open") { composition.requestMCPInventory() }
                    }
                }

                if let settingsError = composition.settingsError {
                    AgentJailSurface {
                        Label(settingsError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .frame(maxWidth: 900)
            .padding(32)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            await composition.refreshSettingsStatus()
        }
    }

    private var daemonDetail: String {
        PanelPresentation(
            state: composition.store.state,
            actionStates: composition.store.actionStates,
            now: SystemApprovalClock().now()
        ).status.detail
    }

    private var networkMonitoringDetail: String {
        if setup.health.isReady { return "Enabled. AgentJail can audit protected-session network traffic." }
        if setup.phase == .awaitingApproval { return "Waiting for one-time approval in macOS System Settings." }
        return "Off. AgentJail still audits supported tool calls; enable network monitoring whenever you are ready."
    }

    @ViewBuilder
    private var networkMonitoringAction: some View {
        if setup.health.isReady {
            AgentJailStatusPill(title: "Enabled", color: .green)
        } else if setup.phase == .awaitingApproval {
            Button("Open System Settings", action: composition.openExtensionApprovalSettings)
        } else if setup.health.localComponentsReady {
            Button("Enable") { setup.beginSetup() }
        } else {
            Button("Set Up") { composition.requestSetup() }
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

    private var notificationDetail: String {
        switch composition.notificationAuthorization {
        case .authorized:
            "Notifications are enabled for new project-host requests."
        case .denied:
            "Notifications are disabled. You can continue reviewing requests from the menu bar."
        case .notDetermined:
            "Enable notifications to receive a generic alert when a project-host request is waiting."
        }
    }

    private var loginDetail: String {
        switch composition.loginStatus {
        case .enabled:
            "AgentJail is enabled to launch at login."
        case .notRegistered:
            "AgentJail is not configured to launch at login."
        case .requiresApproval:
            "macOS requires your approval before AgentJail can launch at login."
        case .notFound:
            "macOS could not find a login-item registration for this app installation."
        case .unknown:
            "macOS returned an unrecognized launch-at-login status."
        }
    }

    private var telemetryDetail: String {
        switch composition.telemetryStatus {
        case .unknown:
            "Checking the local telemetry setting…"
        case .enabled(.config):
            "Enabled in AgentJail settings. You can turn it off here at any time."
        case .disabled(.config):
            "Disabled in AgentJail settings. No new usage events will be sent."
        case .enabled(.environment), .disabled(.environment):
            "Controlled by AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS in this environment."
        case .enabled(.continuousIntegration), .disabled(.continuousIntegration):
            "Disabled automatically in continuous integration."
        case .enabled(.unknown), .disabled(.unknown):
            "Controlled by a setting this app does not recognize. Use the AgentJail CLI to change it."
        case .updating:
            "Saving your choice…"
        case .unavailable:
            "The bundled AgentJail CLI could not read this setting."
        }
    }
}

private struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.headline)
                .padding(.leading, 2)
            AgentJailSurface { VStack(spacing: 14) { content } }
        }
    }
}

private struct SettingsRow<Trailing: View>: View {
    let icon: String
    let color: Color
    let title: String
    let detail: String
    @ViewBuilder let trailing: Trailing

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            AgentJailIconTile(systemImage: icon, color: color)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.callout.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 16)
            trailing
        }
    }
}
