import AgentjailApprovalCore
import SwiftUI

struct ApprovalSettingsView: View {
    @ObservedObject private var composition: ApprovalAppComposition

    init(composition: ApprovalAppComposition) {
        _composition = ObservedObject(wrappedValue: composition)
    }

    var body: some View {
        Form {
            Section("AgentJail daemon") {
                Text(PanelPresentation(
                    state: composition.store.state,
                    actionStates: composition.store.actionStates,
                    now: SystemApprovalClock().now()
                ).status.detail)
                Button("Retry") {
                    composition.refreshFromMenuOpening()
                }
            }

            Section("Notifications") {
                Text(notificationDetail)
                if composition.notificationAuthorization != .authorized {
                    Button("Enable notifications") {
                        Task {
                            await composition.enableNotificationsFromUserAction()
                        }
                    }
                }
                if composition.notificationAuthorization == .denied {
                    Text("To change this choice, open System Settings > Notifications > AgentJail.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Launch at login") {
                Toggle("Launch AgentJail at login", isOn: loginItemEnabled)
                Text(loginDetail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if composition.loginStatus == .requiresApproval {
                    Button("Open Login Items Settings") {
                        composition.openLoginItemsSettings()
                    }
                }
            }

            Section("Approval scope") {
                Text("Approve for future sessions adds the displayed host to the verified project policy. The current session is unchanged.")
                Text("The app communicates only with the local AgentJail daemon. It does not store the control token or read AgentJail databases.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("MCP inventory") {
                Text("Observe-only discovery reads global Claude Code, Codex, and Cursor MCP configuration without launching servers or changing files.")
                Button("Open MCP inventory") {
                    composition.requestMCPInventory()
                }
            }

            Section("Anonymous usage metrics") {
                Toggle("Share anonymous usage metrics", isOn: telemetryEnabled)
                    .disabled(!composition.telemetryStatus.canChange)
                Text(telemetryDetail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Setup metrics contain only fixed stage and outcome values plus app version, OS, and architecture. They never include traffic, hosts, paths, commands, or error text.")
                Text("Review queued events: agentjail telemetry view")
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }

            if let settingsError = composition.settingsError {
                Section {
                    Text(settingsError)
                        .foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 520, height: 520)
        .task {
            await composition.refreshSettingsStatus()
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
