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
                    Text("To change this choice, open System Settings > Notifications > AgentJail Approval.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Launch at login") {
                Toggle("Launch AgentJail Approval at login", isOn: loginItemEnabled)
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
                Text("This companion communicates only with the local AgentJail daemon. It does not store the control token or read AgentJail databases.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let settingsError = composition.settingsError {
                Section {
                    Text(settingsError)
                        .foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 480, height: 420)
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
            "AgentJail Approval is enabled to launch at login."
        case .notRegistered:
            "AgentJail Approval is not configured to launch at login."
        case .requiresApproval:
            "macOS requires your approval before AgentJail Approval can launch at login."
        case .notFound:
            "macOS could not find a login-item registration for this app installation."
        case .unknown:
            "macOS returned an unrecognized launch-at-login status."
        }
    }
}
