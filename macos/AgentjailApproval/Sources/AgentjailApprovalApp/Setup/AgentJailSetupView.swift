import ServiceManagement
import SwiftUI

struct AgentJailSetupView: View {
    @ObservedObject private var coordinator: AgentJailSetupCoordinator
    let onOpenSettings: () -> Void

    init(coordinator: AgentJailSetupCoordinator, onOpenSettings: @escaping () -> Void) {
        _coordinator = ObservedObject(wrappedValue: coordinator)
        self.onOpenSettings = onOpenSettings
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                hero
                setupExplanation
                setupStatus
                privacyNote
            }
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minWidth: 660, minHeight: 600)
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            _ = await coordinator.refresh()
        }
    }

    private var hero: some View {
        HStack(alignment: .top, spacing: 18) {
            Image(nsImage: NSApplication.shared.applicationIconImage)
                .resizable()
                .frame(width: 76, height: 76)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 7) {
                Text("AgentJail")
                    .font(.largeTitle.bold())
                Text("One guardrail for every coding agent")
                    .font(.title3.weight(.medium))
                Text("Protect tool calls, credentials, files, and outbound traffic without changing the agents you already use.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var setupExplanation: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("What setup does")
                .font(.headline)
            SetupExplanationRow(
                number: 1,
                title: "Install local components",
                detail: "Copies the bundled CLI into ~/.agentjail, starts the local daemon, and wires hooks for detected agents."
            )
            SetupExplanationRow(
                number: 2,
                title: "Ask macOS for network access",
                detail: "macOS shows a one-time approval for the signed AgentJail Network Extension. AgentJail cannot approve it for you."
            )
            SetupExplanationRow(
                number: 3,
                title: "Keep certificate trust inside protected sessions",
                detail: "A fresh local CA is created for each protected run and injected only into that agent. No system-wide root certificate is installed."
            )
        }
        .padding(18)
        .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
    }

    private var setupStatus: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Setup status")
                    .font(.headline)
                Spacer()
                setupBadge
            }

            HStack(spacing: 10) {
                HealthChip(title: "App", complete: coordinator.health.appInApplications)
                HealthChip(title: "CLI", complete: coordinator.health.cliInstalled)
                HealthChip(title: "Daemon", complete: coordinator.health.daemonReachable)
                HealthChip(title: "Network", complete: coordinator.health.tunnelProfile.isConfigured)
            }

            Text(statusDetail)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            actionControls
        }
        .padding(18)
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.secondary.opacity(0.18), lineWidth: 1)
        }
    }

    private var setupBadge: some View {
        Label(statusTitle, systemImage: statusIcon)
            .font(.caption.weight(.semibold))
            .foregroundStyle(statusColor)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(statusColor.opacity(0.1), in: Capsule())
    }

    @ViewBuilder
    private var actionControls: some View {
        switch coordinator.phase {
        case .moveToApplications:
            HStack {
                Button("Open Applications Folder") {
                    NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications", isDirectory: true))
                }
                .buttonStyle(.borderedProminent)
                Button("Check again") { coordinator.retry() }
            }
        case .readyToInstall:
            Button("Install AgentJail") { coordinator.beginSetup() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        case .awaitingApproval:
            Button("Open Login Items & Extensions") {
                SMAppService.openSystemSettingsLoginItems()
            }
            .buttonStyle(.borderedProminent)
        case .failed:
            HStack {
                Button("Try again") { coordinator.beginSetup() }
                    .buttonStyle(.borderedProminent)
                Button("Check status") { coordinator.retry() }
            }
        case .ready:
            HStack {
                Label("AgentJail is ready", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                    .font(.headline)
                Spacer()
                Button("Refresh") { coordinator.retry() }
            }
        case .checking, .installingComponents, .enablingExtension, .verifying:
            ProgressView()
                .controlSize(.small)
        }
    }

    private var privacyNote: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "hand.raised.fill")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text("Privacy-safe product metrics")
                    .font(.callout.weight(.semibold))
                Text("Anonymous setup metrics contain only the app version and fixed setup stage/outcome enums. They never include hosts, paths, commands, traffic, or error text.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Review telemetry settings", action: onOpenSettings)
                    .buttonStyle(.link)
            }
        }
    }

    private var statusTitle: String {
        switch coordinator.phase {
        case .checking: "Checking"
        case .moveToApplications: "Action needed"
        case .readyToInstall: "Ready to install"
        case .installingComponents: "Installing"
        case .enablingExtension: "Enabling network"
        case .awaitingApproval: "Approval needed"
        case .verifying: "Verifying"
        case .ready: "Protected"
        case .failed: "Needs attention"
        }
    }

    private var statusDetail: String {
        switch coordinator.phase {
        case .checking:
            "Checking the app, CLI, daemon, and Network Extension."
        case .moveToApplications:
            "Drag AgentJail into Applications, open that copy, then check again. macOS requires the Network Extension host to stay at a stable application path."
        case .readyToInstall:
            "AgentJail is ready to install its user-level components and request the one-time Apple approval."
        case .installingComponents:
            "Installing the CLI, daemon, policy rules, and detected agent hooks in your user account."
        case .enablingExtension:
            "Requesting activation of the signed AgentJail Network Extension. macOS may ask for your approval next."
        case .awaitingApproval:
            "In System Settings, open General → Login Items & Extensions → Network Extensions and enable AgentJail. Setup will continue automatically."
        case .verifying:
            "Confirming that the daemon answers locally and the network profile is enabled."
        case .ready:
            "The local daemon and Network Extension are ready. Start an agent through AgentJail to enforce network policy and process-local TLS inspection."
        case let .failed(failure):
            switch failure {
            case .componentInstall:
                "The local components could not be installed. Nothing was approved or weakened; try again after checking that this app is in Applications."
            case .extensionInstall:
                "The Network Extension did not finish activation. Check Login Items & Extensions, then try again."
            case .verification:
                "Setup finished, but one or more health checks did not become ready. Check status and retry."
            }
        }
    }

    private var statusIcon: String {
        switch coordinator.phase {
        case .ready: "checkmark.shield.fill"
        case .failed: "exclamationmark.triangle.fill"
        case .moveToApplications, .awaitingApproval: "hand.raised.fill"
        case .checking, .installingComponents, .enablingExtension, .verifying: "arrow.triangle.2.circlepath"
        case .readyToInstall: "shield"
        }
    }

    private var statusColor: Color {
        switch coordinator.phase {
        case .ready: .green
        case .failed: .red
        case .moveToApplications, .awaitingApproval: .orange
        case .checking, .installingComponents, .enablingExtension, .verifying: .secondary
        case .readyToInstall: .accentColor
        }
    }
}

private struct SetupExplanationRow: View {
    let number: Int
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(String(number))
                .font(.caption.bold())
                .foregroundStyle(.white)
                .frame(width: 24, height: 24)
                .background(Color.accentColor, in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.callout.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Step \(number). \(title). \(detail)")
    }
}

private struct HealthChip: View {
    let title: String
    let complete: Bool

    var body: some View {
        Label(title, systemImage: complete ? "checkmark.circle.fill" : "circle")
            .font(.caption.weight(.medium))
            .foregroundStyle(complete ? .green : .secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Color.secondary.opacity(0.07), in: Capsule())
            .accessibilityValue(complete ? "ready" : "not ready")
    }
}
