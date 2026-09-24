import AgentjailApprovalCore
import SwiftUI

struct NetworkActivityView: View {
    @ObservedObject private var store: ActivityStore
    @ObservedObject private var setup: AgentJailSetupCoordinator
    let showSetup: () -> Void
    let openExtensionSettings: () -> Void
    @State private var searchText = ""
    @State private var filter: NetworkEventFilter = .all

    init(store: ActivityStore, setup: AgentJailSetupCoordinator, showSetup: @escaping () -> Void, openExtensionSettings: @escaping () -> Void) {
        _store = ObservedObject(wrappedValue: store)
        _setup = ObservedObject(wrappedValue: setup)
        self.showSetup = showSetup
        self.openExtensionSettings = openExtensionSettings
    }

    var body: some View {
        AgentJailPage {
            AgentJailPageHeader(
                eyebrow: "",
                title: "Network",
                detail: "Live traffic observed from protected agent sessions"
            ) {
                HStack(spacing: 10) {
                    if setup.health.tunnelProfile.isConfigured {
                        AgentJailStatusPill(title: tunnelStatusTitle, color: tunnelStatusColor)
                    }
                    Button { Task { await refresh() } } label: {
                        Label(store.isRefreshingNetwork ? "Refreshing" : "Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(store.isRefreshingNetwork)
                    .agentJailInteractiveHover()
                }
            }

            if !setup.health.tunnelProfile.isConfigured {
                NetworkExtensionMissingCard(setup: setup, showSetup: showSetup, openExtensionSettings: openExtensionSettings)
            }

            if let snapshot = store.networkSnapshot {
                NetworkEventTable(events: snapshot.events, searchText: $searchText, filter: $filter)
            } else if store.networkUnavailable {
                ActivityUnavailableCard(
                    systemImage: "network.slash",
                    title: "Network activity unavailable",
                    detail: "AgentJail could not read the local network event feed. Check that the daemon is running, then refresh."
                )
            } else {
                ActivityLoadingCard(title: "Loading network events…")
            }
        }
        .task {
            _ = await setup.refresh()
            store.startNetworkPolling()
        }
        .onDisappear { store.stopNetworkPolling() }
    }

    private func refresh() async {
        async let health: AgentJailSetupHealth = setup.refresh()
        async let events: Void = store.refreshNetwork()
        _ = await (health, events)
    }

    private var tunnelStatusTitle: String {
        switch setup.health.tunnelProfile {
        case .connected: "Monitoring"
        case .connecting: "Connecting"
        case .disconnecting: "Disconnecting"
        case .disconnected: "Ready"
        case .absent, .disabled, .invalid: "Not installed"
        }
    }

    private var tunnelStatusColor: Color {
        switch setup.health.tunnelProfile {
        case .connected: .green
        case .connecting, .disconnecting, .disconnected: .orange
        case .absent, .disabled, .invalid: .red
        }
    }
}

private struct NetworkExtensionMissingCard: View {
    @ObservedObject var setup: AgentJailSetupCoordinator
    let showSetup: () -> Void
    let openExtensionSettings: () -> Void

    var body: some View {
        AgentJailCardSurface(padding: 20) {
            VStack(alignment: .leading, spacing: 14) {
                Label("Add network monitoring", systemImage: "network")
                    .font(.headline)
                Text("Optional. Inspect traffic from agent sessions and evaluate network policies. Your session dashboard and tool-call policies work without network monitoring.")
                    .font(.callout).foregroundStyle(.secondary)
                Text("macOS will ask you to approve the AgentJail Network Extension. Certificate trust stays inside agent sessions; no system-wide root certificate is installed. Enabling monitoring does not turn on policy enforcement.")
                    .font(.caption).foregroundStyle(.secondary)
                if setup.phase == .awaitingApproval {
                    Text("General → Login Items & Extensions → Network Extensions → AgentJail")
                        .font(.callout)
                    Button("Open System Settings", action: openExtensionSettings)
                        .buttonStyle(.borderedProminent)
                } else if setup.phase.isWorking {
                    ProgressView("Preparing network monitoring…")
                } else if setup.health.localComponentsReady {
                    if case .failed = setup.phase {
                        Text("Network setup did not finish. Check macOS approval and try again.")
                            .foregroundStyle(.secondary)
                    }
                    Button("Enable Network Monitoring") { setup.beginSetup() }
                        .buttonStyle(.borderedProminent)
                        .agentJailInteractiveHover()
                } else {
                    Button("Set Up Local Components", action: showSetup)
                        .buttonStyle(.borderedProminent)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private enum NetworkEventFilter: String, CaseIterable, Identifiable {
    case all, allowed, blocked, errors
    var id: String { rawValue }
    var label: String {
        switch self {
        case .all: "All"
        case .allowed: "Allowed"
        case .blocked: "Blocked"
        case .errors: "Errors"
        }
    }
}

private struct NetworkEventTable: View {
    let events: [NetworkEvent]
    @Binding var searchText: String
    @Binding var filter: NetworkEventFilter

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 16) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Recent traffic").font(.title3.bold())
                    Text("Newest first · updates every 2 seconds")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                AgentJailStatusPill(title: "Live", color: .green)
                Text("\(visibleEvents.count) events")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 13)
            .agentJailTableSectionBackground(Color.primary.opacity(0.018))

            HStack(spacing: 12) {
                TextField("Filter by host, path, agent, or policy", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 310)
                Picker("Outcome", selection: $filter) {
                    ForEach(NetworkEventFilter.allCases) { item in Text(item.label).tag(item) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 360)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 12)
            .agentJailTableSectionBackground(Color.primary.opacity(0.018))
            Divider()
            NetworkEventHeader()
            Divider()

            if visibleEvents.isEmpty {
                VStack(spacing: 9) {
                    Image(systemName: events.isEmpty ? "network" : "line.3.horizontal.decrease.circle")
                        .font(.system(size: 26))
                        .foregroundStyle(.secondary)
                    Text(events.isEmpty ? "No network events yet" : "No events match these filters")
                        .font(.headline)
                    Text(events.isEmpty ? "Start a protected agent session; observed requests will appear here automatically." : "Try another host, agent, or outcome filter.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 150)
            } else {
                LazyVStack(spacing: 0) {
                    ForEach(visibleEvents) { event in
                        NetworkEventRow(event: event)
                        if event.id != visibleEvents.last?.id { Divider().padding(.leading, 16) }
                    }
                }
            }
        }
        .compositingGroup()
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .agentJailCardSurface(cornerRadius: 12)
    }

    private var visibleEvents: [NetworkEvent] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return events.filter { event in
            let matchesFilter: Bool = switch filter {
            case .all: true
            case .allowed: event.policyAction.lowercased() == "allow" && event.error.isEmpty
            case .blocked: ["deny", "block"].contains(event.policyAction.lowercased())
            case .errors: !event.error.isEmpty || event.statusCode >= 400
            }
            let haystack = "\(event.host) \(event.path) \(event.agent) \(event.project) \(event.policyAction) \(event.wouldAction) \(event.policyReason)".lowercased()
            return matchesFilter && (query.isEmpty || haystack.contains(query))
        }
    }
}

private struct NetworkEventHeader: View {
    var body: some View {
        HStack(spacing: 14) {
            Text("TIME").frame(width: 68, alignment: .leading)
            Text("DESTINATION").frame(maxWidth: .infinity, alignment: .leading)
            Text("METHOD").frame(width: 62, alignment: .leading)
            Text("STATUS").frame(width: 58, alignment: .trailing)
            Text("AGENT / PROJECT").frame(width: 145, alignment: .leading)
            Text("POLICY").frame(width: 88, alignment: .leading)
            Text("LATENCY").frame(width: 64, alignment: .trailing)
        }
        .font(.caption.weight(.bold))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 16)
        .frame(minHeight: 42)
        .agentJailTableSectionBackground(Color.primary.opacity(0.025))
        .accessibilityHidden(true)
    }
}

private struct NetworkEventRow: View {
    let event: NetworkEvent
    @State private var isHovering = false

    var body: some View {
        HStack(spacing: 14) {
            Text(Date(timeIntervalSince1970: Double(event.timestampUnixMs) / 1_000).formatted(date: .omitted, time: .shortened))
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 68, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(event.host).font(.callout.weight(.semibold)).lineLimit(1)
                Text(event.path.isEmpty ? "/" : event.path)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Text(event.method.isEmpty ? "—" : event.method)
                .font(.caption.weight(.semibold).monospaced())
                .frame(width: 62, alignment: .leading)
            Text(event.statusCode == 0 ? "—" : String(event.statusCode))
                .font(.callout.monospacedDigit())
                .foregroundStyle(statusColor)
                .frame(width: 58, alignment: .trailing)
            HStack(spacing: 7) {
                AgentBrandMark(agent: event.agent, size: 20)
                VStack(alignment: .leading, spacing: 1) {
                    Text(event.agent.isEmpty ? "Unknown" : event.agent).lineLimit(1)
                    Text(event.project.isEmpty ? "Local session" : event.project).foregroundStyle(.secondary).lineLimit(1)
                }
                .font(.caption)
            }
            .frame(width: 145, alignment: .leading)
            Text(event.wouldAction.isEmpty
                 ? (event.policyAction.isEmpty ? "Observed" : event.policyAction.capitalized)
                 : "Would \(event.wouldAction)")
                .font(.caption.weight(.semibold))
                .foregroundStyle(policyColor)
                .frame(width: 88, alignment: .leading)
            Text(durationText)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 64, alignment: .trailing)
        }
        .padding(.horizontal, 16)
        .frame(minHeight: 58)
        .contentShape(Rectangle())
        .agentJailTableSectionBackground(Color.primary.opacity(isHovering ? 0.045 : 0))
        .animation(.easeOut(duration: 0.12), value: isHovering)
        .onHover { isHovering = $0 }
        .help(helpText)
    }

    private var statusColor: Color {
        if !event.error.isEmpty || event.statusCode >= 500 { return .red }
        if event.statusCode >= 400 { return .orange }
        return .primary
    }

    private var policyColor: Color {
        switch event.policyAction.lowercased() {
        case "deny", "block": .red
        case "ask": .orange
        case "allow": .green
        default: .secondary
        }
    }

    private var durationText: String {
        event.elapsedMs < 1_000 ? "\(event.elapsedMs) ms" : String(format: "%.1f s", Double(event.elapsedMs) / 1_000)
    }

    private var helpText: String {
        var detail = "\(event.method) \(event.host)\(event.path)"
        if !event.policyReason.isEmpty { detail += "\n\(event.policyReason)" }
        if !event.error.isEmpty { detail += "\nError: \(event.error)" }
        return detail
    }
}
