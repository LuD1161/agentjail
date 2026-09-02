import AgentjailApprovalCore
import SwiftUI

struct SessionLogsView: View {
    @ObservedObject private var store: ActivityStore
    @State private var searchText = ""
    @State private var filter: SessionActionFilter = .all

    init(store: ActivityStore) {
        _store = ObservedObject(wrappedValue: store)
    }

    var body: some View {
        AgentJailPage {
            AgentJailPageHeader(
                eyebrow: "",
                title: "Logs",
                detail: "Every audited action, grouped by agent session"
            ) {
                Button { Task { await store.refreshLogs() } } label: {
                    Label(store.isRefreshingLogs ? "Refreshing" : "Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(store.isRefreshingLogs)
                .agentJailInteractiveHover()
            }

            if let snapshot = store.sessionLogSnapshot {
                if snapshot.sessions.isEmpty {
                    ActivityUnavailableCard(
                        systemImage: "list.bullet.rectangle.portrait",
                        title: "No audited sessions yet",
                        detail: "Start a protected agent session. Its file, shell, MCP, and policy actions will appear here automatically."
                    )
                } else {
                    SessionChooser(snapshot: snapshot, store: store)
                    let selectedID = store.selectedSessionID.isEmpty ? snapshot.selectedSessionID : store.selectedSessionID
                    if let selected = snapshot.sessions.first(where: { $0.sessionID == selectedID }) {
                        SessionSummaryCard(
                            session: selected,
                            loadedCount: store.sessionEntries.count,
                            totalMatches: store.logTotalMatches
                        )
                        SessionActionTable(
                            entries: store.sessionEntries,
                            totalMatches: store.logTotalMatches,
                            auditedCalls: selected.auditedCalls,
                            store: store,
                            searchText: $searchText,
                            filter: $filter
                        )
                    }
                }
            } else if store.logsUnavailable {
                ActivityUnavailableCard(
                    systemImage: "exclamationmark.triangle",
                    title: "Session logs unavailable",
                    detail: "AgentJail could not read the local audit feed. Check that the daemon is running, then refresh."
                )
            } else {
                ActivityLoadingCard(title: "Loading session logs…")
            }
        }
        .task { store.startLogPolling() }
        .task(id: LogQueryKey(search: searchText, filter: filter)) {
            if !searchText.isEmpty {
                do { try await Task.sleep(for: .milliseconds(250)) }
                catch { return }
            }
            store.setLogQuery(search: searchText, outcomes: filter.outcomes)
        }
        .onDisappear { store.stopLogPolling() }
    }
}

private struct LogQueryKey: Hashable {
    let search: String
    let filter: SessionActionFilter
}

private struct SessionChooser: View {
    let snapshot: SessionLogSnapshotV1
    @ObservedObject var store: ActivityStore

    var body: some View {
        HStack(spacing: 12) {
            Text("Session").font(.headline)
            Picker("Session", selection: Binding(
                get: { store.selectedSessionID.isEmpty ? snapshot.selectedSessionID : store.selectedSessionID },
                set: { store.selectSession($0) }
            )) {
                ForEach(snapshot.sessions) { session in
                    Text(sessionLabel(session)).tag(session.sessionID)
                }
            }
            .labelsHidden()
            .frame(maxWidth: 430)
            Spacer()
            AgentJailStatusPill(title: "Updates every 2 seconds", color: .green)
        }
    }

    private func sessionLabel(_ session: ActivitySession) -> String {
        let project = session.project.isEmpty ? "Local session" : session.project
        let state = session.active ? "Live" : Date(timeIntervalSince1970: Double(session.startedAtUnixMs) / 1_000).formatted(date: .abbreviated, time: .shortened)
        return "\(session.agent) · \(project) · \(state)"
    }
}

private struct SessionSummaryCard: View {
    let session: ActivitySession
    let loadedCount: Int
    let totalMatches: Int

    var body: some View {
        AgentJailCardSurface(padding: 18) {
            HStack(spacing: 16) {
                AgentBrandMark(agent: session.agent, size: 36)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(session.agent.isEmpty ? "Agent session" : session.agent).font(.headline)
                        if session.active { AgentJailStatusPill(title: "Live", color: .green) }
                    }
                    Text(session.project.isEmpty ? "Local session" : session.project)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(shortSessionID).font(.caption.monospaced()).foregroundStyle(.tertiary)
                }
                Spacer()
                summaryMetric("Audited actions", value: session.auditedCalls.formatted())
                Divider().frame(height: 34)
                summaryMetric("Loaded", value: "\(loadedCount.formatted()) of \(totalMatches.formatted())")
                Divider().frame(height: 34)
                summaryMetric("Started", value: startedText)
            }
        }
    }

    private func summaryMetric(_ title: String, value: String) -> some View {
        VStack(alignment: .trailing, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout.weight(.semibold)).monospacedDigit()
        }
    }

    private var shortSessionID: String {
        session.sessionID.count > 28 ? "\(session.sessionID.prefix(12))…\(session.sessionID.suffix(8))" : session.sessionID
    }

    private var startedText: String {
        Date(timeIntervalSince1970: Double(session.startedAtUnixMs) / 1_000).formatted(date: .abbreviated, time: .shortened)
    }
}

private enum SessionActionFilter: String, CaseIterable, Identifiable {
    case all, allowed, asked, denied
    var id: String { rawValue }
    var label: String {
        switch self {
        case .all: "All"
        case .allowed: "Allowed"
        case .asked: "Asked"
        case .denied: "Denied"
        }
    }

    var outcomes: [SessionActionOutcome] {
        switch self {
        case .all: []
        case .allowed: [.allow]
        case .asked: [.ask]
        case .denied: [.deny, .block]
        }
    }
}

private struct SessionActionTable: View {
    let entries: [SessionAction]
    let totalMatches: Int
    let auditedCalls: Int
    @ObservedObject var store: ActivityStore
    @Binding var searchText: String
    @Binding var filter: SessionActionFilter
    @State private var selectedEntry: SessionAction?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Session actions").font(.title3.bold())
                    Text(isFiltering
                         ? "Newest first · searching all \(auditedCalls.formatted()) audited actions"
                         : "Newest first · all \(auditedCalls.formatted()) actions are searchable")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text("\(entries.count.formatted()) of \(totalMatches.formatted()) loaded")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 13)
            .agentJailTableSectionBackground(Color.primary.opacity(0.018))
            HStack(spacing: 12) {
                TextField("Search all \(auditedCalls.formatted()) actions", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 310)
                Picker("Decision", selection: $filter) {
                    ForEach(SessionActionFilter.allCases) { item in Text(item.label).tag(item) }
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
            SessionActionHeader()
            Divider()
            if entries.isEmpty, store.isRefreshingLogs {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(isFiltering ? "Searching all session actions…" : "Loading session actions…")
                        .foregroundStyle(.secondary)
                }
                .font(.callout)
                .frame(maxWidth: .infinity, minHeight: 120)
            } else if entries.isEmpty {
                Text(totalMatches == 0 && isFiltering ? "No actions match these filters." : "No audited actions were recorded for this session.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 120)
            } else {
                LazyVStack(spacing: 0) {
                    ForEach(entries) { entry in
                        SessionActionRow(entry: entry) {
                            selectedEntry = entry
                            Task { await store.loadActionDetail(entry) }
                        }
                        if entry.id != entries.last?.id { Divider().padding(.leading, 16) }
                    }
                }
            }
            if store.logHasMore {
                Divider()
                Button {
                    Task { await store.loadMoreLogs() }
                } label: {
                    HStack(spacing: 8) {
                        if store.isLoadingMoreLogs { ProgressView().controlSize(.small) }
                        Text(store.isLoadingMoreLogs ? "Loading older actions…" : "Load older actions")
                    }
                    .frame(maxWidth: .infinity, minHeight: 44)
                }
                .buttonStyle(.plain)
                .disabled(store.isLoadingMoreLogs || store.isRefreshingLogs)
                .agentJailInteractiveHover()
            } else if !entries.isEmpty {
                Divider()
                Label("All \(totalMatches.formatted()) matching actions loaded", systemImage: "checkmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 42)
            }
        }
        .compositingGroup()
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .agentJailCardSurface(cornerRadius: 12)
        .sheet(item: $selectedEntry) { entry in
            SessionActionDetailSheet(entry: entry, store: store)
                .onDisappear { store.clearActionDetail() }
        }
    }

    private var isFiltering: Bool {
        !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || filter != .all
    }
}

private struct SessionActionHeader: View {
    var body: some View {
        HStack(spacing: 14) {
            Text("TIME").frame(width: 68, alignment: .leading)
            Text("ACTION").frame(maxWidth: .infinity, alignment: .leading)
            Text("TOOL").frame(width: 110, alignment: .leading)
            Text("DECISION").frame(width: 80, alignment: .leading)
            Text("RULE").frame(width: 180, alignment: .leading)
            Text("LATENCY").frame(width: 64, alignment: .trailing)
            Color.clear.frame(width: 10)
        }
        .font(.caption.weight(.bold))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 16)
        .frame(minHeight: 42)
        .agentJailTableSectionBackground(Color.primary.opacity(0.025))
        .accessibilityHidden(true)
    }
}

private struct SessionActionRow: View {
    let entry: SessionAction
    let open: () -> Void
    @State private var isHovering = false

    var body: some View {
        let decision = displayAction(entry)
        Button(action: open) {
            HStack(spacing: 14) {
                Text(Date(timeIntervalSince1970: Double(entry.timestampUnixMs) / 1_000).formatted(date: .omitted, time: .shortened))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .frame(width: 68, alignment: .leading)
                HStack(spacing: 10) {
                    AgentJailIconTile(systemImage: actionIcon(entry), color: actionColor(decision))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.summary.isEmpty ? entry.toolName : entry.summary)
                            .font(.callout.weight(.medium))
                            .lineLimit(1)
                        if !entry.reason.isEmpty {
                            Text(entry.reason).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Text(entry.toolName)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .frame(width: 110, alignment: .leading)
                Text(decision.capitalized)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(actionColor(decision))
                    .frame(width: 80, alignment: .leading)
                Text(entry.ruleID.isEmpty ? "—" : entry.ruleID)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(width: 180, alignment: .leading)
                Text(latencyText)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .frame(width: 64, alignment: .trailing)
                Image(systemName: "chevron.right")
                    .font(.caption.bold())
                    .foregroundStyle(.tertiary)
                    .frame(width: 10)
                    .accessibilityHidden(true)
            }
            .padding(.horizontal, 16)
            .frame(minHeight: 58)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .agentJailTableSectionBackground(Color.primary.opacity(isHovering ? 0.045 : 0))
        .animation(.easeOut(duration: 0.12), value: isHovering)
        .onHover { isHovering = $0 }
        .agentJailPointingCursor()
        .help(helpText)
        .accessibilityHint("Opens full recorded action details")
    }

    private var latencyText: String {
        entry.elapsedUs < 1_000 ? "\(entry.elapsedUs) µs" : String(format: "%.1f ms", Double(entry.elapsedUs) / 1_000)
    }

    private var helpText: String {
        [entry.summary, entry.reason, entry.impact, entry.ruleID].filter { !$0.isEmpty }.joined(separator: "\n")
    }
}

private struct SessionActionDetailSheet: View {
    let entry: SessionAction
    @ObservedObject var store: ActivityStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                AgentJailIconTile(systemImage: actionIcon(entry), color: actionColor(displayAction(entry)))
                VStack(alignment: .leading, spacing: 2) {
                    Text(entry.toolName).font(.title2.bold())
                    Text(timestampText).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(displayAction(entry).capitalized)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(actionColor(displayAction(entry)))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(actionColor(displayAction(entry)).opacity(0.10), in: Capsule())
                Button { dismiss() } label: { Image(systemName: "xmark") }
                    .buttonStyle(.plain)
                    .focusable(false)
                    .agentJailInteractiveHover()
                    .accessibilityLabel("Close action details")
            }
            .padding(22)
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    detailSection(title: "Recorded command") {
                        if let command = store.actionDetail?.command, !command.isEmpty {
                            VStack(alignment: .trailing, spacing: 10) {
                                ScrollView(.horizontal) {
                                    Text(command)
                                        .font(.system(.body, design: .monospaced))
                                        .textSelection(.enabled)
                                        .fixedSize(horizontal: true, vertical: false)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(14)
                                }
                                .frame(maxWidth: .infinity, minHeight: 74, maxHeight: 180)
                                .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
                                AgentJailCopyButton(title: "Copy command", text: command)
                                    .buttonStyle(.bordered)
                                    .focusable(false)
                            }
                        } else if store.actionDetailUnavailable {
                            Label("The full command could not be loaded. The action summary remains available below.", systemImage: "exclamationmark.triangle")
                                .foregroundStyle(.secondary)
                        } else if store.isLoadingActionDetail || store.actionDetail == nil {
                            HStack(spacing: 10) {
                                ProgressView().controlSize(.small)
                                Text("Loading the recorded command…").foregroundStyle(.secondary)
                            }
                            .frame(minHeight: 54)
                        } else {
                            Label("This action did not record a shell command.", systemImage: "info.circle")
                                .foregroundStyle(.secondary)
                        }
                    }

                    detailSection(title: "Action") {
                        VStack(alignment: .leading, spacing: 9) {
                            if !entry.summary.isEmpty { labeled("Summary", entry.summary) }
                            labeled("Tool", entry.toolName)
                            if !entry.reason.isEmpty { labeled("Reason", entry.reason) }
                            if !entry.impact.isEmpty { labeled("Impact", entry.impact) }
                        }
                    }

                    detailSection(title: "Policy decision") {
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 12) {
                            metric("Rule", entry.ruleID.isEmpty ? "—" : entry.ruleID)
                            metric("Effective action", displayAction(entry).capitalized)
                            metric("Policy action", entry.policyAction.isEmpty ? "—" : entry.policyAction.capitalized)
                            metric("Enforcer", entry.enforcer.isEmpty ? "—" : entry.enforcer)
                            metric("Adapter", entry.adapter.isEmpty ? "—" : entry.adapter)
                            metric("Latency", detailLatencyText)
                        }
                    }
                }
                .padding(22)
            }
        }
        .frame(minWidth: 720, idealWidth: 820, minHeight: 500, idealHeight: 620)
    }

    private func detailSection<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.headline)
            content()
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .agentJailCardSurface(cornerRadius: 12)
        }
    }

    private func labeled(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }

    private func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout.weight(.medium)).lineLimit(2).textSelection(.enabled)
        }
    }

    private var timestampText: String {
        Date(timeIntervalSince1970: Double(entry.timestampUnixMs) / 1_000).formatted(date: .long, time: .standard)
    }

    private var detailLatencyText: String {
        entry.elapsedUs < 1_000 ? "\(entry.elapsedUs) µs" : String(format: "%.1f ms", Double(entry.elapsedUs) / 1_000)
    }
}

private func displayAction(_ entry: SessionAction) -> String {
    for value in [entry.finalAction, entry.effectiveAction, entry.policyAction, entry.action] where !value.isEmpty {
        return value
    }
    return "observed"
}

private func actionColor(_ action: String) -> Color {
    switch action.lowercased() {
    case "allow": .green
    case "ask": .orange
    case "deny", "block": .red
    default: .blue
    }
}

private func actionIcon(_ entry: SessionAction) -> String {
    let tool = entry.toolName.lowercased()
    if tool.contains("bash") || tool.contains("shell") { return "terminal.fill" }
    if tool.contains("mcp") { return "point.3.connected.trianglepath.dotted" }
    if tool.contains("read") { return "doc.text.magnifyingglass" }
    if tool.contains("write") || tool.contains("edit") { return "pencil.line" }
    if tool.contains("web") || tool.contains("network") { return "network" }
    return "checkmark.shield"
}

struct ActivityLoadingCard: View {
    let title: String

    var body: some View {
        AgentJailCardSurface {
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text(title).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 140)
        }
    }
}

struct ActivityUnavailableCard: View {
    let systemImage: String
    let title: String
    let detail: String

    var body: some View {
        AgentJailCardSurface {
            VStack(spacing: 9) {
                Image(systemName: systemImage).font(.system(size: 28)).foregroundStyle(.secondary)
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, minHeight: 160)
        }
    }
}
