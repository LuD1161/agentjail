import SwiftUI

struct PoliciesView: View {
    @ObservedObject private var store: PolicyInventoryStore
    @State private var selectedPolicy: PolicyInventorySnapshot.Policy?

    init(store: PolicyInventoryStore) {
        _store = ObservedObject(wrappedValue: store)
    }

    var body: some View {
        AgentJailPage {
            AgentJailPageHeader(
                eyebrow: "",
                title: "Policies",
                detail: pageDetail
            ) {
                Button {
                    Task { await store.refresh() }
                } label: {
                    Label(store.isRefreshing ? "Refreshing" : "Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(store.isRefreshing)
                .agentJailInteractiveHover()
            }
            content
        }
        .task { await store.refresh() }
        .sheet(item: $selectedPolicy) { policy in
            PolicyDetailSheet(
                policy: policy,
                rego: store.snapshot?.rego(for: policy) ?? "",
                historyAvailable: store.snapshot?.historyAvailable ?? false
            )
        }
    }

    private var pageDetail: String {
        guard let snapshot = store.snapshot else { return "Active local Rego rules and recorded matches" }
        return "\(snapshot.policies.count) active rules · counts show selected policy decisions"
    }

    @ViewBuilder
    private var content: some View {
        if let snapshot = store.snapshot {
            if snapshot.policies.isEmpty {
                PolicyEmptyState(
                    title: "No active policies found",
                    detail: "Install local components or check the active rules directory, then refresh."
                )
            } else {
                PolicyTable(snapshot: snapshot, selectedPolicy: $selectedPolicy)
                PolicyCoverageNote(historyAvailable: snapshot.historyAvailable, limited: snapshot.breakdownLimited)
            }
        } else if store.unavailable {
            PolicyEmptyState(
                title: "Policy inventory unavailable",
                detail: "AgentJail could not read the local policy projection. Check local components and try again."
            )
        } else {
            AgentJailCardSurface {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text("Loading active policies…")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 140)
            }
        }
    }
}

private struct PolicyTable: View {
    let snapshot: PolicyInventorySnapshot
    @Binding var selectedPolicy: PolicyInventorySnapshot.Policy?
    @State private var searchText = ""
    @State private var categoryFilter: PolicyCategoryFilter = .all

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Active policies")
                        .font(.title3.bold())
                    Text("Select a rule for its description, examples, match history, and Rego.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(visiblePolicies.count == snapshot.policies.count
                     ? "\(snapshot.policies.count) active"
                     : "\(visiblePolicies.count) of \(snapshot.policies.count)")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.green)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 5)
                    .background(Color.green.opacity(0.11), in: Capsule())
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 13)
            .agentJailTableSectionBackground(Color.primary.opacity(0.018))
            HStack(spacing: 12) {
                TextField("Filter policies", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 250)
                Picker("Category", selection: $categoryFilter) {
                    ForEach(PolicyCategoryFilter.allCases) { category in
                        Text(category.label).tag(category)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 430)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 12)
            .agentJailTableSectionBackground(Color.primary.opacity(0.018))
            Divider()
            PolicyTableHeader()
            Divider()
            if visiblePolicies.isEmpty {
                Text("No policies match these filters.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 90)
            } else {
                ForEach(visiblePolicies) { policy in
                    PolicyTableRow(policy: policy) {
                        selectedPolicy = policy
                    }
                    if policy.id != visiblePolicies.last?.id {
                        Divider().padding(.leading, 16)
                    }
                }
            }
        }
        .compositingGroup()
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .agentJailCardSurface(cornerRadius: 12)
    }

    private var visiblePolicies: [PolicyInventorySnapshot.Policy] {
        PolicyTableProjection.filtered(
            snapshot.policies,
            category: categoryFilter,
            searchText: searchText
        )
    }
}

enum PolicyCategoryFilter: String, CaseIterable, Identifiable, Sendable {
    case all
    case defaults
    case bash
    case git
    case other

    var id: String { rawValue }
    var label: String {
        switch self {
        case .all: "All"
        case .defaults: "Defaults"
        case .bash: "Bash"
        case .git: "Git"
        case .other: "Other"
        }
    }
}

enum PolicyTableProjection {
    static func filtered(
        _ policies: [PolicyInventorySnapshot.Policy],
        category: PolicyCategoryFilter,
        searchText: String
    ) -> [PolicyInventorySnapshot.Policy] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return policies
            .filter { category == .all || classification(of: $0) == category }
            .filter { query.isEmpty || $0.name.lowercased().contains(query) || $0.id.lowercased().contains(query) }
            .sorted { lhs, rhs in
                let lhsRank = rank(of: lhs)
                let rhsRank = rank(of: rhs)
                return lhsRank == rhsRank
                    ? lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
                    : lhsRank < rhsRank
            }
    }

    static func classification(of policy: PolicyInventorySnapshot.Policy) -> PolicyCategoryFilter {
        let identity = "\(policy.id) \(policy.name)".lowercased()
        if identity.contains("default") { return .defaults }
        if identity.contains("git") { return .git }
        if policy.sourceFile == "command_policy.rego" || identity.contains("bash") || identity.contains("command") {
            return .bash
        }
        return .other
    }

    private static func rank(of policy: PolicyInventorySnapshot.Policy) -> Int {
        switch classification(of: policy) {
        case .defaults: 0
        case .bash: 1
        case .git: 2
        case .other: 3
        case .all: 4
        }
    }
}

private struct PolicyTableHeader: View {
    var body: some View {
        HStack(spacing: 16) {
            Text("POLICY").frame(maxWidth: .infinity, alignment: .leading)
            Text("SOURCE").frame(width: 90, alignment: .leading)
            Text("MATCHES").frame(width: 82, alignment: .trailing)
            Text("AGENTS").frame(width: 68, alignment: .trailing)
            Text("SESSIONS").frame(width: 78, alignment: .trailing)
            Color.clear.frame(width: 14)
        }
        .font(.caption.weight(.bold))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 16)
        .frame(minHeight: 42)
        .agentJailTableSectionBackground(Color.primary.opacity(0.025))
        .accessibilityHidden(true)
    }
}

private struct PolicyTableRow: View {
    let policy: PolicyInventorySnapshot.Policy
    let action: () -> Void
    @State private var isHovering = false

    var body: some View {
        let presentation = PolicyPresentationResolver.presentation(for: policy)
        Button(action: action) {
            HStack(spacing: 16) {
                HStack(spacing: 11) {
                    AgentJailIconTile(systemImage: presentation.systemImage, color: presentation.color)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(policy.name)
                            .font(.callout.weight(.semibold))
                            .lineLimit(1)
                        Text(policy.id)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Text(policy.source.label)
                    .font(.caption.weight(.medium))
                    .frame(width: 90, alignment: .leading)
                metric(policy.matchedCount, width: 82)
                metric(policy.agentCount, width: 68)
                metric(policy.sessionCount, width: 78)
                Image(systemName: "chevron.right")
                    .font(.caption.bold())
                    .foregroundStyle(.tertiary)
                    .frame(width: 14)
                    .accessibilityHidden(true)
            }
            .padding(.horizontal, 16)
            .frame(minHeight: 58)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .agentJailTableSectionBackground(Color.primary.opacity(isHovering ? 0.055 : 0))
        .animation(.easeOut(duration: 0.12), value: isHovering)
        .onHover { isHovering = $0 }
        .agentJailPointingCursor()
        .help(policy.description.isEmpty ? "Open \(policy.name) policy details" : policy.description)
        .accessibilityLabel("\(policy.name), \(policy.matchedCount) recorded matches, \(policy.agentCount) agents, \(policy.sessionCount) sessions")
        .accessibilityHint("Opens policy details and Rego source")
    }

    private func metric(_ value: Int64, width: CGFloat) -> some View {
        Text(value.formatted())
            .font(.callout.monospacedDigit())
            .frame(width: width, alignment: .trailing)
    }
}

struct PolicyPresentation {
    let systemImage: String
    let color: Color
}

enum PolicyPresentationResolver {
    static func presentation(for policy: PolicyInventorySnapshot.Policy) -> PolicyPresentation {
        let identity = "\(policy.id) \(policy.name)".lowercased()
        if identity.contains("git") {
            return PolicyPresentation(systemImage: "arrow.triangle.branch", color: .purple)
        }
        if identity.contains("secret") || identity.contains("credential") || identity.contains("token") || identity.contains("env") {
            return PolicyPresentation(systemImage: "key.fill", color: .orange)
        }
        if identity.contains("curl") || identity.contains("proxy") || identity.contains("host") || identity.contains("network") {
            return PolicyPresentation(systemImage: "network", color: .blue)
        }
        if identity.contains("publish") || identity.contains("package") || identity.contains("npm") {
            return PolicyPresentation(systemImage: "shippingbox.fill", color: .indigo)
        }
        if policy.sourceFile.contains("file") || identity.contains("path") || identity.contains("chmod") || identity.contains("remove") {
            return PolicyPresentation(systemImage: "folder.fill", color: .green)
        }
        if identity.contains("aws") || identity.contains("cloud") {
            return PolicyPresentation(systemImage: "cloud.fill", color: .cyan)
        }
        if policy.sourceFile == "command_policy.rego" || identity.contains("bash") || identity.contains("command") || identity.contains("sudo") {
            return PolicyPresentation(systemImage: "terminal.fill", color: .teal)
        }
        if identity.contains("default") || identity.contains("resolver") {
            return PolicyPresentation(systemImage: "slider.horizontal.3", color: .orange)
        }
        return PolicyPresentation(
            systemImage: policy.locked ? "lock.shield.fill" : "checkmark.shield.fill",
            color: policy.locked ? .orange : .green
        )
    }
}

private struct PolicyCoverageNote: View {
    let historyAvailable: Bool
    let limited: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: "info.circle")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    private var message: String {
        if !historyAvailable {
            return "Policy source is available, but local decision history is not. Match counts remain unavailable until the event store exists."
        }
        if limited {
            return "Match totals are exact. Very large per-session breakdowns show the highest-volume recorded sessions only."
        }
        return "A match means this rule was the selected policy decision. AgentJail does not claim that every Rego candidate considered by OPA matched."
    }
}

private struct PolicyEmptyState: View {
    let title: String
    let detail: String

    var body: some View {
        AgentJailCardSurface {
            VStack(spacing: 9) {
                Image(systemName: "checklist.unchecked")
                    .font(.largeTitle)
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text(title).font(.headline)
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, minHeight: 190)
        }
    }
}

private struct PolicyDetailSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var highlightedRego: AttributedString?

    let policy: PolicyInventorySnapshot.Policy
    let rego: String
    let historyAvailable: Bool

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    overview
                    matchHistory
                    examples
                    source
                    sourceEnd
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(minWidth: 760, idealWidth: 900, minHeight: 620, idealHeight: 760)
        .background(Color(nsColor: .windowBackgroundColor))
        .onExitCommand { dismiss() }
        .task(id: policy.id) {
            highlightedRego = nil
            let highlighted = await RegoHighlightCache.shared.highlighted(rego)
            guard !Task.isCancelled else { return }
            highlightedRego = highlighted
        }
    }

    private var header: some View {
        HStack(spacing: 13) {
            AgentJailIconTile(systemImage: policy.locked ? "lock.shield.fill" : "checkmark.shield.fill", color: policy.locked ? .orange : .green)
            VStack(alignment: .leading, spacing: 2) {
                Text(policy.name).font(.title2.bold())
                Text(policy.id)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            PolicySourceBadge(policy: policy)
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.plain)
            .focusable(false)
            .agentJailInteractiveHover()
            .help("Close")
            .accessibilityLabel("Close policy details")
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 16)
    }

    private var overview: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(policy.description)
                .font(.body)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 0) {
                detailMetric("Recorded matches", policy.matchedCount)
                Divider().padding(.horizontal, 20)
                detailMetric("Agents", policy.agentCount)
                Divider().padding(.horizontal, 20)
                detailMetric("Sessions", policy.sessionCount)
                Spacer()
            }
        }
        .padding(18)
        .agentJailCardSurface()
    }

    private func detailMetric(_ title: String, _ value: Int64) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value.formatted())
                .font(.title3.bold().monospacedDigit())
        }
    }

    @ViewBuilder
    private var matchHistory: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Recorded matches by session")
                .font(.headline)
            if !historyAvailable {
                PolicyDetailMessage(text: "Local decision history is unavailable.")
            } else if policy.evaluations.isEmpty {
                PolicyDetailMessage(text: "This active rule has no recorded selected decisions yet.")
            } else {
                LazyVStack(spacing: 0) {
                    ForEach(policy.evaluations) { evaluation in
                        PolicyEvaluationRow(evaluation: evaluation)
                        if evaluation.id != policy.evaluations.last?.id {
                            Divider().padding(.leading, 42)
                        }
                    }
                }
                .padding(.horizontal, 14)
                .agentJailCardSurface(cornerRadius: 12)
                if policy.breakdownLimited {
                    Text("Highest-volume sessions shown; the total above remains exact.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder
    private var examples: some View {
        if !policy.examples.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Text("Policy-authored outcomes")
                    .font(.headline)
                VStack(spacing: 0) {
                    ForEach(policy.examples) { example in
                        PolicyExampleRow(example: example)
                        if example.id != policy.examples.last?.id {
                            Divider()
                        }
                    }
                }
                .padding(.horizontal, 16)
                .agentJailCardSurface(cornerRadius: 12)
            }
        }
    }

    private var source: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Rego source").font(.headline)
                    Text(policy.sourceFile)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                Spacer()
                AgentJailCopyButton(title: "Copy Rego", text: rego)
            }
            ScrollView([.horizontal, .vertical], showsIndicators: true) {
                Text(highlightedRego ?? AttributedString(rego))
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(16)
                    .fixedSize(horizontal: true, vertical: true)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .frame(minHeight: 420, idealHeight: 560, maxHeight: 640)
            .background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 10))
            .overlay {
                RoundedRectangle(cornerRadius: 10)
                    .stroke(Color.primary.opacity(0.08))
            }
        }
    }

    private var sourceEnd: some View {
        HStack(spacing: 7) {
            Image(systemName: "checkmark.circle")
            Text("End of \(policy.sourceFile) · \(rego.split(separator: "\n", omittingEmptySubsequences: false).count) lines")
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .frame(maxWidth: .infinity, alignment: .center)
        .padding(.top, 2)
        .padding(.bottom, 36)
        .accessibilityElement(children: .combine)
    }

}

private struct PolicySourceBadge: View {
    let policy: PolicyInventorySnapshot.Policy

    var body: some View {
        HStack(spacing: 5) {
            if policy.locked {
                Image(systemName: "lock.fill")
            }
            Text(policy.locked ? "Locked \(policy.source.label)" : policy.source.label)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(policy.locked ? .orange : .secondary)
        .padding(.horizontal, 9)
        .padding(.vertical, 5)
        .background(Color.primary.opacity(0.06), in: Capsule())
    }
}

private struct PolicyEvaluationRow: View {
    let evaluation: PolicyInventorySnapshot.Evaluation

    var body: some View {
        HStack(spacing: 11) {
            AgentBrandMark(agent: evaluation.agent, size: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(agentName).font(.callout.weight(.medium))
                HStack(spacing: 6) {
                    Text(evaluation.sessionFolder)
                    Text("·")
                    Text(shortSessionID)
                        .font(.caption.monospaced())
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            Text(evaluation.matchedCount.formatted())
                .font(.callout.bold().monospacedDigit())
            Text("matches")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 11)
        .accessibilityElement(children: .combine)
    }

    private var agentName: String {
        switch evaluation.agent.lowercased() {
        case "claude", "claude-code": "Claude Code"
        case "codex": "Codex"
        case "cursor": "Cursor"
        case "opencode": "OpenCode"
        default: evaluation.agent
        }
    }

    private var shortSessionID: String {
        guard evaluation.sessionID.count > 12 else { return evaluation.sessionID }
        return String(evaluation.sessionID.prefix(12)) + "…"
    }
}

private struct PolicyExampleRow: View {
    let example: PolicyInventorySnapshot.Example

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            if !example.action.isEmpty {
                Text(example.action.uppercased())
                    .font(.caption2.bold())
                    .foregroundStyle(actionColor)
            }
            if !example.reason.isEmpty {
                Text(example.reason)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !example.impact.isEmpty {
                Text(example.impact)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var actionColor: Color {
        switch example.action.lowercased() {
        case "deny": .red
        case "ask": .orange
        case "allow": .green
        default: .secondary
        }
    }
}

private struct PolicyDetailMessage: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.callout)
            .foregroundStyle(.secondary)
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .agentJailCardSurface(cornerRadius: 12)
    }
}
