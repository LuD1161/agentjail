import AgentjailApprovalCore
import SwiftUI

struct MCPInventoryView: View {
    @ObservedObject private var store: MCPInventoryStore

    init(store: MCPInventoryStore) {
        _store = ObservedObject(wrappedValue: store)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                AgentJailPageHeader(
                    eyebrow: "Connections",
                    title: "MCP inventory",
                    detail: "Configured servers across Claude Code, Codex, and Cursor"
                ) {
                    Button {
                        store.refresh()
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(store.isRefreshing)
                }
                summary
                observeOnlyNotice
                inventory
                coverageNotice
            }
            .frame(maxWidth: 1100)
            .padding(32)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            store.refresh()
        }
    }

    private var observeOnlyNotice: some View {
        AgentJailSurface {
            HStack(alignment: .top, spacing: 12) {
                AgentJailIconTile(systemImage: "eye.fill", color: .blue)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Observe only")
                        .font(.headline)
                    Text("Discovery reads configuration metadata only. It never modifies files, launches MCP servers, proxies calls, or changes policy.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .accessibilityElement(children: .combine)
        }
    }

    private var summary: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 12)], spacing: 12) {
            InventorySummaryCard(
                title: "Configured",
                value: store.snapshot.configuredCount,
                color: .green,
                systemImage: "checkmark.circle.fill"
            )
            InventorySummaryCard(
                title: "Cross-client",
                value: store.snapshot.duplicateCount,
                color: .orange,
                systemImage: "square.on.square"
            )
            InventorySummaryCard(
                title: "Needs attention",
                value: store.snapshot.issueCount,
                color: .red,
                systemImage: "exclamationmark.triangle.fill"
            )
        }
    }

    @ViewBuilder
    private var inventory: some View {
        if store.snapshot.items.isEmpty {
            AgentJailSurface {
                VStack(spacing: 8) {
                    Image(systemName: "shippingbox")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    Text("No global MCP servers found")
                        .font(.headline)
                    Text("Add a server in one of the supported clients, then refresh this inventory.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, minHeight: 180)
            }
        } else {
            VStack(alignment: .leading, spacing: 4) {
                Text("Configured servers")
                    .font(.title3.bold())
                Text("Names shared across clients remain separate so their source is always clear.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(store.snapshot.items) { item in
                        MCPInventoryRow(item: item)
                    }
                }
                .padding(.top, 10)
            }
        }
    }

    private var coverageNotice: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "info.circle")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Phase 1 covers the global configuration files shown above. Project-local MCP files and runtime activity are not observed yet, so this inventory is intentionally not presented as complete traffic visibility.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

private struct MCPInventoryRow: View {
    let item: MCPInventoryItem

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(item.name)
                    .font(.headline)
                    .lineLimit(1)
                if item.isDuplicate {
                    Label("In \(item.duplicateCount) clients", systemImage: "square.on.square")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.orange)
                }
                Spacer()
                statusBadge
            }

            HStack(spacing: 8) {
                Label(item.sourceClient.displayName, systemImage: sourceIcon)
                Text("•")
                    .accessibilityHidden(true)
                Text(item.kind.displayName)
                Text("•")
                    .accessibilityHidden(true)
                Text(item.sourceLabel)
                    .monospaced()
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(item.kind == .remote ? "Origin" : "Command")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(item.target)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
            }

            if let detail = item.status.detail {
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text("Adapter \(item.adapterVersion)")
                .font(.caption2.monospaced())
                .foregroundStyle(.tertiary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.primary.opacity(0.08), lineWidth: 1)
        }
        .accessibilityElement(children: .contain)
    }

    private var statusBadge: some View {
        Text(item.status.displayName)
            .font(.caption.weight(.semibold))
            .foregroundStyle(statusColor)
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(statusColor.opacity(0.1), in: Capsule())
    }

    private var statusColor: Color {
        switch item.status {
        case .configured: .green
        case .disabled: .secondary
        case .issue: .red
        }
    }

    private var sourceIcon: String {
        switch item.sourceClient {
        case .claudeCode: "c.circle"
        case .codex: "chevron.left.forwardslash.chevron.right"
        case .cursor: "cursorarrow"
        }
    }
}

private struct InventorySummaryCard: View {
    let title: String
    let value: Int
    let color: Color
    let systemImage: String

    var body: some View {
        AgentJailSurface(padding: 15) {
            HStack(spacing: 12) {
                AgentJailIconTile(systemImage: systemImage, color: color)
                VStack(alignment: .leading, spacing: 2) {
                    Text(String(value))
                        .font(.title2.bold())
                        .monospacedDigit()
                    Text(title)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(title)")
    }
}
