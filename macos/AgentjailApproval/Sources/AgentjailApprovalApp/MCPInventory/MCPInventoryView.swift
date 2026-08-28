import AgentjailApprovalCore
import SwiftUI

struct MCPInventoryView: View {
    @ObservedObject private var store: MCPInventoryStore

    init(store: MCPInventoryStore) {
        _store = ObservedObject(wrappedValue: store)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    observeOnlyNotice
                    summary
                    inventory
                    coverageNotice
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(minWidth: 720, minHeight: 560)
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            store.refresh()
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.title2)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("MCP inventory")
                    .font(.title2.bold())
                Text("Claude Code, Codex, and Cursor")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                store.refresh()
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(store.isRefreshing)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 18)
    }

    private var observeOnlyNotice: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "eye.fill")
                .foregroundStyle(.blue)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text("Observe only")
                    .font(.headline)
                Text("AgentJail reads configuration metadata to show what is connected. It does not modify configuration, launch MCP servers, proxy calls, or change policy.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .combine)
    }

    private var summary: some View {
        HStack(spacing: 10) {
            InventorySummaryChip(
                title: "Configured",
                value: store.snapshot.configuredCount,
                color: .green,
                systemImage: "checkmark.circle.fill"
            )
            InventorySummaryChip(
                title: "Duplicates",
                value: store.snapshot.duplicateCount,
                color: .orange,
                systemImage: "square.on.square"
            )
            InventorySummaryChip(
                title: "Issues",
                value: store.snapshot.issueCount,
                color: .red,
                systemImage: "exclamationmark.triangle.fill"
            )
        }
    }

    @ViewBuilder
    private var inventory: some View {
        if store.snapshot.items.isEmpty {
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
            .overlay {
                RoundedRectangle(cornerRadius: 12)
                    .stroke(Color.secondary.opacity(0.18), lineWidth: 1)
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(store.snapshot.items) { item in
                    MCPInventoryRow(item: item)
                }
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
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.secondary.opacity(0.14), lineWidth: 1)
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

private struct InventorySummaryChip: View {
    let title: String
    let value: Int
    let color: Color
    let systemImage: String

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: systemImage)
                .accessibilityHidden(true)
            Text(String(value))
                .font(.headline)
                .monospacedDigit()
            Text(title)
                .font(.caption.weight(.medium))
        }
        .foregroundStyle(color)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(color.opacity(0.08), in: Capsule())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(title)")
    }
}
