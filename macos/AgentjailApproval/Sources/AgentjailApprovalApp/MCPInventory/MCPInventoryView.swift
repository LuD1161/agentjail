import AgentjailApprovalCore
import AppKit
import SwiftUI

struct MCPInventoryView: View {
    @ObservedObject private var store: MCPInventoryStore
    @State private var clientFilter = "all"

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
        AgentJailSurface(padding: 14) {
            HStack(spacing: 0) {
                InventorySummaryMetric(title: "Servers", value: store.snapshot.configuredCount, color: .green, systemImage: "server.rack")
                Divider().padding(.horizontal, 20)
                InventorySummaryMetric(title: "Cross-client", value: store.snapshot.duplicateCount, color: .orange, systemImage: "square.on.square")
                Divider().padding(.horizontal, 20)
                InventorySummaryMetric(title: "Needs attention", value: store.snapshot.issueCount, color: .red, systemImage: "exclamationmark.triangle.fill")
                Spacer()
                Text("Global configuration")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.secondary.opacity(0.1), in: Capsule())
            }
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
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Configured servers").font(.title3.bold())
                        Text("Names shared across clients remain separate.").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Picker("Client", selection: $clientFilter) {
                        Text("All").tag("all")
                        Label("Claude", systemImage: "c.circle").tag("claude")
                        Label("Codex", systemImage: "sparkles").tag("codex")
                        Label("Cursor", systemImage: "cursorarrow").tag("cursor")
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 330)
                }
                MCPTableHeader()
                VStack(spacing: 0) {
                    ForEach(filteredItems) { item in MCPInventoryRow(item: item) }
                }
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
                .overlay { RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.08), lineWidth: 1) }
            }
        }
    }

    private var filteredItems: [MCPInventoryItem] {
        guard clientFilter != "all" else { return store.snapshot.items }
        return store.snapshot.items.filter {
            switch (clientFilter, $0.sourceClient) {
            case ("claude", .claudeCode), ("codex", .codex), ("cursor", .cursor): true
            default: false
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
        HStack(spacing: 12) {
            HStack(spacing: 9) {
                MCPBrandMark.server(named: item.name)
                VStack(alignment: .leading, spacing: 3) {
                Text(item.name)
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                if item.isDuplicate {
                    Label("In \(item.duplicateCount) clients", systemImage: "square.on.square")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.orange)
                }
                Text(item.target)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 7) {
                MCPBrandMark.agent(item.sourceClient)
                Text(item.sourceClient.displayName)
            }
            .frame(width: 112, alignment: .leading)
            Text("—").frame(width: 54).help("Tool counts require connecting to the MCP server. This inventory remains read-only and never launches servers.")
            Text("Global").frame(width: 108, alignment: .leading)
            statusBadge.frame(width: 112, alignment: .trailing)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) { Divider().padding(.leading, 14) }
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

private struct MCPBrandMark: View {
    private let asset: String?
    private let fallback: String
    private let tint: Color

    private init(asset: String?, fallback: String, tint: Color) {
        self.asset = asset
        self.fallback = fallback
        self.tint = tint
    }

    static func server(named name: String) -> MCPBrandMark {
        switch name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "linear": MCPBrandMark(asset: "server-linear", fallback: "L", tint: .white)
        default: MCPBrandMark(asset: nil, fallback: String(name.prefix(1)).uppercased(), tint: .blue)
        }
    }

    static func agent(_ client: MCPSourceClient) -> MCPBrandMark {
        switch client {
        case .claudeCode: MCPBrandMark(asset: "agent-claude", fallback: "C", tint: .orange)
        case .codex: MCPBrandMark(asset: "agent-codex", fallback: "C", tint: .green)
        case .cursor: MCPBrandMark(asset: "agent-cursor", fallback: "C", tint: .primary)
        }
    }

    var body: some View {
        Group {
            if let asset, let image = Self.load(asset) {
                Image(nsImage: image).resizable().interpolation(.high).scaledToFit()
            } else {
                Text(fallback).font(.caption.weight(.bold)).foregroundStyle(tint)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 5))
            }
        }
        .frame(width: 18, height: 18)
        .accessibilityHidden(true)
    }

    private static func load(_ name: String) -> NSImage? {
        guard let url = Bundle.main.url(forResource: name, withExtension: "svg") else { return nil }
        return NSImage(contentsOf: url)
    }
}

private struct MCPTableHeader: View {
    var body: some View {
        HStack(spacing: 12) {
            Text("SERVER").frame(maxWidth: .infinity, alignment: .leading)
            Text("AGENT").frame(width: 112, alignment: .leading)
            Text("TOOLS").frame(width: 54, alignment: .leading)
            Text("SCOPE").frame(width: 108, alignment: .leading)
            Text("STATUS").frame(width: 112, alignment: .trailing)
        }
        .font(.caption2.weight(.semibold))
        .foregroundStyle(.tertiary)
        .padding(.horizontal, 14)
        .padding(.top, 14)
        .padding(.bottom, 6)
    }
}

private struct InventorySummaryMetric: View {
    let title: String
    let value: Int
    let color: Color
    let systemImage: String

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: systemImage).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 1) {
                Text(String(value)).font(.headline.monospacedDigit())
                Text(title).font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(title)")
    }
}
