import AgentjailApprovalCore
import AppKit
import SwiftUI

struct MCPInventoryView: View {
    @ObservedObject private var store: MCPInventoryStore
    @State private var clientFilter = "all"
    @State private var showsDiscoveryConfirmation = false

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
                    HStack(spacing: 8) {
                        Button {
                            showsDiscoveryConfirmation = true
                        } label: {
                            if store.isDiscoveringTools {
                                Label("Discovering", systemImage: "arrow.triangle.2.circlepath")
                            } else {
                                Label("Discover tools", systemImage: "sparkle.magnifyingglass")
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(store.isDiscoveringTools)
                        Button {
                            Task { await store.refresh() }
                        } label: {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                        .disabled(store.isRefreshing || store.isDiscoveringTools)
                    }
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
            await store.refresh()
        }
        .alert("Discover tools from every configured MCP server?", isPresented: $showsDiscoveryConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Discover tools") { Task { await store.discoverTools() } }
        } message: {
            Text("AgentJail will temporarily start configured local MCP server commands and contact configured remote endpoints using their configured credentials. It requests tool metadata only and never invokes a tool.")
        }
    }

    private var observeOnlyNotice: some View {
        AgentJailSurface {
            HStack(alignment: .top, spacing: 12) {
                AgentJailIconTile(systemImage: "eye.fill", color: .blue)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Observe only")
                        .font(.headline)
                    Text("Normal refresh reads configuration metadata and local audit history only. It never modifies files, launches MCP servers, contacts endpoints, or changes policy.")
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
                if let summary = store.discoverySummary {
                    Label(summary, systemImage: summary.hasPrefix("Found") ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 2)
                        .padding(.vertical, 6)
                }
                VStack(spacing: 0) {
                    ForEach(filteredItems) { item in
                        MCPInventoryRow(
                            item: item,
                            observedTools: store.observedTools(for: item.name),
                            toolDataUnavailable: store.toolDataUnavailable,
                            discoveryStatus: store.discoveryStatus(for: item.name)
                        )
                    }
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
            Text("Refresh remains observe-only. Discover tools is an explicit tools/list pass that may start local server commands and contact remote endpoints. Project-local MCP files remain outside this phase.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

private struct MCPInventoryRow: View {
    let item: MCPInventoryItem
    let observedTools: [String]
    let toolDataUnavailable: Bool
    let discoveryStatus: MCPToolDiscoveryStatus?
    @State private var isExpanded = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                HStack(spacing: 9) {
                    MCPBrandMark.server(named: item.name, target: item.target)
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
                toolSummary.frame(width: 100, alignment: .leading)
                Text("Global").frame(width: 108, alignment: .leading)
                statusBadge.frame(width: 112, alignment: .trailing)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
            .frame(maxWidth: .infinity, alignment: .leading)

            if isExpanded {
                Divider().padding(.leading, 14)
                VStack(alignment: .leading, spacing: 9) {
                    Text("Observed tools")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), alignment: .leading)], alignment: .leading, spacing: 7) {
                        ForEach(observedTools, id: \.self) { tool in
                            Text(tool)
                                .font(.caption.monospaced())
                                .lineLimit(1)
                                .help(tool)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 5)
                                .background(Color.accentColor.opacity(0.09), in: RoundedRectangle(cornerRadius: 6))
                        }
                    }
                }
                .padding(.horizontal, 42)
                .padding(.vertical, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.primary.opacity(0.018))
            }
        }
        .overlay(alignment: .bottom) { Divider().padding(.leading, 14) }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private var toolSummary: some View {
        if toolDataUnavailable {
            Text("Unavailable")
                .font(.caption)
                .foregroundStyle(.secondary)
                .help("The local AgentJail daemon could not provide observed tool data.")
        } else if observedTools.isEmpty {
            Text(emptyToolStatus)
                .font(.caption)
                .foregroundStyle(emptyToolStatusColor)
                .help(emptyToolStatusHelp)
        } else {
            Button {
                withAnimation(.easeInOut(duration: 0.16)) { isExpanded.toggle() }
            } label: {
                HStack(spacing: 5) {
                    Text(observedTools.count.formatted())
                        .font(.callout.weight(.semibold).monospacedDigit())
                    Image(systemName: "chevron.right")
                        .font(.caption2.weight(.bold))
                        .rotationEffect(.degrees(isExpanded ? 90 : 0))
                }
            }
            .buttonStyle(.plain)
            .foregroundStyle(.tint)
            .help(isExpanded ? "Hide observed tools" : "Show observed tools")
            .accessibilityLabel("\(observedTools.count) observed tools")
            .accessibilityValue(isExpanded ? "Expanded" : "Collapsed")
        }
    }

    private var emptyToolStatus: String {
        switch discoveryStatus {
        case .connected: "0 tools"
        case .authRequired: "Sign in required"
        case .unreachable: "Unreachable"
        case .timeout: "Timed out"
        case nil: "Not discovered"
        }
    }

    private var emptyToolStatusColor: Color {
        switch discoveryStatus {
        case .authRequired, .unreachable, .timeout: .orange
        default: .secondary
        }
    }

    private var emptyToolStatusHelp: String {
        switch discoveryStatus {
        case .connected: "The server responded to tools/list with an empty catalog."
        case .authRequired: "The server requires authentication before it can enumerate tools."
        case .unreachable: "AgentJail could not connect to this configured MCP server."
        case .timeout: "The server did not finish tool discovery within the time limit."
        case nil: "Choose Discover tools to enumerate this server, or wait for an audited tool call."
        }
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
    @Environment(\.colorScheme) private var colorScheme

    private init(asset: String?, fallback: String, tint: Color) {
        self.asset = asset
        self.fallback = fallback
        self.tint = tint
    }

    static func server(named name: String, target: String) -> MCPBrandMark {
        let identity = "\(name) \(target)".lowercased()
        if identity.contains("linear") || identity.contains("mcp.linear.app") {
            return MCPBrandMark(asset: "server-linear", fallback: "L", tint: .white)
        }
        switch name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "chrome-devtools": return MCPBrandMark(asset: "server-chrome", fallback: "C", tint: .blue)
        case "context7": return MCPBrandMark(asset: "server-context7", fallback: "7", tint: .purple)
        default: return MCPBrandMark(asset: nil, fallback: String(name.prefix(1)).uppercased(), tint: .blue)
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
        let resolvedAsset = asset == "agent-codex" && colorScheme == .dark ? "agent-codex-light" : asset
        Group {
            if let resolvedAsset, let image = Self.load(resolvedAsset) {
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
        let svg = Bundle.main.url(forResource: name, withExtension: "svg")
        let ico = Bundle.main.url(forResource: name, withExtension: "ico")
        guard let url = svg ?? ico else { return nil }
        return NSImage(contentsOf: url)
    }
}

private struct MCPTableHeader: View {
    var body: some View {
        HStack(spacing: 12) {
            Text("SERVER").frame(maxWidth: .infinity, alignment: .leading)
            Text("AGENT").frame(width: 112, alignment: .leading)
            Text("TOOLS").frame(width: 100, alignment: .leading)
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
