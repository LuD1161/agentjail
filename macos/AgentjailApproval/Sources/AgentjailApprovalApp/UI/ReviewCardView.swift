import AgentjailApprovalCore
import SwiftUI

struct ReviewCardView: View {
    let presentation: ReviewCardPresentation
    let isFocusTarget: Bool
    let onApprove: (ReviewID) -> Void
    let onDeny: (ReviewID) -> Void

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                context
                reason

                if let effect = presentation.effect {
                    Label(effect, systemImage: "arrow.forward.circle")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityLabel("Approval effect. \(effect)")
                }

                stateMessages
                actions
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label("Project host request", systemImage: "network")
                .font(.headline)
        }
        .overlay {
            if isFocusTarget {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.accentColor, lineWidth: 2)
                    .accessibilityHidden(true)
            }
        }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private var context: some View {
        switch presentation.context {
        case let .verified(host, projectName, projectPath):
            VStack(alignment: .leading, spacing: 6) {
                LabeledContent("Requested host") {
                    Text(host)
                        .font(.body.monospaced())
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                .accessibilityElement(children: .combine)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Verified project")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(projectName)
                        .font(.body.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(projectPath)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Verified project \(projectName), full path \(projectPath)")
            }
        case let .unavailable(reason):
            VStack(alignment: .leading, spacing: 4) {
                Label(reason.title, systemImage: "exclamationmark.triangle")
                    .font(.body.weight(.semibold))
                Text(reason.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(reason.title). \(reason.detail)")
        }
    }

    private var reason: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("Agent-provided reason")
                .font(.caption.weight(.semibold))
            Text(presentation.reason)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)

            if presentation.reasonWasSanitized || presentation.reasonWasTruncated {
                Text(reasonNotice)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Agent-provided reason. \(presentation.reason). \(reasonNotice)")
        .accessibilityHint("This text was supplied by the requesting agent and is not trusted.")
    }

    private var reasonNotice: String {
        switch (presentation.reasonWasSanitized, presentation.reasonWasTruncated) {
        case (true, true):
            "Unsafe controls were removed and the reason was shortened for display."
        case (true, false):
            "Unsafe controls were removed for display."
        case (false, true):
            "The reason was shortened for display."
        case (false, false):
            ""
        }
    }

    @ViewBuilder
    private var stateMessages: some View {
        if presentation.isStale {
            StatusLine(
                text: "Stale — reconnect to act",
                systemImage: "exclamationmark.triangle",
                color: .orange
            )
        }

        if presentation.isExpired {
            StatusLine(
                text: "Expired — this request is no longer actionable",
                systemImage: "clock",
                color: .orange
            )
        }

        switch presentation.action {
        case .idle:
            EmptyView()
        case .approving:
            HStack(spacing: 7) {
                ProgressView()
                    .controlSize(.small)
                Text("Approving for future sessions…")
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Approval in progress")
        case .denying:
            HStack(spacing: 7) {
                ProgressView()
                    .controlSize(.small)
                Text("Denying request…")
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Denial in progress")
        case let .failed(failure):
            VStack(alignment: .leading, spacing: 3) {
                Label(failure.title, systemImage: failure.systemImage)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.red)
                Text(failure.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(failure.title). \(failure.detail)")
        }
    }

    private var actions: some View {
        HStack(spacing: 10) {
            Spacer()

            Button(role: .destructive) {
                onDeny(presentation.id)
            } label: {
                Text(ReviewCardPresentation.denyButtonTitle)
            }
            .buttonStyle(.bordered)
            .disabled(!presentation.canDeny)
            .accessibilityHint("Rejects this request without changing project policy.")

            if presentation.showsApproveAction {
                Button {
                    onApprove(presentation.id)
                } label: {
                    Text(ReviewCardPresentation.approvalButtonTitle)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!presentation.canApprove)
                .accessibilityHint("Adds the displayed host to this verified project for future sessions. The current session is unchanged.")
            }
        }
    }
}

private struct StatusLine: View {
    let text: String
    let systemImage: String
    let color: Color

    var body: some View {
        Label(text, systemImage: systemImage)
            .font(.callout.weight(.semibold))
            .foregroundStyle(color)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityLabel(text)
    }
}
