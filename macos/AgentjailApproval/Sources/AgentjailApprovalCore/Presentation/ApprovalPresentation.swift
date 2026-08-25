import Foundation

public struct ReviewFocusRequest: Equatable, Sendable {
    public let reviewID: ReviewID
    public let generation: UInt64

    public init(reviewID: ReviewID, generation: UInt64) {
        self.reviewID = reviewID
        self.generation = generation
    }
}

public enum ReviewFocusUnavailableReason: Equatable, Sendable {
    case snapshotNotAuthoritative
    case noLongerPending
    case expired

    public var message: String {
        switch self {
        case .snapshotNotAuthoritative:
            "Refresh AgentJail before reviewing this request."
        case .noLongerPending:
            "This approval request is no longer pending."
        case .expired:
            "This approval request has expired and is no longer actionable."
        }
    }
}

public enum ReviewFocusPresentation: Equatable, Sendable {
    case none
    case target(ReviewFocusRequest)
    case unavailable(ReviewFocusRequest, ReviewFocusUnavailableReason)

    public var generation: UInt64? {
        switch self {
        case .none:
            nil
        case let .target(request), let .unavailable(request, _):
            request.generation
        }
    }

    public var consumableRequest: ReviewFocusRequest? {
        switch self {
        case .none:
            nil
        case let .target(request):
            request
        case let .unavailable(request, reason):
            switch reason {
            case .snapshotNotAuthoritative:
                nil
            case .noLongerPending, .expired:
                request
            }
        }
    }
}

public enum ApprovalPanelStatusKind: Equatable, Sendable {
    case starting
    case connecting
    case ready
    case disconnected
    case unauthorized
    case unsupportedProtocol
}

public struct ApprovalPanelStatusPresentation: Equatable, Sendable {
    public let kind: ApprovalPanelStatusKind
    public let title: String
    public let detail: String
    public let systemImage: String
    public let canRetry: Bool
    public let accessibilityText: String

    public init(
        kind: ApprovalPanelStatusKind,
        title: String,
        detail: String,
        systemImage: String,
        canRetry: Bool,
        accessibilityText: String
    ) {
        self.kind = kind
        self.title = title
        self.detail = detail
        self.systemImage = systemImage
        self.canRetry = canRetry
        self.accessibilityText = accessibilityText
    }
}

public struct ApprovalEmptyPresentation: Equatable, Sendable {
    public let title: String
    public let detail: String
    public let systemImage: String

    public init(title: String, detail: String, systemImage: String) {
        self.title = title
        self.detail = detail
        self.systemImage = systemImage
    }
}

public enum ApprovalContextUnavailableReason: Equatable, Sendable {
    case unbound
    case unrepresentable
    case unsafeAuthorityDisplay

    public var title: String {
        "Project context is not available for approval"
    }

    public var detail: String {
        switch self {
        case .unbound:
            "AgentJail could not bind this request to a verified project. You can deny it."
        case .unrepresentable:
            "AgentJail could not represent the complete project context safely. You can deny it."
        case .unsafeAuthorityDisplay:
            "The verified host or project path cannot be displayed exactly and safely. You can deny it."
        }
    }
}

public enum ApprovalContextPresentation: Equatable, Sendable {
    case verified(host: String, projectName: String, projectPath: String)
    case unavailable(ApprovalContextUnavailableReason)
}

public struct ApprovalFailurePresentation: Equatable, Sendable {
    public let title: String
    public let detail: String
    public let systemImage: String

    public init(title: String, detail: String, systemImage: String) {
        self.title = title
        self.detail = detail
        self.systemImage = systemImage
    }
}

public enum ReviewActionPresentation: Equatable, Sendable {
    case idle
    case approving
    case denying
    case failed(ApprovalFailurePresentation)

    public var isInFlight: Bool {
        switch self {
        case .approving, .denying:
            true
        case .idle, .failed:
            false
        }
    }
}

public struct ReviewCardPresentation: Equatable, Sendable, Identifiable {
    public static let approvalButtonTitle = "Approve for future sessions"
    public static let denyButtonTitle = "Deny"
    public static let effectText = "Adds this host to the project policy for future sessions. The current session is unchanged."

    public let id: ReviewID
    public let context: ApprovalContextPresentation
    public let reason: String
    public let reasonWasSanitized: Bool
    public let reasonWasTruncated: Bool
    public let effect: String?
    public let isStale: Bool
    public let isExpired: Bool
    public let action: ReviewActionPresentation
    public let showsApproveAction: Bool
    public let canApprove: Bool
    public let canDeny: Bool
    public let createdAt: UnixMilliseconds
    public let expiresAt: UnixMilliseconds

    public init(
        id: ReviewID,
        context: ApprovalContextPresentation,
        reason: String,
        reasonWasSanitized: Bool,
        reasonWasTruncated: Bool,
        effect: String?,
        isStale: Bool,
        isExpired: Bool,
        action: ReviewActionPresentation,
        showsApproveAction: Bool,
        canApprove: Bool,
        canDeny: Bool,
        createdAt: UnixMilliseconds,
        expiresAt: UnixMilliseconds
    ) {
        self.id = id
        self.context = context
        self.reason = reason
        self.reasonWasSanitized = reasonWasSanitized
        self.reasonWasTruncated = reasonWasTruncated
        self.effect = effect
        self.isStale = isStale
        self.isExpired = isExpired
        self.action = action
        self.showsApproveAction = showsApproveAction
        self.canApprove = canApprove
        self.canDeny = canDeny
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }
}

public struct PanelPresentation: Equatable, Sendable {
    public let status: ApprovalPanelStatusPresentation
    public let totalPending: Int
    public let truncated: Bool
    public let cards: [ReviewCardPresentation]
    public let empty: ApprovalEmptyPresentation?
    public let focus: ReviewFocusPresentation

    public var pendingCountText: String {
        totalPending == 1 ? "1 pending" : "\(totalPending) pending"
    }

    public var truncationText: String? {
        guard truncated else { return nil }
        return "Showing the \(cards.count) newest of \(totalPending) pending requests."
    }

    public init(
        state: ApprovalStoreState,
        actionStates: [ReviewID: ReviewActionState],
        now: UnixMilliseconds,
        focusRequest: ReviewFocusRequest? = nil
    ) {
        let source = Self.source(for: state)
        status = source.status
        totalPending = source.totalPending
        truncated = source.truncated
        cards = Self.cards(
            from: source.reviews,
            actionStates: actionStates,
            now: now,
            isStale: source.isStale
        )
        empty = cards.isEmpty ? Self.emptyPresentation(for: source.status.kind) : nil
        focus = Self.focusPresentation(
            request: focusRequest,
            state: state,
            cards: cards
        )
    }
}

public enum ApprovalMenuLabelState: Equatable, Sendable {
    case starting
    case connecting
    case ready
    case disconnected
    case unauthorized
    case unsupportedProtocol
}

public struct ApprovalMenuLabelPresentation: Equatable, Sendable {
    public let state: ApprovalMenuLabelState
    public let systemImage: String
    public let badgeText: String?
    public let accessibilityLabel: String
    public let accessibilityValue: String

    public init(state: ApprovalStoreState) {
        accessibilityLabel = "AgentJail approvals"

        switch state {
        case .starting:
            self.state = .starting
            systemImage = "shield"
            badgeText = nil
            accessibilityValue = "Starting"
        case .connecting:
            self.state = .connecting
            systemImage = "hourglass"
            badgeText = nil
            accessibilityValue = "Connecting"
        case let .ready(snapshot):
            self.state = .ready
            systemImage = snapshot.totalPending == 0 ? "checkmark.shield" : "shield"
            badgeText = snapshot.totalPending == 0 ? nil : String(snapshot.totalPending)
            accessibilityValue = Self.pendingAccessibilityValue(snapshot.totalPending, qualifier: nil)
        case let .disconnected(snapshot, _):
            self.state = .disconnected
            systemImage = "exclamationmark.triangle"
            badgeText = Self.cachedBadge(snapshot?.totalPending)
            accessibilityValue = Self.pendingAccessibilityValue(snapshot?.totalPending ?? 0, qualifier: "Disconnected; cached")
        case let .unauthorized(snapshot):
            self.state = .unauthorized
            systemImage = "lock.shield"
            badgeText = Self.cachedBadge(snapshot?.totalPending)
            accessibilityValue = Self.pendingAccessibilityValue(snapshot?.totalPending ?? 0, qualifier: "Authorization required; cached")
        case let .unsupportedProtocol(snapshot):
            self.state = .unsupportedProtocol
            systemImage = "exclamationmark.triangle"
            badgeText = Self.cachedBadge(snapshot?.totalPending)
            accessibilityValue = Self.pendingAccessibilityValue(snapshot?.totalPending ?? 0, qualifier: "Unsupported protocol; cached")
        }
    }
}

private extension PanelPresentation {
    struct Source {
        let status: ApprovalPanelStatusPresentation
        let totalPending: Int
        let truncated: Bool
        let reviews: [Review]
        let isStale: Bool
    }

    static func source(for state: ApprovalStoreState) -> Source {
        switch state {
        case .starting:
            Source(
                status: status(
                    kind: .starting,
                    title: "Starting",
                    detail: "Preparing approval review.",
                    systemImage: "shield",
                    canRetry: false
                ),
                totalPending: 0,
                truncated: false,
                reviews: [],
                isStale: false
            )
        case .connecting:
            Source(
                status: status(
                    kind: .connecting,
                    title: "Connecting",
                    detail: "Connecting to the local AgentJail daemon.",
                    systemImage: "hourglass",
                    canRetry: false
                ),
                totalPending: 0,
                truncated: false,
                reviews: [],
                isStale: false
            )
        case let .ready(snapshot):
            Source(
                status: status(
                    kind: .ready,
                    title: "Ready",
                    detail: pendingDetail(snapshot.totalPending),
                    systemImage: "checkmark.shield",
                    canRetry: false
                ),
                totalPending: snapshot.totalPending,
                truncated: snapshot.truncated,
                reviews: snapshot.reviews,
                isStale: false
            )
        case let .disconnected(snapshot, failure):
            Source(
                status: status(
                    kind: .disconnected,
                    title: "Disconnected",
                    detail: "\(connectionFailureDetail(failure)) Cached requests are stale and cannot be acted on.",
                    systemImage: "exclamationmark.triangle",
                    canRetry: true
                ),
                totalPending: snapshot?.totalPending ?? 0,
                truncated: snapshot?.truncated ?? false,
                reviews: snapshot?.reviews ?? [],
                isStale: true
            )
        case let .unauthorized(snapshot):
            Source(
                status: status(
                    kind: .unauthorized,
                    title: "Authorization required",
                    detail: "AgentJail rejected the local control token. Cached requests are stale and cannot be acted on.",
                    systemImage: "lock.shield",
                    canRetry: true
                ),
                totalPending: snapshot?.totalPending ?? 0,
                truncated: snapshot?.truncated ?? false,
                reviews: snapshot?.reviews ?? [],
                isStale: true
            )
        case let .unsupportedProtocol(snapshot):
            Source(
                status: status(
                    kind: .unsupportedProtocol,
                    title: "Update required",
                    detail: "This app and the AgentJail daemon use incompatible review protocols. Cached requests are stale and cannot be acted on.",
                    systemImage: "exclamationmark.triangle",
                    canRetry: true
                ),
                totalPending: snapshot?.totalPending ?? 0,
                truncated: snapshot?.truncated ?? false,
                reviews: snapshot?.reviews ?? [],
                isStale: true
            )
        }
    }

    static func status(
        kind: ApprovalPanelStatusKind,
        title: String,
        detail: String,
        systemImage: String,
        canRetry: Bool
    ) -> ApprovalPanelStatusPresentation {
        ApprovalPanelStatusPresentation(
            kind: kind,
            title: title,
            detail: detail,
            systemImage: systemImage,
            canRetry: canRetry,
            accessibilityText: "\(title). \(detail)"
        )
    }

    static func pendingDetail(_ count: Int) -> String {
        switch count {
        case 0:
            "No approvals waiting."
        case 1:
            "1 approval request waiting."
        default:
            "\(count) approval requests waiting."
        }
    }

    static func connectionFailureDetail(_ failure: ApprovalConnectionFailure) -> String {
        switch failure {
        case .tokenMissing, .tokenUnreadable:
            "The local control token is unavailable."
        case .unavailable:
            "The local AgentJail daemon is unavailable."
        case .timeout:
            "The local AgentJail daemon did not respond in time."
        case .malformedReply, .oversizedReply:
            "AgentJail returned an invalid review response."
        case .invalidSocketPath:
            "The local AgentJail control socket path is invalid."
        case .serverRefused:
            "AgentJail refused the review request."
        }
    }

    static func emptyPresentation(for status: ApprovalPanelStatusKind) -> ApprovalEmptyPresentation {
        switch status {
        case .starting:
            ApprovalEmptyPresentation(
                title: "Preparing approvals",
                detail: "AgentJail is starting.",
                systemImage: "shield"
            )
        case .connecting:
            ApprovalEmptyPresentation(
                title: "Connecting",
                detail: "Waiting for the local AgentJail daemon.",
                systemImage: "hourglass"
            )
        case .ready:
            ApprovalEmptyPresentation(
                title: "No approvals waiting",
                detail: "New project host requests will appear here.",
                systemImage: "checkmark.shield"
            )
        case .disconnected:
            ApprovalEmptyPresentation(
                title: "Approvals unavailable",
                detail: "Reconnect to load current approval requests.",
                systemImage: "exclamationmark.triangle"
            )
        case .unauthorized:
            ApprovalEmptyPresentation(
                title: "Authorization required",
                detail: "Retry after restoring the local AgentJail control token.",
                systemImage: "lock.shield"
            )
        case .unsupportedProtocol:
            ApprovalEmptyPresentation(
                title: "Update required",
                detail: "Update AgentJail or the daemon before reviewing requests.",
                systemImage: "exclamationmark.triangle"
            )
        }
    }

    static func cards(
        from reviews: [Review],
        actionStates: [ReviewID: ReviewActionState],
        now: UnixMilliseconds,
        isStale: Bool
    ) -> [ReviewCardPresentation] {
        reviews
            .map { review in
                card(
                    from: review,
                    actionState: actionStates[review.id] ?? .idle,
                    now: now,
                    isStale: isStale
                )
            }
    }

    static func card(
        from review: Review,
        actionState: ReviewActionState,
        now: UnixMilliseconds,
        isStale: Bool
    ) -> ReviewCardPresentation {
        let context = contextPresentation(for: review)
        let reason = DisplaySanitizer.reason(review.reason, limit: 160)
        let action = actionPresentation(for: actionState)
        let isExpired = review.expiresAt <= now
        let hasVerifiedContext: Bool
        switch context {
        case .verified:
            hasVerifiedContext = true
        case .unavailable:
            hasVerifiedContext = false
        }
        let canAct = !isStale && !isExpired && !action.isInFlight

        return ReviewCardPresentation(
            id: review.id,
            context: context,
            reason: reason.text,
            reasonWasSanitized: reason.didSanitizeUnsafeScalars,
            reasonWasTruncated: review.reasonTruncated || reason.didTruncateGraphemes,
            effect: hasVerifiedContext ? ReviewCardPresentation.effectText : nil,
            isStale: isStale,
            isExpired: isExpired,
            action: action,
            showsApproveAction: hasVerifiedContext,
            canApprove: canAct && hasVerifiedContext && review.canApprove,
            canDeny: canAct && review.canDeny,
            createdAt: review.createdAt,
            expiresAt: review.expiresAt
        )
    }

    static func contextPresentation(for review: Review) -> ApprovalContextPresentation {
        switch review.contextState {
        case .unbound:
            return .unavailable(.unbound)
        case .unrepresentable:
            return .unavailable(.unrepresentable)
        case .verified:
            guard let host = exactAuthorityDisplay(review.host),
                  let projectPath = exactAuthorityDisplay(review.projectPath)
            else {
                return .unavailable(.unsafeAuthorityDisplay)
            }
            return .verified(
                host: host,
                projectName: projectName(for: projectPath),
                projectPath: projectPath
            )
        }
    }

    static func exactAuthorityDisplay(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        let checked = DisplaySanitizer.text(value, limit: value.count + 1)
        guard checked.text == value,
              !checked.didSanitizeUnsafeScalars,
              !checked.didTruncateGraphemes
        else {
            return nil
        }
        return value
    }

    static func projectName(for projectPath: String) -> String {
        projectPath.split(separator: "/", omittingEmptySubsequences: true).last.map(String.init) ?? projectPath
    }

    static func actionPresentation(for action: ReviewActionState) -> ReviewActionPresentation {
        switch action {
        case .idle:
            .idle
        case .approving:
            .approving
        case .denying:
            .denying
        case let .failed(failure):
            .failed(failurePresentation(for: failure))
        }
    }

    static func failurePresentation(for failure: ApprovalActionFailure) -> ApprovalFailurePresentation {
        let detail: String
        switch failure {
        case .refused:
            detail = "AgentJail refused the action. The request may have expired or already been resolved."
        case .unavailable:
            detail = "The local AgentJail daemon is unavailable. Refresh before trying again."
        case .timeout:
            detail = "AgentJail did not respond in time. Refresh before trying again."
        case .unauthorized:
            detail = "AgentJail rejected the local control token."
        case .unsupportedProtocol:
            detail = "The app and daemon use incompatible review protocols."
        case .malformedReply, .oversizedReply:
            detail = "AgentJail returned an invalid response."
        case .tokenUnavailable:
            detail = "The local AgentJail control token is unavailable."
        case .invalidSocketPath:
            detail = "The local AgentJail control socket path is invalid."
        }
        return ApprovalFailurePresentation(
            title: "Action failed",
            detail: detail,
            systemImage: "exclamationmark.triangle"
        )
    }

    static func focusPresentation(
        request: ReviewFocusRequest?,
        state: ApprovalStoreState,
        cards: [ReviewCardPresentation]
    ) -> ReviewFocusPresentation {
        guard let request else { return .none }
        guard case .ready = state else {
            return .unavailable(request, .snapshotNotAuthoritative)
        }
        guard let card = cards.first(where: { $0.id == request.reviewID }) else {
            return .unavailable(request, .noLongerPending)
        }
        guard !card.isExpired else {
            return .unavailable(request, .expired)
        }
        return .target(request)
    }
}

private extension ApprovalMenuLabelPresentation {
    static func cachedBadge(_ count: Int?) -> String? {
        guard let count, count > 0 else { return nil }
        return String(count)
    }

    static func pendingAccessibilityValue(_ count: Int, qualifier: String?) -> String {
        let pending: String
        switch count {
        case 0:
            pending = "No pending approvals"
        case 1:
            pending = "1 pending approval"
        default:
            pending = "\(count) pending approvals"
        }
        guard let qualifier else { return pending }
        return "\(qualifier). \(pending); actions disabled"
    }
}
