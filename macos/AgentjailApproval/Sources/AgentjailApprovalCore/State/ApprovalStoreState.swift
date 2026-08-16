import Foundation

public struct AuthoritativeApprovalSnapshot: Equatable, Sendable {
    public let generatedAt: UnixMilliseconds
    public let totalPending: Int
    public let truncated: Bool
    public let reviews: [Review]

    init(_ snapshot: ReviewSnapshotV1) {
        self.init(
            generatedAt: snapshot.generatedAt,
            totalPending: snapshot.totalPending,
            truncated: snapshot.truncated,
            reviews: snapshot.reviews
        )
    }

    init(generatedAt: UnixMilliseconds, totalPending: Int, truncated: Bool, reviews: [Review]) {
        self.generatedAt = generatedAt
        self.totalPending = totalPending
        self.truncated = truncated
        var seen = Set<ReviewID>()
        self.reviews = reviews.filter { seen.insert($0.id).inserted }
    }
}

public struct StaleApprovalSnapshot: Equatable, Sendable {
    public let generatedAt: UnixMilliseconds
    public let totalPending: Int
    public let truncated: Bool
    public let reviews: [Review]

    init(_ snapshot: AuthoritativeApprovalSnapshot) {
        generatedAt = snapshot.generatedAt
        totalPending = snapshot.totalPending
        truncated = snapshot.truncated
        reviews = snapshot.reviews
    }
}

public enum ApprovalConnectionFailure: Equatable, Sendable {
    case tokenMissing
    case tokenUnreadable
    case unavailable
    case timeout
    case malformedReply
    case oversizedReply
    case invalidSocketPath
    case serverRefused
}

public enum ApprovalStoreState: Equatable, Sendable {
    case starting
    case connecting
    case ready(AuthoritativeApprovalSnapshot)
    case disconnected(StaleApprovalSnapshot?, ApprovalConnectionFailure)
    case unauthorized(StaleApprovalSnapshot?)
    case unsupportedProtocol(StaleApprovalSnapshot?)
}

public enum ReviewActionState: Equatable, Sendable {
    case idle
    case approving
    case denying
    case failed(ApprovalActionFailure)
}

public enum ApprovalActionFailure: Equatable, Sendable {
    case refused
    case unavailable
    case timeout
    case unauthorized
    case unsupportedProtocol
    case malformedReply
    case oversizedReply
    case tokenUnavailable
    case invalidSocketPath
}

public enum ApprovalActionResult: Equatable, Sendable {
    case completed
    case notActionable
    case failed(ApprovalActionFailure)
    case cancelled
}

public enum ApprovalRefreshResult: Equatable, Sendable {
    case authoritative(AuthoritativeApprovalSnapshot)
    case disconnected(ApprovalConnectionFailure)
    case unauthorized
    case unsupportedProtocol
    case cancelled
    case superseded
}

extension ApprovalStoreState {
    var authoritativeSnapshot: AuthoritativeApprovalSnapshot? {
        guard case let .ready(snapshot) = self else { return nil }
        return snapshot
    }

    var staleSnapshot: StaleApprovalSnapshot? {
        switch self {
        case let .ready(snapshot):
            return StaleApprovalSnapshot(snapshot)
        case let .disconnected(snapshot, _), let .unauthorized(snapshot), let .unsupportedProtocol(snapshot):
            return snapshot
        case .starting, .connecting:
            return nil
        }
    }
}
