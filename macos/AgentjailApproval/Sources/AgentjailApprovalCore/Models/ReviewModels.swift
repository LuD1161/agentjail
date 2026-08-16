import Foundation

public enum ReviewModelError: Error, Equatable, Sendable {
    case invalidReviewID
    case unsupportedProtocolVersion(UInt32)
    case unsupportedReviewKind(String)
    case unsupportedApprovalScope(String)
    case unsupportedContextState(String)
    case invalidSnapshot
    case invalidReview
}

public struct ReviewID: Hashable, Sendable, Codable {
    public let rawValue: String

    public init(rawValue: String) throws {
        let bytes = Array(rawValue.utf8)
        guard !bytes.isEmpty, bytes.count <= 64,
              bytes.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 45 || $0 == 95 })
        else {
            throw ReviewModelError.invalidReviewID
        }
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        try self.init(rawValue: String(from: decoder))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public enum ReviewKind: String, Codable, Sendable, CaseIterable {
    case projectHost = "project_host"

    public init(from decoder: Decoder) throws {
        let value = try String(from: decoder)
        guard let kind = Self(rawValue: value) else {
            throw ReviewModelError.unsupportedReviewKind(value)
        }
        self = kind
    }
}

public enum ApprovalScope: String, Codable, Sendable {
    case futureProjectSessions = "future_project_sessions"

    public init(from decoder: Decoder) throws {
        let value = try String(from: decoder)
        guard let scope = Self(rawValue: value) else {
            throw ReviewModelError.unsupportedApprovalScope(value)
        }
        self = scope
    }
}

public enum ReviewContextState: String, Codable, Sendable {
    case verified
    case unbound
    case unrepresentable

    public init(from decoder: Decoder) throws {
        let value = try String(from: decoder)
        guard let state = Self(rawValue: value) else {
            throw ReviewModelError.unsupportedContextState(value)
        }
        self = state
    }
}

public struct UnixMilliseconds: Hashable, Codable, Sendable, Comparable {
    public let rawValue: Int64

    public init(rawValue: Int64) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        self.init(rawValue: try Int64(from: decoder))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public struct Review: Hashable, Codable, Sendable {
    public let id: ReviewID
    public let kind: ReviewKind
    public let host: String?
    public let projectPath: String?
    public let reason: String
    public let reasonTruncated: Bool
    public let contextState: ReviewContextState
    public let createdAt: UnixMilliseconds
    public let expiresAt: UnixMilliseconds
    public let approvalScope: ApprovalScope
    public let canApprove: Bool
    public let canDeny: Bool

    enum CodingKeys: String, CodingKey {
        case id = "review_id"
        case kind, host
        case projectPath = "project_path"
        case reason
        case reasonTruncated = "reason_truncated"
        case contextState = "context_state"
        case createdAt = "created_at_unix_ms"
        case expiresAt = "expires_at_unix_ms"
        case approvalScope = "approval_scope"
        case canApprove = "can_approve"
        case canDeny = "can_deny"
    }

    public init(id: ReviewID, kind: ReviewKind, host: String?, projectPath: String?, reason: String, reasonTruncated: Bool, contextState: ReviewContextState, createdAt: UnixMilliseconds, expiresAt: UnixMilliseconds, approvalScope: ApprovalScope, canApprove: Bool, canDeny: Bool) throws {
        self.id = id
        self.kind = kind
        self.host = host
        self.projectPath = projectPath
        self.reason = reason
        self.reasonTruncated = reasonTruncated
        self.contextState = contextState
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.approvalScope = approvalScope
        self.canApprove = canApprove
        self.canDeny = canDeny
        try validate()
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: values.decode(ReviewID.self, forKey: .id),
            kind: values.decode(ReviewKind.self, forKey: .kind),
            host: values.decodeIfPresent(String.self, forKey: .host),
            projectPath: values.decodeIfPresent(String.self, forKey: .projectPath),
            reason: values.decode(String.self, forKey: .reason),
            reasonTruncated: values.decode(Bool.self, forKey: .reasonTruncated),
            contextState: values.decode(ReviewContextState.self, forKey: .contextState),
            createdAt: values.decode(UnixMilliseconds.self, forKey: .createdAt),
            expiresAt: values.decode(UnixMilliseconds.self, forKey: .expiresAt),
            approvalScope: values.decode(ApprovalScope.self, forKey: .approvalScope),
            canApprove: values.decode(Bool.self, forKey: .canApprove),
            canDeny: values.decode(Bool.self, forKey: .canDeny)
        )
    }

    private func validate() throws {
        guard host.map({ $0.utf8.count <= 255 }) ?? true,
              projectPath.map({ $0.utf8.count <= 2_048 }) ?? true,
              reason.utf8.count <= 256
        else {
            throw ReviewModelError.invalidReview
        }
        guard kind == .projectHost, approvalScope == .futureProjectSessions, canDeny else {
            throw ReviewModelError.invalidReview
        }
        switch contextState {
        case .verified:
            guard host?.isEmpty == false, projectPath?.isEmpty == false, canApprove else { throw ReviewModelError.invalidReview }
        case .unbound:
            guard host?.isEmpty == false, projectPath == nil, !canApprove else { throw ReviewModelError.invalidReview }
        case .unrepresentable:
            guard !canApprove, !(host?.isEmpty == false && projectPath?.isEmpty == false) else { throw ReviewModelError.invalidReview }
        }
    }
}

public struct ReviewSnapshotV1: Hashable, Codable, Sendable {
    public static let protocolVersion: UInt32 = 1

    public let version: UInt32
    public let generatedAt: UnixMilliseconds
    public let totalPending: Int
    public let truncated: Bool
    public let reviews: [Review]

    enum CodingKeys: String, CodingKey {
        case version = "protocol_version"
        case generatedAt = "generated_at_unix_ms"
        case totalPending = "total_pending"
        case truncated, reviews
    }

    public init(version: UInt32, generatedAt: UnixMilliseconds, totalPending: Int, truncated: Bool, reviews: [Review]) throws {
        guard version == Self.protocolVersion else { throw ReviewModelError.unsupportedProtocolVersion(version) }
        guard totalPending >= reviews.count, reviews.count <= 3, truncated == (totalPending > reviews.count), Set(reviews.map(\.id)).count == reviews.count else {
            throw ReviewModelError.invalidSnapshot
        }
        self.version = version
        self.generatedAt = generatedAt
        self.totalPending = totalPending
        self.truncated = truncated
        self.reviews = reviews
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            version: values.decode(UInt32.self, forKey: .version),
            generatedAt: values.decode(UnixMilliseconds.self, forKey: .generatedAt),
            totalPending: values.decode(Int.self, forKey: .totalPending),
            truncated: values.decode(Bool.self, forKey: .truncated),
            reviews: values.decode([Review].self, forKey: .reviews)
        )
    }
}
