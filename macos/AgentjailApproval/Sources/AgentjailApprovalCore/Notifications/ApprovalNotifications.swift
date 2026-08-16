import CryptoKit
import Foundation

public enum ApprovalNotificationAuthorization: Equatable, Sendable {
    case notDetermined
    case denied
    case authorized
}

public enum ApprovalNotificationAction: Equatable, Sendable {
    case review
    case deny
    case other
}

public struct ApprovalNotificationResponse: Equatable, Sendable {
    public let action: ApprovalNotificationAction
    public let reviewID: ReviewID?

    public init(action: ApprovalNotificationAction, reviewID: ReviewID?) {
        self.action = action
        self.reviewID = reviewID
    }
}

public struct ApprovalNotificationReviewRoute: Equatable, Sendable {
    public let reviewID: ReviewID
    public let generation: UInt64

    public init(reviewID: ReviewID, generation: UInt64) {
        self.reviewID = reviewID
        self.generation = generation
    }
}

public struct ApprovalNotificationRequest: Equatable, Sendable {
    public let identifier: String
    public let title: String
    public let body: String
    public let categoryIdentifier: String
    public let userInfo: [String: String]

    public init(identifier: String, title: String, body: String, categoryIdentifier: String, userInfo: [String: String]) {
        self.identifier = identifier
        self.title = title
        self.body = body
        self.categoryIdentifier = categoryIdentifier
        self.userInfo = userInfo
    }
}

public enum ApprovalNotificationConfiguration {
    public static let requestIdentifierPrefix = "com.blinkerlm.agentjail.approval.review."
    public static let categoryIdentifier = "com.blinkerlm.agentjail.approval.review.v1"
    public static let reviewActionIdentifier = "com.blinkerlm.agentjail.approval.review-action.v1"
    public static let denyActionIdentifier = "com.blinkerlm.agentjail.approval.deny-action.v1"
    public static let reviewIDUserInfoKey = "review_id"
    public static let title = "AgentJail approval requested"
    public static let body = "Review a project host request."
    public static let maximumRememberedReviewIDs = 64

    public static func requestIdentifier(for reviewID: ReviewID) -> String {
        let digest = SHA256.hash(data: Data(reviewID.rawValue.utf8))
        return requestIdentifierPrefix + digest.map { String(format: "%02x", $0) }.joined()
    }

    public static func request(for reviewID: ReviewID) -> ApprovalNotificationRequest {
        ApprovalNotificationRequest(
            identifier: requestIdentifier(for: reviewID),
            title: title,
            body: body,
            categoryIdentifier: categoryIdentifier,
            userInfo: [reviewIDUserInfoKey: reviewID.rawValue]
        )
    }
}

@MainActor
public protocol ApprovalNotificationCenter: AnyObject {
    func registerApprovalCategory()
    func authorizationStatus() async -> ApprovalNotificationAuthorization
    func requestAuthorizationFromUser() async throws -> Bool
    func schedule(_ request: ApprovalNotificationRequest) async throws
    func existingRequestIdentifiers() async -> Set<String>
    func removeRequests(identifiers: Set<String>)
}

@MainActor
public protocol ApprovalNotificationDedupeStoring: AnyObject {
    func loadRememberedReviewIDs() -> Set<ReviewID>
    func saveRememberedReviewIDs(_ reviewIDs: Set<ReviewID>)
}

@MainActor
public final class ApprovalNotificationCoordinator {
    private let center: any ApprovalNotificationCenter
    private let storage: any ApprovalNotificationDedupeStoring
    private let store: ApprovalStore
    private var categoriesRegistered = false
    private var handledDenyReviewIDs: Set<ReviewID> = []
    private var nextReviewRouteGeneration: UInt64 = 0

    public var reviewRouteHandler: ((ApprovalNotificationReviewRoute) -> Void)?

    public init(
        center: any ApprovalNotificationCenter,
        storage: any ApprovalNotificationDedupeStoring,
        store: ApprovalStore
    ) {
        self.center = center
        self.storage = storage
        self.store = store
    }

    public func registerCategories() {
        guard !categoriesRegistered else { return }
        categoriesRegistered = true
        center.registerApprovalCategory()
    }

    public func notificationAuthorizationStatus() async -> ApprovalNotificationAuthorization {
        await center.authorizationStatus()
    }

    @discardableResult
    public func enableNotificationsFromUserAction() async -> ApprovalNotificationAuthorization {
        do {
            _ = try await center.requestAuthorizationFromUser()
        } catch {
            return .denied
        }
        return await center.authorizationStatus()
    }

    public func synchronize(snapshot: AuthoritativeApprovalSnapshot) async {
        let currentReviewIDs = Set(snapshot.reviews.map(\.id))
        let currentRequestIdentifiers = Set(snapshot.reviews.map { ApprovalNotificationConfiguration.requestIdentifier(for: $0.id) })
        let existingIdentifiers = await center.existingRequestIdentifiers()
        let staleIdentifiers = Set(existingIdentifiers.filter {
            $0.hasPrefix(ApprovalNotificationConfiguration.requestIdentifierPrefix) && !currentRequestIdentifiers.contains($0)
        })
        if !staleIdentifiers.isEmpty {
            center.removeRequests(identifiers: staleIdentifiers)
        }

        var remembered = storage.loadRememberedReviewIDs().intersection(currentReviewIDs)
        if remembered.count > ApprovalNotificationConfiguration.maximumRememberedReviewIDs {
            let retained = Set(snapshot.reviews.prefix(ApprovalNotificationConfiguration.maximumRememberedReviewIDs).map(\.id))
            remembered.formIntersection(retained)
        }

        guard await center.authorizationStatus() == .authorized else {
            storage.saveRememberedReviewIDs(remembered)
            return
        }

        for review in snapshot.reviews {
            let identifier = ApprovalNotificationConfiguration.requestIdentifier(for: review.id)
            if remembered.contains(review.id) || existingIdentifiers.contains(identifier) {
                remembered.insert(review.id)
                continue
            }
            do {
                try await center.schedule(ApprovalNotificationConfiguration.request(for: review.id))
                remembered.insert(review.id)
            } catch {
                continue
            }
        }
        let retained = Set(snapshot.reviews.prefix(ApprovalNotificationConfiguration.maximumRememberedReviewIDs).map(\.id))
        remembered.formIntersection(retained)
        storage.saveRememberedReviewIDs(remembered)
    }

    public func handleNotificationResponse(_ response: ApprovalNotificationResponse) async {
        guard let reviewID = response.reviewID else { return }
        switch response.action {
        case .review:
            nextReviewRouteGeneration &+= 1
            reviewRouteHandler?(ApprovalNotificationReviewRoute(reviewID: reviewID, generation: nextReviewRouteGeneration))
        case .deny:
            guard recordDenyResponse(reviewID) else { return }
            let refresh = await store.refreshNow()
            guard case let .authoritative(snapshot) = refresh,
                  snapshot.reviews.contains(where: { $0.id == reviewID && $0.canDeny })
            else {
                return
            }
            _ = await store.deny(reviewID)
        case .other:
            return
        }
    }

    private func recordDenyResponse(_ reviewID: ReviewID) -> Bool {
        guard !handledDenyReviewIDs.contains(reviewID) else { return false }
        guard handledDenyReviewIDs.count < ApprovalNotificationConfiguration.maximumRememberedReviewIDs else { return false }
        handledDenyReviewIDs.insert(reviewID)
        return true
    }
}
