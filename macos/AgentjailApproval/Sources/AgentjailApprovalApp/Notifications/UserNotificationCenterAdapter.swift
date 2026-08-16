import Foundation
@preconcurrency import UserNotifications
import AgentjailApprovalCore

@MainActor
public final class UserNotificationCenterAdapter: NSObject, ApprovalNotificationCenter {
    private let center: UNUserNotificationCenter

    public init(center: UNUserNotificationCenter = .current()) {
        self.center = center
    }

    public func registerApprovalCategory() {
        center.setNotificationCategories([Self.approvalCategory])
    }

    public func authorizationStatus() async -> ApprovalNotificationAuthorization {
        await withCheckedContinuation { (continuation: CheckedContinuation<ApprovalNotificationAuthorization, Never>) in
            center.getNotificationSettings { settings in
                continuation.resume(returning: Self.authorization(from: settings.authorizationStatus))
            }
        }
    }

    public func requestAuthorizationFromUser() async throws -> Bool {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Bool, Error>) in
            center.requestAuthorization(options: [.alert, .sound]) { granted, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: granted)
                }
            }
        }
    }

    public func schedule(_ request: ApprovalNotificationRequest) async throws {
        let content = UNMutableNotificationContent()
        content.title = request.title
        content.body = request.body
        content.categoryIdentifier = request.categoryIdentifier
        content.userInfo = request.userInfo
        let nativeRequest = UNNotificationRequest(identifier: request.identifier, content: content, trigger: nil)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            center.add(nativeRequest) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    public func existingRequestIdentifiers() async -> Set<String> {
        let pending = await withCheckedContinuation { (continuation: CheckedContinuation<[String], Never>) in
            center.getPendingNotificationRequests { continuation.resume(returning: $0.map(\.identifier)) }
        }
        let delivered = await withCheckedContinuation { (continuation: CheckedContinuation<[String], Never>) in
            center.getDeliveredNotifications { continuation.resume(returning: $0.map(\.request.identifier)) }
        }
        return Set(pending).union(delivered)
    }

    public func removeRequests(identifiers: Set<String>) {
        let values = Array(identifiers)
        center.removePendingNotificationRequests(withIdentifiers: values)
        center.removeDeliveredNotifications(withIdentifiers: values)
    }

    static var approvalCategory: UNNotificationCategory {
        let review = UNNotificationAction(
            identifier: ApprovalNotificationConfiguration.reviewActionIdentifier,
            title: "Review",
            options: [.foreground]
        )
        let deny = UNNotificationAction(
            identifier: ApprovalNotificationConfiguration.denyActionIdentifier,
            title: "Deny",
            options: [.destructive, .authenticationRequired]
        )
        return UNNotificationCategory(
            identifier: ApprovalNotificationConfiguration.categoryIdentifier,
            actions: [review, deny],
            intentIdentifiers: [],
            options: []
        )
    }

    private nonisolated static func authorization(from status: UNAuthorizationStatus) -> ApprovalNotificationAuthorization {
        switch status {
        case .authorized:
            .authorized
        case .denied:
            .denied
        case .notDetermined, .provisional:
            .notDetermined
        @unknown default:
            .denied
        }
    }
}

public final class ApprovalNotificationDelegate: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    public static let foregroundPresentationOptions: UNNotificationPresentationOptions = [.banner, .list, .sound]

    private let responseHandler: @MainActor @Sendable (ApprovalNotificationResponse) async throws -> Void

    public init(responseHandler: @escaping @MainActor @Sendable (ApprovalNotificationResponse) async throws -> Void) {
        self.responseHandler = responseHandler
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        Self.presentForeground(completionHandler: completionHandler)
    }

    static func presentForeground(
        completionHandler: (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler(foregroundPresentationOptions)
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        receiveResponse(
            actionIdentifier: response.actionIdentifier,
            userInfo: response.notification.request.content.userInfo,
            completionHandler: completionHandler
        )
    }

    func receiveResponse(
        actionIdentifier: String,
        userInfo: [AnyHashable: Any],
        completionHandler: @escaping () -> Void
    ) {
        let response = Self.response(actionIdentifier: actionIdentifier, userInfo: userInfo)
        let completion = NotificationResponseCompletion(completionHandler)
        Task { @MainActor [responseHandler, completion] in
            defer { completion.finish() }
            try? await responseHandler(response)
        }
    }

    static func response(actionIdentifier: String, userInfo: [AnyHashable: Any]) -> ApprovalNotificationResponse {
        guard userInfo.count == 1,
              let rawReviewID = userInfo[ApprovalNotificationConfiguration.reviewIDUserInfoKey] as? String,
              let reviewID = try? ReviewID(rawValue: rawReviewID)
        else {
            return ApprovalNotificationResponse(action: .other, reviewID: nil)
        }

        switch actionIdentifier {
        case ApprovalNotificationConfiguration.reviewActionIdentifier:
            return ApprovalNotificationResponse(action: .review, reviewID: reviewID)
        case ApprovalNotificationConfiguration.denyActionIdentifier:
            return ApprovalNotificationResponse(action: .deny, reviewID: reviewID)
        default:
            return ApprovalNotificationResponse(action: .other, reviewID: reviewID)
        }
    }
}

private final class NotificationResponseCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: (() -> Void)?

    init(_ completion: @escaping () -> Void) {
        self.completion = completion
    }

    func finish() {
        let completion = lock.withLock { () -> (() -> Void)? in
            defer { self.completion = nil }
            return self.completion
        }
        completion?()
    }
}

@MainActor
public final class UserDefaultsApprovalNotificationDedupeStorage: ApprovalNotificationDedupeStoring {
    private let defaults: UserDefaults
    private let key: String

    public init(
        defaults: UserDefaults = .standard,
        key: String = "com.blinkerlm.agentjail.approval.notified-review-ids"
    ) {
        self.defaults = defaults
        self.key = key
    }

    public func loadRememberedReviewIDs() -> Set<ReviewID> {
        let values = defaults.stringArray(forKey: key) ?? []
        return Set(values.compactMap { try? ReviewID(rawValue: $0) })
    }

    public func saveRememberedReviewIDs(_ reviewIDs: Set<ReviewID>) {
        defaults.set(reviewIDs.map(\.rawValue).sorted(), forKey: key)
    }
}
