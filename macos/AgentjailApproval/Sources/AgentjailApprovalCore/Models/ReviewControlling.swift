import Foundation

public protocol ReviewControlling: Sendable {
    func fetchSnapshot() async throws -> ReviewSnapshotV1
    func approve(_ reviewID: ReviewID) async throws
    func deny(_ reviewID: ReviewID) async throws
}

public enum ApprovalControlError: Error, Equatable, Sendable {
    case tokenMissing
    case tokenUnreadable
    case unauthorized
    case daemonUnavailable
    case timeout
    case protocolMismatch
    case malformedReply
    case oversizedReply
    case invalidSocketPath
    case serverRefused(String)
}
