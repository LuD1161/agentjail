import Foundation
import XCTest
@testable import AgentjailApprovalCore

final class ReviewModelsTests: XCTestCase {
    func testCanonicalGoFixturePreservesProjectionFieldsAndOrder() throws {
        let fixture = try Data(contentsOf: fixtureURL())
        let envelope = try JSONDecoder().decode(FixtureEnvelope.self, from: fixture)
        XCTAssertTrue(envelope.ok)
        let snapshot = try XCTUnwrap(envelope.snapshot)
        XCTAssertEqual(snapshot.version, 1)
        XCTAssertEqual(snapshot.generatedAt.rawValue, 1_786_816_800_123)
        XCTAssertEqual(snapshot.totalPending, 3)
        XCTAssertFalse(snapshot.truncated)
        XCTAssertEqual(snapshot.reviews.map(\.id.rawValue), ["review-verified-001", "review-unbound-002", "review-unrepresentable-003"])
        XCTAssertEqual(snapshot.reviews.map(\.canDeny), [true, true, true])
        XCTAssertTrue(snapshot.reviews[0].canApprove)
        XCTAssertTrue(snapshot.reviews[2].reasonTruncated == false)
    }

    func testUnknownAdditiveFieldsAreToleratedButUnknownVersionAndEnumsFail() throws {
        var object = try JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL())) as! [String: Any]
        object["future_envelope"] = ["ignored": true]
        let additive = try JSONSerialization.data(withJSONObject: object)
        XCTAssertNoThrow(try JSONDecoder().decode(FixtureEnvelope.self, from: additive))

        var snapshot = object["review_snapshot"] as! [String: Any]
        snapshot["protocol_version"] = 2
        object["review_snapshot"] = snapshot
        XCTAssertThrowsError(try JSONDecoder().decode(FixtureEnvelope.self, from: JSONSerialization.data(withJSONObject: object))) { error in
            XCTAssertEqual(error as? ReviewModelError, .unsupportedProtocolVersion(2))
        }

        snapshot["protocol_version"] = 1
        var reviews = snapshot["reviews"] as! [[String: Any]]
        reviews[0]["kind"] = "future_kind"
        snapshot["reviews"] = reviews
        object["review_snapshot"] = snapshot
        XCTAssertThrowsError(try JSONDecoder().decode(FixtureEnvelope.self, from: JSONSerialization.data(withJSONObject: object))) { error in
            XCTAssertEqual(error as? ReviewModelError, .unsupportedReviewKind("future_kind"))
        }
    }

    func testReviewIDRejectsControlCharactersAndOversizedValues() throws {
        XCTAssertNoThrow(try ReviewID(rawValue: "review_123-ABC"))
        XCTAssertThrowsError(try ReviewID(rawValue: "review id"))
        XCTAssertThrowsError(try ReviewID(rawValue: "review\n123"))
        XCTAssertThrowsError(try ReviewID(rawValue: String(repeating: "a", count: 65)))
    }

    func testAuthorityAndReasonByteLimitsMatchGoProjection() throws {
        let id = try ReviewID(rawValue: "review-limits")
        let created = UnixMilliseconds(rawValue: 1)
        XCTAssertThrowsError(try Review(id: id, kind: .projectHost, host: String(repeating: "h", count: 256), projectPath: "/project", reason: "reason", reasonTruncated: false, contextState: .verified, createdAt: created, expiresAt: created, approvalScope: .futureProjectSessions, canApprove: true, canDeny: true))
        XCTAssertThrowsError(try Review(id: id, kind: .projectHost, host: "host", projectPath: "/" + String(repeating: "p", count: 2_048), reason: "reason", reasonTruncated: false, contextState: .verified, createdAt: created, expiresAt: created, approvalScope: .futureProjectSessions, canApprove: true, canDeny: true))
        XCTAssertThrowsError(try Review(id: id, kind: .projectHost, host: "host", projectPath: "/project", reason: String(repeating: "r", count: 257), reasonTruncated: false, contextState: .verified, createdAt: created, expiresAt: created, approvalScope: .futureProjectSessions, canApprove: true, canDeny: true))
    }

    private func fixtureURL() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("internal/grantctl/testdata/review_snapshot_v1.json")
    }
}

private struct FixtureEnvelope: Decodable {
    let ok: Bool
    let snapshot: ReviewSnapshotV1?

    enum CodingKeys: String, CodingKey { case ok; case snapshot = "review_snapshot" }
}
