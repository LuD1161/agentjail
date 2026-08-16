import Foundation

public struct ReviewControlClient: ReviewControlling {
    private let tokenLoader: any ControlTokenLoading
    private let transport: any ControlFraming

    public init(tokenLoader: any ControlTokenLoading = FileControlTokenLoader(), transport: any ControlFraming = UnixControlTransport()) {
        self.tokenLoader = tokenLoader
        self.transport = transport
    }

    public func fetchSnapshot() async throws -> ReviewSnapshotV1 {
        let response = try await send(type: "review_snapshot", reviewID: nil)
        guard let snapshot = response.snapshot else { throw ApprovalControlError.protocolMismatch }
        return snapshot
    }

    public func approve(_ reviewID: ReviewID) async throws {
        _ = try await send(type: "grant_approve", reviewID: reviewID)
    }

    public func deny(_ reviewID: ReviewID) async throws {
        _ = try await send(type: "grant_deny", reviewID: reviewID)
    }

    private func send(type: String, reviewID: ReviewID?) async throws -> Response {
        return try await Task.detached(priority: .userInitiated) {
            let token: String
            do {
                token = try tokenLoader.loadToken()
            } catch let error as ApprovalControlError {
                throw error
            } catch {
                throw ApprovalControlError.tokenUnreadable
            }
            let request = Request(type: type, token: token, protocolVersion: type == "review_snapshot" ? ReviewSnapshotV1.protocolVersion : nil, grantID: reviewID)
            let frame: Data
            do {
                frame = try request.frame()
            } catch {
                throw ApprovalControlError.malformedReply
            }
            let reply: Data
            do {
                reply = try transport.roundTrip(frame)
            } catch let error as ApprovalControlError {
                throw error
            } catch {
                throw ApprovalControlError.daemonUnavailable
            }
            return try Response.decode(frame: reply, redacting: token)
        }.value
    }
}

private struct Request: Encodable, Sendable {
    let type: String
    let token: String
    let protocolVersion: UInt32?
    let grantID: ReviewID?

    enum CodingKeys: String, CodingKey { case type; case token = "ctl_token"; case protocolVersion = "protocol_version"; case grantID = "grant_id" }

    func frame() throws -> Data {
        let payload = try JSONEncoder().encode(self)
        guard !payload.contains(10), payload.count + 1 <= UnixControlTransport.maximumFrameBytes else { throw ApprovalControlError.malformedReply }
        return payload + Data([10])
    }
}

private struct Response: Decodable, Sendable {
    let ok: Bool
    let error: String?
    let snapshot: ReviewSnapshotV1?

    enum CodingKeys: String, CodingKey { case ok, error; case snapshot = "review_snapshot" }

    static func decode(frame: Data, redacting token: String) throws -> Self {
        guard frame.last == 10, frame.count <= UnixControlTransport.maximumFrameBytes else { throw ApprovalControlError.oversizedReply }
        do {
            let response = try JSONDecoder().decode(Self.self, from: frame.dropLast())
            guard response.ok else {
                let message = String((response.error ?? "request refused").replacingOccurrences(of: token, with: "[redacted]").prefix(512))
                if message == "unauthorized" { throw ApprovalControlError.unauthorized }
                throw ApprovalControlError.serverRefused(message)
            }
            return response
        } catch let error as ApprovalControlError {
            throw error
        } catch let error as ReviewModelError {
            switch error {
            case .unsupportedProtocolVersion: throw ApprovalControlError.protocolMismatch
            default: throw ApprovalControlError.malformedReply
            }
        } catch {
            throw ApprovalControlError.malformedReply
        }
    }
}
