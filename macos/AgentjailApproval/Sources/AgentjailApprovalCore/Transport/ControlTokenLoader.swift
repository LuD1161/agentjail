import Foundation

public protocol ControlTokenLoading: Sendable {
    func loadToken() throws -> String
}

public struct FileControlTokenLoader: ControlTokenLoading {
    public let path: URL

    public init(path: URL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".agentjail/control.token")) {
        self.path = path
    }

    public func loadToken() throws -> String {
        guard FileManager.default.fileExists(atPath: path.path) else {
            throw ApprovalControlError.tokenMissing
        }
        let data: Data
        do {
            data = try Data(contentsOf: path)
        } catch {
            let error = error as NSError
            if error.domain == NSCocoaErrorDomain, error.code == CocoaError.fileNoSuchFile.rawValue {
                throw ApprovalControlError.tokenMissing
            }
            throw ApprovalControlError.tokenUnreadable
        }
        guard let token = String(data: data, encoding: .utf8) else { throw ApprovalControlError.tokenUnreadable }
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.utf8.count == 64, trimmed.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }) else {
            throw ApprovalControlError.tokenUnreadable
        }
        return trimmed
    }
}
