import Foundation

enum NotificationSettingsDestination {
    private static let paneIdentifier = "com.apple.Notifications-Settings.extension"

    static func applicationURL(bundleIdentifier: String?) -> URL? {
        guard let bundleIdentifier, !bundleIdentifier.isEmpty else { return nil }

        var components = URLComponents()
        components.scheme = "x-apple.systempreferences"
        components.path = paneIdentifier
        components.queryItems = [URLQueryItem(name: "id", value: bundleIdentifier)]
        return components.url
    }

    static var paneURL: URL {
        URL(string: "x-apple.systempreferences:\(paneIdentifier)")!
    }
}
