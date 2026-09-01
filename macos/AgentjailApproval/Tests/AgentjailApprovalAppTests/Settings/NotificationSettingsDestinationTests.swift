import Testing
@testable import AgentjailApprovalApp

struct NotificationSettingsDestinationTests {
    @Test func targetsTheApplicationsNotificationControls() {
        let destination = NotificationSettingsDestination.applicationURL(
            bundleIdentifier: "com.blinkerlm.agentjail"
        )

        #expect(
            destination?.absoluteString
                == "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=com.blinkerlm.agentjail"
        )
    }

    @Test func omitsAnApplicationTargetWithoutABundleIdentifier() {
        #expect(NotificationSettingsDestination.applicationURL(bundleIdentifier: nil) == nil)
        #expect(NotificationSettingsDestination.applicationURL(bundleIdentifier: "") == nil)
    }

    @Test func providesTheNotificationsPaneFallback() {
        #expect(
            NotificationSettingsDestination.paneURL.absoluteString
                == "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
        )
    }
}
