import Foundation
import UserNotifications

/// What the extension shows (spec iOS foundations §5.3).
public enum NotificationContent {
    /// Fills `content` from the quick sync; returns `shown`, or `original`
    /// when it leaves the push as it came ("New message").
    /// While the app is locked (`locked`), nothing but "New message" shows:
    /// no name, no text, no thread (spec §6.1).
    public static func apply(_ summary: SyncSummary?, to content: UNMutableNotificationContent,
                             locked: Bool = AppLock.isLockedForExtension) -> String {
        guard let messages = summary?.newMessages, let first = messages.first else { return "original" }
        if locked {
            content.title = ""
            content.body = localized("NEW_MESSAGE", fallback: "New message")
            content.threadIdentifier = ""
            return "shown"
        }
        let oneContact = messages.allSatisfy { $0.contact == first.contact }
        if messages.count == 1 {
            content.title = first.name
            content.body = first.text
        } else {
            content.title = oneContact ? first.name : ""
            content.body = String(format: localized("NEW_MESSAGES_COUNT", fallback: "%lld new messages"), Int64(messages.count))
        }
        content.threadIdentifier = oneContact ? first.contact : ""
        return "shown"
    }

    private final class Marker {}

    static func localized(_ key: String, fallback: String) -> String {
        NSLocalizedString(key, tableName: nil, bundle: Bundle(for: Marker.self), value: fallback, comment: "")
    }
}
