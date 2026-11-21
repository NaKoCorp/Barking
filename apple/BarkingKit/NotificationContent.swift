import Foundation
import UserNotifications

/// What the extension shows (spec iOS foundations §5.3).
public enum NotificationContent {
    /// Fills `content` from the quick sync; returns `shown`, `original` (the
    /// push stays as it came, "New message") or `suppressed` (the wake had
    /// nothing visible: title, body and thread are cleared, and the extension
    /// delivers an empty content that the system drops, spec §5.5).
    /// Only a clean sync that read everything (`nothingToShow`) suppresses:
    /// a failed or offline one never does.
    /// While the app is locked (`locked`) or the preview is `.generic`,
    /// nothing but "New message" shows: no name, no text, no thread (spec §5.4, §6.1).
    /// `.nameOnly` keeps the name and the thread but never the text.
    public static func apply(_ summary: SyncSummary?, to content: UNMutableNotificationContent,
                             preview: PushPreview, locked: Bool) -> String {
        guard let summary else { return "original" }
        let messages = summary.newMessages
        let reactions = summary.newReactions
        let count = messages.count + reactions.count
        guard count > 0 else {
            guard summary.nothingToShow else { return "original" }
            content.title = ""
            content.body = ""
            content.threadIdentifier = ""
            return "suppressed"
        }
        if locked || preview == .generic {
            content.title = ""
            content.body = localized("NEW_MESSAGE", fallback: "New message")
            content.threadIdentifier = ""
            return "shown"
        }
        let contacts = messages.map(\.contact) + reactions.map(\.contact)
        let oneContact = Set(contacts).count == 1
        if count == 1 {
            if let m = messages.first {
                content.title = m.name
                content.body = preview != .nameAndText ? localized("NEW_MESSAGE", fallback: "New message")
                    : m.needsUpdate ? localized("NEEDS_UPDATE", fallback: "This message needs a newer version of Barking.")
                    : m.text
            } else if let r = reactions.first {
                content.title = r.name
                content.body = reactionBody(r, withText: preview == .nameAndText)
            }
        } else {
            content.title = oneContact ? (messages.first?.name ?? reactions.first?.name ?? "") : ""
            content.body = String(format: localized("NEW_MESSAGES_COUNT", fallback: "%lld new messages"), Int64(count))
        }
        content.threadIdentifier = oneContact ? (contacts.first ?? "") : ""
        return "shown"
    }

    private static func reactionBody(_ r: NewReaction, withText: Bool) -> String {
        guard withText else { return localized("REACTED", fallback: "Reacted") }
        let emojis = r.emojis.joined()
        if let excerpt = r.excerpt, !excerpt.isEmpty {
            return String(format: localized("REACTED_TO", fallback: "Reacted %1$@ to “%2$@”"), emojis, excerpt)
        }
        return String(format: localized("REACTED_EMOJI", fallback: "Reacted %@"), emojis)
    }

    private final class Marker {}

    static func localized(_ key: String, fallback: String) -> String {
        NSLocalizedString(key, tableName: nil, bundle: Bundle(for: Marker.self), value: fallback, comment: "")
    }
}
