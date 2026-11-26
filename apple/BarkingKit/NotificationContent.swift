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
    /// An ephemeral never shows its text, whatever the preview: "Disappearing
    /// message", and a reaction to one says so without its emoji (spec
    /// deletion/ephemeral §5.4). A wake with no message or reaction but
    /// contact requests to notify shows the invitation ("INVITE_*"); a message
    /// in the same wake wins. `bundle`: the strings (tests pass French);
    /// `locale`: the quotation marks around a declared name.
    public static func apply(_ summary: SyncSummary?, to content: UNMutableNotificationContent,
                             preview: PushPreview, locked: Bool,
                             bundle: Bundle = Bundle(for: Marker.self), locale: Locale = .current) -> String {
        guard let summary else { return "original" }
        let messages = summary.newMessages
        let reactions = summary.newReactions
        let count = messages.count + reactions.count
        guard count > 0 else {
            let requests = summary.newRequests
            if !requests.isEmpty {
                content.title = ""
                content.body = invitationBody(requests, hidden: locked || preview == .generic,
                                              bundle: bundle, locale: locale)
                content.threadIdentifier = ""
                return "shown"
            }
            guard summary.nothingToShow else { return "original" }
            content.title = ""
            content.body = ""
            content.threadIdentifier = ""
            return "suppressed"
        }
        if locked || preview == .generic {
            content.title = ""
            content.body = localized("NEW_MESSAGE", fallback: "New message", bundle: bundle)
            content.threadIdentifier = ""
            return "shown"
        }
        let contacts = messages.map(\.contact) + reactions.map(\.contact)
        let oneContact = Set(contacts).count == 1
        if count == 1 {
            if let m = messages.first {
                content.title = m.name
                content.body = m.ephemeral
                    ? localized("EPHEMERAL_MESSAGE", fallback: "Disappearing message", bundle: bundle)
                    : preview != .nameAndText ? localized("NEW_MESSAGE", fallback: "New message", bundle: bundle)
                    : m.needsUpdate
                    ? localized("NEEDS_UPDATE", fallback: "This message needs a newer version of Barking.", bundle: bundle)
                    : m.text
            } else if let r = reactions.first {
                content.title = r.name
                content.body = reactionBody(r, withText: preview == .nameAndText, bundle: bundle)
            }
        } else {
            content.title = oneContact ? (messages.first?.name ?? reactions.first?.name ?? "") : ""
            content.body = String(format: localized("NEW_MESSAGES_COUNT", fallback: "%lld new messages", bundle: bundle), Int64(count))
        }
        content.threadIdentifier = oneContact ? (contacts.first ?? "") : ""
        return "shown"
    }

    /// One request: who invited, their declared name quoted. Several, or
    /// while the name must not show: "New invitation". No thread: a
    /// requester has no conversation yet.
    private static func invitationBody(_ requests: [NewRequest], hidden: Bool, bundle: Bundle, locale: Locale) -> String {
        guard !hidden, requests.count == 1, let r = requests.first else {
            return localized("INVITE_GENERIC", fallback: "New invitation", bundle: bundle)
        }
        let name = DeclaredName.quoted(r.name, fingerprint: r.contact, locale: locale)
        let format = r.resent
            ? localized("INVITE_RESENT", fallback: "%@ resent their invitation", bundle: bundle)
            : localized("INVITE_NEW", fallback: "New invitation from %@", bundle: bundle)
        return String(format: format, name)
    }

    private static func reactionBody(_ r: NewReaction, withText: Bool, bundle: Bundle) -> String {
        // Neither the emoji nor the text of an ephemeral: only that it was one.
        if r.onEphemeral {
            return localized("REACTED_EPHEMERAL", fallback: "Reacted to a disappearing message", bundle: bundle)
        }
        guard withText else { return localized("REACTED", fallback: "Reacted", bundle: bundle) }
        let emojis = r.emojis.joined()
        if let excerpt = r.excerpt, !excerpt.isEmpty {
            return String(format: localized("REACTED_TO", fallback: "Reacted %1$@ to “%2$@”", bundle: bundle), emojis, excerpt)
        }
        return String(format: localized("REACTED_EMOJI", fallback: "Reacted %@", bundle: bundle), emojis)
    }

    public final class Marker {}

    static func localized(_ key: String, fallback: String, bundle: Bundle = Bundle(for: Marker.self)) -> String {
        NSLocalizedString(key, tableName: nil, bundle: bundle, value: fallback, comment: "")
    }
}
