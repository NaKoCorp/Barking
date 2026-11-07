import Foundation
import UserNotifications

/// The slice of `UNUserNotificationCenter` the failure notice needs, so a
/// test can stand in for it.
public protocol NotificationPosting: Sendable {
    /// The user allowed notifications (the prompt is the onboarding's).
    func isAuthorized() async -> Bool
    func add(_ request: UNNotificationRequest) async throws
}

/// The system's notification center.
public struct SystemNotificationCenter: NotificationPosting {
    public init() {}

    public func isAuthorized() async -> Bool {
        switch await UNUserNotificationCenter.current().notificationSettings().authorizationStatus {
        case .authorized, .provisional, .ephemeral: true
        default: false
        }
    }

    public func add(_ request: UNNotificationRequest) async throws {
        try await UNUserNotificationCenter.current().add(request)
    }
}

/// Tells the user, while the app is not in front, that sent messages are
/// confirmed not delivered (spec Lot M §15.6). One notification per contact,
/// worded without a name or any content: it shows on the lock screen.
public struct FailureNotifier: Sendable {
    /// `userInfo` keys: the contact's fingerprint and the first failed
    /// message's row id; the app opens the conversation on that message.
    public static let contactKey = "contact"
    public static let messageIdKey = "message_id"

    private let center: any NotificationPosting
    private let bundle: Bundle

    public init(center: any NotificationPosting = SystemNotificationCenter(),
                bundle: Bundle = Bundle(for: Marker.self)) {
        self.center = center
        self.bundle = bundle
    }

    public final class Marker {}

    /// Nothing when the app is active (it shows the failure itself) or when
    /// notifications are not allowed.
    public func post(_ notices: [DeliveryChange], appActive: Bool) async {
        guard !appActive, !notices.isEmpty, await center.isAuthorized() else { return }
        var byContact: [String: [Int64]] = [:]
        for n in notices { byContact[n.contact, default: []].append(n.messageId) }
        for contact in byContact.keys.sorted() {
            let ids = Set(byContact[contact]!)
            let first = ids.min()!
            let content = UNMutableNotificationContent()
            content.body = body(count: ids.count)
            content.threadIdentifier = contact
            content.sound = .default
            content.userInfo = [Self.contactKey: contact, Self.messageIdKey: first]
            // Same failure, same request: a repeat replaces, never doubles.
            let request = UNNotificationRequest(identifier: "failure.\(contact).\(first)", content: content, trigger: nil)
            try? await center.add(request)
        }
    }

    func body(count: Int) -> String {
        if count == 1 {
            return NSLocalizedString("FAILED_MESSAGE", tableName: nil, bundle: bundle,
                                     value: "A message couldn’t be delivered.", comment: "")
        }
        return String(format: NSLocalizedString("FAILED_MESSAGES_COUNT", tableName: nil, bundle: bundle,
                                                value: "%lld messages couldn’t be delivered.", comment: ""),
                      Int64(count))
    }
}
