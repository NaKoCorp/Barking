import BarkingKit
import UserNotifications

/// Wakes on the relay's push: quick sync, decrypt, show (spec iOS
/// foundations §5.3), and records the measurement (§6.1). Whatever fails,
/// the push is delivered as it came ("New message"); nothing is lost, the
/// packets stay on the nodes.
final class NotificationService: UNNotificationServiceExtension, @unchecked Sendable {
    /// Lock of the shared container: 2 s at most (spec iOS push §6.1).
    static let lockTimeoutMs: UInt64 = 2_000
    /// 5 s of margin on the 25 s iOS grants.
    static let deadlineMs: UInt64 = 20_000

    private let delivery = NSLock()
    private var handler: ((UNNotificationContent) -> Void)?
    private var original: UNNotificationContent?

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        handler = contentHandler
        original = request.content
        guard let content = request.content.mutableCopy() as? UNMutableNotificationContent else {
            return deliver(request.content)
        }
        DispatchQueue.global(qos: .userInitiated).async {
            var (record, summary) = BenchRun.run(
                source: "extension", deadlineMs: Self.deadlineMs, lockTimeoutMs: Self.lockTimeoutMs)
            let shown = NotificationContent.apply(summary, to: content)
            if record.outcome.isEmpty { record.outcome = shown }
            try? BenchStore.shared().append(record)
            self.deliver(content)
        }
    }

    override func serviceExtensionTimeWillExpire() {
        if let original { deliver(original) }
    }

    /// Delivers once: the work and the expiry may both get here.
    private func deliver(_ content: UNNotificationContent) {
        delivery.lock()
        let h = handler
        handler = nil
        delivery.unlock()
        h?(content)
    }
}
