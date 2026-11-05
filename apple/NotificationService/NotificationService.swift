import BarkingKit
import UserNotifications

/// Wakes on the relay's push: quick sync, decrypt, show (spec iOS
/// foundations §5.3), and records the measurement (§6.1). Whatever fails,
/// the push is delivered as it came ("New message"); nothing is lost, the
/// packets stay on the nodes.
final class NotificationService: UNNotificationServiceExtension, @unchecked Sendable {
    private let delivery = NSLock()
    private var handler: ((UNNotificationContent) -> Void)?
    private var original: UNNotificationContent?
    /// iOS cut the time: the push went out as it came.
    private var expired = false

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        handler = contentHandler
        original = request.content
        guard let content = request.content.mutableCopy() as? UNMutableNotificationContent else {
            deliver(request.content)
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            var (record, summary) = BenchRun.run(source: "extension")
            let shown = NotificationContent.apply(summary, to: content)
            if record.outcome.isEmpty { record.outcome = shown }
            if self.deliver(content) == false { record.outcome = "expired" }
            try? BenchStore.shared().append(record)
        }
    }

    override func serviceExtensionTimeWillExpire() {
        if let original { deliver(original) }
    }

    /// Delivers once: the work and the expiry may both get here. False when
    /// the other one delivered first.
    @discardableResult
    private func deliver(_ content: UNNotificationContent) -> Bool {
        delivery.lock()
        let h = handler
        handler = nil
        delivery.unlock()
        h?(content)
        return h != nil
    }
}
