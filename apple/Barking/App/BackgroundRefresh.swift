import BackgroundTasks
import BarkingKit
import UserNotifications

/// The refresh iOS grants now and then (spec iOS push §5.6): the fallback
/// when instant notifications are off or a push did not get through. A full
/// sync, then one local notification for what is new, shown as the extension
/// would show it (same preview, same lock rule).
enum BackgroundRefresh {
    static let identifier = "com.nakocorp.barking.refresh"
    /// iOS may run it no sooner than this after the request.
    static let interval: TimeInterval = 3600

    /// Before the end of `didFinishLaunching` (a `BGTaskScheduler` rule).
    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            guard let task = task as? BGAppRefreshTask else { return }
            handle(task)
        }
    }

    static func request(now: Date) -> BGAppRefreshTaskRequest {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = now.addingTimeInterval(interval)
        return request
    }

    static func schedule(now: Date = Date()) {
        // Refused in the simulator and when the refresh is off: nothing to do.
        try? BGTaskScheduler.shared.submit(request(now: now))
    }

    /// Syncs, then posts one notification for the new messages. `false` when
    /// there is no open core (no device, wipe pending, before first unlock:
    /// nothing is opened here) or the network was down.
    @MainActor
    static func run(service: CoreService?, locked: Bool,
                    post: (UNNotificationRequest) async -> Void) async -> Bool {
        guard let service else { return false }
        let outcome = await service.refreshSync()
        // Expired meanwhile (the sync itself is not cancelled with us): post nothing.
        if Task.isCancelled { return false }
        if !outcome.newMessages.isEmpty {
            let preview = (try? await service.notificationPrefs().preview) ?? .generic
            if Task.isCancelled { return false }
            let content = UNMutableNotificationContent()
            let summary = SyncSummary(itemsReceived: UInt32(outcome.items), sent: UInt32(outcome.sent),
                                      newMessages: outcome.newMessages, networkUp: outcome.networkUp, error: nil)
            _ = NotificationContent.apply(summary, to: content, preview: preview, locked: locked)
            await post(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
        return outcome.networkUp
    }

    /// Completes a task exactly once, whichever of the run's end and the
    /// expiration comes first: BGTask does not allow a second completion.
    final class OnceCompletion: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        private let complete: @Sendable (Bool) -> Void

        init(_ complete: @escaping @Sendable (Bool) -> Void) { self.complete = complete }

        /// Completes with `success` the first time; `false` (and nothing) after.
        @discardableResult
        func finish(success: Bool) -> Bool {
            let first = lock.withLock { () -> Bool in
                defer { done = true }
                return !done
            }
            if first { complete(success) }
            return first
        }
    }

    private static func handle(_ task: BGAppRefreshTask) {
        // Always asks for the next one, whatever happens to this one.
        schedule()
        // `BGAppRefreshTask` is not `Sendable`; `setTaskCompleted` may be called from any thread.
        nonisolated(unsafe) let bg = task
        let completion = OnceCompletion { bg.setTaskCompleted(success: $0) }
        let work = Task { @MainActor in
            let ok = await run(service: AppRouter.current?.core, locked: AppLock.isLockedForExtension) {
                try? await UNUserNotificationCenter.current().add($0)
            }
            completion.finish(success: ok)
        }
        task.expirationHandler = {
            work.cancel()
            completion.finish(success: false)
        }
    }
}
