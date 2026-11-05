import BarkingKit
import SwiftUI

/// Foreground syncs (spec iOS messaging §4.2): on start, then every 15 s with
/// a conversation open, 60 s otherwise; stopped in the background.
@MainActor
final class SyncLoop {
    private let core: CoreService
    private var task: Task<Void, Never>?
    var scheduler = SyncScheduler(conversationOpen: false)

    init(core: CoreService) { self.core = core }

    func start(reason: SyncReason) {
        stop()
        task = Task { [weak self] in
            guard let self else { return }
            _ = await core.sync(reason: reason)
            while !Task.isCancelled {
                try? await Task.sleep(for: scheduler.nextDelay())
                if Task.isCancelled { break }
                _ = await core.sync(reason: .timer)
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }
}
