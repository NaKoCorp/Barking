import BarkingKit
import SwiftUI

/// Foreground syncs (spec iOS messaging §4.2): a sync when the app comes to
/// the front (`.launch` the first time, `.foreground` after), then every
/// 15 s with a conversation open, 60 s otherwise; stopped in the background.
/// One per ready core, owned by `MainTabView`. The notification extension
/// has its own quick sync and never runs this.
@MainActor
final class SyncLoop {
    private let sync: @Sendable (SyncReason) async -> Void
    private let sleep: @Sendable (Duration) async throws -> Void
    private var task: Task<Void, Never>?
    /// The first time it starts is the launch.
    private var started = false
    private var scheduler = SyncScheduler(conversationOpen: false)

    /// A conversation is on screen: the shorter cadence. A change restarts
    /// the wait at the new cadence, without a sync of its own.
    var conversationOpen: Bool {
        get { scheduler.conversationOpen }
        set {
            guard newValue != scheduler.conversationOpen else { return }
            scheduler.conversationOpen = newValue
            if isRunning { run(first: nil) }
        }
    }

    var isRunning: Bool { task != nil }

    /// `sync` runs one sync; `sleep` waits (throws when cancelled).
    init(sync: @escaping @Sendable (SyncReason) async -> Void,
         sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) }) {
        self.sync = sync
        self.sleep = sleep
    }

    convenience init(core: CoreService) {
        self.init(sync: { _ = await core.sync(reason: $0) })
    }

    /// Active: syncs now and runs (not again if it already runs: an
    /// inactive spell, such as the app switcher, did not stop it).
    /// Background: stops. Inactive: leaves it as it is.
    func scenePhaseChanged(to phase: ScenePhase) {
        switch phase {
        case .active:
            guard !isRunning else { return }
            run(first: started ? .foreground : .launch)
            started = true
        case .background:
            stop()
        default:
            break
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    /// Syncs for `first` (if any), then on the timer until cancelled.
    private func run(first: SyncReason?) {
        task?.cancel()
        let sync = self.sync, sleep = self.sleep, delay = scheduler.nextDelay()
        task = Task {
            if let first { await sync(first) }
            while !Task.isCancelled {
                do { try await sleep(delay) } catch { return }
                if Task.isCancelled { return }
                await sync(.timer)
            }
        }
    }
}

extension EnvironmentValues {
    /// The ready core's sync loop (nil in previews and before the tabs).
    @Entry var syncLoop: SyncLoop?
}
