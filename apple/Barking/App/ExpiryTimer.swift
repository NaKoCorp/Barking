import BarkingKit
import Foundation

/// Erases ephemerals while the app is in front, whatever the screen (spec
/// deletion/ephemeral §5.3): on becoming active it expires what fell due,
/// then sleeps until `nextExpiry()` and expires again. `arm()` runs again
/// after anything that can move the next expiry (an expiry, a sync, a
/// send); inactive, nothing waits. Owned by `MainTabView`.
///
/// The open conversation keeps its own timer, which also follows its seen
/// reports: both erase through the core, so a second call at the same due
/// time finds nothing and only re-reads the next expiry.
@MainActor
final class ExpiryTimer {
    /// A due time already past (the core's clock and this one differ):
    /// wait this long rather than spin.
    static let pastDueWait: Duration = .seconds(1)

    private let nextExpiry: () async -> UInt64?
    private let expire: () async -> Void
    var now: () -> Date = Date.init
    var sleep: @Sendable (Duration) async throws -> Void
    private var active = false
    /// Bumped by each arm: an older arm that comes back late does nothing.
    private var generation = 0
    private(set) var task: Task<Void, Never>?

    init(nextExpiry: @escaping () async -> UInt64?, expire: @escaping () async -> Void,
         sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) }) {
        self.nextExpiry = nextExpiry
        self.expire = expire
        self.sleep = sleep
    }

    /// The core's expiry; `expireEphemeral` publishes `.expired`.
    convenience init(core: CoreService) {
        self.init(nextExpiry: { (try? await core.nextExpiry()) ?? nil },
                  expire: { _ = try? await core.expireEphemeral() })
    }

    /// Active: expires what is due, then arms. Otherwise stops.
    func phaseChanged(active: Bool) async {
        self.active = active
        guard active else { stop(); return }
        await expire()
        await arm()
    }

    /// One wait, to the next expiry (none without any), while active.
    func arm() async {
        guard active else { return }
        generation += 1
        let mine = generation
        let due = await nextExpiry()
        guard active, mine == generation else { return }
        task?.cancel()
        task = nil
        guard let due else { return }
        let left = Double(due) - now().timeIntervalSince1970
        let wait: Duration = left > 0 ? .milliseconds(Int64((left * 1000).rounded(.up))) : Self.pastDueWait
        let sleep = self.sleep
        task = Task { [weak self] in
            do { try await sleep(wait) } catch { return }
            guard !Task.isCancelled, let self else { return }
            self.task = nil
            await self.expire()
            await self.arm()
        }
    }

    func stop() {
        active = false
        generation += 1
        task?.cancel()
        task = nil
    }
}
