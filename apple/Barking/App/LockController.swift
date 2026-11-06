import BarkingKit
import Foundation
import Observation
import SwiftUI

/// The app lock as the screens see it (spec §6.1): whether the cover shows
/// and the two settings. The state itself lives in `AppLock`, in the App
/// Group, where the notification extension reads it.
@MainActor @Observable
final class LockController {
    private let lock: AppLock
    /// The app is locked: only `unlock()` (after `Owner.check()`) opens it.
    private(set) var locked: Bool
    private(set) var enabled: Bool
    private(set) var phase: ScenePhase = .active
    /// What Settings shows; `reload` sets it without writing it back.
    private var storedDelay: TimeInterval
    /// Set from Settings: saved for the extension.
    var delay: TimeInterval {
        get { storedDelay }
        set {
            storedDelay = newValue
            lock.delay = newValue
        }
    }

    init(lock: AppLock = .live, now: Date = Date()) {
        self.lock = lock
        locked = lock.needsUnlock(at: now)
        enabled = lock.enabled
        storedDelay = lock.delay
    }

    /// Turns the lock on or off. A phone without a passcode refuses it:
    /// nothing could unlock the app.
    @discardableResult
    func setEnabled(_ on: Bool) -> Bool {
        if on, !AppLock.canEnable() { return false }
        lock.enabled = on
        enabled = on
        locked = false
        return true
    }

    /// The cover goes up whenever the lock is on and the app is not active
    /// (the app switcher shows it), whatever the delay, and stays while locked.
    var covered: Bool { locked || (enabled && phase != .active) }

    func phaseChanged(to phase: ScenePhase, now: Date = Date()) {
        self.phase = phase
        switch phase {
        case .background: lock.didEnterBackground(at: now)
        case .active: if lock.didBecomeActive(at: now) { locked = true }
        default: break
        }
    }

    /// Asks for the owner once the lock screen is up; "Unlock" asks again.
    func promptIfLocked(owner: () async -> Bool = { await Owner.check(reason: String(localized: "Unlock Barking")) }) async {
        guard locked else { return }
        if await owner() { unlock() }
    }

    /// While the app is active, renews the lease the extension reads, so
    /// that a crash leaves it open for a minute at most.
    func keepOpen(every interval: Duration = .seconds(AppLock.leaseRefresh)) async {
        while !Task.isCancelled {
            if enabled, !locked { lock.refreshLease(at: Date()) }
            try? await Task.sleep(for: interval)
        }
    }

    func unlock() {
        lock.unlocked()
        locked = false
    }

    /// After an erase: the settings are gone with the rest. Reads only: a
    /// write here would put a `barking.lock.` key back after the wipe.
    func reload() {
        enabled = lock.enabled
        storedDelay = lock.delay
        locked = lock.needsUnlock(at: Date())
    }
}
