import Foundation
import LocalAuthentication

/// The app lock (spec §6.1): off by default, kept in the App Group's defaults
/// so that the notification extension can read it. The app is locked at a
/// cold start, and once the delay has run out when it comes back from the
/// background.
public final class AppLock: @unchecked Sendable {
    /// What the picker offers, in seconds: immediately, 1 min, 5 min, 1 h.
    public static let delays: [TimeInterval] = [0, 60, 300, 3600]

    enum Key {
        static let enabled = "barking.lock.enabled"
        static let delay = "barking.lock.delay"
        static let backgroundAt = "barking.lock.backgroundAt"
        static let locked = "barking.lock.locked"
    }

    private let defaults: UserDefaults
    private let state = NSLock()
    /// This launch has been unlocked since the last time the app was left.
    private var open = false

    /// A new instance is a cold start: locked while the lock is on.
    public init(defaults: UserDefaults) {
        self.defaults = defaults
        if defaults.bool(forKey: Key.enabled) {
            defaults.set(true, forKey: Key.locked)
        }
    }

    /// The lock of the App Group.
    public static var shared: AppLock { AppLock(defaults: groupDefaults) }

    private static var groupDefaults: UserDefaults {
        UserDefaults(suiteName: SharedPaths.appGroup) ?? .standard
    }

    public var enabled: Bool {
        get { defaults.bool(forKey: Key.enabled) }
        set {
            defaults.set(newValue, forKey: Key.enabled)
            // Turned on from inside the app: the app stays open.
            state.withLock { open = true }
            clear()
        }
    }

    /// Seconds in the background before the app locks; one of `delays`.
    public var delay: TimeInterval {
        get { defaults.double(forKey: Key.delay) }
        set { defaults.set(newValue, forKey: Key.delay) }
    }

    public func didEnterBackground(at date: Date) {
        defaults.set(date.timeIntervalSince1970, forKey: Key.backgroundAt)
    }

    public func needsUnlock(at date: Date) -> Bool {
        guard enabled else { return false }
        if !state.withLock({ open }) { return true }
        return Self.elapsed(defaults: defaults, at: date)
    }

    /// The app is active again: locks it if the delay has run out, else
    /// forgets the time spent away. Returns whether it is now locked.
    @discardableResult
    public func didBecomeActive(at date: Date) -> Bool {
        if needsUnlock(at: date) {
            state.withLock { open = false }
            defaults.set(true, forKey: Key.locked)
            return true
        }
        defaults.removeObject(forKey: Key.backgroundAt)
        return false
    }

    public func unlocked() {
        state.withLock { open = true }
        clear()
    }

    private func clear() {
        defaults.set(false, forKey: Key.locked)
        defaults.removeObject(forKey: Key.backgroundAt)
    }

    private static func elapsed(defaults: UserDefaults, at date: Date) -> Bool {
        guard defaults.object(forKey: Key.backgroundAt) != nil else { return false }
        let left = Date(timeIntervalSince1970: defaults.double(forKey: Key.backgroundAt))
        return date >= left.addingTimeInterval(defaults.double(forKey: Key.delay))
    }

    /// What the extension asks: the lock is on and the app is locked, by a
    /// cold start or because it has been away for the whole delay.
    public static func isLocked(defaults: UserDefaults, at date: Date = Date()) -> Bool {
        guard defaults.bool(forKey: Key.enabled) else { return false }
        return defaults.bool(forKey: Key.locked) || elapsed(defaults: defaults, at: date)
    }

    public static var isLockedForExtension: Bool { isLocked(defaults: groupDefaults) }

    /// A phone with no passcode cannot lock the app: nothing would unlock it.
    public static func canEnable() -> Bool {
        #if BARKING_DEV
        if ProcessInfo.processInfo.arguments.contains("-BarkingUITestReset") { return true }
        #endif
        var error: NSError?
        let ok = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        return ok || (error as? LAError)?.code != .passcodeNotSet
    }
}
