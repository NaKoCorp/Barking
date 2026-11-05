import Foundation

/// Opens or creates the identity of this device. The only place that builds
/// a `DeviceConfig`.
public enum DeviceFactory {
    /// Shared keychain group from the Info.plist; `nil` when the build has
    /// no team prefix (unsigned simulator builds use the default group).
    static var keychainGroup: String? {
        guard let g = Bundle.main.object(forInfoDictionaryKey: "BarkingKeychainGroup") as? String,
              !g.hasPrefix("com.") else { return nil }
        return g
    }

    static var keyStore: KeyStore { KeyStore(accessGroup: keychainGroup) }

    static var allowPrivate: Bool {
        #if BARKING_DEV
        true
        #else
        false
        #endif
    }

    /// A database exists in the shared container.
    public static var hasIdentity: Bool {
        guard let path = try? SharedPaths.database.path else { return false }
        return FileManager.default.fileExists(atPath: path)
    }

    public static func config(key: Data, lockTimeoutMs: UInt64) throws -> DeviceConfig {
        DeviceConfig(
            dbPath: try SharedPaths.database.path, lockPath: try SharedPaths.lock.path,
            dbKey: key, lockTimeoutMs: lockTimeoutMs, allowPrivate: allowPrivate)
    }

    /// The existing identity; `nil` without a key or a database. Creates nothing.
    public static func openExisting(lockTimeoutMs: UInt64) throws -> Device? {
        guard !Wipe.isPending() else { throw Wipe.Incomplete(failures: []) }
        guard let key = try keyStore.read() else { return nil }
        let cfg = try config(key: key, lockTimeoutMs: lockTimeoutMs)
        guard deviceExists(config: cfg) else { return nil }
        return try Device.open(config: cfg)
    }

    /// The existing identity without opening it (no lock, nothing read): the
    /// extension spends its lock wait on the quick sync only. `nil` without a
    /// key (before the first unlock) or a database. Creates nothing.
    public static func existing(lockTimeoutMs: UInt64, paths: WipePaths = .live) throws -> Device? {
        // A wipe in progress: the database is on its way out, never opened.
        guard !Wipe.isPending(paths: paths) else { return nil }
        guard let key = try keyStore.read() else { return nil }
        let cfg = try config(key: key, lockTimeoutMs: lockTimeoutMs)
        guard deviceExists(config: cfg) else { return nil }
        return try Device.at(config: cfg)
    }

    /// A new identity: new key, new database, files protected. A key left
    /// without its database (reinstall, failed creation) is replaced; a key
    /// whose database exists is never touched (`create` fails).
    public static func createNew(deviceName: String) throws -> CreatedDevice {
        try Wipe.finishPending()
        let probe = try config(key: Data(count: 32), lockTimeoutMs: Budget.appLockMs)
        let key = deviceExists(config: probe) ? try keyStore.create() : try keyStore.replace()
        let created = try createDevice(config: config(key: key, lockTimeoutMs: Budget.appLockMs), deviceName: deviceName)
        for url in [try SharedPaths.database, try SharedPaths.lock] { try SharedPaths.protect(url) }
        return created
    }

    /// Recovers an identity from its 24 words (a key left without its
    /// database is replaced, as for `createNew`).
    public static func recover(phrase: String, deviceName: String) throws -> Device {
        try Wipe.finishPending()
        let probe = try config(key: Data(count: 32), lockTimeoutMs: Budget.appLockMs)
        let key = deviceExists(config: probe) ? try keyStore.create() : try keyStore.replace()
        let device = try recoverDevice(config: config(key: key, lockTimeoutMs: Budget.appLockMs),
                                       phrase: phrase, deviceName: deviceName)
        for url in [try SharedPaths.database, try SharedPaths.lock] { try SharedPaths.protect(url) }
        return device
    }

    /// Starts linking this device to an existing identity.
    public static func beginLink(offer: Data, deviceName: String) throws -> PendingLink {
        try Wipe.finishPending()
        let probe = try config(key: Data(count: 32), lockTimeoutMs: Budget.appLockMs)
        let key = deviceExists(config: probe) ? try keyStore.create() : try keyStore.replace()
        let pending = try BarkingKit.beginLink(config: config(key: key, lockTimeoutMs: Budget.appLockMs),
                                               offer: offer, deviceName: deviceName)
        for url in [try SharedPaths.database, try SharedPaths.lock] { try SharedPaths.protect(url) }
        return pending
    }

    /// Removes this device's identity (`Wipe.run`: database and its
    /// sidecars, lock, key, pending files, settings): to start a pending link
    /// again, which holds nothing yet, and for the UI tests. A wipe that
    /// fails throws; its marker blocks a new identity until it finishes.
    public static func resetIdentity() throws {
        try Wipe.runRetrying(paths: .live, keys: KeyStore.live)
    }
}
