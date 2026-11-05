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

    /// The database file is there (whatever its key); checked with a dummy key.
    static func databaseExists() throws -> Bool {
        deviceExists(config: try config(key: Data(count: 32), lockTimeoutMs: 0))
    }

    /// Spec §7.1: the clear key is zeroed once the FFI has taken it. The
    /// config is built inside the call so that `key` is, as far as Swift lets
    /// us tell, the last holder of its buffer when `wipe` runs; the FFI keeps
    /// its own copy for the device's lifetime (each call reopens the database).
    private static func handing<T>(_ key: inout Data, lockTimeoutMs: UInt64,
                                   _ body: (DeviceConfig) throws -> T) throws -> T {
        defer { key.wipe() }
        return try body(config(key: key, lockTimeoutMs: lockTimeoutMs))
    }

    /// The existing identity; `nil` without a key or a database. Creates nothing.
    public static func openExisting(lockTimeoutMs: UInt64) throws -> Device? {
        guard !Wipe.isPending() else { throw Wipe.Incomplete(failures: []) }
        guard var key = try keyStore.read() else { return nil }
        guard try databaseExists() else { key.wipe(); return nil }
        let device = try handing(&key, lockTimeoutMs: lockTimeoutMs) { try Device.open(config: $0) }
        try? SharedPaths.excludeFromBackup()
        return device
    }

    /// The existing identity without opening it (no lock, nothing read): the
    /// extension spends its lock wait on the quick sync only. `nil` without a
    /// key or a database; `KeyStore.Locked` before the first unlock. Creates nothing.
    /// `keyRead` runs once the key is read and unwrapped (the bench times it).
    public static func existing(lockTimeoutMs: UInt64, paths: WipePaths = .live,
                                keyRead: () -> Void = {}) throws -> Device? {
        // A wipe in progress: the database is on its way out, never opened.
        guard !Wipe.isPending(paths: paths) else { return nil }
        let read = try keyStore.read()
        keyRead()
        guard var key = read else { return nil }
        guard try databaseExists() else { key.wipe(); return nil }
        return try handing(&key, lockTimeoutMs: lockTimeoutMs) { try Device.at(config: $0) }
    }

    /// A new key for a new database. A key left without its database
    /// (reinstall, failed creation) is replaced; a key whose database exists
    /// is never touched (`create` fails).
    private static func newKey() throws -> Data {
        try databaseExists() ? try keyStore.create() : try keyStore.replace()
    }

    /// Protects the files just created and keeps them out of backups.
    private static func protectNewFiles() throws {
        for url in [try SharedPaths.database, try SharedPaths.lock] { try SharedPaths.protect(url) }
        try? SharedPaths.excludeFromBackup()
    }

    /// A new identity: new key, new database, files protected.
    public static func createNew(deviceName: String) throws -> CreatedDevice {
        try Wipe.finishPending()
        var key = try newKey()
        let created = try handing(&key, lockTimeoutMs: Budget.appLockMs) {
            try createDevice(config: $0, deviceName: deviceName)
        }
        try protectNewFiles()
        return created
    }

    /// Recovers an identity from its 24 words (a key left without its
    /// database is replaced, as for `createNew`).
    public static func recover(phrase: String, deviceName: String) throws -> Device {
        try Wipe.finishPending()
        var key = try newKey()
        let device = try handing(&key, lockTimeoutMs: Budget.appLockMs) {
            try recoverDevice(config: $0, phrase: phrase, deviceName: deviceName)
        }
        try protectNewFiles()
        return device
    }

    /// Starts linking this device to an existing identity.
    public static func beginLink(offer: Data, deviceName: String) throws -> PendingLink {
        try Wipe.finishPending()
        var key = try newKey()
        let pending = try handing(&key, lockTimeoutMs: Budget.appLockMs) {
            try BarkingKit.beginLink(config: $0, offer: offer, deviceName: deviceName)
        }
        try protectNewFiles()
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
