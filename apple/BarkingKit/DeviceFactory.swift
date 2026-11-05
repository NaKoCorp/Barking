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

    public static func config(key: Data, lockTimeoutMs: UInt64) -> DeviceConfig {
        DeviceConfig(
            dbPath: SharedPaths.database.path, lockPath: SharedPaths.lock.path,
            dbKey: key, lockTimeoutMs: lockTimeoutMs, allowPrivate: allowPrivate)
    }

    /// The existing identity; `nil` without a key or a database. Creates nothing.
    public static func openExisting(lockTimeoutMs: UInt64) throws -> Device? {
        guard let key = try keyStore.read() else { return nil }
        let cfg = config(key: key, lockTimeoutMs: lockTimeoutMs)
        guard deviceExists(config: cfg) else { return nil }
        return try Device.open(config: cfg)
    }

    /// A new identity: new key, new database, files protected.
    public static func createNew(deviceName: String) throws -> CreatedDevice {
        let key = try keyStore.create()
        let created = try createDevice(config: config(key: key, lockTimeoutMs: 10_000), deviceName: deviceName)
        for url in [SharedPaths.database, SharedPaths.lock] { try SharedPaths.protect(url) }
        return created
    }
}
