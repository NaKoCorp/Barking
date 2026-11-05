import Foundation

/// Files of the App Group container shared by the app and the extension
/// (spec iOS foundations §4.1).
public enum SharedPaths {
    /// App Group identifier, from the Info.plist of the running bundle.
    static var appGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "BarkingAppGroup") as? String
            ?? "group.com.nakocorp.barking"
    }

    public struct NoContainer: Error {}

    /// The shared container. Without it (App Group missing from the
    /// entitlements) only Debug builds fall back to the temporary directory:
    /// elsewhere the identity would land where iOS purges it, and where the
    /// extension never looks.
    public static var container: URL {
        get throws {
            #if DEBUG
            let fallback = true
            #else
            let fallback = false
            #endif
            return try resolve(
                FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup),
                fallbackAllowed: fallback)
        }
    }

    static func resolve(_ group: URL?, fallbackAllowed: Bool) throws -> URL {
        if let group { return group }
        guard fallbackAllowed else { throw NoContainer() }
        return FileManager.default.temporaryDirectory
    }

    public static var database: URL { get throws { try container.appending(path: "barking.db") } }
    public static var lock: URL { get throws { try container.appending(path: "barking.lock") } }

    /// Measurement records (spec §6.1), created on demand.
    public static var bench: URL {
        get throws {
            let url = try container.appending(path: "bench", directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            try protect(url)
            return url
        }
    }

    /// Readable once the device has been unlocked after a reboot, so that
    /// the extension can open the database while the iPhone is locked.
    public static func protect(_ url: URL) throws {
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: url.path)
    }

    #if BARKING_DEV
    /// Development files for scripted checks (card, APNs token). Written to
    /// the shared container and to the app's Documents, which
    /// `xcrun devicectl device copy from --domain-type appDataContainer` can
    /// read on a real device (the App Group container is not listed there).
    public static func devExport(_ name: String, _ text: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        for dir in [try? container, docs].compactMap({ $0 }) {
            try? Data(text.utf8).write(to: dir.appending(path: name))
        }
    }

    /// Copies the measurement records to the app's Documents/bench, for
    /// `devicectl` (see `devExport`).
    public static func devExportBench() {
        guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first,
              let source = try? bench else { return }
        let target = docs.appending(path: "bench", directoryHint: .isDirectory)
        try? FileManager.default.removeItem(at: target)
        try? FileManager.default.copyItem(at: source, to: target)
    }
    #endif
}
