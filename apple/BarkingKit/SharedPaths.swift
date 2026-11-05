import Foundation

/// Files of the App Group container shared by the app and the extension
/// (spec iOS foundations §4.1).
public enum SharedPaths {
    /// App Group identifier, from the Info.plist of the running bundle.
    static var appGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "BarkingAppGroup") as? String
            ?? "group.com.nakocorp.barking"
    }

    /// The shared container; the temporary directory when the App Group is
    /// unavailable (unsigned test builds).
    public static var container: URL {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
            ?? FileManager.default.temporaryDirectory
    }

    public static var database: URL { container.appending(path: "barking.db") }
    public static var lock: URL { container.appending(path: "barking.lock") }

    /// Measurement records (spec §6.1), created on demand.
    public static var bench: URL {
        get throws {
            let url = container.appending(path: "bench", directoryHint: .isDirectory)
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
}
