import Foundation

/// The secrets that open this device's database. `KeyStore.deleteAll`
/// deletes the wrapped key, a clear one and the Secure Enclave key (spec §6.2, §7).
public protocol KeyWiping: Sendable {
    func deleteAll() throws
}

extension KeyStore: KeyWiping {
    /// The keys the app and the extension share.
    public static var live: KeyStore { DeviceFactory.keyStore }

    /// Every key of this identity. Deleting a missing one is not an error.
    public func deleteAll() throws {
        try delete()
    }
}

/// Where a wipe looks.
public struct WipePaths {
    /// The shared container: its whole content goes, except the system's
    /// metadata and `Library`. `nil` without an App Group (Release builds without the
    /// entitlement): only the key and the settings are left to delete.
    public var container: URL?
    /// The app's temporary directory: device link packages and contact cards
    /// shared from there.
    public var temporary: URL
    /// The app's settings and the group's: every `barking.` key goes.
    public var defaults: [UserDefaults]
    /// Longest wait for the database lock (the extension may hold it).
    public var lockTimeoutMs: UInt64

    public init(container: URL?, temporary: URL, defaults: [UserDefaults], lockTimeoutMs: UInt64) {
        self.container = container
        self.temporary = temporary
        self.defaults = defaults
        self.lockTimeoutMs = lockTimeoutMs
    }

    public static var live: WipePaths {
        WipePaths(container: try? SharedPaths.container,
                  temporary: FileManager.default.temporaryDirectory,
                  defaults: [.standard, UserDefaults(suiteName: SharedPaths.appGroup)].compactMap { $0 },
                  lockTimeoutMs: Budget.appLockMs)
    }
}

/// Erases everything Barking keeps on this device (spec §6.2): the emergency
/// wipe, the reset of a removed device and the end of a departure (§8) all
/// come here. A marker makes a wipe cut short (app killed) finish at the next
/// launch, before the database is opened.
public enum Wipe {
    public static let markerName = "wipe-pending"

    /// Some steps failed; the marker stays for the next launch.
    public struct Incomplete: Error {
        public let failures: [any Error]
    }

    /// Stops `core` first (no call in flight, none accepted after), then
    /// wipes, trying a failed wipe once more. The FFI holds the lock for one
    /// call only, so a closed service leaves no open database behind. A
    /// throw means the marker is still there: the caller must not start a
    /// new identity as if the device were clean.
    public static func run(closing core: CoreService?, paths: WipePaths = .live,
                           keys: any KeyWiping = KeyStore.live) async throws {
        await core?.close()
        try runRetrying(paths: paths, keys: keys)
    }

    /// A wipe started and not finished: nothing may open the database.
    public static func isPending(paths: WipePaths = .live) -> Bool {
        guard let container = paths.container else { return false }
        return FileManager.default.fileExists(atPath: container.appending(path: markerName).path)
    }

    /// Finishes a pending wipe before a new identity is made, so that the
    /// marker can never erase an identity created after it. Throws (and
    /// creates nothing) if the wipe still cannot finish.
    public static func finishPending(paths: WipePaths = .live, keys: any KeyWiping = KeyStore.live) throws {
        if isPending(paths: paths) { try runRetrying(paths: paths, keys: keys) }
    }

    static func runRetrying(paths: WipePaths, keys: any KeyWiping) throws {
        do {
            try run(paths: paths, keys: keys)
        } catch {
            try run(paths: paths, keys: keys)
        }
    }

    /// The wipe itself. Never opens the database; call it with no
    /// `CoreService` in use (`run(closing:)`).
    public static func run(paths: WipePaths = .live, keys: any KeyWiping = KeyStore.live) throws {
        var failures: [any Error] = []
        let fm = FileManager.default
        let marker = paths.container?.appending(path: markerName)
        if let marker {
            do { try Data().write(to: marker) } catch { failures.append(error) }
        }
        // The extension may be inside a call: wait for it, but a wipe never
        // gives up for a lock (its open files go with their last close).
        let lock = paths.container.map { lockFile($0.appending(path: "barking.lock"), timeoutMs: paths.lockTimeoutMs) }
        defer { if let lock, lock >= 0 { close(lock) } }

        do { try keys.deleteAll() } catch { failures.append(error) }

        if let container = paths.container {
            let items = (try? fm.contentsOfDirectory(at: container, includingPropertiesForKeys: nil)) ?? []
            for item in items where !kept(item.lastPathComponent) {
                remove(item, into: &failures)
            }
        }
        let temporary = (try? fm.contentsOfDirectory(at: paths.temporary, includingPropertiesForKeys: nil)) ?? []
        for item in temporary where ["barkinglink", "barkingcard"].contains(item.pathExtension) {
            remove(item, into: &failures)
        }
        for defaults in paths.defaults {
            for key in defaults.dictionaryRepresentation().keys where key.hasPrefix("barking.") {
                defaults.removeObject(forKey: key)
            }
        }

        guard failures.isEmpty else { throw Incomplete(failures: failures) }
        if let marker { remove(marker, into: &failures) }
        if !failures.isEmpty { throw Incomplete(failures: failures) }
    }

    /// Finishes a wipe cut short; `true` if there was one. Call it at launch,
    /// before anything opens the database. Throws if it still cannot finish:
    /// the database must then stay closed.
    @discardableResult
    public static func resumeIfNeeded(paths: WipePaths = .live, keys: any KeyWiping = KeyStore.live) throws -> Bool {
        guard isPending(paths: paths) else { return false }
        try runRetrying(paths: paths, keys: keys)
        return true
    }

    /// The marker (removed last) and what the system keeps in every
    /// container: its metadata (`.com.apple.mobile_container_manager…`,
    /// without which the container is lost) and `Library`.
    private static func kept(_ name: String) -> Bool {
        name == markerName || name == "Library" || name.hasPrefix(".")
    }

    private static func remove(_ url: URL, into failures: inout [any Error]) {
        do {
            try FileManager.default.removeItem(at: url)
        } catch CocoaError.fileNoSuchFile {
            // Already gone.
        } catch {
            failures.append(error)
        }
    }

    /// The database lock (`flock`, as the FFI takes it), waited for up to
    /// `timeoutMs`. Returns the descriptor, held or not; -1 if it does not open.
    private static func lockFile(_ url: URL, timeoutMs: UInt64) -> Int32 {
        let fd = open(url.path, O_RDWR | O_CREAT, 0o600)
        guard fd >= 0 else { return fd }
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000)
        while flock(fd, LOCK_EX | LOCK_NB) != 0, Date() < deadline {
            usleep(20_000)
        }
        return fd
    }
}
