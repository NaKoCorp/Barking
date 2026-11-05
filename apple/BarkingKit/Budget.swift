import Foundation

/// Time budgets (spec iOS foundations §3.3, §5.3). Every device call ends,
/// and releases the database lock, before iOS cuts the time it grants:
/// about 30 s for a background task, 25 s for the extension.
public enum Budget {
    /// Lock wait in the app (spec §3.3).
    public static let appLockMs: UInt64 = 10_000
    /// Full sync in the app: lock wait + sync + shutdown stay under 26 s.
    public static let appSyncMs: UInt64 = 15_000
    /// Lock wait in the extension (spec iOS push §6.1).
    public static let extensionLockMs: UInt64 = 2_000
    /// The extension's work from its start; 5 s of margin on the 25 s.
    public static let extensionWorkMs: UInt64 = 17_000
    /// Closing of a sync's runtime (barking-ffi `SHUTDOWN`).
    public static let shutdownMs: UInt64 = 1_000

    /// What is left of the extension's work for the quick sync.
    public static func quickSyncDeadline(elapsedMs: UInt64) -> UInt64 {
        extensionWorkMs > elapsedMs ? extensionWorkMs - elapsedMs : 0
    }
}
