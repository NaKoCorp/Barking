import Foundation

/// The nodes the app was built with: the Info.plist key
/// `BarkingBootstrapNodes`, filled from the build setting
/// `BARKING_BOOTSTRAP_NODES` (empty in the repository, set in the git-ignored
/// `Local.xcconfig`). Entries `<base32 identifier>@<ip:port>`, separated by
/// spaces or commas. They become hand-added nodes, which the core tries when
/// too few known nodes answer.
public enum BootstrapNodes {
    public struct Entry: Equatable, Sendable {
        public let id: String
        public let addr: String
    }

    /// The entries of `info`; one without `@` or with an empty side is skipped
    /// (the core checks the identifier and the address).
    public static func entries(info: [String: Any]) -> [Entry] {
        let raw = info["BarkingBootstrapNodes"] as? String ?? ""
        return raw.split(whereSeparator: { $0 == "," || $0.isWhitespace }).compactMap { entry in
            let parts = entry.split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
            return Entry(id: String(parts[0]), addr: String(parts[1]))
        }
    }

    /// Adds every entry of `info` to `core`. Adding a node again changes
    /// nothing; an entry the core refuses is skipped.
    public static func add(to core: CoreService, info: [String: Any]) async {
        for entry in entries(info: info) {
            try? await core.addNode(id: entry.id, addr: entry.addr)
        }
    }
}
