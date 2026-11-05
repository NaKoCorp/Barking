import Foundation

/// One measured run (spec iOS foundations §6.1). No message text, no contact
/// fingerprint.
public struct BenchRecord: Codable, Sendable {
    public struct Step: Codable, Sendable {
        public var name: String
        public var atMs: UInt64
        public var footprintBytes: UInt64
    }

    /// `extension` or `app`.
    public var source: String
    /// Hardware model, e.g. `iPhone14,5`.
    public var device: String
    public var startedAt: Date
    public var steps: [Step]
    public var peakBytes: UInt64
    public var totalMs: UInt64
    /// `shown`, `original`, `locked`, `no-key`, `network-down` or `error`.
    public var outcome: String
}

/// Records in the shared container, one JSON file each, the latest `keep` kept.
public struct BenchStore: Sendable {
    let directory: URL
    let keep: Int

    public init(directory: URL, keep: Int = 50) {
        self.directory = directory
        self.keep = keep
    }

    /// The store of the shared container.
    public static func shared() throws -> BenchStore { BenchStore(directory: try SharedPaths.bench) }

    public func append(_ r: BenchRecord) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ms = UInt64(r.startedAt.timeIntervalSince1970 * 1000)
        let name = String(format: "%016llu-%@.json", ms, UUID().uuidString)
        try JSONEncoder().encode(r).write(to: directory.appending(path: name), options: .atomic)
        let files = try sortedFiles()
        for old in files.dropLast(keep) { try? FileManager.default.removeItem(at: old) }
    }

    /// Oldest first.
    public func all() throws -> [BenchRecord] {
        try sortedFiles().compactMap { try? JSONDecoder().decode(BenchRecord.self, from: Data(contentsOf: $0)) }
    }

    private func sortedFiles() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }
}
