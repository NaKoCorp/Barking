import Foundation
@testable import BarkingKit

/// A database in a temporary directory with a random key.
enum TestDevice {
    static func config(lockTimeoutMs: UInt64 = 1000) throws -> DeviceConfig {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let key = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        return DeviceConfig(
            dbPath: dir.appending(path: "barking.db").path,
            lockPath: dir.appending(path: "barking.lock").path,
            dbKey: key, lockTimeoutMs: lockTimeoutMs, allowPrivate: false)
    }

    static func with(_ c: DeviceConfig, lockTimeoutMs: UInt64) -> DeviceConfig {
        var c = c
        c.lockTimeoutMs = lockTimeoutMs
        return c
    }
}
