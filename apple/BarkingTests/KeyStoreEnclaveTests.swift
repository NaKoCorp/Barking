import XCTest
@testable import BarkingKit

/// The keychain in memory: the items of one `KeyStore`, by account.
final class MemoryEntries: KeyEntries, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    subscript(account: String) -> Data? {
        get { lock.withLock { items[account] } }
        set { lock.withLock { items[account] = newValue } }
    }

    func get(_ account: String) throws -> Data? { self[account] }

    func add(_ account: String, _ value: Data) throws {
        try lock.withLock {
            guard items[account] == nil else { throw KeyStore.Failure(status: errSecDuplicateItem) }
            items[account] = value
        }
    }

    func delete(_ account: String) throws { self[account] = nil }
}

final class KeyStoreEnclaveTests: XCTestCase {
    let entries = MemoryEntries()
    let wrapper = SoftwareKey()
    var store: KeyStore { KeyStore(entries: entries, wrapper: wrapper) }
    let legacy = Data((0..<32).map { UInt8($0) })

    func testCreateStoresOnlyTheWrappedKey() throws {
        let key = try store.create()
        XCTAssertEqual(key.count, 32)
        XCTAssertNil(entries["db-key"])
        let wrapped = try XCTUnwrap(entries["db-key-wrapped"])
        XCTAssertNotEqual(wrapped, key)
        XCTAssertEqual(try store.read(), key)
    }

    func testMigratesLegacyKey() throws {
        entries["db-key"] = legacy
        XCTAssertEqual(try store.read(), legacy)
        XCTAssertNotNil(entries["db-key-wrapped"])
        XCTAssertNil(entries["db-key"])
        // The next read goes through the wrapped key alone.
        XCTAssertEqual(try store.read(), legacy)
    }

    /// Crash between writing `db-key-wrapped` and deleting `db-key`.
    func testMigrationInterruptedKeepsTheKey() throws {
        entries["db-key-wrapped"] = try wrapper.wrap(legacy)
        entries["db-key"] = legacy
        XCTAssertEqual(try store.read(), legacy)
        XCTAssertNil(entries["db-key"])
        XCTAssertNotNil(entries["db-key-wrapped"])
    }

    /// The wrapping key is gone (backup restored on another iPhone): the
    /// "could not open your data" screen, nothing deleted or replaced.
    func testMissingWrapperKeyIsNotOverwritten() throws {
        _ = try store.create()
        let wrapped = entries["db-key-wrapped"]
        try wrapper.delete()
        XCTAssertThrowsError(try store.read()) { XCTAssertTrue($0 is KeyStore.Unavailable) }
        XCTAssertEqual(entries["db-key-wrapped"], wrapped)
        XCTAssertNil(entries["db-key"])
    }

    /// A legacy key not migrated yet still belongs to a database: `create`
    /// must not put a new wrapped key next to it.
    func testCreateFailsWhenAnyKeyExists() throws {
        entries["db-key"] = legacy
        XCTAssertThrowsError(try store.create())
        XCTAssertNil(entries["db-key-wrapped"])
        XCTAssertEqual(entries["db-key"], legacy)
    }

    func testReplaceDrawsANewKey() throws {
        let old = try store.create()
        let new = try store.replace()
        XCTAssertNotEqual(old, new)
        XCTAssertEqual(try store.read(), new)
    }

    /// Without a Secure Enclave the key stays in clear in the keychain, as before.
    func testWithoutWrapperKeepsTheClearKey() throws {
        let plain = KeyStore(entries: entries, wrapper: nil)
        let key = try plain.create()
        XCTAssertEqual(entries["db-key"], key)
        XCTAssertNil(entries["db-key-wrapped"])
        XCTAssertEqual(try plain.read(), key)
        XCTAssertEqual(plain.protection, "keychain")
    }

    /// Only a hardware wrapper counts as the Secure Enclave.
    func testProtection() throws {
        _ = try store.create()
        XCTAssertEqual(store.protection, "keychain")
        XCTAssertEqual(KeyStore(entries: entries, wrapper: HardwareStub(inner: wrapper)).protection, "secure-enclave")
        XCTAssertEqual(KeyStore(entries: MemoryEntries(), wrapper: HardwareStub(inner: wrapper)).protection, "keychain")
    }

    /// A wipe deletes the wrapped key, a legacy one and the wrapping key (spec §6.2).
    func testDeleteAllRemovesEveryKey() throws {
        _ = try store.create()
        entries["db-key"] = legacy
        try store.deleteAll()
        XCTAssertNil(entries["db-key"])
        XCTAssertNil(entries["db-key-wrapped"])
        XCTAssertFalse(wrapper.exists)
    }

    /// The bench times reading (and unwrapping) the key apart from opening.
    func testBenchRecordsTheKeyRead() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "bench-\(UUID())")
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = WipePaths(container: dir, temporary: dir, defaults: [], lockTimeoutMs: 100)
        let (record, _) = BenchRun.run(source: "test", paths: paths, sync: false)
        XCTAssertTrue(record.steps.contains { $0.name == "key" })
        XCTAssertNotNil(record.unwrapMs)
    }

    func testDatabaseDirectoryExcludedFromBackup() throws {
        try SharedPaths.excludeFromBackup()
        let values = try SharedPaths.container.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }
}

/// `SoftwareKey` presented as the Secure Enclave.
private struct HardwareStub: KeyWrapper {
    let inner: SoftwareKey
    var hardware: Bool { true }
    func wrap(_ key: Data) throws -> Data { try inner.wrap(key) }
    func unwrap(_ blob: Data) throws -> Data { try inner.unwrap(blob) }
    func delete() throws { try inner.delete() }
}
