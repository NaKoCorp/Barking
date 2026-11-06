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

    /// Before the first unlock: every read refuses.
    var locked = false

    func get(_ account: String) throws -> Data? {
        if lock.withLock({ locked }) { throw KeyStore.Locked() }
        return self[account]
    }

    func add(_ account: String, _ value: Data) throws {
        try lock.withLock {
            guard items[account] == nil else { throw KeyStore.Failure(status: errSecDuplicateItem) }
            items[account] = value
        }
    }

    /// Accounts whose deletion fails.
    var failDelete: Set<String> = []

    func delete(_ account: String) throws {
        if lock.withLock({ failDelete.contains(account) }) { throw KeyStore.Failure(status: errSecIO) }
        self[account] = nil
    }
}

/// The enclave is there but wrapping fails (entitlement, enclave error).
private struct BrokenWrapper: KeyWrapper {
    struct Broken: Error {}
    var hardware: Bool { true }
    func wrap(_ key: Data) throws -> Data { throw Broken() }
    func unwrap(_ blob: Data) throws -> Data { throw Broken() }
    func delete() throws {}
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

    /// A clear `db-key` left beside the wrapped one (migration interrupted,
    /// unwrap failing) is not "protected by the Secure Enclave".
    func testProtectionNeedsTheClearKeyGone() throws {
        _ = try store.create()
        let hardware = KeyStore(entries: entries, wrapper: HardwareStub(inner: wrapper))
        XCTAssertEqual(hardware.protection, "secure-enclave")
        entries["db-key"] = legacy
        XCTAssertEqual(hardware.protection, "keychain")
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

    /// A failing enclave must not block every new identity: the key is
    /// kept in clear, as without an enclave (fix round 1, item 1).
    func testCreateFallsBackToTheClearKeyWhenWrappingFails() throws {
        let broken = KeyStore(entries: entries, wrapper: BrokenWrapper())
        let key = try broken.create()
        XCTAssertEqual(entries["db-key"], key)
        XCTAssertNil(entries["db-key-wrapped"])
        XCTAssertEqual(try broken.read(), key)
        XCTAssertEqual(broken.protection, "keychain")
    }

    /// The enclave key goes last: a failed deletion never leaves
    /// `db-key-wrapped` without the key that opens it (item 4).
    func testEnclaveKeyDeletedOnlyAfterTheEntries() throws {
        let key = try store.create()
        entries.failDelete = ["db-key-wrapped"]
        XCTAssertThrowsError(try store.deleteAll())
        XCTAssertTrue(wrapper.exists)
        XCTAssertEqual(try store.read(), key)
        entries.failDelete = []
        try store.deleteAll()
        XCTAssertFalse(wrapper.exists)
    }

    /// The clear key is overwritten in place once used (spec §7.1, item 3).
    func testWipeZeroesTheKeyBuffer() {
        var key = Data((1...32).map { UInt8($0) })
        key.wipe()
        XCTAssertEqual(key, Data(count: 32))
    }

    func testDatabaseDirectoryExcludedFromBackup() throws {
        try SharedPaths.excludeFromBackup()
        let values = try SharedPaths.container.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }
}

/// Unwraps by throwing `error`: the enclave answering something other than "here is the key".
private struct FailingUnwrap: KeyWrapper {
    let error: any Error
    var hardware: Bool { true }
    func wrap(_ key: Data) throws -> Data { Data(key.reversed()) }
    func unwrap(_ blob: Data) throws -> Data { throw error }
    func delete() throws {}
}

/// Only a key that is gone, or that no longer opens the blob, makes the data
/// unreadable; a keychain or enclave error that may pass must not offer to
/// erase a readable database (fix round 2).
final class UnwrapFailureTests: XCTestCase {
    private let blob = Data([1, 2, 3])

    private func fail(_ error: any Error) throws -> Data { throw error }

    private func store(throwing error: any Error) throws -> KeyStore {
        let entries = MemoryEntries()
        entries["db-key-wrapped"] = blob
        return KeyStore(entries: entries, wrapper: FailingUnwrap(error: error))
    }

    func testKeychainErrorIsNotUnavailable() throws {
        let s = try store(throwing: KeyStore.Failure(status: errSecIO))
        XCTAssertThrowsError(try s.read()) { XCTAssertFalse($0 is KeyStore.Unavailable) }
    }

    func testLockedCFErrorIsNotUnavailable() throws {
        let locked = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInteractionNotAllowed))
        let s = try store(throwing: locked)
        XCTAssertThrowsError(try s.read()) { XCTAssertFalse($0 is KeyStore.Unavailable) }
    }

    func testGoneKeyIsUnavailable() throws {
        let s = try store(throwing: KeyStore.WrappingKeyGone())
        XCTAssertThrowsError(try s.read()) { XCTAssertTrue($0 is KeyStore.Unavailable) }
    }

    /// Fix round 3 ruling: with a key under the tag, no error is proof the
    /// data is unreadable, however it looks.
    func testUnknownEnclaveErrorIsNotUnavailable() throws {
        let s = try store(throwing: NSError(domain: NSOSStatusErrorDomain, code: -2070))
        XCTAssertThrowsError(try s.read()) { XCTAssertFalse($0 is KeyStore.Unavailable) }
    }

    func testDecryptLookingErrorIsNotUnavailable() throws {
        let s = try store(throwing: NSError(domain: NSOSStatusErrorDomain, code: Int(errSecDecode)))
        XCTAssertThrowsError(try s.read()) { XCTAssertFalse($0 is KeyStore.Unavailable) }
    }

    /// The enclave says "gone" only without any key under the tag.
    func testEnclaveGoneOnlyWithoutKeys() {
        let decryptFailed = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecDecode))
        XCTAssertThrowsError(try EnclaveKey.firstOpening([Int](), { _ in Data() })) {
            XCTAssertTrue($0 is KeyStore.WrappingKeyGone)
        }
        XCTAssertThrowsError(try EnclaveKey.firstOpening([1, 2], { _ in try self.fail(decryptFailed) })) {
            XCTAssertFalse($0 is KeyStore.WrappingKeyGone)
        }
        XCTAssertEqual(try EnclaveKey.firstOpening([1, 2], { $0 == 1 ? try self.fail(decryptFailed) : Data([9]) }),
                       Data([9]))
    }

    /// A software key that is there but refuses the blob is not "gone" either.
    func testSoftwareKeyRefusingTheBlobIsNotGone() throws {
        let key = SoftwareKey()
        _ = try key.wrap(Data([1]))
        XCTAssertThrowsError(try key.unwrap(Data(repeating: 0, count: 40))) {
            XCTAssertFalse($0 is KeyStore.WrappingKeyGone)
        }
        try key.delete()
        XCTAssertThrowsError(try key.unwrap(Data(repeating: 0, count: 40))) {
            XCTAssertTrue($0 is KeyStore.WrappingKeyGone)
        }
    }

    /// Before the first unlock the keychain answers "interaction not
    /// allowed": that is not "no key" (item 2).
    func testKeychainLockedIsNotMissing() {
        XCTAssertThrowsError(try KeychainEntries.result(status: errSecInteractionNotAllowed, item: nil)) {
            XCTAssertTrue($0 is KeyStore.Locked)
        }
        XCTAssertNil(try KeychainEntries.result(status: errSecItemNotFound, item: nil))
        XCTAssertEqual(try KeychainEntries.result(status: errSecSuccess, item: Data([1]) as CFData), Data([1]))
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
