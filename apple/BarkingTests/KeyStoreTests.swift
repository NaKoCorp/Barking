import XCTest
@testable import BarkingKit

final class KeyStoreTests: XCTestCase {
    let store = KeyStore(service: "test.\(UUID())", accessGroup: nil)

    override func tearDown() { try? store.delete() }

    func testCreateThenRead() throws {
        let k = try store.create()
        XCTAssertEqual(k.count, 32)
        XCTAssertEqual(try store.read(), k)
    }

    func testCreateTwiceFails() throws {
        _ = try store.create()
        XCTAssertThrowsError(try store.create())
    }

    func testReadMissingKeyReturnsNilAndCreatesNothing() throws {
        XCTAssertNil(try store.read())
        XCTAssertNil(try store.read())
    }

    /// Reinstall: iOS deletes the container but keeps the keychain item. A key
    /// without its database protects nothing and must not block a new identity.
    func testReplaceOverwritesAnOrphanKey() throws {
        let old = try store.create()
        let new = try store.replace()
        XCTAssertNotEqual(old, new)
        XCTAssertEqual(try store.read(), new)
    }
}
