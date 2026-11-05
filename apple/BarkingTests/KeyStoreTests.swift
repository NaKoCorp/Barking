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
}
