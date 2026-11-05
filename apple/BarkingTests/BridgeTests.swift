import XCTest
@testable import BarkingKit

final class BridgeTests: XCTestCase {
    func testCreateReopenAndTypedError() throws {
        let cfg = try TestDevice.config()
        let created = try createDevice(config: cfg, deviceName: "sim")
        XCTAssertEqual(created.recoveryPhrase.split(separator: " ").count, 24)
        XCTAssertEqual(try Device.open(config: cfg).fingerprint(), try created.device.fingerprint())
        XCTAssertThrowsError(try created.device.addContact(card: "junk", alias: nil)) { e in
            guard case BarkingError.InvalidInput = e else { return XCTFail("\(e)") }
        }
    }
}

final class SharedPathsTests: XCTestCase {
    func testProtectionApplied() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try Data("x".utf8).write(to: url)
        try SharedPaths.protect(url)
        let v = try url.resourceValues(forKeys: [.fileProtectionKey])
        XCTAssertEqual(v.fileProtection, .completeUntilFirstUserAuthentication)
    }
}
