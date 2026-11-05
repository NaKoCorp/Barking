import XCTest
@testable import BarkingKit
@testable import Barking

final class LockReleaseTests: XCTestCase {
    func testLockIsFreeAfterEachCall() async throws {
        let cfg = try TestDevice.config(lockTimeoutMs: 200)
        let created = try createDevice(config: cfg, deviceName: "t")
        let device = created.device
        let fp = try await DeviceCall.run("fingerprint") { try device.fingerprint() }
        XCTAssertFalse(fp.isEmpty)
        // A second taker gets the lock at once: the app does not keep it
        // between two calls (spec §3.3).
        XCTAssertNoThrow(try Device.open(config: TestDevice.with(cfg, lockTimeoutMs: 1)))
    }

    func testErrorsComeBackTyped() async throws {
        let created = try createDevice(config: try TestDevice.config(), deviceName: "t")
        let device = created.device
        do {
            _ = try await DeviceCall.run("send") { try device.sendText(contact: "nobody", text: "x") }
            XCTFail("expected an error")
        } catch BarkingError.NotFound {}
    }
}
