import UserNotifications
import XCTest
@testable import Barking
@testable import BarkingKit

/// Settings › Notifications: the state the screen shows, and what the
/// switch and the preview choices do.
@MainActor
final class NotificationsModelTests: XCTestCase {
    private func push(_ status: UNAuthorizationStatus, relay: Bool = true) -> PushToken {
        let push = PushToken()
        push.info = relay ? ["BarkingRelayHost": "relay.local"] : ["BarkingRelayHost": ""]
        push.authorization = { status }
        return push
    }

    private func model(_ d: FakeDevice, _ push: PushToken, locked: Bool = false,
                       request: (@Sendable () async -> Void)? = nil) -> NotificationsModel {
        let suite = "notifications.tests.\(UUID())"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        let lock = AppLock(defaults: defaults)
        lock.enabled = locked
        return NotificationsModel(core: CoreService(device: d, runner: DirectRunner()),
                                  push: push, lock: lock, request: request)
    }

    func testStateNoRelayWins() async {
        let m = model(FakeDevice(), push(.notDetermined, relay: false))
        await m.load()
        XCTAssertEqual(m.state, .noRelay)
        let denied = model(FakeDevice(), push(.denied, relay: false))
        await denied.load()
        XCTAssertEqual(denied.state, .noRelay)
    }

    func testStateNotAsked() async {
        let m = model(FakeDevice(), push(.notDetermined))
        await m.load()
        XCTAssertEqual(m.state, .notAsked)
    }

    func testStateDenied() async {
        let m = model(FakeDevice(), push(.denied))
        await m.load()
        XCTAssertEqual(m.state, .denied)
    }

    func testStateOnOff() async {
        let d = FakeDevice()
        let m = model(d, push(.authorized))
        await m.load()
        XCTAssertEqual(m.state, .on)
        d.prefs.instant = false
        await m.load()
        XCTAssertEqual(m.state, .off)
        XCTAssertFalse(m.instant)
    }

    func testLoadReadsThePreviewAndTheLock() async {
        let d = FakeDevice()
        d.prefs.preview = .generic
        let m = model(d, push(.authorized), locked: true)
        await m.load()
        XCTAssertEqual(m.preview, .generic)
        XCTAssertTrue(m.appLocked)
    }

    func testSetInstantStoresAndSyncs() async {
        let d = FakeDevice()
        let m = model(d, push(.authorized))
        await m.load()
        await m.setInstant(false)
        XCTAssertEqual(d.prefs.instant, false)
        XCTAssertEqual(m.state, .off)
        await m.lastSync?.value
        XCTAssertEqual(d.syncCalls, 1, "a full sync, so the wake subscription follows at once")
    }

    func testSetPreviewStores() async {
        let d = FakeDevice()
        let m = model(d, push(.authorized))
        await m.load()
        await m.setPreview(.nameOnly)
        XCTAssertEqual(d.prefs.preview, .nameOnly)
        XCTAssertEqual(m.preview, .nameOnly)
    }

    func testRequestPermissionReapplies() async {
        let d = FakeDevice()
        let status = StatusBox(.notDetermined)
        let p = push(.notDetermined)
        p.authorization = { status.value }
        p.token = Data([1, 2, 3])
        p.info = [
            "BarkingRelayHost": "relay.local", "BarkingRelayPort": "4434",
            "BarkingRelayId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "BarkingRelaySealId": "1", "BarkingRelaySealPublic": String(repeating: "5e", count: 32),
        ]
        let m = model(d, p, request: { status.value = .authorized })
        await m.load()
        XCTAssertEqual(m.state, .notAsked)
        await m.requestPermission()
        XCTAssertNotNil(d.pushSettings.last ?? nil, "the wake settings are given to the core once allowed")
        XCTAssertEqual(m.state, .on)
    }
}

private final class StatusBox: @unchecked Sendable {
    private let lock = NSLock()
    private var status: UNAuthorizationStatus
    init(_ status: UNAuthorizationStatus) { self.status = status }
    var value: UNAuthorizationStatus {
        get { lock.withLock { status } }
        set { lock.withLock { status = newValue } }
    }
}
