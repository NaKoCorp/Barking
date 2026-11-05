import XCTest
@testable import BarkingKit

final class AppLockTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!
    private let t = Date(timeIntervalSince1970: 1_000_000)

    override func setUp() {
        suite = "applock.tests.\(UUID())"
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDown() { defaults.removePersistentDomain(forName: suite) }

    func testOffByDefault() {
        let lock = AppLock(defaults: defaults)
        XCTAssertFalse(lock.enabled)
        XCTAssertEqual(lock.delay, 0)
    }

    func testDelayRespected() {
        let lock = AppLock(defaults: defaults)
        lock.enabled = true
        lock.delay = 60
        lock.didEnterBackground(at: t)
        XCTAssertFalse(lock.needsUnlock(at: t.addingTimeInterval(59)))
        XCTAssertTrue(lock.needsUnlock(at: t.addingTimeInterval(61)))
    }

    func testImmediateDelayLocksAtOnce() {
        let lock = AppLock(defaults: defaults)
        lock.enabled = true
        lock.delay = 0
        lock.didEnterBackground(at: t)
        XCTAssertTrue(lock.needsUnlock(at: t))
    }

    func testDisabledNeverLocks() {
        let lock = AppLock(defaults: defaults)
        lock.didEnterBackground(at: t)
        XCTAssertFalse(lock.needsUnlock(at: t.addingTimeInterval(10_000)))
        XCTAssertFalse(AppLock(defaults: defaults).needsUnlock(at: t))
        XCTAssertFalse(AppLock.isLocked(defaults: defaults, at: t.addingTimeInterval(10_000)))
    }

    func testColdStartLocksWhenEnabled() {
        let first = AppLock(defaults: defaults)
        first.enabled = true
        XCTAssertFalse(first.needsUnlock(at: t), "enabling it inside the app does not lock the app")
        let second = AppLock(defaults: defaults)
        XCTAssertTrue(second.needsUnlock(at: t))
    }

    func testUnlockedClearsTheLock() {
        let lock = AppLock(defaults: defaults)
        lock.enabled = true
        lock.didEnterBackground(at: t)
        XCTAssertTrue(lock.needsUnlock(at: t))
        lock.unlocked()
        XCTAssertFalse(lock.needsUnlock(at: t.addingTimeInterval(5)))
        XCTAssertFalse(AppLock.isLocked(defaults: defaults, at: t.addingTimeInterval(5)))
    }

    func testReturningWithinTheDelayKeepsItOpenForGood() {
        let lock = AppLock(defaults: defaults)
        lock.enabled = true
        lock.delay = 60
        lock.didEnterBackground(at: t)
        XCTAssertFalse(lock.didBecomeActive(at: t.addingTimeInterval(10)))
        XCTAssertFalse(lock.needsUnlock(at: t.addingTimeInterval(500)), "foreground time does not count")
    }

    func testReturningAfterTheDelayStaysLockedUntilUnlocked() {
        let lock = AppLock(defaults: defaults)
        lock.enabled = true
        lock.delay = 60
        lock.didEnterBackground(at: t)
        XCTAssertTrue(lock.didBecomeActive(at: t.addingTimeInterval(61)))
        XCTAssertTrue(lock.needsUnlock(at: t.addingTimeInterval(62)))
        lock.unlocked()
        XCTAssertFalse(lock.needsUnlock(at: t.addingTimeInterval(63)))
    }

    func testExtensionSeesTheLockOnlyOnceTheAppIsLocked() {
        let lock = AppLock(defaults: defaults)
        lock.enabled = true
        lock.delay = 300
        XCTAssertFalse(AppLock.isLocked(defaults: defaults, at: t))
        lock.didEnterBackground(at: t)
        XCTAssertFalse(AppLock.isLocked(defaults: defaults, at: t.addingTimeInterval(299)))
        XCTAssertTrue(AppLock.isLocked(defaults: defaults, at: t.addingTimeInterval(300)))
    }

    func testExtensionSeesTheColdStartLock() {
        let first = AppLock(defaults: defaults)
        first.enabled = true
        _ = AppLock(defaults: defaults)
        XCTAssertTrue(AppLock.isLocked(defaults: defaults, at: t))
    }

    func testTurningItOffUnlocks() {
        let lock = AppLock(defaults: defaults)
        lock.enabled = true
        lock.didEnterBackground(at: t)
        lock.enabled = false
        XCTAssertFalse(lock.needsUnlock(at: t))
        XCTAssertFalse(AppLock.isLocked(defaults: defaults, at: t))
    }

    func testDelaysAreTheOffered() {
        XCTAssertEqual(AppLock.delays, [0, 60, 300, 3600])
    }
}
