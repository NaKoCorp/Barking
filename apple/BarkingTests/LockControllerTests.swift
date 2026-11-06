import SwiftUI
import XCTest
@testable import Barking
@testable import BarkingKit

@MainActor
final class LockControllerTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!

    override func setUp() {
        suite = "lockcontroller.tests.\(UUID())"
        defaults = UserDefaults(suiteName: suite)
        defaults.set(true, forKey: "barking.lock.enabled")
    }

    override func tearDown() { defaults.removePersistentDomain(forName: suite) }

    /// Fix round 1: every wipe path ends in `restartOnboarding`, which reloads
    /// the lock; Settings must not show a lock that is gone.
    func testRestartingOnboardingReloadsTheLock() {
        let lock = LockController(lock: AppLock(defaults: defaults))
        let router = AppRouter(start: .onboarding)
        router.lock = lock
        XCTAssertTrue(lock.enabled)
        XCTAssertTrue(lock.locked)
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix("barking.") {
            defaults.removeObject(forKey: key)   // what `Wipe` does
        }
        router.restartOnboarding()
        XCTAssertFalse(lock.enabled)
        XCTAssertFalse(lock.locked)
    }

    func testEraseAndRestartWipesThenReloads() async throws {
        let lock = LockController(lock: AppLock(defaults: defaults))
        let router = AppRouter(start: .onboarding)
        router.lock = lock
        try await router.eraseAndRestart { _ in self.defaults.removeObject(forKey: "barking.lock.enabled") }
        XCTAssertFalse(lock.enabled)
        guard case .onboarding = router.state else { return XCTFail() }
    }

    func testFailedEraseStaysAndKeepsTheLock() async {
        let lock = LockController(lock: AppLock(defaults: defaults))
        let router = AppRouter(start: .failed)
        router.lock = lock
        struct Boom: Error {}
        do { try await router.eraseAndRestart { _ in throw Boom() }; XCTFail() } catch {}
        XCTAssertTrue(lock.enabled)
        guard case .failed = router.state else { return XCTFail() }
    }

    func testPromptUnlocksOnlyWhenTheOwnerPasses() async {
        let lock = LockController(lock: AppLock(defaults: defaults))
        await lock.promptIfLocked { false }
        XCTAssertTrue(lock.locked)
        await lock.promptIfLocked { true }
        XCTAssertFalse(lock.locked)
    }

    func testPromptDoesNothingWhenNotLocked() async {
        let lock = LockController(lock: AppLock(defaults: defaults))
        lock.unlock()
        var asked = false
        await lock.promptIfLocked { asked = true; return true }
        XCTAssertFalse(asked)
    }

    func testCoverFollowsThePhaseOnlyWithTheLockOn() {
        let lock = LockController(lock: AppLock(defaults: defaults))
        lock.unlock()
        XCTAssertFalse(lock.covered)
        lock.phaseChanged(to: .inactive)
        XCTAssertTrue(lock.covered)
        lock.phaseChanged(to: .active)
        XCTAssertFalse(lock.covered)
        _ = lock.setEnabled(false)
        lock.phaseChanged(to: .inactive)
        XCTAssertFalse(lock.covered)
    }

    /// Final review 5: reloading after a wipe reads the settings, it never
    /// writes one back into the emptied group defaults.
    func testReloadAfterAWipeWritesNothingBack() {
        defaults.set(300.0, forKey: "barking.lock.delay")
        let lock = LockController(lock: AppLock(defaults: defaults))
        XCTAssertEqual(lock.delay, 300)
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix("barking.") {
            defaults.removeObject(forKey: key)   // what `Wipe` does
        }
        lock.reload()
        XCTAssertEqual(lock.delay, 0)
        XCTAssertEqual(defaults.dictionaryRepresentation().keys.filter { $0.hasPrefix("barking.lock.") }, [])
        // A change from Settings is still saved.
        lock.delay = 60
        XCTAssertEqual(defaults.double(forKey: "barking.lock.delay"), 60)
    }
}
