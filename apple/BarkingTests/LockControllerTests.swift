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

    /// Changing the lock asks for the owner first; a refusal changes and saves nothing.
    func testTurningTheLockOffNeedsTheOwner() async {
        let lock = LockController(lock: AppLock(defaults: defaults))
        var r = await lock.setEnabled(false, canEnable: { true }, owner: { false })
        XCTAssertEqual(r, .denied)
        XCTAssertTrue(lock.enabled)
        XCTAssertTrue(defaults.bool(forKey: "barking.lock.enabled"))
        r = await lock.setEnabled(false, canEnable: { true }, owner: { true })
        XCTAssertEqual(r, .changed)
        XCTAssertFalse(lock.enabled)
        XCTAssertFalse(defaults.bool(forKey: "barking.lock.enabled"))
    }

    func testTurningTheLockOnNeedsTheOwner() async {
        defaults.set(false, forKey: "barking.lock.enabled")
        let lock = LockController(lock: AppLock(defaults: defaults))
        var r = await lock.setEnabled(true, canEnable: { true }, owner: { false })
        XCTAssertEqual(r, .denied)
        XCTAssertFalse(lock.enabled)
        XCTAssertFalse(defaults.bool(forKey: "barking.lock.enabled"))
        r = await lock.setEnabled(true, canEnable: { true }, owner: { true })
        XCTAssertEqual(r, .changed)
        XCTAssertTrue(lock.enabled)
        XCTAssertTrue(defaults.bool(forKey: "barking.lock.enabled"))
    }

    func testNoPasscodeRefusesBeforeAskingTheOwner() async {
        defaults.set(false, forKey: "barking.lock.enabled")
        let lock = LockController(lock: AppLock(defaults: defaults))
        var asked = false
        let result = await lock.setEnabled(true, canEnable: { false }, owner: { asked = true; return true })
        XCTAssertEqual(result, .noPasscode)
        XCTAssertFalse(asked)
        XCTAssertFalse(lock.enabled)
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

    func testCoverFollowsThePhaseOnlyWithTheLockOn() async {
        let lock = LockController(lock: AppLock(defaults: defaults))
        lock.unlock()
        XCTAssertFalse(lock.covered)
        lock.phaseChanged(to: .inactive)
        XCTAssertTrue(lock.covered)
        lock.phaseChanged(to: .active)
        XCTAssertFalse(lock.covered)
        _ = await lock.setEnabled(false, owner: { true })
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
