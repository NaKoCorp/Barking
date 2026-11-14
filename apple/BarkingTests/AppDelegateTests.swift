import UIKit
import UserNotifications
import XCTest
@testable import Barking
@testable import BarkingKit

/// A background (receipt) push wakes the app: the delegate runs a quick sync
/// and tells iOS whether anything came of it.
@MainActor
final class AppDelegateTests: XCTestCase {
    private func wake(_ delegate: AppDelegate) async -> UIBackgroundFetchResult {
        await withCheckedContinuation { done in
            delegate.application(UIApplication.shared, didReceiveRemoteNotification: [:]) { result in
                done.resume(returning: result)
            }
        }
    }

    private func delegate(syncing device: FakeDevice) -> AppDelegate {
        let core = CoreService(device: device, runner: DirectRunner())
        let delegate = AppDelegate()
        delegate.service = { core }
        return delegate
    }

    func testWakeRunsAQuickSyncAndReportsNoDataWhenNothingChanges() async {
        let d = FakeDevice()
        d.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: true, error: nil)
        let result = await wake(delegate(syncing: d))
        XCTAssertEqual(result, .noData)
        XCTAssertEqual(d.quickSyncDeadlines, [Budget.appQuickSyncMs])
        XCTAssertEqual(d.syncCalls, 0, "a quick sync, not a full one")
    }

    func testWakeReportsNewDataWhenSomethingArrived() async {
        // A receipt: an item fetched, no new message to show.
        let d = FakeDevice()
        d.summary = SyncSummary(itemsReceived: 1, sent: 0, newMessages: [], networkUp: true, error: nil)
        let result = await wake(delegate(syncing: d))
        XCTAssertEqual(result, .newData)
        XCTAssertEqual(d.quickSyncDeadlines.count, 1)
    }

    func testWakeReportsFailedWhenTheSyncFails() async {
        let down = FakeDevice()
        down.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: false, error: nil)
        let failed = await wake(delegate(syncing: down))
        XCTAssertEqual(failed, .failed)
        let throwing = FakeDevice()
        throwing.quickSyncError = BarkingError.Locked
        let thrown = await wake(delegate(syncing: throwing))
        XCTAssertEqual(thrown, .failed)
    }

    func testWakeBeforeTheDeviceIsReadyHasNoData() async {
        let delegate = AppDelegate()
        delegate.service = { nil }
        let result = await wake(delegate)
        XCTAssertEqual(result, .noData)
    }

    func testBackgroundWakeNotesWake() async {
        let d = FakeDevice()
        _ = await delegate(syncing: d).backgroundWake()
        XCTAssertEqual(d.wakeNotes.count, 1)
    }

    private func guarded(_ status: UNAuthorizationStatus, token: Data?, device: FakeDevice) async -> PushToken {
        let push = PushToken()
        push.info = [
            "BarkingRelayHost": "relay.local", "BarkingRelayPort": "4434",
            "BarkingRelayId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "BarkingRelaySealId": "1", "BarkingRelaySealPublic": String(repeating: "5e", count: 32),
        ]
        push.authorization = { status }
        push.token = token
        await push.apply(to: CoreService(device: device, runner: DirectRunner()))
        return push
    }

    func testDeniedClearsPushWithoutToken() async {
        let d = FakeDevice()
        let push = await guarded(.denied, token: nil, device: d)
        XCTAssertEqual(d.pushSettings.count, 1)
        XCTAssertNil(d.pushSettings.last ?? nil)
        XCTAssertEqual(push.status, .denied)
    }

    func testNotDeterminedClearsPush() async {
        let d = FakeDevice()
        let push = await guarded(.notDetermined, token: Data([1, 2]), device: d)
        XCTAssertEqual(d.pushSettings.count, 1)
        XCTAssertNil(d.pushSettings.last ?? nil)
        XCTAssertEqual(push.status, .notDetermined)
    }

    func testAuthorizedGivesSettings() async {
        let d = FakeDevice()
        _ = await guarded(.authorized, token: Data([1, 2]), device: d)
        XCTAssertEqual(d.pushSettings.count, 1)
        XCTAssertNotNil(d.pushSettings.last ?? nil)
    }
}
