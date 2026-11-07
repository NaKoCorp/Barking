import XCTest
@testable import BarkingKit

final class SyncSchedulerTests: XCTestCase {
    func testCadence() {
        XCTAssertEqual(SyncScheduler(conversationOpen: true).nextDelay(), .seconds(15))
        XCTAssertEqual(SyncScheduler(conversationOpen: false).nextDelay(), .seconds(60))
    }
}

final class CoreServiceTests: XCTestCase {
    /// Reset of a removed device: `close` waits for the sync in flight, then
    /// no call reaches the device any more.
    func testCloseWaitsForSyncThenRefusesCalls() async {
        let d = FakeDevice()
        d.syncDelay = 0.3
        let core = CoreService(device: d, runner: DirectRunner())
        let started = Date()
        let sync = Task { await core.sync(reason: .pull) }
        try? await Task.sleep(for: .milliseconds(50))
        await core.close()
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(started), 0.25)
        _ = await sync.value
        let again = await core.sync(reason: .pull)
        XCTAssertFalse(again.networkUp)
        XCTAssertEqual(d.syncCalls, 1)
        do {
            _ = try await core.myDevices()
            XCTFail("call after close")
        } catch {}
    }

    func testConcurrentSyncsShareOne() async {
        let device = FakeDevice()
        device.syncDelay = 0.2
        let core = CoreService(device: device, runner: DirectRunner())
        async let a = core.sync(reason: .pull)
        async let b = core.sync(reason: .timer)
        _ = await (a, b)
        XCTAssertEqual(device.syncCalls, 1)
    }

    /// A send during a receipt wake's quick sync: the quick one does not
    /// deposit messages, so the full sync runs after it instead of joining it.
    func testFullSyncDuringAQuickOneRunsAfterIt() async {
        let device = FakeDevice()
        device.syncDelay = 0.2
        let core = CoreService(device: device, runner: DirectRunner())
        let quick = Task { await core.quickSync() }
        try? await Task.sleep(for: .milliseconds(50))
        _ = await core.sync(reason: .afterSend)
        _ = await quick.value
        XCTAssertEqual(device.syncEvents, ["quick", "quick-done", "sync", "sync-done"])
    }

    /// A quick sync asked during a full one gets the full one's outcome.
    func testQuickSyncDuringAFullOneJoinsIt() async {
        let device = FakeDevice()
        device.syncDelay = 0.2
        let core = CoreService(device: device, runner: DirectRunner())
        let full = Task { await core.sync(reason: .timer) }
        try? await Task.sleep(for: .milliseconds(50))
        _ = await core.quickSync()
        _ = await full.value
        XCTAssertEqual(device.syncEvents, ["sync", "sync-done"])
    }

    func testMutationPublishesChange() async throws {
        let core = CoreService(device: FakeDevice(), runner: DirectRunner())
        let stream = await core.changes
        let first = Task { () -> CoreChange? in
            for await change in stream { return change }
            return nil
        }
        try await core.markVerified("fp-bob")
        let change = await first.value
        XCTAssertEqual(change, .contacts)
    }

    func testTerminalLines() async {
        let device = FakeDevice()
        device.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: false, error: nil)
        let core = CoreService(device: device, runner: DirectRunner())
        let down = await core.sync(reason: .pull)
        XCTAssertEqual(down.lines, ["$ barking sync", "internet: network unreachable, nothing is lost"])
        XCTAssertFalse(down.networkUp)
        let newMessages = (0..<3).map { NewMessage(contact: "c", name: "n", text: "t\($0)") }
        device.summary = SyncSummary(itemsReceived: 3, sent: 1, newMessages: newMessages, networkUp: true, error: nil)
        let up = await core.sync(reason: .pull)
        XCTAssertEqual(up.lines, ["$ barking sync", "internet: 3 messages received, 1 sent"])
    }
}
