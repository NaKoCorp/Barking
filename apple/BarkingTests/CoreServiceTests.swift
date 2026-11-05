import XCTest
@testable import BarkingKit

final class SyncSchedulerTests: XCTestCase {
    func testCadence() {
        XCTAssertEqual(SyncScheduler(conversationOpen: true).nextDelay(), .seconds(15))
        XCTAssertEqual(SyncScheduler(conversationOpen: false).nextDelay(), .seconds(60))
    }
}

final class CoreServiceTests: XCTestCase {
    func testConcurrentSyncsShareOne() async {
        let device = FakeDevice()
        device.syncDelay = 0.2
        let core = CoreService(device: device, runner: DirectRunner())
        async let a = core.sync(reason: .pull)
        async let b = core.sync(reason: .timer)
        _ = await (a, b)
        XCTAssertEqual(device.syncCalls, 1)
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
