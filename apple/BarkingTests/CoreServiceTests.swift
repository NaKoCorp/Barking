import XCTest
@testable import BarkingKit

final class SyncSchedulerTests: XCTestCase {
    func testCadence() {
        XCTAssertEqual(SyncScheduler(conversationOpen: true).nextDelay(), .seconds(15))
        XCTAssertEqual(SyncScheduler(conversationOpen: false).nextDelay(), .seconds(60))
    }
}

final class CoreServiceTests: XCTestCase {
    func testBlockNodeGoesThroughCoreQueue() async throws {
        let device = FakeDevice()
        let runner = RecordingRunner()
        let core = CoreService(device: device, runner: runner)
        try await core.blockNode(id: "N1")
        try await core.unblockNode(id: "N1")
        try await core.removeNode(id: "N2")
        XCTAssertEqual(device.nodeCalls, ["block:N1", "unblock:N1", "remove:N2"])
        XCTAssertEqual(runner.names.count, 3)
        let n = try await core.usableNodesIfBlocked(id: "N1")
        XCTAssertEqual(n, 4)
        let d = try await core.dismissedDefaultsCount()
        XCTAssertEqual(d, 1)
    }

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

    /// A sync that only brought a contact request (nothing received, sent or
    /// changed otherwise): the chat list, which shows requests, reloads.
    func testRequestOnlySyncPublishesContacts() async {
        let device = FakeDevice()
        device.summary = SyncSummary(itemsReceived: 1, sent: 0, newMessages: [], networkUp: true, error: nil,
                                     requestContacts: ["fp"])
        let core = CoreService(device: device, runner: DirectRunner())
        let seen = Seen(await core.changes)
        let outcome = await core.sync(reason: .pull)
        XCTAssertEqual(outcome.requestContacts, ["fp"])
        let ok = await seen.eventually { $0.contains(.contacts) }
        XCTAssertTrue(ok, "\(seen.all)")
    }

    /// Each request action publishes `.contacts`; accepting also reloads the
    /// new contact's conversation (its held messages).
    func testRequestActionsPublish() async throws {
        let device = FakeDevice()
        device.requestList = [ContactRequestInfo(fingerprint: "FPR", displayName: "Alice", firstSeen: 1, lastSeen: 2,
                                                 inviteCount: 1, pendingMessages: 0, hidden: false, unseen: true,
                                                 nameClash: false)]
        let core = CoreService(device: device, runner: DirectRunner())
        let seen = Seen(await core.changes)
        try await core.setRequestHidden("FPR", hidden: true)
        try await core.markRequestsSeen()
        let fp = try await core.acceptRequest("FPR", alias: "Ali")
        XCTAssertEqual(fp, "FPR")
        try await core.refuseRequest("X")
        try await core.blockRequest("Y")
        try await core.invite("C1")
        try await core.setInviteNotifications(false)
        XCTAssertEqual(device.hidden.map(\.0), ["FPR"])
        XCTAssertEqual(device.seenMarks, 1)
        XCTAssertEqual(device.accepted.map(\.alias), ["Ali"])
        XCTAssertTrue(device.requestList.isEmpty)
        XCTAssertEqual([device.refused, device.blockedRequests, device.invited], [["X"], ["Y"], ["C1"]])
        XCTAssertEqual(device.inviteNotifications, [false])
        let ok = await seen.eventually { $0.filter { $0 == .contacts }.count >= 6 && $0.contains(.messages(contact: "FPR")) }
        XCTAssertTrue(ok, "\(seen.all)")
        let status = try await core.inviteStatus("C1")
        XCTAssertEqual(status, InviteStatus.none)
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

    /// A reaction (a contact's, or mine from another device, a removal
    /// included) changes a conversation without a new message: it reloads.
    func testReactionContactsReloadConversations() async {
        let d = FakeDevice()
        d.summary = SyncSummary(itemsReceived: 1, sent: 0, newMessages: [], networkUp: true, error: nil,
                                newReactions: [NewReaction(contact: "FP1", name: "Bob", emojis: ["👍"], excerpt: nil)],
                                reactionContacts: ["FP1"])
        let core = CoreService(device: d, runner: DirectRunner())
        let seen = Seen(await core.changes)
        let outcome = await core.sync(reason: .timer)
        XCTAssertEqual(outcome.reactionContacts, ["FP1"])
        XCTAssertEqual(outcome.newReactions.map(\.emojis), [["👍"]])
        let ok = await seen.eventually { $0.contains(.messages(contact: "FP1")) }
        XCTAssertTrue(ok, "\(seen.all)")
    }

    func testSendCarriesTheReplyAndReactionsAreSet() async throws {
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner())
        let seen = Seen(await core.changes)
        try await core.send("re", to: "FP1", replyTo: 7)
        try await core.send("plain", to: "FP1")
        XCTAssertEqual(d.sent.map(\.replyTo), [7, nil])
        try await core.setReactions(7, emojis: ["👍", "🎉"], contact: "FP1")
        XCTAssertEqual(d.reactions, [7: ["👍", "🎉"]])
        let ok = await seen.eventually { $0.filter { $0 == .messages(contact: "FP1") }.count >= 3 }
        XCTAssertTrue(ok, "\(seen.all)")
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

    // MARK: Final review 1: seen and deletions leave at once

    /// Polls `device.syncEvents` until a sync started, or gives up after `timeout`.
    private func syncStarted(_ device: FakeDevice, timeout: Duration = .seconds(5)) async -> Bool {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if device.syncEvents.contains("sync") { return true }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return false
    }

    /// An ephemeral seen here: my other devices must start its countdown
    /// now, not at the next timer sync (the app may go to the background).
    func testMarkSeenStartsASync() async throws {
        let device = FakeDevice()
        let core = CoreService(device: device, runner: DirectRunner())
        try await core.markSeen([])
        let none = await syncStarted(device, timeout: .milliseconds(300))
        XCTAssertFalse(none, "nothing reported, nothing to send")
        try await core.markSeen([7])
        XCTAssertEqual(device.seen, [[7]])
        let started = await syncStarted(device)
        XCTAssertTrue(started, "\(device.syncEvents)")
    }

    /// A deletion that deleted something syncs at once (its `SyncDelete`
    /// leaves for my other devices); one that deleted nothing does not.
    func testDeletionStartsASyncWhenSomethingWasDeleted() async throws {
        let deleted = DeleteOutcome(deleted: 1, cancelled: 0, partlyCancelled: 0, alreadyLeft: 1,
                                    stillReceiving: [], ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0,
                                    changes: [DeliveryChange(contact: "FP1", messageId: 7)])
        let calls: [(String, (CoreService) async throws -> DeleteOutcome)] = [
            ("one", { try await $0.deleteMessage(7) }),
            ("several", { try await $0.deleteMessages([7, 8]) }),
            ("cancel all", { try await $0.cancelAllPending() }),
        ]
        for (name, call) in calls {
            let idle = FakeDevice()
            _ = try await call(CoreService(device: idle, runner: DirectRunner()))
            let none = await syncStarted(idle, timeout: .milliseconds(300))
            XCTAssertFalse(none, "\(name): nothing deleted, no sync")

            let device = FakeDevice()
            device.deleteResult = deleted
            _ = try await call(CoreService(device: device, runner: DirectRunner()))
            let started = await syncStarted(device)
            XCTAssertTrue(started, "\(name): \(device.syncEvents)")
        }
    }
}

/// Counts the calls that go through the core's runner.
final class RecordingRunner: CallRunner, @unchecked Sendable {
    private let lock = NSLock()
    private var _names: [String] = []
    var names: [String] { lock.withLock { _names } }
    func run<T: Sendable>(_ name: String, _ body: @escaping @Sendable () throws -> T) async throws -> T {
        lock.withLock { _names.append(name) }
        return try body()
    }
}
