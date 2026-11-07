import SwiftUI
import XCTest
@testable import Barking
@testable import BarkingKit

/// A sleep the test opens by hand: the 250 ms window of the delivery
/// changes without waiting for the clock.
actor DeliveryGate {
    private var waiting: [CheckedContinuation<Void, Never>] = []
    private(set) var requested: [Duration] = []

    func sleep(_ d: Duration) async {
        requested.append(d)
        await withCheckedContinuation { waiting.append($0) }
    }
    /// How many sleeps wait for `open`.
    var waits: Int { waiting.count }
    /// Lets the waiting sleeps return; waits first for one to start (the
    /// window opens in a task of its own).
    func open() async {
        for _ in 0..<200 where waiting.isEmpty { try? await Task.sleep(for: .milliseconds(10)) }
        let all = waiting
        waiting = []
        for c in all { c.resume() }
    }
}

/// What a stream of changes yielded so far.
final class Seen: @unchecked Sendable {
    private let lock = NSLock()
    private var _all: [CoreChange] = []
    private var task: Task<Void, Never>?
    var all: [CoreChange] { lock.withLock { _all } }

    init(_ stream: AsyncStream<CoreChange>) {
        task = Task { [weak self] in
            for await c in stream { self?.lock.withLock { self?._all.append(c) } }
        }
    }
    deinit { task?.cancel() }

    /// Waits (at most 2 s) until `condition` holds on what was seen.
    func eventually(_ condition: ([CoreChange]) -> Bool) async -> Bool {
        for _ in 0..<200 {
            if condition(all) { return true }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return condition(all)
    }
}

private func changes(_ pairs: (String, Int64)...) -> [DeliveryChange] {
    pairs.map { DeliveryChange(contact: $0.0, messageId: $0.1) }
}

private func deliveries(_ all: [CoreChange]) -> [CoreChange] {
    all.filter { if case .delivery = $0 { true } else { false } }
}

final class DeliveryCoreTests: XCTestCase {
    private func summary(newMessages: [NewMessage] = [], deliveryChanges: [DeliveryChange]) -> SyncSummary {
        SyncSummary(itemsReceived: 1, sent: 0, newMessages: newMessages, networkUp: true, error: nil,
                    deliveryChanges: deliveryChanges, failed: [])
    }

    func testTheWindowIs250ms() {
        XCTAssertEqual(CoreService.deliveryWindow, .milliseconds(250))
    }

    /// Two syncs 100 ms apart, one window: one `.delivery` with both ids.
    func testDeliveryChangesAreBatchedOver250ms() async {
        let gate = DeliveryGate()
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner(), sleep: { await gate.sleep($0) })
        let seen = Seen(await core.changes)
        d.summary = summary(deliveryChanges: changes(("b", 1)))
        _ = await core.sync(reason: .pull)
        d.summary = summary(deliveryChanges: changes(("b", 2), ("b", 1)))
        _ = await core.quickSync()
        let waits = await gate.waits
        XCTAssertEqual(waits, 1, "one window for the burst")
        let requested = await gate.requested
        XCTAssertEqual(requested, [.milliseconds(250)])
        XCTAssertTrue(deliveries(seen.all).isEmpty, "nothing before the window ends")
        await gate.open()
        let ok = await seen.eventually { !deliveries($0).isEmpty }
        XCTAssertTrue(ok, "\(seen.all)")
        XCTAssertEqual(deliveries(seen.all), [.delivery(contact: "b", ids: [1, 2])])
    }

    /// With the real clock: the change comes out after the window, not before.
    func testTheRealWindowHoldsTheChange() async {
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner())
        let seen = Seen(await core.changes)
        d.summary = summary(deliveryChanges: changes(("b", 1)))
        let start = ContinuousClock.now
        _ = await core.sync(reason: .pull)
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertTrue(deliveries(seen.all).isEmpty)
        let ok = await seen.eventually { !deliveries($0).isEmpty }
        XCTAssertTrue(ok, "\(seen.all)")
        XCTAssertGreaterThanOrEqual(ContinuousClock.now - start, .milliseconds(240))
    }

    func testEachContactGetsItsOwnDeliveryChange() async {
        let gate = DeliveryGate()
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner(), sleep: { await gate.sleep($0) })
        let seen = Seen(await core.changes)
        d.summary = summary(deliveryChanges: changes(("b", 1), ("a", 7), ("b", 2)))
        _ = await core.sync(reason: .pull)
        await gate.open()
        let ok = await seen.eventually { deliveries($0).count == 2 }
        XCTAssertTrue(ok, "\(seen.all)")
        XCTAssertEqual(deliveries(seen.all), [.delivery(contact: "a", ids: [7]), .delivery(contact: "b", ids: [1, 2])])
    }

    func testSyncWithOnlyStateChangesEmitsDeliveryNotMessages() async {
        let gate = DeliveryGate()
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner(), sleep: { await gate.sleep($0) })
        let seen = Seen(await core.changes)
        d.summary = summary(deliveryChanges: changes(("b", 4)))
        _ = await core.sync(reason: .pull)
        await gate.open()
        let ok = await seen.eventually { !deliveries($0).isEmpty }
        XCTAssertTrue(ok, "\(seen.all)")
        XCTAssertFalse(seen.all.contains { if case .messages = $0 { true } else { false } })
        XCTAssertEqual(deliveries(seen.all), [.delivery(contact: "b", ids: [4])])
    }

    /// A new message makes the conversation reload as a whole: the state
    /// changes of that contact are not repeated after it.
    func testNewMessageEmitsMessagesAndAbsorbsTheDeliveryChange() async {
        let gate = DeliveryGate()
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner(), sleep: { await gate.sleep($0) })
        let seen = Seen(await core.changes)
        d.summary = summary(newMessages: [NewMessage(contact: "b", name: "Bob", text: "hi")],
                            deliveryChanges: changes(("b", 4), ("c", 9)))
        _ = await core.sync(reason: .pull)
        await gate.open()
        let ok = await seen.eventually { c in
            c.contains(.messages(contact: "b")) && c.contains(.delivery(contact: "c", ids: [9]))
        }
        XCTAssertTrue(ok, "\(seen.all)")
        XCTAssertFalse(seen.all.contains(.delivery(contact: "b", ids: [4])))
    }

    func testQuickSyncPublishesDeliveryChangesToo() async {
        let gate = DeliveryGate()
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner(), sleep: { await gate.sleep($0) })
        let seen = Seen(await core.changes)
        d.summary = summary(deliveryChanges: changes(("b", 3)))
        _ = await core.quickSync()
        await gate.open()
        let ok = await seen.eventually { !deliveries($0).isEmpty }
        XCTAssertTrue(ok, "\(seen.all)")
        XCTAssertEqual(deliveries(seen.all), [.delivery(contact: "b", ids: [3])])
    }

    /// Lot N: a full sync asked during a quick one still waits, then runs.
    func testFullSyncStillWaitsForTheQuickOne() async {
        let d = FakeDevice()
        d.syncDelay = 0.1
        d.summary = summary(deliveryChanges: changes(("b", 1)))
        let core = CoreService(device: d, runner: DirectRunner())
        let quick = Task { await core.quickSync() }
        try? await Task.sleep(for: .milliseconds(30))
        _ = await core.sync(reason: .afterSend)
        _ = await quick.value
        XCTAssertEqual(d.syncEvents, ["quick", "quick-done", "sync", "sync-done"])
        XCTAssertEqual(d.quickSyncDeadlines, [Budget.appQuickSyncMs])
    }

    func testDeleteReloadsEachConversationItTouched() async throws {
        let d = FakeDevice()
        d.deleteResult = DeleteOutcome(deleted: 3, cancelled: 3, partlyCancelled: 0, alreadyLeft: 0, stillReceiving: [],
                                       ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0,
                                       changes: changes(("a", 1), ("b", 2), ("a", 3)))
        let core = CoreService(device: d, runner: DirectRunner())
        let seen = Seen(await core.changes)
        let outcome = try await core.deleteMessages([1, 2, 3])
        XCTAssertEqual(outcome.deleted, 3)
        XCTAssertEqual(d.deleted, [[1, 2, 3]])
        let ok = await seen.eventually { $0.contains(.network) }
        XCTAssertTrue(ok, "\(seen.all)")
        XCTAssertTrue(seen.all.contains(.messages(contact: "a")))
        XCTAssertTrue(seen.all.contains(.messages(contact: "b")))
        XCTAssertTrue(seen.all.contains(.contacts))
        XCTAssertEqual(seen.all.filter { $0 == .messages(contact: "a") }.count, 1)
    }

    /// After `close`, the open window publishes nothing.
    func testNothingIsPublishedAfterClose() async {
        let gate = DeliveryGate()
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner(), sleep: { await gate.sleep($0) })
        let seen = Seen(await core.changes)
        d.summary = summary(deliveryChanges: changes(("b", 1)))
        _ = await core.sync(reason: .pull)
        await core.close()
        await gate.open()
        try? await Task.sleep(for: .milliseconds(50))
        XCTAssertTrue(deliveries(seen.all).isEmpty, "\(seen.all)")
    }

    /// A deletion reloads its contact whole: its waiting state changes go,
    /// those of the other contacts stay.
    func testDeleteClearsWaitingIdsOfItsContact() async throws {
        let gate = DeliveryGate()
        let d = FakeDevice()
        let core = CoreService(device: d, runner: DirectRunner(), sleep: { await gate.sleep($0) })
        let seen = Seen(await core.changes)
        d.summary = summary(deliveryChanges: changes(("b", 1), ("c", 2)))
        _ = await core.sync(reason: .pull)
        d.deleteResult = DeleteOutcome(deleted: 1, cancelled: 1, partlyCancelled: 0, alreadyLeft: 0, stillReceiving: [],
                                       ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0, changes: changes(("b", 1)))
        _ = try await core.deleteMessage(1)
        await gate.open()
        let ok = await seen.eventually { !deliveries($0).isEmpty }
        XCTAssertTrue(ok, "\(seen.all)")
        XCTAssertEqual(deliveries(seen.all), [.delivery(contact: "c", ids: [2])])
        XCTAssertTrue(seen.all.contains(.messages(contact: "b")))
    }

    func testDeleteOneAndCancelAllReportTheOutcome() async throws {
        let d = FakeDevice()
        d.deleteResult = DeleteOutcome(deleted: 1, cancelled: 0, partlyCancelled: 0, alreadyLeft: 1,
                                       stillReceiving: ["Alice"], ownCopiesKept: true, devicesLeft: 0, devicesTotal: 0, changes: changes(("a", 5)))
        let core = CoreService(device: d, runner: DirectRunner())
        let one = try await core.deleteMessage(5)
        XCTAssertEqual(one.alreadyLeft, 1)
        XCTAssertEqual(d.deleted, [[5]])
        let all = try await core.cancelAllPending()
        XCTAssertEqual(all.stillReceiving, ["Alice"])
        XCTAssertEqual(d.cancelAllCalls, 1)
    }

    func testFailedDeleteChangesNothing() async {
        let d = FakeDevice()
        d.deliveryError = BarkingError.Internal(detail: "boom")
        let core = CoreService(device: d, runner: DirectRunner())
        let seen = Seen(await core.changes)
        do {
            _ = try await core.deleteMessage(1)
            XCTFail("expected an error")
        } catch {}
        try? await Task.sleep(for: .milliseconds(30))
        XCTAssertTrue(seen.all.isEmpty)
    }

    /// A retry names its row: `.delivery` for the contact (other screens
    /// update even offline), the chat list and the pending count; a sync follows.
    func testRetryMessagePublishesItsRowAndSyncs() async throws {
        let d = FakeDevice()
        let gate = DeliveryGate()
        let core = CoreService(device: d, runner: DirectRunner(), sleep: { await gate.sleep($0) })
        let seen = Seen(await core.changes)
        try await core.retryMessage(7, contact: "b")
        XCTAssertEqual(d.retried, [7])
        await gate.open()
        let ok = await seen.eventually {
            $0.contains(.delivery(contact: "b", ids: [7])) && $0.contains(.contacts) && $0.contains(.network)
        }
        XCTAssertTrue(ok, "\(seen.all)")
        // The retry sends: a sync follows.
        for _ in 0..<100 where d.syncCalls == 0 { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertEqual(d.syncCalls, 1)
    }

    /// A copy of a message I sent from another device reloads its
    /// conversation, like a new message.
    func testSyncedSentCopyReloadsItsConversation() async {
        let d = FakeDevice()
        d.summary = SyncSummary(itemsReceived: 1, sent: 0, newMessages: [], networkUp: true, error: nil,
                                syncedContacts: ["b"])
        let core = CoreService(device: d, runner: DirectRunner())
        let seen = Seen(await core.changes)
        let outcome = await core.sync(reason: .timer)
        XCTAssertEqual(outcome.syncedContacts, ["b"])
        let ok = await seen.eventually { $0.contains(.messages(contact: "b")) }
        XCTAssertTrue(ok, "\(seen.all)")
    }

    /// A refused retry publishes nothing.
    func testFailedRetryPublishesNothing() async {
        let d = FakeDevice()
        d.retryError = BarkingError.NothingToRetry
        let core = CoreService(device: d, runner: DirectRunner())
        let seen = Seen(await core.changes)
        try? await core.retryMessage(7, contact: "b")
        try? await Task.sleep(for: .milliseconds(300))
        XCTAssertTrue(seen.all.isEmpty, "\(seen.all)")
    }

    func testRetryAllReturnsTheCountAndReloadsTheContact() async throws {
        let d = FakeDevice()
        d.retryAllCount = 2
        let core = CoreService(device: d, runner: DirectRunner())
        let seen = Seen(await core.changes)
        let n = try await core.retryAll(contact: "b")
        XCTAssertEqual(n, 2)
        XCTAssertEqual(d.retriedAll, ["b"])
        let ok = await seen.eventually { $0.contains(.messages(contact: "b")) }
        XCTAssertTrue(ok, "\(seen.all)")
    }

    func testNothingToRetryIsItsOwnError() async {
        let d = FakeDevice()
        d.deliveryError = BarkingError.NothingToRetry
        let core = CoreService(device: d, runner: DirectRunner())
        do {
            try await core.retryMessage(1, contact: "b")
            XCTFail("expected an error")
        } catch let e as BarkingError {
            XCTAssertEqual(e, .NothingToRetry)
        } catch { XCTFail("\(error)") }
    }

    func testReadsPassThrough() async throws {
        let d = FakeDevice()
        let update = DeliveryUpdate(messageId: 4, delivery: .state(.received), removed: false)
        d.deliveryUpdates[4] = update
        d.deliveryCountsByContact["b"] = DeliveryCounts(pending: 1, onNetwork: 2, received: 3, notDelivered: 4)
        let row = DeliveryRowInfo(messageId: 4, body: "hi", at: 9, delivery: .state(.pending))
        d.deliveryRows["b"] = [.pending: [row, row, row]]
        d.pendingInfo = PendingPackets(messages: [], sync: [], packets: 6)
        let core = CoreService(device: d, runner: DirectRunner())
        let got = try await core.deliveriesOf([4, 99])
        XCTAssertEqual(got.map(\.removed), [false, true])
        XCTAssertEqual(got.first, update)
        let counts = try await core.deliveryCounts(contact: "b")
        XCTAssertEqual(counts.notDelivered, 4)
        let page = try await core.deliveryPage(contact: "b", state: .pending, limit: 2, offset: 1)
        XCTAssertEqual(page.count, 2)
        let sheet = try await core.messageDelivery(4)
        XCTAssertNil(sheet)
        let packets = try await core.pendingPackets()
        XCTAssertEqual(packets.packets, 6)
    }
}

@MainActor
final class DeliveryNetworkLineTests: XCTestCase {
    func testPendingCountFeedsTheNetworkLine() async {
        let d = FakeDevice()
        d.pendingCountValue = 4
        let m = NetworkModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.load()
        XCTAssertEqual(m.pending, 4)
    }
}

final class DeleteBannerTests: XCTestCase {
    private func outcome(cancelled: UInt32 = 0, partly: UInt32 = 0, left: UInt32 = 0,
                         still: [String] = []) -> DeleteOutcome {
        DeleteOutcome(deleted: max(1, cancelled + partly + left), cancelled: cancelled, partlyCancelled: partly,
                      alreadyLeft: left, stillReceiving: still, ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0, changes: [])
    }

    private func bundle(_ lang: String) throws -> Bundle {
        let path = try XCTUnwrap(Bundle.main.path(forResource: lang, ofType: "lproj"))
        return try XCTUnwrap(Bundle(path: path))
    }

    private func text(_ m: DeleteBanner.Message?, _ lang: String) throws -> String? {
        try m?.string(bundle: bundle(lang), locale: Locale(identifier: lang))
    }

    // MARK: The table of §6.7, row by row

    func testPendingCancelledSaysNothing() {
        XCTAssertNil(DeleteBanner.message(shown: .pending, outcome: outcome(cancelled: 1), contactName: "Alice"))
        XCTAssertNil(DeleteBanner.text(shown: .pending, outcome: outcome(cancelled: 1), contactName: "Alice"))
    }

    func testPendingButAlreadyLeft() throws {
        let m = DeleteBanner.message(shown: .pending, outcome: outcome(left: 1), contactName: "Alice")
        XCTAssertEqual(m, .alreadyLeft(name: "Alice"))
        XCTAssertNotNil(DeleteBanner.text(shown: .pending, outcome: outcome(left: 1), contactName: "Alice"))
        XCTAssertEqual(try text(m, "en"), "It had already left: Alice will still receive it.")
        XCTAssertEqual(try text(m, "fr"), "Il était déjà parti\u{00A0}: Alice le recevra quand même.")
    }

    func testPendingButPartlyLeft() throws {
        let m = DeleteBanner.message(shown: .pending, outcome: outcome(partly: 1), contactName: "Alice",
                                     devices: (left: 1, total: 2))
        XCTAssertEqual(m, .partlyLeft(name: "Alice", left: 1, total: 2))
        XCTAssertEqual(try text(m, "en"), "Part of it had already left: Alice will receive it on 1 of their 2 devices.")
        XCTAssertEqual(try text(m, "fr"),
                       "Une partie était déjà partie\u{00A0}: Alice le recevra sur 1 de ses 2 appareils.")
    }

    func testPartlyLeftThreeDevices() throws {
        let m = DeleteBanner.Message.partlyLeft(name: "Alice", left: 2, total: 3)
        XCTAssertEqual(try text(m, "en"), "Part of it had already left: Alice will receive it on 2 of their 3 devices.")
        XCTAssertEqual(try text(m, "fr"),
                       "Une partie était déjà partie\u{00A0}: Alice le recevra sur 2 de ses 3 appareils.")
    }

    func testPartlyLeftWithoutTheDeviceCountStaysTrue() throws {
        let m = DeleteBanner.message(shown: .pending, outcome: outcome(partly: 1), contactName: "Alice")
        XCTAssertEqual(m, .alreadyLeft(name: "Alice"))
    }

    func testShownOnTheNetworkOrReceivedSaysNothing() {
        for shown in [DeliveryState.onNetwork, .received, .notDelivered] {
            for o in [outcome(cancelled: 1), outcome(left: 1), outcome(partly: 1)] {
                XCTAssertNil(DeleteBanner.message(shown: shown, outcome: o, contactName: "Alice"), "\(shown)")
                XCTAssertNil(DeleteBanner.text(shown: shown, outcome: o, contactName: "Alice"), "\(shown)")
            }
        }
    }

    func testSeveralWithSomeAlreadyGone() throws {
        let o = outcome(cancelled: 1, partly: 1, left: 1, still: ["Alice"])
        let m = DeleteBanner.message(shown: nil, outcome: o, contactName: "Alice")
        XCTAssertEqual(m, .several(count: 2, names: ["Alice"]))
        XCTAssertNotNil(DeleteBanner.text(shown: nil, outcome: o, contactName: "Alice"))
    }

    /// The pronoun follows the number of messages, the French verb the number of names.
    func testSeveralAgreesInNumber() throws {
        let nb = "\u{00A0}"
        let cases: [(Int, [String], String, String)] = [
            (1, ["Alice"], "1 had already left: Alice will still receive it.",
             "1 était déjà parti\(nb): Alice le recevra quand même."),
            (2, ["Alice"], "2 had already left: Alice will still receive them.",
             "2 étaient déjà partis\(nb): Alice les recevra quand même."),
            (1, ["Alice", "Sam"], "1 had already left: Alice and Sam will still receive it.",
             "1 était déjà parti\(nb): Alice et Sam le recevront quand même."),
            (2, ["Alice", "Sam"], "2 had already left: Alice and Sam will still receive them.",
             "2 étaient déjà partis\(nb): Alice et Sam les recevront quand même."),
            (2, ["Alice", "Sam", "Lou"], "2 had already left: Alice, Sam and 1 other will still receive them.",
             "2 étaient déjà partis\(nb): Alice, Sam et 1 autre personne les recevront quand même."),
            (3, ["A", "B", "C", "D"], "3 had already left: A, B and 2 others will still receive them.",
             "3 étaient déjà partis\(nb): A, B et 2 autres personnes les recevront quand même."),
        ]
        for (count, names, en, fr) in cases {
            let m = DeleteBanner.Message.several(count: count, names: names)
            XCTAssertEqual(try text(m, "en"), en)
            XCTAssertEqual(try text(m, "fr"), fr)
        }
    }

    /// "Cancel all" with no name to give: a sentence without one.
    func testSeveralWithoutNamesIsNameless() throws {
        let m = DeleteBanner.message(shown: nil, outcome: outcome(left: 2), contactName: "")
        XCTAssertEqual(m, .several(count: 2, names: []))
        XCTAssertEqual(try text(m, "en"), "2 had already left and will still be delivered.")
        XCTAssertEqual(try text(m, "fr"), "2 étaient déjà partis et seront quand même distribués.")
        let one = DeleteBanner.Message.several(count: 1, names: [])
        XCTAssertEqual(try text(one, "en"), "1 had already left and will still be delivered.")
        XCTAssertEqual(try text(one, "fr"), "1 était déjà parti et sera quand même distribué.")
    }

    func testSeveralNothingGoneSaysNothing() {
        XCTAssertNil(DeleteBanner.message(shown: nil, outcome: outcome(cancelled: 3), contactName: "Alice"))
    }

    func testSeveralNamesComeFromTheOutcome() {
        let o = outcome(left: 2, still: ["Alice", "Sam", "Lou", "Max"])
        XCTAssertEqual(DeleteBanner.message(shown: nil, outcome: o, contactName: ""),
                       .several(count: 2, names: ["Alice", "Sam", "Lou", "Max"]))
    }

    func testNamesListAtMostTwoThenTheOthers() throws {
        let en = try bundle("en"), fr = try bundle("fr")
        let enLocale = Locale(identifier: "en"), frLocale = Locale(identifier: "fr")
        XCTAssertEqual(DeleteBanner.names(["Alice"], bundle: en, locale: enLocale), "Alice")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam"], bundle: en, locale: enLocale), "Alice and Sam")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam"], bundle: fr, locale: frLocale), "Alice et Sam")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam", "Lou"], bundle: en, locale: enLocale), "Alice, Sam and 1 other")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam", "Lou"], bundle: fr, locale: frLocale),
                       "Alice, Sam et 1 autre personne")
        XCTAssertEqual(DeleteBanner.names(["A", "B", "C", "D"], bundle: en, locale: enLocale), "A, B and 2 others")
        XCTAssertEqual(DeleteBanner.names(["A", "B", "C", "D"], bundle: fr, locale: frLocale), "A, B et 2 autres personnes")
    }

    // MARK: Writing rules (spec §7)

    func testTextsFollowTheWritingRules() throws {
        let all: [DeleteBanner.Message] = [
            .alreadyLeft(name: "Alice"), .partlyLeft(name: "Alice", left: 1, total: 2),
            .several(count: 1, names: ["Alice"]), .several(count: 2, names: ["Alice", "Sam"]),
            .several(count: 2, names: ["A", "B", "C"]), .several(count: 1, names: []), .several(count: 2, names: []),
        ]
        for lang in ["en", "fr"] {
            for m in all {
                let s = try XCTUnwrap(text(m, lang))
                XCTAssertFalse(s.contains("\u{2014}"), "em dash in \(s)")
                XCTAssertFalse(s.contains("!"), "exclamation mark in \(s)")
                XCTAssertFalse(s.contains("%"), "unresolved placeholder in \(s)")
                XCTAssertFalse(s.contains("'"), "straight apostrophe in \(s)")
                if lang == "fr" {
                    for mark in [":", "?", ";"] {
                        var from = s.startIndex
                        while let r = s.range(of: mark, range: from..<s.endIndex) {
                            if r.lowerBound > s.startIndex {
                                let before = s[s.index(before: r.lowerBound)]
                                XCTAssertTrue(before == "\u{202F}" || before == "\u{00A0}", "no non-breaking space before \(mark) in \(s)")
                            }
                            from = r.upperBound
                        }
                    }
                }
            }
        }
    }
}
