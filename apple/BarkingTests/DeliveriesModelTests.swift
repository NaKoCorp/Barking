import XCTest
@testable import Barking
@testable import BarkingKit

/// "Deliveries" (spec Lot M §6.5): the groups, their pages, the rows moving
/// between them, "Retry all", and the header button that opens it.
@MainActor
final class DeliveriesModelTests: XCTestCase {
    private let t0: UInt64 = 1_800_000_000

    // MARK: Fixtures

    private func row(_ id: Int64, _ state: DeliveryState, at: UInt64? = nil) -> DeliveryRowInfo {
        DeliveryRowInfo(messageId: id, body: "m\(id)", at: at ?? t0 + UInt64(id), delivery: .state(state))
    }

    private func update(_ id: Int64, _ state: DeliveryState?, removed: Bool = false) -> DeliveryUpdate {
        DeliveryUpdate(messageId: id, delivery: state.map { .state($0) }, removed: removed)
    }

    /// Rows are given newest first, as the core pages them; the counts follow.
    private func seed(_ d: FakeDevice, _ rows: [DeliveryState: [DeliveryRowInfo]], contact: String = "b") {
        d.deliveryRows[contact] = rows
        d.deliveryCountsByContact[contact] = DeliveryCounts(
            pending: UInt32(rows[.pending]?.count ?? 0), onNetwork: UInt32(rows[.onNetwork]?.count ?? 0),
            received: UInt32(rows[.received]?.count ?? 0), notDelivered: UInt32(rows[.notDelivered]?.count ?? 0))
    }

    private func make(_ d: FakeDevice) -> DeliveriesModel {
        DeliveriesModel(core: CoreService(device: d, runner: DirectRunner()), contact: "b", contactName: "Bob")
    }

    private func ids(_ m: DeliveriesModel, _ state: DeliveryState) -> [Int64] {
        m.groups.first { $0.state == state }?.rows.map(\.id) ?? []
    }

    private func count(_ m: DeliveriesModel, _ state: DeliveryState) -> Int? {
        m.groups.first { $0.state == state }?.count
    }

    // MARK: Groups

    func testGroupsInOrderAndEmptyOnesHidden() async {
        let d = FakeDevice()
        seed(d, [.received: [row(1, .received)], .pending: [row(2, .pending)], .notDelivered: [row(3, .notDelivered)]])
        let m = make(d)
        XCTAssertEqual(m.phase, .loading)
        await m.load()
        XCTAssertEqual(m.phase, .loaded)
        XCTAssertEqual(m.groups.map(\.state), [.notDelivered, .pending, .received], "On the network is empty: absent")
        XCTAssertEqual(m.groups.map(\.count), [1, 1, 1])
        XCTAssertFalse(m.isEmpty)
    }

    func testNothingSentIsEmpty() async {
        let m = make(FakeDevice())
        await m.load()
        XCTAssertTrue(m.groups.isEmpty)
        XCTAssertTrue(m.isEmpty)
    }

    func testPagesOf50PerGroup() async {
        let d = FakeDevice()
        // Newest first: 120 pending rows with ids 120...1, and 2 received.
        seed(d, [.pending: (1...120).reversed().map { row(Int64($0), .pending) },
                 .received: [row(201, .received), row(200, .received)]])
        let m = make(d)
        await m.load()
        XCTAssertEqual(ids(m, .pending).count, 50)
        XCTAssertEqual(ids(m, .pending).first, 120)
        XCTAssertEqual(count(m, .pending), 120, "the title counts all of them")
        XCTAssertEqual(ids(m, .received), [201, 200])
        XCTAssertTrue(m.groups[0].hasMore)

        await m.loadMore(.pending)
        XCTAssertEqual(ids(m, .pending).count, 100)
        await m.loadMore(.pending)
        XCTAssertEqual(ids(m, .pending), (1...120).reversed().map(Int64.init))
        XCTAssertFalse(m.groups[0].hasMore)
        await m.loadMore(.pending)
        XCTAssertEqual(ids(m, .pending).count, 120, "nothing more to read")
        await m.loadMore(.received)
        XCTAssertEqual(ids(m, .received), [201, 200])
    }

    // MARK: Changes

    func testRowMovesBetweenGroupsAndCountsFollow() async {
        let d = FakeDevice()
        seed(d, [.pending: [row(5, .pending), row(3, .pending), row(1, .pending)],
                 .onNetwork: [row(4, .onNetwork), row(2, .onNetwork)]])
        let m = make(d)
        await m.load()
        let reads = d.deliveryPageCalls

        // 3 reaches the network: it joins On the network between 4 and 2.
        d.deliveryUpdates[3] = update(3, .onNetwork)
        await m.apply(.delivery(contact: "b", ids: [3]))
        XCTAssertEqual(ids(m, .pending), [5, 1])
        XCTAssertEqual(ids(m, .onNetwork), [4, 3, 2])
        XCTAssertEqual(m.groups.map(\.count), [2, 3])
        XCTAssertEqual(d.deliveryPageCalls, reads, "no page read again")

        // The last pending row goes to a group that did not exist: it appears.
        d.deliveryUpdates[5] = update(5, .notDelivered)
        d.deliveryUpdates[1] = update(1, .pending)
        await m.apply(.delivery(contact: "b", ids: [5, 1]))
        XCTAssertEqual(m.groups.map(\.state), [.notDelivered, .pending, .onNetwork])
        XCTAssertEqual(ids(m, .notDelivered), [5])
        XCTAssertEqual(m.groups.map(\.count), [1, 1, 3])

        // The only row of a group leaves: the group is hidden.
        d.deliveryUpdates[5] = update(5, nil, removed: true)
        await m.apply(.delivery(contact: "b", ids: [5]))
        XCTAssertEqual(m.groups.map(\.state), [.pending, .onNetwork])

        // The same state, new times: the row stays in place.
        var later = Delivery.state(.onNetwork)
        later = Delivery(state: .onNetwork, sealedAt: later.sealedAt, depositedAt: 99, receivedAt: nil, expiredAt: nil,
                         devices: 1, devicesReceived: 0, devicesLeft: 1, devicesPending: 0)
        d.deliveryUpdates[4] = DeliveryUpdate(messageId: 4, delivery: later, removed: false)
        await m.apply(.delivery(contact: "b", ids: [4]))
        XCTAssertEqual(ids(m, .onNetwork), [4, 3, 2])
        XCTAssertEqual(m.groups[1].rows[0].delivery.depositedAt, 99)

        // A row with no summary any more leaves, like a deleted one.
        d.deliveryUpdates[2] = update(2, nil)
        await m.apply(.delivery(contact: "b", ids: [2]))
        XCTAssertEqual(ids(m, .onNetwork), [4, 3])
        XCTAssertEqual(count(m, .onNetwork), 2)
    }

    /// A row going past the rows loaded of a partly loaded group only adds to
    /// its count; one landing within them takes its place.
    func testRowIntoAPartlyLoadedGroupOnlyCounts() async {
        let d = FakeDevice()
        // 60 received rows, newest first (ids 160...101); the pending one is the newest of all.
        let received = (101...160).reversed().map { row(Int64($0), .received) }
        seed(d, [.received: received, .pending: [row(500, .pending), row(100, .pending), row(1, .pending)]])
        let m = make(d)
        await m.load()
        XCTAssertEqual(ids(m, .received).count, 50)
        let calls = d.deliveryPageCalls

        // 1 (oldest) becomes received: past the last row loaded.
        d.deliveryUpdates[1] = update(1, .received)
        await m.apply(.delivery(contact: "b", ids: [1]))
        XCTAssertEqual(ids(m, .received).count, 50, "its page is not loaded yet")
        XCTAssertEqual(count(m, .received), 61)
        XCTAssertEqual(d.deliveryPageCalls, calls)

        // 500 (newest) becomes received: before the rows loaded, it shows.
        d.deliveryUpdates[500] = update(500, .received)
        await m.apply(.delivery(contact: "b", ids: [500]))
        XCTAssertEqual(ids(m, .received).first, 500)
        XCTAssertEqual(ids(m, .received).count, 51)
        XCTAssertEqual(count(m, .received), 62)
        XCTAssertEqual(ids(m, .pending), [100])
    }

    /// A row never loaded (it lay on a page not read): its new group reads
    /// again, and the counts with it.
    func testUnknownRowReadsItsGroupAndTheCounts() async {
        let d = FakeDevice()
        seed(d, [.pending: [row(3, .pending)], .received: [row(1, .received)]])
        let m = make(d)
        await m.load()

        // The core now has 2 as received too (it was never on screen).
        seed(d, [.pending: [row(3, .pending)], .received: [row(2, .received), row(1, .received)]])
        d.deliveryUpdates[2] = update(2, .received)
        await m.apply(.delivery(contact: "b", ids: [2]))
        XCTAssertEqual(ids(m, .received), [2, 1])
        XCTAssertEqual(count(m, .received), 2)
        XCTAssertEqual(ids(m, .pending), [3])
    }

    /// `.messages` of this contact reads everything again; other contacts' changes do nothing.
    func testMessagesChangeReadsAgainAndOthersAreIgnored() async {
        let d = FakeDevice()
        seed(d, [.pending: [row(1, .pending)]])
        let m = make(d)
        await m.load()
        seed(d, [.pending: [row(2, .pending), row(1, .pending)], .onNetwork: [row(0, .onNetwork)]])
        await m.apply(.messages(contact: "c"))
        await m.apply(.delivery(contact: "c", ids: [1]))
        XCTAssertEqual(ids(m, .pending), [1])
        await m.apply(.messages(contact: "b"))
        XCTAssertEqual(ids(m, .pending), [2, 1])
        XCTAssertEqual(ids(m, .onNetwork), [0])
    }

    func testReadFailureAndRetry() async {
        let d = FakeDevice()
        seed(d, [.pending: [row(1, .pending)]])
        d.deliveryError = BarkingError.Storage(detail: "boom")
        let m = make(d)
        await m.load()
        XCTAssertEqual(m.phase, .failed)
        XCTAssertFalse(m.isEmpty, "an error is not the empty state")
        d.deliveryError = nil
        await m.load()
        XCTAssertEqual(m.phase, .loaded)
        XCTAssertEqual(ids(m, .pending), [1])
        // A later failed refresh keeps what is shown.
        d.deliveryError = BarkingError.Storage(detail: "boom")
        await m.apply(.messages(contact: "b"))
        XCTAssertEqual(m.phase, .loaded)
        XCTAssertEqual(ids(m, .pending), [1])
    }

    // MARK: Retry all

    func testRetryAllCallsTheCore() async {
        let d = FakeDevice()
        seed(d, [.notDelivered: [row(2, .notDelivered), row(1, .notDelivered)]])
        d.retryAllCount = 2
        let m = make(d)
        await m.load()
        // The core sends them again: they are pending now.
        seed(d, [.pending: [row(2, .pending), row(1, .pending)]])
        await m.retryAll()
        XCTAssertEqual(d.retriedAll, ["b"])
        XCTAssertEqual(m.groups.map(\.state), [.pending])
        XCTAssertNil(m.notice)
    }

    func testRetryAllWithoutADeviceWarnsAndNothingToRetryIsQuiet() async {
        let d = FakeDevice()
        seed(d, [.notDelivered: [row(1, .notDelivered)]])
        let m = make(d)
        var said: [String] = []
        m.announce = { said.append($0) }
        await m.load()
        d.retryAllError = BarkingError.NoSession
        await m.retryAll()
        XCTAssertEqual(m.notice, .noReachableDevice(name: "Bob"))
        XCTAssertEqual(said, ["Bob has no reachable device left. The message can’t be sent again."])
        d.retryAllError = BarkingError.NothingToRetry
        await m.retryAll()
        XCTAssertNil(m.notice, "a new attempt clears the warning")
    }

    // MARK: Header button

    /// §6.5: the header button is disabled until a message has been sent.
    func testHeaderButtonDisabledWithoutSentMessage() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "b", alias: "bob", displayName: "Bob", verified: false)]
        d.messageList = ["b": [Message(id: 8, outgoing: false, body: "x", at: 2)]]
        let conversation = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        await conversation.onAppear()
        XCTAssertFalse(conversation.hasSentMessage)
        d.messageList = ["b": [Message(id: 7, outgoing: true, body: "y", at: 1, delivery: .state(.pending)),
                               Message(id: 8, outgoing: false, body: "x", at: 2)]]
        await conversation.reload()
        XCTAssertTrue(conversation.hasSentMessage)
        // Sent from another of my devices: no delivery to list.
        d.messageList = ["b": [Message(id: 7, outgoing: true, body: "y", at: 1)]]
        await conversation.reload()
        XCTAssertFalse(conversation.hasSentMessage)
    }

    // MARK: Time

    /// §6.5: "14:02" today, "lun. 14:02" this week, "3 nov." before.
    func testTimeText() throws {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let now = Date(timeIntervalSince1970: 1_794_060_127 + 86_400 * 3) // a Tuesday, mid-afternoon
        let today = now.addingTimeInterval(-3_600)
        let week = now.addingTimeInterval(-2 * 86_400)
        let old = now.addingTimeInterval(-20 * 86_400)
        for code in ["en_GB", "fr"] {
            let locale = Locale(identifier: code)
            let got = [today, week, old].map { DeliveriesModel.timeText($0, now: now, calendar: cal, locale: locale) }
            XCTAssertTrue(got[0].contains(":"), "\(code): \(got[0])")
            XCTAssertTrue(got[1].contains(":") && got[1].count > got[0].count, "\(code): \(got[1])")
            XCTAssertFalse(got[2].contains(":"), "\(code): \(got[2])")
        }
        let fr = Locale(identifier: "fr")
        XCTAssertTrue(DeliveriesModel.timeText(week, now: now, calendar: cal, locale: fr).hasPrefix("lun.")
                      || DeliveriesModel.timeText(week, now: now, calendar: cal, locale: fr).hasPrefix("dim."))
        XCTAssertTrue(DeliveriesModel.timeText(old, now: now, calendar: cal, locale: fr).hasSuffix("."), "nov.")
    }
}
