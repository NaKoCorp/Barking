import XCTest
@testable import Barking
@testable import BarkingKit

@MainActor
final class ConversationModelTests: XCTestCase {
    func make(_ d: FakeDevice) -> ConversationModel {
        d.contactList = [Contact(fingerprint: "b", alias: "bob", displayName: "Bob", verified: false)]
        return ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
    }

    func testDoubleSendSendsOnce() async {
        let d = FakeDevice()
        d.syncDelay = 0.1
        let m = make(d)
        m.draft = "hello"
        async let a: Void = m.send()
        async let b: Void = m.send()
        _ = await (a, b)
        XCTAssertEqual(d.sent.count, 1)
        XCTAssertEqual(m.draft, "")
    }

    func testCounterAndLimit() {
        let m = make(FakeDevice())
        m.draft = String(repeating: "a", count: 3499)
        XCTAssertFalse(m.showsCounter)
        m.draft = String(repeating: "a", count: 3500)
        XCTAssertTrue(m.showsCounter)
        m.draft = String(repeating: "a", count: 4001)
        XCTAssertFalse(m.canSend)
        m.draft = String(repeating: "😀", count: 1001) // 4 bytes each: 4004 bytes
        XCTAssertEqual(m.byteCount, 4004)
        XCTAssertFalse(m.canSend)
        m.draft = "   "
        XCTAssertFalse(m.canSend)
    }

    private func sent(_ id: Int64, at: UInt64 = 1, _ state: DeliveryState?) -> Message {
        Message(id: id, outgoing: true, body: "m\(id)", at: at, delivery: state.map { .state($0) })
    }

    private func update(_ id: Int64, _ state: DeliveryState?, removed: Bool = false) -> DeliveryUpdate {
        DeliveryUpdate(messageId: id, delivery: state.map { .state($0) }, removed: removed)
    }

    /// Spec Lot M §6.3: a state change patches the rows it names; only
    /// `.messages` of this contact reloads the conversation.
    func testDeliveryChangePatchesWithoutReload() async {
        let d = FakeDevice()
        d.messageList = ["b": [sent(7, .pending), sent(8, .pending), sent(9, .onNetwork),
                               Message(id: 10, outgoing: false, body: "x", at: 2)]]
        let m = make(d)
        await m.onAppear()
        let calls = d.messagesCalls
        d.deliveryUpdates[7] = update(7, .received)
        d.deliveryUpdates[8] = update(8, nil, removed: true)
        d.deliveryUpdates[9] = update(9, nil)
        await m.handle(.delivery(contact: "b", ids: [7, 8, 9]))
        XCTAssertEqual(d.messagesCalls, calls, "a state change does not reload")
        XCTAssertEqual(m.items.map(\.id), [7, 9, 10], "a removed row goes")
        XCTAssertEqual(m.items[0].state, .received)
        XCTAssertNil(m.items[1].delivery, "no summary: time only")
        XCTAssertNil(m.items[1].state)
        // Nothing for this conversation, or not about its messages: no reload.
        await m.handle(.delivery(contact: "z", ids: [7]))
        await m.handle(.network)
        await m.handle(.contacts)
        await m.handle(.messages(contact: "z"))
        XCTAssertEqual(d.messagesCalls, calls)
        XCTAssertEqual(m.items[0].state, .received)
        // A new message or a deletion here reloads whole.
        await m.handle(.messages(contact: "b"))
        XCTAssertEqual(d.messagesCalls, calls + 1)
    }

    /// A retry is the same row, patched in place: back to pending.
    func testRetryCallsTheCoreAndKeepsThePlace() async {
        let d = FakeDevice()
        d.messageList = ["b": [sent(7, .notDelivered), Message(id: 8, outgoing: false, body: "later", at: 2)]]
        let m = make(d)
        await m.onAppear()
        let calls = d.messagesCalls
        d.deliveryUpdates[7] = update(7, .pending)
        await m.retry(7)
        XCTAssertEqual(d.retried, [7])
        XCTAssertTrue(d.sent.isEmpty, "a retry is not a new message")
        XCTAssertEqual(m.items.map(\.id), [7, 8], "same row, same place")
        XCTAssertEqual(m.items[0].state, .pending)
        XCTAssertEqual(d.messagesCalls, calls, "the row is patched, not reloaded")
        XCTAssertNil(m.notice)
    }

    /// The core says it already left: the row is refreshed, nothing is said.
    func testRetryWithNothingToRetryRefreshesTheRow() async {
        let d = FakeDevice()
        d.messageList = ["b": [sent(7, .notDelivered)]]
        let m = make(d)
        await m.onAppear()
        d.retryError = BarkingError.NothingToRetry
        d.deliveryUpdates[7] = update(7, .received)
        await m.retry(7)
        XCTAssertEqual(m.items.first?.state, .received)
        XCTAssertNil(m.notice)
    }

    /// Spec §9: no device of the contact left to seal for.
    func testRetryWithoutAReachableDeviceSaysSo() async {
        let d = FakeDevice()
        d.messageList = ["b": [sent(7, .notDelivered)]]
        let m = make(d)
        var said: [String] = []
        m.announce = { said.append($0) }
        await m.onAppear()
        d.retryError = BarkingError.NoSession
        d.deliveryUpdates[7] = update(7, .notDelivered)
        await m.retry(7)
        XCTAssertEqual(m.notice, .noReachableDevice(name: "bob"))
        XCTAssertEqual(m.items.first?.state, .notDelivered)
        // The banner is said once, without moving the focus.
        XCTAssertEqual(said, ["bob has no reachable device left. The message can’t be sent again."])
    }

    /// A retry running on one row does not drop a retry on another.
    func testRetriesOfTwoRowsBothRun() async {
        let d = FakeDevice()
        d.syncDelay = 0.1
        d.messageList = ["b": [sent(7, .notDelivered), sent(8, .notDelivered)]]
        let m = make(d)
        await m.onAppear()
        async let a: Void = m.retry(7)
        async let b: Void = m.retry(8)
        async let again: Void = m.retry(7)
        _ = await (a, b, again)
        XCTAssertEqual(d.retried.sorted(), [7, 8])
    }

    /// Spec §6.7: the bubble goes at once; the banner says what really happened.
    func testDeleteRemovesTheBubbleAndSaysWhatHappened() async {
        let d = FakeDevice()
        d.messageList = ["b": [sent(7, .pending), sent(8, .pending)]]
        let m = make(d)
        await m.onAppear()
        d.deleteResult = DeleteOutcome(deleted: 1, cancelled: 0, partlyCancelled: 0, alreadyLeft: 1,
                                       stillReceiving: ["bob"], ownCopiesKept: false, changes: [])
        let outcome = await m.delete(7)
        XCTAssertEqual(outcome?.alreadyLeft, 1)
        XCTAssertEqual(d.deleted, [[7]])
        XCTAssertEqual(m.items.map(\.id), [8])
        XCTAssertEqual(m.notice, .deleted(.alreadyLeft(name: "bob")))
        XCTAssertEqual(m.notice?.text(), "It had already left: bob will still receive it.")
        // Cancelled: nothing to say.
        d.deleteResult = DeleteOutcome(deleted: 1, cancelled: 1, partlyCancelled: 0, alreadyLeft: 0,
                                       stillReceiving: [], ownCopiesKept: false, changes: [])
        _ = await m.delete(8)
        XCTAssertTrue(m.items.isEmpty)
        XCTAssertNil(m.notice)
    }

    func testFailedDeleteKeepsTheBubble() async {
        let d = FakeDevice()
        d.messageList = ["b": [sent(7, .pending)]]
        let m = make(d)
        await m.onAppear()
        d.deliveryError = BarkingError.Storage(detail: "full")
        let outcome = await m.delete(7)
        XCTAssertNil(outcome)
        XCTAssertEqual(m.items.map(\.id), [7])
        XCTAssertEqual(m.notice, .deleteFailed)
    }

    /// Spec §6.3: two sent messages in the same minute and the same state
    /// show the line under the last only; never at accessibility sizes.
    func testBurstShowsMetaUnderTheLastOnly() {
        let at = { (s: TimeInterval) in Date(timeIntervalSince1970: 6_000 + s) }
        let delivery = { (s: DeliveryState) in Delivery.state(s) }
        let items: [ConversationModel.Item] = [
            .init(id: 1, outgoing: true, text: "a", at: at(0), delivery: delivery(.pending)),
            .init(id: 2, outgoing: true, text: "b", at: at(10), delivery: delivery(.pending)),
            .init(id: 3, outgoing: true, text: "c", at: at(20), delivery: delivery(.onNetwork)),
            .init(id: 4, outgoing: true, text: "d", at: at(70), delivery: delivery(.onNetwork)),
            .init(id: 5, outgoing: false, text: "e", at: at(71), delivery: nil),
            .init(id: 6, outgoing: false, text: "f", at: at(72), delivery: nil),
            .init(id: 7, outgoing: true, text: "g", at: at(80), delivery: delivery(.notDelivered)),
            .init(id: 8, outgoing: true, text: "h", at: at(81), delivery: delivery(.notDelivered)),
            .init(id: 9, outgoing: true, text: "i", at: at(90), delivery: nil),
            .init(id: 10, outgoing: true, text: "j", at: at(91), delivery: nil),
        ]
        let shown = ConversationModel.metaShown(items, accessibilitySize: false)
        // 1 hides under 2 (same minute and state); 3 stays (next minute
        // differs); received messages always show their time; each not
        // delivered keeps its Retry; time-only messages burst too.
        XCTAssertEqual(shown, [2, 3, 4, 5, 6, 7, 8, 10])
        XCTAssertEqual(ConversationModel.metaShown(items, accessibilitySize: true), Set(items.map(\.id)))
    }

    /// Spec §8: only Received and Not delivered, only for a bubble on
    /// screen, at most one every 3 s, grouped.
    func testAnnouncementsOnlyForVisibleReceivedOrNotDelivered() async {
        let d = FakeDevice()
        d.messageList = ["b": [sent(7, .pending), sent(8, .pending), sent(9, .pending), sent(10, .onNetwork)]]
        let m = make(d)
        var said: [String] = []
        var clock = Date(timeIntervalSince1970: 1_000)
        m.announce = { said.append($0) }
        m.now = { clock }
        await m.onAppear()
        for id: Int64 in [7, 8, 10] { m.bubbleAppeared(id) }
        m.apply([update(9, .received)])
        XCTAssertEqual(said, [], "9 is off screen")
        m.apply([update(7, .onNetwork)])
        XCTAssertEqual(said, [], "only Received and Not delivered are announced")
        m.apply([update(7, .received), update(8, .received)])
        XCTAssertEqual(said, ["2 messages received by bob."], "grouped")
        m.apply([update(7, .received)])
        XCTAssertEqual(said.count, 1, "no change, nothing said")
        clock += 1
        m.bubbleDisappeared(8)
        m.apply([update(10, .notDelivered)])
        XCTAssertEqual(said.count, 1, "within 3 s of the last one: it waits")
        clock += 1
        m.flushAnnouncements()
        XCTAssertEqual(said.count, 1)
        clock += 1
        m.flushAnnouncements()
        XCTAssertEqual(said.last, "Message not delivered. Retry is in the actions.")
        clock += 10
        m.apply([update(8, .notDelivered)])
        XCTAssertEqual(said.count, 2, "8 left the screen")
        m.bubbleAppeared(8)
        m.apply([update(8, .received)])
        XCTAssertEqual(said.last, "Message received by bob.")
        m.onDisappear()
        clock += 10
        m.apply([update(7, .notDelivered)])
        XCTAssertEqual(said.count, 3, "the conversation is closed")
    }

    /// Spec §7.4 "Choix du cas", and its texts in both languages.
    func testDeleteConfirmationCaseAndText() throws {
        func d(_ s: DeliveryState, left: UInt32, pending: UInt32, devices: UInt32 = 2) -> Delivery {
            Delivery(state: s, sealedAt: 1, depositedAt: nil, receivedAt: nil, expiredAt: nil,
                     devices: devices, devicesReceived: 0, devicesLeft: left, devicesPending: pending)
        }
        XCTAssertEqual(DeleteConfirmation(outgoing: true, delivery: d(.pending, left: 0, pending: 2)), .pending)
        XCTAssertEqual(DeleteConfirmation(outgoing: true, delivery: d(.received, left: 1, pending: 1)), .mixed(left: 1, total: 2))
        XCTAssertEqual(DeleteConfirmation(outgoing: true, delivery: d(.onNetwork, left: 2, pending: 0)), .onNetwork)
        XCTAssertEqual(DeleteConfirmation(outgoing: true, delivery: d(.received, left: 2, pending: 0)), .received)
        XCTAssertEqual(DeleteConfirmation(outgoing: true, delivery: d(.notDelivered, left: 0, pending: 0)), .notDelivered)
        XCTAssertEqual(DeleteConfirmation(outgoing: false, delivery: nil), .receivedMessage)
        XCTAssertEqual(DeleteConfirmation(outgoing: true, delivery: nil), .sentElsewhere,
                       "no receipt is known for a message sent from another device")
        let path = try XCTUnwrap(Bundle.main.path(forResource: "fr", ofType: "lproj"))
        let fr = (bundle: try XCTUnwrap(Bundle(path: path)), locale: Locale(identifier: "fr"))
        let enPath = try XCTUnwrap(Bundle.main.path(forResource: "en", ofType: "lproj"))
        let en = (bundle: try XCTUnwrap(Bundle(path: enPath)), locale: Locale(identifier: "en"))
        XCTAssertEqual(DeleteConfirmation.mixed(left: 1, total: 2).message(name: "Alice", bundle: en.bundle, locale: en.locale),
                       "It already left for 1 of Alice’s 2 devices: that one keeps it. The rest is cancelled.")
        XCTAssertEqual(DeleteConfirmation.mixed(left: 2, total: 3).message(name: "Alice", bundle: en.bundle, locale: en.locale),
                       "It already left for 2 of Alice’s 3 devices: those keep it. The rest is cancelled.")
        XCTAssertEqual(DeleteConfirmation.mixed(left: 1, total: 2).message(name: "Alice", bundle: fr.bundle, locale: fr.locale),
                       "Il est déjà parti vers 1 de ses 2 appareils\u{00A0}: Alice le garde sur celui-ci. Le reste est annulé.")
        XCTAssertEqual(DeleteConfirmation.sentElsewhere.message(name: "Alice", bundle: en.bundle, locale: en.locale),
                       "Your other devices keep their copy.")
        XCTAssertEqual(DeleteConfirmation.sentElsewhere.message(name: "Alice", bundle: fr.bundle, locale: fr.locale),
                       "Vos autres appareils gardent leur copie.")
        XCTAssertEqual(DeleteConfirmation.pending.message(name: "Alice", bundle: fr.bundle, locale: fr.locale),
                       "Il n’a pas quitté cet iPhone. Alice ne le recevra pas.")
        var a = DeliveryAnnouncements()
        a.add(received: 3, notDelivered: 0)
        XCTAssertEqual(a.take(now: .now, name: "Sam", bundle: fr.bundle, locale: fr.locale), "3 messages reçus par Sam.")
        a.add(received: 1, notDelivered: 1)
        XCTAssertNil(a.take(now: .now, name: "Sam", bundle: fr.bundle, locale: fr.locale), "3 s apart")
        XCTAssertEqual(a.take(now: .now + 3, name: "Sam", bundle: fr.bundle, locale: fr.locale),
                       "Message reçu par Sam. Message non distribué. Réessayer est dans les actions.")
    }

    /// Spec §6.5: the header opens the last sent message.
    func testHeaderOpensTheLastSentMessage() async {
        let d = FakeDevice()
        d.messageList = ["b": [sent(7, .pending), Message(id: 8, outgoing: false, body: "x", at: 2)]]
        let m = make(d)
        await m.onAppear()
        XCTAssertEqual(m.lastSentId, 7)
        d.messageList = ["b": [Message(id: 8, outgoing: false, body: "x", at: 2)]]
        await m.reload()
        XCTAssertNil(m.lastSentId)
    }

    func testOpeningMarksRead() async {
        let d = FakeDevice()
        d.messageList = ["b": [
            Message(id: 3, outgoing: false, body: "a", at: 1),
            Message(id: 5, outgoing: false, body: "b", at: 2),
            Message(id: 6, outgoing: true, body: "c", at: 3, delivery: .state(.onNetwork)),
        ]]
        let m = make(d)
        await m.onAppear()
        XCTAssertEqual(d.reads.last?.0, "b")
        XCTAssertEqual(d.reads.last?.1, 5)
    }

    func testKeyChangeBanner() async {
        let d = FakeDevice()
        d.keyChangeList = [KeyChange(contact: "b", at: 10)]
        let m = make(d)
        await m.onAppear()
        XCTAssertTrue(m.keyChanged)
    }

    /// UI review U-20: the header says the trust, read from the contact.
    func testHeaderTrust() async {
        let d = FakeDevice()
        let m = make(d)
        await m.onAppear()
        XCTAssertEqual(m.trust, .notVerified)
        d.contactList = [Contact(fingerprint: "b", alias: "bob", displayName: "Bob", verified: true)]
        await m.reload()
        XCTAssertEqual(m.trust, .verified)
    }
}
