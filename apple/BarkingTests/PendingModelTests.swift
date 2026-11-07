import XCTest
@testable import Barking
@testable import BarkingKit

/// "Pending" (spec Lot M §6.6, §7.3, §7.4): what has not left this iPhone,
/// the selection, "Cancel all", and the Network line that opens it.
@MainActor
final class PendingModelTests: XCTestCase {
    private let t0: UInt64 = 1_800_000_000
    private var now: Date { Date(timeIntervalSince1970: TimeInterval(t0)) }

    // MARK: Fixtures

    private func msg(_ id: Int64, to name: String = "Alice", contact: String = "a", body: String = "hello",
                     expiresIn: UInt64 = 80_000, sealedAgo: UInt64 = 3_600, packets: UInt32 = 1,
                     devices: UInt32 = 1, left: UInt32 = 0, tried: UInt32 = 0) -> PendingMessage {
        PendingMessage(messageId: id, contact: contact, name: name, body: body, sealedAt: t0 - sealedAgo,
                       expiresAt: t0 + expiresIn, packets: packets, devices: devices, devicesLeft: left, devicesTried: tried)
    }

    private func info(_ messages: [PendingMessage], sync: [PendingSync] = []) -> PendingPackets {
        PendingPackets(messages: messages, sync: sync,
                       packets: messages.reduce(0) { $0 + $1.packets } + sync.reduce(0) { $0 + $1.packets })
    }

    private func make(_ d: FakeDevice) -> PendingModel {
        let m = PendingModel(core: CoreService(device: d, runner: DirectRunner()))
        m.now = { [now] in now }
        m.announce = { _ in }
        return m
    }

    private func lang(_ code: String) throws -> (bundle: Bundle, locale: Locale) {
        let path = try XCTUnwrap(Bundle.main.path(forResource: code, ofType: "lproj"))
        return (try XCTUnwrap(Bundle(path: path)), Locale(identifier: code))
    }

    /// Spaces of every kind (the French ones are non-breaking) as plain ones.
    private func flat(_ s: String) -> String {
        s.replacingOccurrences(of: "\u{00A0}", with: " ").replacingOccurrences(of: "\u{202F}", with: " ")
    }

    // MARK: Reading

    func testSortedByNearestExpiry() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, expiresIn: 9_000), msg(2, expiresIn: 4_000), msg(3, expiresIn: 9_000), msg(4, expiresIn: 70_000)])
        let m = make(d)
        XCTAssertEqual(m.phase, .loading)
        await m.load()
        XCTAssertEqual(m.phase, .loaded)
        XCTAssertEqual(m.messages.map(\.id), [2, 1, 3, 4], "nearest expiry first, the id breaks a tie")
    }

    func testWarnUnderTwoHours() throws {
        let fr = try lang("fr"), en = try lang("en")
        func meta(_ expiresIn: UInt64, _ l: (bundle: Bundle, locale: Locale)) -> PendingModel.Meta {
            let row = PendingModel.Row(msg(1, expiresIn: expiresIn, sealedAgo: 7_200))
            return PendingModel.meta(for: row, now: now, bundle: l.bundle, locale: l.locale)
        }
        let soon = meta(3_600, fr)
        XCTAssertTrue(soon.warn, "expires in 1 h: the warning colour and the triangle")
        XCTAssertEqual(flat(soon.expires), "expire dans 1 h")
        XCTAssertEqual(flat(soon.ago), "il y a 2 h")
        XCTAssertTrue(meta(7_199, en).warn)
        XCTAssertFalse(meta(7_200, en).warn, "two hours is not under two hours")
        XCTAssertFalse(meta(79_200, en).warn)
        XCTAssertEqual(flat(meta(79_200, en).expires), "expires in 22 h")
        XCTAssertEqual(flat(meta(79_200, en).ago), "2 h ago")
        XCTAssertEqual(flat(meta(90, en).expires), "expires in 2 min", "rounded up to the minute")
        XCTAssertTrue(meta(90, en).warn)
    }

    func testMetaSaysWhichDevicesTheMessageAlreadyLeftFor() throws {
        let fr = try lang("fr"), en = try lang("en")
        let row = PendingModel.Row(msg(1, devices: 2, left: 1))
        XCTAssertEqual(PendingModel.meta(for: row, now: now, bundle: en.bundle, locale: en.locale).left,
                       "already left for 1 of 2 devices")
        XCTAssertEqual(PendingModel.meta(for: row, now: now, bundle: fr.bundle, locale: fr.locale).left,
                       "déjà parti vers 1 de ses 2 appareils")
        let none = PendingModel.Row(msg(2, devices: 2, left: 0))
        XCTAssertNil(PendingModel.meta(for: none, now: now).left)
    }

    func testPacketsCountAcrossBothSectionsAndMatchTheNetworkLine() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, packets: 2), msg(2, packets: 1)],
                             sync: [PendingSync(kind: .ownCopy, packets: 3, names: []), PendingSync(kind: .ack, packets: 1, names: ["Sam"])])
        d.pendingCountValue = 7
        let m = make(d)
        await m.load()
        XCTAssertEqual(m.messagePackets, 3)
        XCTAssertEqual(m.syncPackets, 4)
        XCTAssertEqual(m.total, 7)
        let network = NetworkModel(core: CoreService(device: d, runner: DirectRunner()))
        await network.load()
        XCTAssertEqual(network.pending, m.total, "the Network count is the sum of the two sections (§14.4)")
    }

    func testSyncSectionIsReadOnlyOneRowPerKind() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1)], sync: [
            PendingSync(kind: .cardUpdate, packets: 1, names: ["Alice"]),
            PendingSync(kind: .ownCopy, packets: 2, names: []),
            PendingSync(kind: .ack, packets: 2, names: ["Alice", "Sam"]),
            PendingSync(kind: .deviceSync, packets: 1, names: []),
            PendingSync(kind: .deviceSync, packets: 0, names: []),
        ])
        let m = make(d)
        await m.load()
        XCTAssertEqual(m.sync.map(\.kind), [.ack, .ownCopy, .deviceSync, .cardUpdate], "one row per kind, a fixed order, none empty")
        m.selecting = true
        m.selectAll()
        XCTAssertEqual(m.selection, [1], "only messages are selectable")
        m.toggle(99)
        XCTAssertEqual(m.selection, [1], "an unknown row cannot be selected")

        let en = try lang("en"), fr = try lang("fr")
        XCTAssertEqual(flat(PendingModel.title(of: m.sync[0], bundle: en.bundle, locale: en.locale)), "Receipts for Alice and Sam · 2")
        XCTAssertEqual(flat(PendingModel.title(of: m.sync[0], bundle: fr.bundle, locale: fr.locale)), "Accusés de réception pour Alice et Sam · 2")
        XCTAssertEqual(PendingModel.title(of: m.sync[1], bundle: en.bundle, locale: en.locale),
                       "Copies of your messages for your other devices · 2")
        XCTAssertEqual(PendingModel.title(of: m.sync[2], bundle: en.bundle, locale: en.locale), "Updates for your other devices · 1")
        XCTAssertEqual(PendingModel.title(of: m.sync[3], bundle: en.bundle, locale: en.locale), "Your card, for your contacts · 1")
        let unknown = PendingModel.SyncRow(PendingSync(kind: .ack, packets: 1, names: []))
        XCTAssertEqual(PendingModel.title(of: unknown, bundle: en.bundle, locale: en.locale), "Receipts · 1",
                       "an acknowledgement of unknown contact names nobody")
    }

    func testEmptyAndSyncOnlyStates() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        XCTAssertTrue(m.isEmpty)
        XCTAssertFalse(m.canSelect, "no Select when nothing can be selected")
        XCTAssertFalse(m.showsCancelAll)
        XCTAssertFalse(m.syncOnly)

        d.pendingInfo = info([], sync: [PendingSync(kind: .ownCopy, packets: 1, names: [])])
        await m.load()
        XCTAssertFalse(m.isEmpty)
        XCTAssertTrue(m.syncOnly, "\"None of your messages are waiting.\"")
        XCTAssertFalse(m.canSelect)
        XCTAssertFalse(m.showsCancelAll)

        d.pendingInfo = info([msg(1)])
        await m.load()
        XCTAssertFalse(m.syncOnly)
        XCTAssertTrue(m.canSelect)
        XCTAssertTrue(m.showsCancelAll)
    }

    func testCancelAllHiddenWhileSelecting() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1), msg(2)])
        let m = make(d)
        await m.load()
        XCTAssertTrue(m.showsCancelAll)
        m.selecting = true
        XCTAssertFalse(m.showsCancelAll)
        m.selecting = false
        XCTAssertTrue(m.showsCancelAll)
    }

    func testLeavingSelectionClearsIt() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1), msg(2)])
        let m = make(d)
        await m.load()
        m.selecting = true
        m.toggle(1)
        m.toggle(2)
        XCTAssertEqual(m.selection, [1, 2])
        m.toggle(2)
        XCTAssertEqual(m.selection, [1])
        m.selecting = false
        XCTAssertTrue(m.selection.isEmpty)
        m.toggle(1)
        XCTAssertTrue(m.selection.isEmpty, "nothing is selected outside the selection mode")
    }

    func testSelectedRowThatLeavesIsDeselected() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1), msg(2), msg(3)])
        let m = make(d)
        await m.load()
        m.selecting = true
        m.selectAll()
        XCTAssertEqual(m.selectionCount, 3)
        // 2 was deposited during a sync.
        d.pendingInfo = info([msg(1), msg(3)])
        await m.apply(.network)
        XCTAssertEqual(m.messages.map(\.id), [1, 3])
        XCTAssertEqual(m.selection, [1, 3])
        XCTAssertEqual(m.selectionCount, 2, "the number follows")
        XCTAssertTrue(m.selecting)
    }

    func testTheLastRowLeavingEndsTheSelection() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1)])
        let m = make(d)
        await m.load()
        m.selecting = true
        m.selectAll()
        d.pendingInfo = info([], sync: [])
        await m.apply(.delivery(contact: "a", ids: [1]))
        XCTAssertTrue(m.isEmpty)
        XCTAssertFalse(m.selecting, "nothing left to select")
    }

    func testEveryChangeThatCanAlterTheQueueReadsItAgain() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1)])
        let m = make(d)
        await m.load()
        let changes: [CoreChange] = [.network, .messages(contact: "a"), .delivery(contact: "a", ids: [1]), .contacts, .devices]
        for (i, change) in changes.enumerated() {
            d.pendingInfo = info(Array((0...i).map { msg(Int64($0 + 1)) }))
            await m.apply(change)
            XCTAssertEqual(m.messages.count, i + 1, "\(change)")
        }
        d.pendingInfo = info([])
        await m.apply(.identity)
        XCTAssertEqual(m.messages.count, 5, "the identity does not touch the queue")
    }

    func testReadFailureKeepsWhatIsShownAndSaysSo() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1)])
        let m = make(d)
        d.deliveryError = BarkingError.NoSession
        await m.load()
        XCTAssertEqual(m.phase, .failed)
        d.deliveryError = nil
        await m.load()
        XCTAssertEqual(m.phase, .loaded)
        d.deliveryError = BarkingError.NoSession
        await m.load()
        XCTAssertEqual(m.phase, .loaded, "a refresh that fails keeps the rows")
        XCTAssertTrue(m.readFailed)
        XCTAssertEqual(m.messages.map(\.id), [1])
    }

    // MARK: Deleting

    func testDeleteSelectedAsksTheCoreAndTellsWhatAlreadyLeft() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1), msg(2), msg(3)])
        d.deleteResult = DeleteOutcome(deleted: 2, cancelled: 1, partlyCancelled: 0, alreadyLeft: 1, stillReceiving: ["Sam"],
                                       ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0, changes: [])
        let m = make(d)
        await m.load()
        m.selecting = true
        m.toggle(1)
        m.toggle(3)
        d.pendingInfo = info([msg(2)])
        await m.deleteSelected()
        XCTAssertEqual(d.deleted, [[1, 3]])
        XCTAssertEqual(m.notice, .deleted(.several(count: 1, names: ["Sam"])))
        XCTAssertTrue(m.selection.isEmpty)
        XCTAssertFalse(m.selecting)
        XCTAssertEqual(m.messages.map(\.id), [2], "the list reads again")
        XCTAssertTrue(m.deleting.isEmpty)
    }

    func testDeleteSelectedThatCancelledEverythingSaysNothing() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1), msg(2)])
        d.deleteResult = DeleteOutcome(deleted: 2, cancelled: 2, partlyCancelled: 0, alreadyLeft: 0, stillReceiving: [],
                                       ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0, changes: [])
        let m = make(d)
        await m.load()
        m.selecting = true
        m.selectAll()
        await m.deleteSelected()
        XCTAssertNil(m.notice)
    }

    func testDeleteFailureKeepsTheSelectionAndSaysNothingChanged() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1), msg(2)])
        let m = make(d)
        await m.load()
        m.selecting = true
        m.selectAll()
        d.deliveryError = BarkingError.NoSession
        await m.deleteSelected()
        XCTAssertEqual(m.notice, .deleteFailed)
        XCTAssertEqual(m.selection, [1, 2])
        XCTAssertTrue(m.selecting)
        XCTAssertEqual(m.messages.count, 2)
        XCTAssertTrue(m.deleting.isEmpty)
    }

    func testCancelAllAsksTheCoreOnceAndTellsWhatAlreadyLeft() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1), msg(2)])
        d.deleteResult = DeleteOutcome(deleted: 2, cancelled: 0, partlyCancelled: 1, alreadyLeft: 1, stillReceiving: ["Alice", "Sam"],
                                       ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0, changes: [])
        let m = make(d)
        await m.load()
        d.pendingInfo = info([])
        await m.cancelAll()
        XCTAssertEqual(d.cancelAllCalls, 1)
        XCTAssertEqual(d.deleted, [], "no per message deletion")
        XCTAssertEqual(m.notice, .deleted(.several(count: 2, names: ["Alice", "Sam"])))
        XCTAssertTrue(m.isEmpty)
    }

    func testSingleDeletionConfirmsFromTheCoreDeliveryAndTellsWhatLeft() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, devices: 2)])
        let pending = Delivery(state: .pending, sealedAt: t0, depositedAt: nil, receivedAt: nil, expiredAt: nil,
                               devices: 2, devicesReceived: 0, devicesLeft: 0, devicesPending: 2)
        d.messageDeliveries[1] = MessageDelivery(messageId: 1, delivery: pending, devices: [], relays: [],
                                                 ownCopies: OwnCopies(total: 0, left: 0, waiting: 0))
        d.deleteResult = DeleteOutcome(deleted: 1, cancelled: 0, partlyCancelled: 0, alreadyLeft: 1, stillReceiving: ["Alice"],
                                       ownCopiesKept: false, devicesLeft: 0, devicesTotal: 0, changes: [])
        let m = make(d)
        await m.load()
        let maybe = await m.askDelete(1)
        let ask = try XCTUnwrap(maybe)
        XCTAssertEqual(ask.confirmation, .pending)
        XCTAssertEqual(ask.message, "It hasn’t left this iPhone. Alice won’t receive it.")
        await m.delete(1, shown: ask.shown)
        XCTAssertEqual(d.deleted, [[1]])
        XCTAssertEqual(m.notice, .deleted(.alreadyLeft(name: "Alice")), "the deposit crossed the cancellation: the banner corrects")
    }

    func testSingleDeletionOfAPartlyLeftMessageSaysMixedAndKeepsCopies() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, devices: 2, left: 1)])
        let mixed = Delivery(state: .onNetwork, sealedAt: t0, depositedAt: t0, receivedAt: nil, expiredAt: nil,
                             devices: 2, devicesReceived: 0, devicesLeft: 1, devicesPending: 1)
        d.messageDeliveries[1] = MessageDelivery(messageId: 1, delivery: mixed, devices: [], relays: [],
                                                 ownCopies: OwnCopies(total: 1, left: 1, waiting: 0))
        let m = make(d)
        await m.load()
        let maybe = await m.askDelete(1)
        let ask = try XCTUnwrap(maybe)
        XCTAssertEqual(ask.confirmation, .mixed(left: 1, total: 2))
        XCTAssertTrue(ask.message.hasSuffix("\nYour other devices keep their copy."))
    }

    func testSingleDeletionOfAMessageThatLeftTheListAsksNothing() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1)])
        let m = make(d)
        await m.load()
        // No delivery any more: deleted elsewhere (§9).
        let ask = await m.askDelete(1)
        XCTAssertNil(ask)
    }

    // MARK: Confirmations (§7.4)

    func testSelectionConfirmationSaysWhatIsCancelledAndWhatStillArrives() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, to: "Sam", contact: "s", devices: 2, left: 1), msg(2), msg(3, to: "Bob", contact: "b")])
        let m = make(d)
        await m.load()
        m.selecting = true
        m.selectAll()
        let en = try lang("en"), fr = try lang("fr")
        let e = m.selectionConfirmation(bundle: en.bundle, locale: en.locale)
        XCTAssertEqual(e.title, "Delete 3 messages?")
        XCTAssertEqual(e.message, "2 haven’t left and will be cancelled. 1 is already on the network: Sam will still receive it.")
        XCTAssertEqual(e.button, "Delete 3")
        let f = m.selectionConfirmation(bundle: fr.bundle, locale: fr.locale)
        XCTAssertEqual(f.title, "Supprimer 3 messages\u{00A0}?")
        XCTAssertEqual(f.message, "2 ne sont pas partis et seront annulés. 1 est déjà sur le réseau\u{00A0}: Sam le recevra quand même.")
        XCTAssertEqual(f.button, "Supprimer 3")

        // Only messages that left nowhere.
        m.toggle(1)
        let only = m.selectionConfirmation(bundle: en.bundle, locale: en.locale)
        XCTAssertEqual(only.title, "Delete 2 messages?")
        XCTAssertEqual(only.message, "2 haven’t left and will be cancelled.")
        m.toggle(3)
        let one = m.selectionConfirmation(bundle: en.bundle, locale: en.locale)
        XCTAssertEqual(one.title, "Delete 1 message?")
        XCTAssertEqual(one.message, "1 hasn’t left and will be cancelled.")
    }

    func testCancelAllConfirmationNamesTheRecipients() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, to: "Alice", contact: "a"), msg(2, to: "Sam", contact: "s"),
                              msg(3, to: "Bob", contact: "b"), msg(4, to: "Alice", contact: "a")])
        let m = make(d)
        await m.load()
        let en = try lang("en"), fr = try lang("fr")
        let e = m.cancelAllConfirmation(bundle: en.bundle, locale: en.locale)
        XCTAssertEqual(e.title, "Cancel 4 messages?")
        XCTAssertEqual(e.message, "They haven’t left this iPhone. Alice, Sam and 1 other won’t receive them.")
        XCTAssertEqual(e.button, "Delete and cancel")
        let f = m.cancelAllConfirmation(bundle: fr.bundle, locale: fr.locale)
        XCTAssertEqual(f.title, "Annuler 4 messages\u{00A0}?")
        XCTAssertEqual(f.message, "Ils n’ont pas quitté cet iPhone. Alice, Sam et 1 autre personne ne les recevront pas.")
        XCTAssertEqual(f.button, "Supprimer et annuler")
    }

    func testCancelAllConfirmationAgreesForOneMessageAndTwoNames() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, to: "Alice", contact: "a")])
        let m = make(d)
        await m.load()
        let en = try lang("en"), fr = try lang("fr")
        XCTAssertEqual(m.cancelAllConfirmation(bundle: en.bundle, locale: en.locale).message,
                       "It hasn’t left this iPhone. Alice won’t receive it.")
        XCTAssertEqual(m.cancelAllConfirmation(bundle: fr.bundle, locale: fr.locale).message,
                       "Il n’a pas quitté cet iPhone. Alice ne le recevra pas.")
        d.pendingInfo = info([msg(1, to: "Alice", contact: "a"), msg(2, to: "Sam", contact: "s")])
        await m.load()
        XCTAssertEqual(m.cancelAllConfirmation(bundle: fr.bundle, locale: fr.locale).message,
                       "Ils n’ont pas quitté cet iPhone. Alice et Sam ne les recevront pas.")
    }

    /// §14.1: a message that already left for one device is received by that
    /// one, whatever "Cancel all" cancels: the dialog never says otherwise.
    func testCancelAllNeverSaysACommittedMessageWillNotBeReceived() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, to: "Alice", contact: "a"), msg(2, to: "Sam", contact: "s", devices: 2, left: 1)])
        let m = make(d)
        await m.load()
        let en = try lang("en"), fr = try lang("fr")
        let e = m.cancelAllConfirmation(bundle: en.bundle, locale: en.locale)
        XCTAssertFalse(e.message.contains("won’t receive"))
        XCTAssertEqual(e.message, "1 hasn’t left and will be cancelled. 1 is already on the network: Sam will still receive it.")
        let f = m.cancelAllConfirmation(bundle: fr.bundle, locale: fr.locale)
        XCTAssertFalse(f.message.contains("ne le recevra pas") || f.message.contains("ne les recevront pas"))
    }

    // MARK: A tried deposit may have left (§14.1)

    /// A deposit request was sent and its answer lost: a node may have the
    /// packet, so no text says its contact will not receive the message.
    func testTriedOnlyMessageIsNeverCancelledInTheTexts() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, to: "Alice", contact: "a", tried: 1), msg(2, to: "Sam", contact: "s")])
        let m = make(d)
        await m.load()
        let en = try lang("en"), fr = try lang("fr")
        let all = m.cancelAllConfirmation(bundle: en.bundle, locale: en.locale)
        XCTAssertEqual(all.message, "1 hasn’t left and will be cancelled. 1 is already on the network: Alice will still receive it.")
        XCTAssertFalse(m.cancelAllConfirmation(bundle: fr.bundle, locale: fr.locale).message.contains("ne le recevra pas"))
        m.selecting = true
        m.toggle(1)
        let only = m.selectionConfirmation(bundle: en.bundle, locale: en.locale)
        XCTAssertEqual(only.message, "1 is already on the network: Alice will still receive it.")
        m.toggle(2)
        XCTAssertEqual(m.selectionConfirmation(bundle: en.bundle, locale: en.locale).message, all.message)
    }

    func testSingleDeletionOfATriedMessageSaysOnTheNetwork() async throws {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1, tried: 1), msg(2, devices: 2, tried: 1)])
        let tried = Delivery(state: .pending, sealedAt: t0, depositedAt: nil, receivedAt: nil, expiredAt: nil, devices: 1,
                             devicesReceived: 0, devicesLeft: 0, devicesTried: 1, devicesPending: 1)
        let mixed = Delivery(state: .pending, sealedAt: t0, depositedAt: nil, receivedAt: nil, expiredAt: nil, devices: 2,
                             devicesReceived: 0, devicesLeft: 0, devicesTried: 1, devicesPending: 2)
        let none = OwnCopies(total: 0, left: 0, waiting: 0)
        d.messageDeliveries[1] = MessageDelivery(messageId: 1, delivery: tried, devices: [], relays: [], ownCopies: none)
        d.messageDeliveries[2] = MessageDelivery(messageId: 2, delivery: mixed, devices: [], relays: [], ownCopies: none)
        let m = make(d)
        await m.load()
        let one = await m.askDelete(1)
        XCTAssertEqual(one?.confirmation, .onNetwork)
        XCTAssertEqual(one?.message, "It’s already on the network: Alice will still receive it.")
        let two = await m.askDelete(2)
        XCTAssertEqual(two?.confirmation, .mixed(left: 1, total: 2))
        // Unreadable delivery: the row's own numbers say the same.
        d.messageDeliveries = [:]
        d.deliveryError = BarkingError.NoSession
        let fallback = await m.askDelete(1)
        XCTAssertEqual(fallback?.confirmation, .onNetwork)
    }

    // MARK: Network line (§7.3)

    func testNetworkLineSaysNothingPendingAtZero() throws {
        let en = try lang("en"), fr = try lang("fr")
        XCTAssertEqual(NetworkModel.pendingLine(0, bundle: en.bundle, locale: en.locale), "Nothing pending")
        XCTAssertEqual(NetworkModel.pendingLine(0, bundle: fr.bundle, locale: fr.locale), "Rien en attente")
        XCTAssertEqual(NetworkModel.pendingLine(1, bundle: en.bundle, locale: en.locale), "1 packet pending")
        XCTAssertEqual(NetworkModel.pendingLine(3, bundle: en.bundle, locale: en.locale), "3 packets pending")
        XCTAssertEqual(NetworkModel.pendingLine(3, bundle: fr.bundle, locale: fr.locale), "3 paquets en attente")
    }

    // MARK: Names (§7)

    func testRecipientNamesListFormatter() throws {
        let en = try lang("en"), fr = try lang("fr")
        XCTAssertEqual(DeleteBanner.names(["Alice"], bundle: en.bundle, locale: en.locale), "Alice")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam"], bundle: en.bundle, locale: en.locale), "Alice and Sam")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam", "Bob"], bundle: en.bundle, locale: en.locale), "Alice, Sam and 1 other")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam", "Bob"], bundle: fr.bundle, locale: fr.locale), "Alice, Sam et 1 autre personne")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam", "Bob", "Eve"], bundle: fr.bundle, locale: fr.locale), "Alice, Sam et 2 autres personnes")
        XCTAssertEqual(DeleteBanner.names(["Alice", "Sam", "Bob", "Eve"], bundle: en.bundle, locale: en.locale), "Alice, Sam and 2 others")
    }

    // MARK: Offline

    func testUnreachableNetworkIsSaidAtTheTop() async {
        let d = FakeDevice()
        d.pendingInfo = info([msg(1)])
        let core = CoreService(device: d, runner: DirectRunner())
        let m = PendingModel(core: core)
        await m.load()
        XCTAssertFalse(m.unreachable, "no sync yet: nothing to say")

        d.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: false, error: nil)
        _ = await core.sync(reason: .pull)
        await m.apply(.network)
        XCTAssertTrue(m.unreachable)

        d.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: true, error: nil)
        _ = await core.sync(reason: .pull)
        await m.apply(.network)
        XCTAssertFalse(m.unreachable)
    }
}
