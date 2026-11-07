import XCTest
@testable import Barking
@testable import BarkingKit

/// The message sheet (spec Lot M §6.4, §7.2, §7.4): its timeline, the
/// contact's devices, my copies, and what deleting it says.
@MainActor
final class MessageSheetModelTests: XCTestCase {
    private let t0: UInt64 = 1_800_000_000
    private let utc = TimeZone(identifier: "UTC")!

    // MARK: Fixtures

    private func delivery(_ state: DeliveryState, deposited: UInt64? = nil, received: UInt64? = nil,
                          expired: UInt64? = nil, devices: UInt32 = 1, devicesReceived: UInt32 = 0,
                          left: UInt32 = 0, pending: UInt32 = 0) -> Delivery {
        Delivery(state: state, sealedAt: t0, depositedAt: deposited, receivedAt: received, expiredAt: expired,
                 devices: devices, devicesReceived: devicesReceived, devicesLeft: left, devicesPending: pending)
    }

    private func device(_ id: String, _ name: String, _ state: DeliveryState, deposited: UInt64? = nil,
                        received: UInt64? = nil, expired: UInt64? = nil) -> DeviceDelivery {
        DeviceDelivery(device: id, name: name, state: state, sealedAt: t0, depositedAt: deposited,
                       node: deposited == nil ? nil : "K7QX2M4A", receivedAt: received, expiredAt: expired)
    }

    private func sheet(_ d: Delivery, devices: [DeviceDelivery] = [], relays: [RelayHop] = [],
                       own: OwnCopies = OwnCopies(total: 0, left: 0, waiting: 0)) -> MessageDelivery {
        MessageDelivery(messageId: 7, delivery: d, devices: devices, relays: relays, ownCopies: own)
    }

    private func lang(_ code: String) throws -> (bundle: Bundle, locale: Locale) {
        let path = try XCTUnwrap(Bundle.main.path(forResource: code, ofType: "lproj"))
        return (try XCTUnwrap(Bundle(path: path)), Locale(identifier: code))
    }

    private func lines(_ md: MessageDelivery, size: UInt32? = 1024, now: UInt64? = nil,
                       _ code: String = "en") throws -> [MessageSheetModel.Line] {
        let l = try lang(code)
        return MessageSheetModel.lines(for: md, sealedSize: size, contactName: "Alice",
                                       bundle: l.bundle, locale: l.locale, timeZone: utc)
    }

    private func clock(_ at: UInt64, _ locale: Locale) -> String {
        var style = Date.FormatStyle(locale: locale, timeZone: utc).hour().minute()
        style.timeZone = utc
        return Date(timeIntervalSince1970: TimeInterval(at)).formatted(style)
    }

    private func make(_ d: FakeDevice, outgoing: Bool = true) -> MessageSheetModel {
        d.contactList = [Contact(fingerprint: "a", alias: nil, displayName: "Alice", verified: true)]
        d.messageList = ["a": [Message(id: 7, outgoing: outgoing, body: "On se voit au marché à 18 h", at: t0,
                                       delivery: outgoing ? .state(.pending) : nil)]]
        return MessageSheetModel(core: CoreService(device: d, runner: DirectRunner()), messageId: 7,
                                 contact: "a", contactName: "Alice")
    }

    // MARK: Timeline

    /// §6.4 point 3: one timeline per state, the §7.2 texts.
    func testStepsForEachState() throws {
        // Pending: sealed, then the deposit and the receipt ahead.
        let pending = try lines(sheet(delivery(.pending, pending: 1)))
        XCTAssertEqual(pending.map(\.title), ["Sealed and saved on this iPhone", "Deposited on a relay", "Received"])
        XCTAssertEqual(pending.map(\.phase), [.done, .ahead, .ahead])
        XCTAssertEqual(pending[0].detail, "1 device · 1 KB")
        XCTAssertNil(pending[0].glyph, "sealed is a neutral dot")
        XCTAssertNil(pending[1].at)

        // On the network: one line per distinct relay, in the order of the
        // first deposit, with what it could see (purple rule).
        let relays = [RelayHop(node: "K7QX2M4A", at: t0 + 34, size: 1024),
                      RelayHop(node: "B2C3D4E5", at: t0 + 40, size: 1024),
                      RelayHop(node: "K7QX2M4A", at: t0 + 50, size: 1024)]
        let onNetwork = try lines(sheet(delivery(.onNetwork, deposited: t0 + 34, devices: 2, left: 2),
                                        relays: relays))
        XCTAssertEqual(onNetwork.map(\.title), ["Sealed and saved on this iPhone", "Deposited on relay K7QX2M4A",
                                                "Deposited on relay B2C3D4E5", "Received on all their devices"])
        XCTAssertEqual(onNetwork.map(\.phase), [.done, .done, .done, .ahead])
        XCTAssertEqual(onNetwork[0].detail, "2 devices · 1 KB")
        XCTAssertEqual(onNetwork[1].glyph, .onNetwork)
        XCTAssertEqual(onNetwork[1].at, Date(timeIntervalSince1970: TimeInterval(t0 + 34)))
        XCTAssertEqual(onNetwork[1].spelled, "K7QX2M4A", "relay ids are spelled out")
        XCTAssertTrue(onNetwork[1].privacy)
        XCTAssertEqual(onNetwork[1].detail,
                       "Could see: a sealed packet of 1 KB for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever deposited it.")
        let fr = try lines(sheet(delivery(.onNetwork, deposited: t0 + 34, devices: 2, left: 2), relays: relays),
                           size: 1024, "fr")
        XCTAssertEqual(fr[1].title, "Déposé sur le relais K7QX2M4A")
        XCTAssertEqual(fr[1].detail,
                       "A pu voir\u{00A0}: un paquet scellé de 1 Ko pour une boîte aux lettres qui change chaque jour. Ni l’expéditeur, ni le texte. L’adresse IP de qui l’a déposé.")
        XCTAssertEqual(fr.last?.title, "Reçu sur tous ses appareils")

        // Received on 1 of 2: the first receipt, then "all" ahead.
        let some = try lines(sheet(delivery(.received, deposited: t0 + 34, received: t0 + 185, devices: 2,
                                            devicesReceived: 1, left: 2),
                                   devices: [device("aa", "iPhone", .received, deposited: t0 + 34, received: t0 + 185),
                                             device("bb", "iPad", .onNetwork, deposited: t0 + 34)],
                                   relays: [relays[0]]))
        XCTAssertEqual(some.map(\.title), ["Sealed and saved on this iPhone", "Deposited on relay K7QX2M4A",
                                           "Received on 1 of 2 devices", "Received on all their devices"])
        XCTAssertEqual(some.map(\.phase), [.done, .done, .done, .ahead])
        XCTAssertEqual(some[2].glyph, .received)
        XCTAssertEqual(some[2].at, Date(timeIntervalSince1970: TimeInterval(t0 + 185)))
        let someFr = try lines(sheet(delivery(.received, deposited: t0 + 34, received: t0 + 185, devices: 2,
                                              devicesReceived: 1, left: 2), relays: [relays[0]]), size: 1024, "fr")
        XCTAssertEqual(someFr[2].title, "Reçu sur 1 de ses 2 appareils")

        // Received on its only device.
        let one = try lines(sheet(delivery(.received, deposited: t0 + 34, received: t0 + 60, devicesReceived: 1,
                                           left: 1), relays: [relays[0]]))
        XCTAssertEqual(one.map(\.title).last, "Received")
        XCTAssertEqual(one.last?.phase, .done)

        // Not delivered, never deposited: stops on the triangle, nothing after.
        let expiry = t0 + 86_400
        let never = try lines(sheet(delivery(.notDelivered, expired: expiry)))
        XCTAssertEqual(never.map(\.phase), [.done, .stopped])
        XCTAssertEqual(never.last?.glyph, .notDelivered)
        XCTAssertEqual(never.last?.title, "Not delivered")
        let on = MessageSheetModel.dayAndTime(Date(timeIntervalSince1970: TimeInterval(expiry)),
                                              bundle: try lang("en").bundle, locale: Locale(identifier: "en"),
                                              timeZone: utc)
        XCTAssertEqual(on, "Jan 16 at \(clock(expiry, Locale(identifier: "en")))")
        XCTAssertEqual(never.last?.detail, "Expired on \(on) before a relay accepted it. It never left this iPhone.")
        let neverFr = try lines(sheet(delivery(.notDelivered, expired: expiry)), size: 1024, "fr")
        XCTAssertEqual(neverFr.last?.detail,
                       "Expiré le 16 janv. à \(clock(expiry, Locale(identifier: "fr"))) avant qu’un relais l’accepte. Il n’a jamais quitté cet iPhone.")

        // Not delivered after a deposit: the relay stays, then the stop.
        let lost = try lines(sheet(delivery(.notDelivered, deposited: t0 + 34, expired: expiry), relays: [relays[0]]))
        XCTAssertEqual(lost.map(\.title), ["Sealed and saved on this iPhone", "Deposited on relay K7QX2M4A", "Not delivered"])
        XCTAssertEqual(lost.map(\.phase), [.done, .done, .stopped])
        XCTAssertEqual(lost.last?.detail,
                       "None of Alice’s devices picked it up within 24 hours. The relay erased it on \(on).")
        let lostFr = try lines(sheet(delivery(.notDelivered, deposited: t0 + 34, expired: expiry), relays: [relays[0]]),
                               size: 1024, "fr")
        XCTAssertEqual(lostFr.last?.detail,
                       "Aucun appareil de Alice ne l’a relevé en 24\u{00A0}h. Le relais l’a effacé le 16 janv. à \(clock(expiry, Locale(identifier: "fr"))).")

        // Expired, verdict pending: still on the network, one line says so.
        let en = try lang("en")
        let d = delivery(.onNetwork, deposited: t0 + 34, left: 1)
        XCTAssertNil(MessageSheetModel.verdictPending(d, now: Date(timeIntervalSince1970: TimeInterval(t0 + 3600)),
                                                      bundle: en.bundle, locale: en.locale, timeZone: utc))
        XCTAssertEqual(MessageSheetModel.verdictPending(d, now: Date(timeIntervalSince1970: TimeInterval(expiry + 60)),
                                                        bundle: en.bundle, locale: en.locale, timeZone: utc),
                       "Expired at \(clock(expiry, en.locale)). Checking with the relays at the next sync.")
        XCTAssertNil(MessageSheetModel.verdictPending(delivery(.received, deposited: t0 + 34, received: t0 + 50),
                                                      now: Date(timeIntervalSince1970: TimeInterval(expiry + 60)),
                                                      bundle: en.bundle, locale: en.locale, timeZone: utc),
                     "only a message still on the network waits for a verdict")
    }

    /// §6.4: a receipt that came before the deposit was traced, or a
    /// migrated message: "Deposited on a relay", time "not recorded".
    func testDepositWithoutTimeSaysNotRecorded() throws {
        let l = try lines(sheet(delivery(.received, received: t0 + 60, devicesReceived: 1, left: 1)))
        XCTAssertEqual(l.map(\.title), ["Sealed and saved on this iPhone", "Deposited on a relay", "Received"])
        XCTAssertEqual(l[1].phase, .done, "done without a time reads \"not recorded\"")
        XCTAssertNil(l[1].at)
        XCTAssertNil(l[1].spelled)
        let fr = try lines(sheet(delivery(.received, received: t0 + 60, devicesReceived: 1, left: 1)), size: nil, "fr")
        XCTAssertEqual(fr[1].title, "Déposé sur un relais")
        XCTAssertEqual(fr[0].detail, "1 appareil", "no size known: the device count alone")
        let (bundle, locale) = try lang("fr")
        XCTAssertEqual(String(localized: "not recorded", bundle: bundle, locale: locale), "non notée")
    }

    // MARK: Delete confirmation

    /// §7.4 "Choix du cas", from the delivery the sheet shows.
    func testConfirmationCaseChoice() async throws {
        let d = FakeDevice()
        let m = make(d)
        d.messageDeliveries[7] = sheet(delivery(.pending, devices: 2, pending: 2))
        await m.load()
        XCTAssertEqual(m.confirmation, .pending)
        d.messageDeliveries[7] = sheet(delivery(.onNetwork, deposited: t0 + 1, devices: 2, left: 1, pending: 1))
        await m.load()
        XCTAssertEqual(m.confirmation, .mixed(left: 1, total: 2))
        let fr = try lang("fr")
        XCTAssertEqual(m.confirmationMessage(bundle: fr.bundle, locale: fr.locale),
                       "Il est déjà parti vers 1 de ses 2 appareils\u{00A0}: Alice le garde sur celui-ci. Le reste est annulé.")
        d.messageDeliveries[7] = sheet(delivery(.received, deposited: t0 + 1, received: t0 + 2, devices: 2,
                                                devicesReceived: 1, left: 2))
        await m.load()
        XCTAssertEqual(m.confirmation, .received)
        d.messageDeliveries[7] = sheet(delivery(.notDelivered, expired: t0 + 86_400))
        await m.load()
        XCTAssertEqual(m.confirmation, .notDelivered)
        XCTAssertTrue(m.canRetry)
        d.messageDeliveries[7] = nil
        await m.load()
        XCTAssertEqual(m.content, .sentElsewhere)
        XCTAssertEqual(m.confirmation, .sentElsewhere)

        let received = make(FakeDevice(), outgoing: false)
        await received.load()
        XCTAssertEqual(received.content, .received)
        XCTAssertEqual(received.confirmation, .receivedMessage)
        XCTAssertEqual(received.confirmation.title, "Delete this message from this iPhone?")
    }

    /// §5.1 and §7.4: "Your other devices keep their copy." only when
    /// devices are linked and the deletion keeps a copy for them.
    func testOwnCopiesSentenceOnlyWhenKept() async throws {
        let none = OwnCopies(total: 0, left: 0, waiting: 0)
        let waiting = OwnCopies(total: 1, left: 0, waiting: 1)
        let gone = OwnCopies(total: 1, left: 1, waiting: 0)
        let pending = delivery(.pending, pending: 1)
        let onNetwork = delivery(.onNetwork, deposited: t0 + 1, left: 1)
        XCTAssertFalse(DeleteConfirmation.keepsOwnCopies(delivery: onNetwork, ownCopies: none), "no linked device")
        XCTAssertFalse(DeleteConfirmation.keepsOwnCopies(delivery: pending, ownCopies: waiting),
                       "nobody receives it: the copy is cancelled too")
        XCTAssertTrue(DeleteConfirmation.keepsOwnCopies(delivery: pending, ownCopies: gone),
                      "a copy that left cannot be recalled")
        XCTAssertTrue(DeleteConfirmation.keepsOwnCopies(delivery: onNetwork, ownCopies: waiting))
        XCTAssertTrue(DeleteConfirmation.keepsOwnCopies(delivery: onNetwork, ownCopies: gone))

        let en = try lang("en")
        XCTAssertEqual(DeleteConfirmation.onNetwork.message(name: "Alice", keepsOwnCopies: true,
                                                            bundle: en.bundle, locale: en.locale),
                       "It’s already on the network: Alice will still receive it.\nYour other devices keep their copy.")
        XCTAssertEqual(DeleteConfirmation.onNetwork.message(name: "Alice", keepsOwnCopies: false,
                                                            bundle: en.bundle, locale: en.locale),
                       "It’s already on the network: Alice will still receive it.")
        XCTAssertEqual(DeleteConfirmation.sentElsewhere.message(name: "Alice", keepsOwnCopies: true,
                                                                bundle: en.bundle, locale: en.locale),
                       "Your other devices keep their copy.", "said once")

        // The sheet: copies line and the confirmation follow the same rule.
        let d = FakeDevice()
        let m = make(d)
        d.messageDeliveries[7] = sheet(pending, own: waiting)
        await m.load()
        XCTAssertFalse(m.keepsOwnCopies)
        XCTAssertEqual(m.ownCopies, "Copy for your other devices: pending.")
        d.messageDeliveries[7] = sheet(onNetwork, own: gone)
        d.routes[7] = [RouteStepInfo(at: t0 + 5, step: "deposited", node: "K7QX2M4A", size: nil, deviceName: nil, own: true)]
        await m.load()
        XCTAssertTrue(m.keepsOwnCopies)
        let left = Date(timeIntervalSince1970: TimeInterval(t0 + 5)).formatted(.dateTime.hour().minute())
        XCTAssertEqual(m.ownCopies, "Copy for your other devices: left at \(left).")
        d.messageDeliveries[7] = sheet(onNetwork, own: none)
        await m.load()
        XCTAssertNil(m.ownCopies, "absent without a linked device")
        XCTAssertFalse(m.keepsOwnCopies)

        // A received message: my linked devices got their own packet.
        let r = FakeDevice()
        let received = make(r, outgoing: false)
        r.devicesList = [MyDeviceInfo(id: "aa", name: "iPhone", issuedAt: 1, thisDevice: true, admin: true)]
        await received.load()
        XCTAssertFalse(received.keepsOwnCopies)
        r.devicesList.append(MyDeviceInfo(id: "bb", name: "iPad", issuedAt: 1, thisDevice: false, admin: false))
        await received.load()
        XCTAssertTrue(received.keepsOwnCopies)
        XCTAssertEqual(received.confirmationMessage(bundle: en.bundle, locale: en.locale),
                       "Alice keeps their copy.\nYour other devices keep their copy.")
    }

    // MARK: Devices

    /// §6.4 point 4: the card's names; two alike get the first 4
    /// characters of their id; a device off the card is "Removed device".
    func testDuplicateDeviceNamesGetIdPrefix() throws {
        let en = try lang("en")
        let rows = MessageSheetModel.deviceRows([
            device("a1b2c3d4", "Pixel", .received, deposited: t0 + 1, received: t0 + 60),
            device("e5f6a7b8", "Pixel", .onNetwork, deposited: t0 + 2),
            device("0a0b0c0d", "", .pending),
            device("1a1b1c1d", "iPad", .notDelivered, expired: t0 + 86_400),
        ], bundle: en.bundle, locale: en.locale, timeZone: utc)
        XCTAssertEqual(rows.map(\.name), ["Pixel · a1b2", "Pixel · e5f6", "Removed device", "iPad"])
        XCTAssertEqual(rows.map(\.status), ["received \(clock(t0 + 60, en.locale))",
                                            "on the network \(clock(t0 + 2, en.locale))", "pending", "not delivered"])
        XCTAssertEqual(rows.map(\.state), [.received, .onNetwork, .pending, .notDelivered])
        let fr = try lang("fr")
        let frRows = MessageSheetModel.deviceRows([device("0a0b0c0d", "", .pending)],
                                                  bundle: fr.bundle, locale: fr.locale, timeZone: utc)
        XCTAssertEqual(frRows.map(\.name), ["Appareil retiré"])
        XCTAssertEqual(frRows.map(\.status), ["en attente"])
        XCTAssertEqual(MessageSheetModel.devicesSentence(delivery(.received, devices: 2, devicesReceived: 1, left: 2),
                                                         bundle: fr.bundle, locale: fr.locale),
                       "Reçu sur 1 de ses 2 appareils.")
        XCTAssertNil(MessageSheetModel.devicesSentence(delivery(.onNetwork, devices: 2, left: 2),
                                                       bundle: fr.bundle, locale: fr.locale))
    }

    // MARK: Changes while open

    /// §9: the sheet follows its message, and closes when it is deleted
    /// elsewhere (a `.delivery` naming it removed, or the full reload).
    func testSheetClosesWhenTheMessageIsDeletedElsewhere() async {
        let d = FakeDevice()
        let m = make(d)
        d.messageDeliveries[7] = sheet(delivery(.pending, pending: 1))
        await m.load()
        XCTAssertEqual(m.confirmation, .pending)

        // A state change of this message refreshes the sheet.
        d.messageDeliveries[7] = sheet(delivery(.onNetwork, deposited: t0 + 1, left: 1),
                                       relays: [RelayHop(node: "K7QX2M4A", at: t0 + 1, size: 0)])
        d.deliveryUpdates[7] = DeliveryUpdate(messageId: 7, delivery: .state(.onNetwork), removed: false)
        await m.handle(.delivery(contact: "b", ids: [7]))
        XCTAssertEqual(m.confirmation, .pending, "another contact's change")
        await m.handle(.delivery(contact: "a", ids: [8]))
        XCTAssertEqual(m.confirmation, .pending, "another message")
        await m.handle(.delivery(contact: "a", ids: [6, 7]))
        XCTAssertEqual(m.confirmation, .onNetwork)
        XCTAssertEqual(m.lines.map(\.title).dropFirst().first, "Deposited on relay K7QX2M4A")

        // The full reload of the conversation refreshes it too.
        d.messageDeliveries[7] = sheet(delivery(.received, deposited: t0 + 1, received: t0 + 9, devicesReceived: 1, left: 1))
        await m.handle(.messages(contact: "a"))
        XCTAssertEqual(m.confirmation, .received)
        XCTAssertNil(m.exit)

        // Deleted elsewhere: a `.delivery` that names it removed closes it.
        d.deliveryUpdates[7] = nil
        await m.handle(.delivery(contact: "a", ids: [7]))
        XCTAssertEqual(m.exit, .removedElsewhere)

        // Or the reload no longer finds it.
        let d2 = FakeDevice()
        let m2 = make(d2)
        d2.messageDeliveries[7] = sheet(delivery(.pending, pending: 1))
        await m2.load()
        d2.messageList = ["a": []]
        await m2.handle(.messages(contact: "a"))
        XCTAssertEqual(m2.exit, .removedElsewhere)
    }

    // MARK: Actions

    /// §6.7: after a deletion from the sheet, the banner compares the
    /// state shown with the outcome; the sheet closes.
    func testDeleteFromTheSheetReportsTheBanner() async {
        let d = FakeDevice()
        let m = make(d)
        d.messageDeliveries[7] = sheet(delivery(.pending, devices: 2, pending: 2))
        await m.load()
        d.deleteResult = DeleteOutcome(deleted: 1, cancelled: 0, partlyCancelled: 1, alreadyLeft: 0,
                                       stillReceiving: ["Alice"], ownCopiesKept: false, changes: [])
        let shown = m.delivery
        // One device's packet left while the dialog was open: the pending
        // text shown is corrected, with the number read just before.
        d.deliveryUpdates[7] = DeliveryUpdate(
            messageId: 7, delivery: delivery(.onNetwork, deposited: t0 + 1, devices: 2, left: 1, pending: 1), removed: false)
        await m.delete(shown: shown)
        XCTAssertEqual(d.deleted, [[7]])
        XCTAssertEqual(m.exit, .deleted(.partlyLeft(name: "Alice", left: 1, total: 2)))

        // A shown Pending has no device left: never "0 of 2".
        XCTAssertEqual(DeleteBanner.message(shown: .pending, outcome: d.deleteResult, contactName: "Alice",
                                            devices: (left: 0, total: 2)),
                       .alreadyLeft(name: "Alice"))

        let d2 = FakeDevice()
        let m2 = make(d2)
        d2.messageDeliveries[7] = sheet(delivery(.onNetwork, deposited: t0 + 1, devices: 2, left: 1, pending: 1))
        await m2.load()
        XCTAssertEqual(m2.confirmation, .mixed(left: 1, total: 2))
        d2.deleteResult = DeleteOutcome(deleted: 1, cancelled: 1, partlyCancelled: 0, alreadyLeft: 0,
                                        stillReceiving: [], ownCopiesKept: false, changes: [])
        await m2.delete(shown: m2.delivery)
        XCTAssertEqual(m2.exit, .deleted(nil))

        let d3 = FakeDevice()
        let m3 = make(d3)
        d3.messageDeliveries[7] = sheet(delivery(.pending, devices: 2, pending: 2))
        await m3.load()
        d3.deleteResult = DeleteOutcome(deleted: 1, cancelled: 0, partlyCancelled: 0, alreadyLeft: 1,
                                        stillReceiving: ["Alice"], ownCopiesKept: false, changes: [])
        await m3.delete(shown: m3.delivery)
        XCTAssertEqual(m3.exit, .deleted(.alreadyLeft(name: "Alice")))

        let d4 = FakeDevice()
        let m4 = make(d4)
        d4.messageDeliveries[7] = sheet(delivery(.pending, devices: 2, pending: 2))
        await m4.load()
        d4.deliveryError = BarkingError.Storage(detail: "full")
        await m4.delete(shown: m4.delivery)
        XCTAssertNil(m4.exit, "nothing changed: the sheet stays")
        XCTAssertEqual(m4.notice, .deleteFailed)
    }

    /// §6.4: Retry on a not delivered message; no reachable device says so.
    func testRetry() async {
        let d = FakeDevice()
        let m = make(d)
        d.messageDeliveries[7] = sheet(delivery(.notDelivered, expired: t0 + 86_400))
        await m.load()
        XCTAssertTrue(m.canRetry)
        d.messageDeliveries[7] = sheet(delivery(.pending, pending: 1))
        d.deliveryUpdates[7] = DeliveryUpdate(messageId: 7, delivery: .state(.pending), removed: false)
        await m.retry()
        XCTAssertEqual(d.retried, [7])
        XCTAssertEqual(m.confirmation, .pending, "refreshed at once")
        XCTAssertFalse(m.canRetry)

        d.messageDeliveries[7] = sheet(delivery(.notDelivered, expired: t0 + 86_400))
        await m.load()
        d.retryError = BarkingError.NoSession
        await m.retry()
        XCTAssertEqual(m.notice, .noReachableDevice(name: "Alice"))
    }

    /// §6.4 "Erreur de lecture": a warning, the message unchanged.
    func testReadErrorSaysDetailsUnavailable() async throws {
        let d = FakeDevice()
        let m = make(d)
        d.deliveryError = BarkingError.Storage(detail: "x")
        await m.load()
        XCTAssertEqual(m.content, .unavailable)
        let fr = try lang("fr")
        XCTAssertEqual(String(localized: "Details unavailable. The message itself is unchanged.",
                              bundle: fr.bundle, locale: fr.locale),
                       "Détails indisponibles. Le message lui-même n’a pas changé.")
    }
}
