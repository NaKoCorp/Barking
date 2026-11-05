import XCTest
@testable import Barking
@testable import BarkingKit

@MainActor
final class MinorFixTests: XCTestCase {
    // A failed message stays hidden once a later copy of it was sent.
    func testRetriedFailedMessageStaysHiddenAfterReopen() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "b", alias: nil, displayName: "Bob", verified: false)]
        d.messageList = ["b": [
            Message(id: 1, outgoing: true, body: "hello", status: "failed", at: 1, failed: true),
            Message(id: 2, outgoing: true, body: "hello", status: "sent", at: 2, failed: false),
        ]]
        let m = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        await m.onAppear()
        XCTAssertEqual(m.items.map(\.id), [2])
    }

    // A QR code holding a card link (byte mode) is read as a link.
    func testByteQRHoldingALinkIsRead() async throws {
        let me = try tempDevice()
        let bob = try tempDevice("Bob")
        let link = "barking://card#" + (try bob.contactCard(displayName: "Bob"))
        let m = AddContactModel(core: CoreService(device: me, runner: DirectRunner()))
        await m.scanned(Data(link.utf8))
        XCTAssertEqual(m.preview?.displayName, "Bob")
        await m.scannedText("barking://card#" + (try bob.contactCard(displayName: "Bob")))
        XCTAssertEqual(m.preview?.displayName, "Bob")
        await m.scannedText("WIFI:S:home;;")
        XCTAssertEqual(m.error, .notACard)
    }

    // Model errors are keys, rendered in the current language at display time.
    func testModelErrorsAreKeysNotTranslatedText() {
        XCTAssertEqual(LinkModel.text(for: .expired), "This offer has expired. Start again.")
        let n = NetworkModel(core: CoreService(device: FakeDevice(), runner: DirectRunner()))
        Task { _ = await n.addRelay(id: "x", addr: "y") }
    }

    func testChatsUseOneSummaryCall() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "a", alias: nil, displayName: "Léa", verified: true)]
        d.messageList = ["a": [Message(id: 4, outgoing: false, body: "hi", status: "delivered", at: 9, failed: false)]]
        d.unread = [UnreadCount(contact: "a", count: 1)]
        let m = ChatsModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.reload()
        XCTAssertEqual(d.summaryCalls, 1)
        XCTAssertEqual(m.rows.first?.unread, 1)
        XCTAssertEqual(m.rows.first?.lastText, "hi")
    }
}

final class DayLabelTests: XCTestCase {
    func testTodayAndYesterdayAreNamed() {
        let cal = Calendar.current
        let now = Date()
        XCTAssertEqual(DayLabel.text(for: now, now: now), String(localized: "Today"))
        XCTAssertEqual(DayLabel.text(for: cal.date(byAdding: .day, value: -1, to: now)!, now: now),
                       String(localized: "Yesterday"))
        let old = cal.date(byAdding: .day, value: -10, to: now)!
        XCTAssertEqual(DayLabel.text(for: old, now: now), old.formatted(.dateTime.weekday(.wide).day().month()))
    }
}
