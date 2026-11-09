import CoreImage
import XCTest
@testable import Barking
@testable import BarkingKit

/// A real identity in a temporary directory (for real card bytes).
func tempDevice(_ name: String = "Alice") throws -> Device {
    let created = try createDevice(config: TestDevice.config(), deviceName: "\(name)-phone")
    try created.device.setDisplayName(name: name)
    return created.device
}

final class QRPayloadTests: XCTestCase {
    private func roundTrip(_ data: Data) -> Data? {
        let image = QRPayload.ciImage(for: data)
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])!
        let feature = detector.features(in: image).first as? CIQRCodeFeature
        return feature?.symbolDescriptor.flatMap(QRPayload.bytes(from:))
    }

    func testRoundTripCardBytes() throws {
        let card = try tempDevice().contactCardBytes()
        XCTAssertGreaterThan(card.count, 1500)
        XCTAssertEqual(roundTrip(card), card)
    }

    /// A card link (another Barking or the CLI's `card`) is about 2,400
    /// characters: its QR is read back whole.
    @MainActor
    func testRoundTripCardLink() async throws {
        // Whether the generator splits a link depends on the card: several.
        let m = AddContactModel(core: CoreService(device: try tempDevice(), runner: DirectRunner()))
        for _ in 0..<5 {
            let link = "barking://card#" + (try tempDevice("Bob").contactCard(displayName: "Bob"))
            let read = try XCTUnwrap(roundTrip(Data(link.utf8)), "the symbol was not read as bytes")
            XCTAssertEqual(read, Data(link.utf8))
            await m.scanned(read)
            XCTAssertEqual(m.preview?.displayName, "Bob")
        }
    }

    /// The generator splits some payloads into segments of other modes (a
    /// run of digits, of capitals): every segment is read, up to the
    /// terminator.
    func testEverySegmentIsRead() throws {
        var bits = ""
        func put(_ v: Int, _ n: Int) {
            let b = String(v, radix: 2)
            bits += String(repeating: "0", count: n - b.count) + b
        }
        put(0b0100, 4); put(2, 8); put(0x61, 8); put(0x62, 8)    // byte "ab"
        put(0b0010, 4); put(3, 9); put(12 * 45 + 13, 11); put(36, 6) // alphanumeric "CD "
        put(0b0001, 4); put(4, 10); put(123, 10); put(4, 4)      // numeric "1234"
        put(0b0111, 4); put(26, 8)                               // ECI 26 (UTF-8)
        put(0b0100, 4); put(1, 8); put(0x7A, 8)                  // byte "z"
        put(0, 4)
        while bits.count % 8 != 0 { bits += "0" }
        var payload = Data()
        var i = bits.startIndex
        while i < bits.endIndex {
            let next = bits.index(i, offsetBy: 8)
            payload.append(UInt8(bits[i..<next], radix: 2)!)
            i = next
        }
        payload.append(contentsOf: [0xEC, 0x11])
        let d = try XCTUnwrap(CIQRCodeDescriptor(payload: payload, symbolVersion: 2, maskPattern: 0, errorCorrectionLevel: .levelL))
        XCTAssertEqual(QRPayload.bytes(from: d), Data("abCD 1234z".utf8))
    }

    func testForeignAndTruncatedPayloadsAreRejected() throws {
        let url = Data("https://example.org".utf8)
        XCTAssertThrowsError(try inspectCard(bytes: roundTrip(url) ?? url))
        let cut = try tempDevice().contactCardBytes().prefix(100)
        XCTAssertThrowsError(try inspectCard(bytes: Data(cut)))
    }
}

@MainActor
final class AddContactModelTests: XCTestCase {
    func testForeignLinkShowsNotACard() async throws {
        let m = AddContactModel(core: CoreService(device: try tempDevice(), runner: DirectRunner()))
        await m.opened(link: "barking1:garbage")
        XCTAssertEqual(m.error, .notACard)
        XCTAssertNil(m.preview)
    }

    func testOwnCardShowsOwnCard() async throws {
        let me = try tempDevice()
        let m = AddContactModel(core: CoreService(device: me, runner: DirectRunner()))
        await m.scanned(try me.contactCardBytes())
        XCTAssertEqual(m.error, .ownCard)
    }

    func testAddTwiceAddsOnce() async throws {
        let me = try tempDevice()
        let bob = try tempDevice("Bob")
        let m = AddContactModel(core: CoreService(device: me, runner: DirectRunner()))
        await m.scanned(try bob.contactCardBytes())
        XCTAssertEqual(m.preview?.displayName, "Bob")
        async let a: Bool = m.add(alias: "bob")
        async let b: Bool = m.add(alias: "bob")
        let results = await [a, b]
        XCTAssertEqual(results.filter { $0 }.count, 1)
        XCTAssertEqual(try me.contacts().count, 1)
        // The sheet goes on to this contact's safety code.
        XCTAssertEqual(m.added, try me.contacts().first?.fingerprint)
        XCTAssertNotNil(m.added)
    }
}

@MainActor
final class ChatsModelTests: XCTestCase {
    func contact(_ fp: String, _ name: String, alias: String? = nil) -> Contact {
        Contact(fingerprint: fp, alias: alias, displayName: name, verified: false)
    }

    func testRowsSortedByLastMessageAndFiltered() async {
        let d = FakeDevice()
        d.contactList = [contact("a", "Léa"), contact("b", "Sam", alias: "sammy")]
        d.messageList = [
            "a": [Message(id: 1, outgoing: false, body: "old", at: 100)],
            "b": [Message(id: 2, outgoing: true, body: "new", at: 200, delivery: .state(.onNetwork))],
        ]
        let m = ChatsModel(core: CoreService(device: d, runner: DirectRunner()))
        await m.reload()
        XCTAssertEqual(m.visibleRows.map(\.contact), ["b", "a"])
        m.query = "lea"
        XCTAssertEqual(m.visibleRows.map(\.contact), ["a"])
        m.query = "SAMMY"
        XCTAssertEqual(m.visibleRows.map(\.contact), ["b"])
    }

    func testOfflineBannerFollowsLastSync() async {
        let d = FakeDevice()
        d.summary = SyncSummary(itemsReceived: 0, sent: 0, newMessages: [], networkUp: false, error: nil)
        let core = CoreService(device: d, runner: DirectRunner())
        let m = ChatsModel(core: core)
        _ = await core.sync(reason: .pull)
        await m.reload()
        XCTAssertTrue(m.offline)
    }

    /// UI review U-20/U-22: the second line is the last message, else the
    /// contact's trust, as a glyph and a word.
    func testRowSecondLine() {
        let row = { (text: String?, verified: Bool) in
            ChatRow(contact: "a", name: "Sam", verified: verified, lastText: text, lastAt: nil,
                    lastStatus: nil, unread: 0)
        }
        XCTAssertEqual(row(nil, false).line, .trust(.notVerified))
        XCTAssertEqual(row("", true).line, .trust(.verified))
        XCTAssertEqual(row("hello", false).line, .preview("hello"))
        XCTAssertEqual(Trust.verified.glyph, "✓")
        XCTAssertEqual(Trust.verified.token, "ok")
        XCTAssertEqual(Trust.notVerified.glyph, "○")
        XCTAssertEqual(Trust.notVerified.token, "fgMuted")
        XCTAssertEqual(Trust(verified: true), .verified)
    }

    /// B4 carry: the conversation title stays inside the bar at AX sizes.
    func testChatTitleIsCappedForTheBar() {
        let ax5 = UITraitCollection(preferredContentSizeCategory: .accessibilityExtraExtraExtraLarge)
        XCTAssertEqual(BarkingFont.scaledSize(16, relativeTo: .headline, maximum: ChatTitle.nameMaximum, traits: ax5), 20)
        XCTAssertEqual(BarkingFont.scaledSize(12, relativeTo: .caption, maximum: ChatTitle.lineMaximum, traits: ax5), 14)
        XCTAssertLessThanOrEqual(ChatTitle.nameMaximum + ChatTitle.lineMaximum * 1.3, 44)
    }
}
