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
            "a": [Message(id: 1, outgoing: false, body: "old", status: "delivered", at: 100, failed: false)],
            "b": [Message(id: 2, outgoing: true, body: "new", status: "sent", at: 200, failed: false)],
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
}
