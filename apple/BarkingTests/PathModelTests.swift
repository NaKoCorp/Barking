import XCTest
@testable import Barking
@testable import BarkingKit

/// Path screen (spec block 2b §4.2): which rows a recorded route gives.
@MainActor
final class PathModelTests: XCTestCase {
    private let t0: UInt64 = 1_800_000_000

    private func step(_ name: String, at: UInt64, node: String? = nil, size: UInt32? = nil,
                      device: String? = nil, own: Bool = false) -> RouteStepInfo {
        RouteStepInfo(at: at, step: name, node: node, size: size, deviceName: device, own: own)
    }

    private func model(outgoing: Bool, route: [RouteStepInfo], hint: String? = "internet:1",
                       devices: [MyDeviceInfo] = []) -> (PathModel, FakeDevice) {
        let d = FakeDevice()
        d.devicesList = devices
        d.contactList = [Contact(fingerprint: "sam", alias: nil, displayName: "Sam", verified: true)]
        d.messageList = ["sam": [Message(id: 4, outgoing: outgoing, body: "Power's out", status: "delivered",
                                         at: t0, failed: false, route: hint)]]
        d.routes = [4: route]
        let core = CoreService(device: d, runner: DirectRunner())
        return (PathModel(core: core, messageId: 4, contact: "sam", contactName: "Sam"), d)
    }

    func testSentMessageRows() async {
        let (m, _) = model(outgoing: true, route: [
            step("sealed", at: t0, size: 2048),
            step("deposited", at: t0 + 1, node: "K7QX2M4A"),
            step("ack_verified", at: t0 + 60),
        ])
        await m.load()
        XCTAssertFalse(m.notRecorded)
        XCTAssertEqual(m.rows.map(\.title), ["This device", "Internet relay · K7QX2M4A", "Sam's phone"])
        XCTAssertEqual(m.rows.map(\.glyph), [.sender, .relay, .recipient])
        XCTAssertTrue(m.rows[0].saw.contains("everything"))
        XCTAssertTrue(m.rows[0].saw.contains("sender"))
        XCTAssertTrue(m.rows[1].saw.contains("2 KB"), m.rows[1].saw)
        XCTAssertTrue(m.rows[1].saw.contains("daily") || m.rows[1].saw.contains("every day"), m.rows[1].saw)
        XCTAssertTrue(m.rows[1].saw.contains("whoever deposited it"))
        XCTAssertTrue(m.rows[2].saw.contains("everything"))
        XCTAssertTrue(m.rows[2].saw.contains("recipient"))
        XCTAssertTrue(m.rows[2].subtitle.contains("receipt received"), m.rows[2].subtitle)
        // The badge dates the receipt my device verified, not a delivery.
        XCTAssertTrue(m.times.contains("receipt "), m.times)
        XCTAssertFalse(m.times.contains("received"), m.times)
        XCTAssertEqual(m.quote, "Power's out")
        XCTAssertEqual(m.routeBadge, "Internet · 1 relay")
    }

    func testSentMessageWithOwnCopyRows() async {
        let (m, _) = model(outgoing: true, route: [
            step("sealed", at: t0, size: 2048),
            step("own_copy", at: t0, device: "iPad", own: true),
            step("deposited", at: t0 + 1, node: "K7QX2M4A"),
            step("deposited", at: t0 + 1, node: "M3NB8PQ2"),
        ], hint: "internet:2")
        await m.load()
        XCTAssertEqual(m.rows.map(\.title), ["This device", "Internet relay · K7QX2M4A",
                                             "Internet relay · M3NB8PQ2", "Your other devices · iPad"])
        XCTAssertEqual(m.rows.last?.glyph, .ownDevices)
        XCTAssertTrue(m.rows.last?.saw.contains("your own devices") ?? false)
        XCTAssertEqual(m.routeBadge, "Internet · 2 relays")
    }

    func testReceivedMessageRows() async {
        let (m, _) = model(outgoing: false, route: [
            step("fetched", at: t0 + 1, node: "AB12CD34"),
            step("opened", at: t0 + 1),
        ])
        await m.load()
        XCTAssertEqual(m.rows.map(\.title), ["Sam's phone", "Internet relay · AB12CD34", "This device"])
        XCTAssertTrue(m.rows[0].saw.contains("sender"))
        XCTAssertTrue(m.rows[1].saw.contains("whoever fetched it"), m.rows[1].saw)
        XCTAssertTrue(m.rows[2].saw.contains("recipient"))
        // The app does not know when the receipt leaves.
        XCTAssertTrue(m.rows[2].subtitle.contains("receipt queued"), m.rows[2].subtitle)
    }

    func testCopyDepositsToMyDevicesAreNotRelaysToTheContact() async {
        let (m, _) = model(outgoing: true, route: [
            step("sealed", at: t0, size: 2048),
            step("own_copy", at: t0, device: "iPad", own: true),
            step("deposited", at: t0 + 1, node: "K7QX2M4A"),
            step("deposited", at: t0 + 1, node: "M3NB8PQ2", own: true),
        ])
        await m.load()
        XCTAssertEqual(m.rows.map(\.title), ["This device", "Internet relay · K7QX2M4A", "Your other devices · iPad"])
    }

    func testSyncCopyOfAMessageISentFromAnotherDevice() async {
        let (m, _) = model(outgoing: true, route: [
            step("fetched", at: t0 + 1, node: "AB12CD34"),
            step("opened", at: t0 + 1),
        ])
        await m.load()
        XCTAssertEqual(m.rows.map(\.title), ["Your other device", "Internet relay · AB12CD34", "This device"])
        XCTAssertEqual(m.rows.map(\.glyph), [.sender, .relay, .ownDevices])
        XCTAssertTrue(m.rows[1].saw.contains("whoever fetched it"))
        XCTAssertTrue(m.times.contains("synced"), m.times)
    }

    func testThisDeviceIsCalledByItsName() async {
        let me = MyDeviceInfo(id: "aa", name: "Alice's iPad", issuedAt: 1, thisDevice: true, admin: true)
        let other = MyDeviceInfo(id: "bb", name: "phone", issuedAt: 1, thisDevice: false, admin: false)
        let (m, _) = model(outgoing: false, route: [
            step("fetched", at: t0 + 1, node: "AB12CD34"),
            step("opened", at: t0 + 1),
        ], devices: [other, me])
        await m.load()
        XCTAssertEqual(m.rows.last?.title, "Alice's iPad")
    }

    func testNoStepsShowsNotRecorded() async {
        let (m, _) = model(outgoing: true, route: [], hint: nil)
        await m.load()
        XCTAssertTrue(m.notRecorded)
        XCTAssertTrue(m.rows.isEmpty)
        XCTAssertNil(m.routeBadge)
    }

    func testRouteBadgeText() {
        XCTAssertEqual(RouteBadge.text(for: "internet:1"), "Internet · 1 relay")
        XCTAssertEqual(RouteBadge.text(for: "internet:3"), "Internet · 3 relays")
        XCTAssertNil(RouteBadge.text(for: nil))
        XCTAssertNil(RouteBadge.text(for: "lora:2"))
    }

    func testRoutesReachTheChatsAndConversation() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "sam", alias: nil, displayName: "Sam", verified: false)]
        d.messageList = ["sam": [Message(id: 4, outgoing: false, body: "hi", status: "delivered",
                                         at: t0, failed: false, route: "internet:2")]]
        let core = CoreService(device: d, runner: DirectRunner())
        let chats = ChatsModel(core: core)
        await chats.reload()
        XCTAssertEqual(chats.rows.first?.route, "internet:2")
        let conv = ConversationModel(contact: "sam", core: core)
        await conv.reload()
        XCTAssertEqual(conv.items.first?.route, "internet:2")
        XCTAssertEqual(conv.lastMessageId, 4)
    }
}
