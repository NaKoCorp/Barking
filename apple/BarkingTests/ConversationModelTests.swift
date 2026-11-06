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

    func testRetryResendsAndHidesFailed() async {
        let d = FakeDevice()
        d.messageList = ["b": [Message(id: 7, outgoing: true, body: "lost", status: "failed", at: 1, failed: true)]]
        let m = make(d)
        await m.onAppear()
        XCTAssertEqual(m.items.map(\.id), [7])
        await m.retry(7)
        XCTAssertEqual(d.sent.map(\.1), ["lost"])
        XCTAssertFalse(m.items.contains { $0.id == 7 })
    }

    func testOpeningMarksRead() async {
        let d = FakeDevice()
        d.messageList = ["b": [
            Message(id: 3, outgoing: false, body: "a", status: "delivered", at: 1, failed: false),
            Message(id: 5, outgoing: false, body: "b", status: "delivered", at: 2, failed: false),
            Message(id: 6, outgoing: true, body: "c", status: "sent", at: 3, failed: false),
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
