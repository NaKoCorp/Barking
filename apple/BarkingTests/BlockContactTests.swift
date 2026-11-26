import XCTest
@testable import Barking
@testable import BarkingKit

@MainActor
final class BlockContactTests: XCTestCase {
    private let fp = "zab2-2ccf-kzfa-fsms-5gfi"

    private func device() -> FakeDevice {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: fp, alias: nil, displayName: "Maya", verified: false)]
        return d
    }

    private func core(_ d: FakeDevice) -> CoreService { CoreService(device: d, runner: DirectRunner()) }

    func testBlockMovesTheContactToTheBlockedList() async {
        let d = device()
        let m = ContactModel(contact: fp, core: core(d))
        let ok = await m.block()
        XCTAssertTrue(ok)
        XCTAssertTrue(d.contactList.isEmpty)
        XCTAssertEqual(d.blockedList.map(\.fingerprint), [fp])
    }

    func testFailedBlockIsReported() async {
        let d = device()
        d.blockError = NSError(domain: "test", code: 1)
        let ok = await ContactModel(contact: fp, core: core(d)).block()
        XCTAssertFalse(ok)
        XCTAssertEqual(d.contactList.count, 1)
    }

    func testUnblockFromTheList() async {
        let d = device()
        try? d.blockContact(contact: fp)
        let m = BlockedContactsModel(core: core(d))
        await m.load()
        XCTAssertEqual(m.contacts.map { m.name($0) }, ["Maya"])
        await m.unblock(m.contacts[0])
        XCTAssertTrue(m.contacts.isEmpty)
        XCTAssertFalse(m.failed)
        XCTAssertEqual(d.contactList.map(\.fingerprint), [fp])
    }

    /// A blocked requester is no contact: listed by its fingerprint (the
    /// first 8 characters for a name), and unblocked from there.
    func testBlockedRequesterListedByFingerprint() async {
        let d = FakeDevice()
        let requester = "a11c-e2kf-9qzd-p0mm-7tts"
        d.blockedFingerprintList = [requester]
        let m = BlockedContactsModel(core: core(d))
        await m.load()
        XCTAssertTrue(m.contacts.isEmpty)
        XCTAssertEqual(m.strangers, [requester])
        XCTAssertEqual(m.name(stranger: requester), "a11c-e2k")
        XCTAssertFalse(m.isEmpty)
        await m.unblock(fingerprint: requester)
        XCTAssertFalse(m.failed)
        XCTAssertTrue(m.strangers.isEmpty)
        XCTAssertTrue(m.isEmpty, "nothing blocked left: the empty line shows")
        XCTAssertTrue(d.blockedFingerprintList.isEmpty)
    }

    func testFailedUnblockIsReported() async {
        let d = device()
        try? d.blockContact(contact: fp)
        d.blockError = NSError(domain: "test", code: 1)
        let m = BlockedContactsModel(core: core(d))
        await m.load()
        await m.unblock(m.contacts[0])
        XCTAssertTrue(m.failed)
        XCTAssertEqual(m.contacts.count, 1)
    }
}
