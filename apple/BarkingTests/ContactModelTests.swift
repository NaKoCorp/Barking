import XCTest
@testable import Barking
@testable import BarkingKit

@MainActor
final class ContactModelTests: XCTestCase {
    func make(_ d: FakeDevice) -> ContactModel {
        d.contactList = [Contact(fingerprint: "zab2-2ccf-kzfa-fsms-5gfi", alias: nil, displayName: "Maya", verified: false)]
        return ContactModel(contact: "zab2-2ccf-kzfa-fsms-5gfi", core: CoreService(device: d, runner: DirectRunner()))
    }

    func testMatchThenUndo() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        await m.match()
        XCTAssertTrue(d.verified.contains(m.contact))
        XCTAssertTrue(m.justVerified)
        await m.undo()
        XCTAssertFalse(d.verified.contains(m.contact))
        XCTAssertFalse(m.justVerified)
    }

    func testMismatchDoesNotVerify() async {
        let d = FakeDevice()
        let m = make(d)
        await m.load()
        m.mismatch()
        XCTAssertTrue(d.verified.isEmpty)
        XCTAssertTrue(m.mismatched)
    }

    func testGroupsAndShortFingerprint() async {
        let m = make(FakeDevice())
        await m.load()
        XCTAssertEqual(m.groups.count, 12)
        // The shared format: a no-break space keeps `·` off the start of a line.
        XCTAssertEqual(m.fingerprintShort, "zab2 2ccf\u{00A0}· kzfa fsms")
        XCTAssertEqual(m.name, "Maya")
    }
}
