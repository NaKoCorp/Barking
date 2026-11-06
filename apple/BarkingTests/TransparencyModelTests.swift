import XCTest
@testable import Barking
@testable import BarkingKit

/// Transparency view (spec block 2b §5): the journal by day, its filter and
/// pages, and where the data is.
@MainActor
final class TransparencyModelTests: XCTestCase {
    private var utc: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }

    /// 2027-01-15 12:00 UTC.
    private let noon: UInt64 = 1_800_000_000 - 1_800_000_000 % 86_400 + 12 * 3_600

    private func entry(_ at: UInt64, security: Bool = false, key: String = "log.node_fetch",
                       args: [String] = ["K7QX2M4A", "3", "1"]) -> LogEntry {
        LogEntry(at: at, family: security ? "security" : "node", key: key, args: args, security: security)
    }

    private func model(_ d: FakeDevice, protection: String = "secure-enclave") -> TransparencyModel {
        TransparencyModel(core: CoreService(device: d, runner: DirectRunner()),
                          protection: { protection }, calendar: utc)
    }

    func testGroupsByDayNewestFirst() async {
        let d = FakeDevice()
        // Newest first, as the core gives them: two today, one yesterday, one three days ago.
        d.logEntries = [entry(noon + 600), entry(noon), entry(noon - 86_400), entry(noon - 3 * 86_400)]
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.days.count, 3)
        XCTAssertEqual(m.days.map { $0.rows.count }, [2, 1, 1])
        let dates = m.days.map(\.date)
        XCTAssertEqual(dates, dates.sorted(by: >))
        XCTAssertEqual(m.days[0].rows.map(\.at), [noon + 600, noon].map { Date(timeIntervalSince1970: TimeInterval($0)) })
        XCTAssertEqual(utc.startOfDay(for: m.days[0].rows[0].at), m.days[0].date)
    }

    func testSecurityFilter() async {
        let d = FakeDevice()
        d.logEntries = [entry(noon + 3), entry(noon + 2, security: true, key: "log.contact_key_changed",
                                                args: ["Bob", "a", "b"]),
                        entry(noon + 1), entry(noon, security: true, key: "log.session_established",
                                               args: ["Bob", "02020202", "@initiator", "@post_quantum"])]
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 4)
        await m.setSecurityOnly(true)
        let rows = m.days.flatMap(\.rows)
        XCTAssertEqual(rows.count, 2)
        XCTAssertTrue(rows.allSatisfy(\.security))
        await m.setSecurityOnly(false)
        XCTAssertEqual(m.days.flatMap(\.rows).count, 4)
    }

    func testPagesOfOneHundred() async {
        let d = FakeDevice()
        d.logEntries = (0..<250).map { entry(noon + UInt64(250 - $0)) }
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 100)
        XCTAssertTrue(m.canLoadMore)
        await m.loadMore()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 200)
        await m.loadMore()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 250)
        XCTAssertFalse(m.canLoadMore)
        // No row twice.
        let ids = m.days.flatMap(\.rows).map(\.id)
        XCTAssertEqual(Set(ids).count, 250)
    }

    func testDataLocationReflectsProtection() async {
        let enclave = model(FakeDevice(), protection: "secure-enclave")
        await enclave.load()
        XCTAssertTrue(enclave.dataRows.contains { $0.title == "Database key protected by the Secure Enclave" })
        let keychain = model(FakeDevice(), protection: "keychain")
        await keychain.load()
        XCTAssertTrue(keychain.dataRows.contains { $0.title == "Database key protected by the keychain only" })
        XCTAssertEqual(keychain.dataRows.count, 4)
    }

    func testRowTextComesFromKeyAndArgs() async {
        let d = FakeDevice()
        d.logEntries = [entry(noon, key: "log.node_fetch", args: ["K7QX2M4A", "3", "1"])]
        let m = model(d)
        await m.load()
        let text = m.days[0].rows[0].text
        XCTAssertTrue(text.contains("K7QX2M4A"), text)
        XCTAssertFalse(text.hasPrefix("log."), text)
    }

    func testEveryCoreKeyRenders() {
        for key in logKeys() {
            let text = LogText.render(LogEntry(at: 0, family: "node", key: key, args: ["a", "b", "c", "d"],
                                               security: false))
            XCTAssertFalse(text.isEmpty, key)
            XCTAssertNotEqual(text, key)
            XCTAssertFalse(text.contains("%"), "\(key): \(text)")
        }
    }

    func testContactDevicesLoad() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "zab2", alias: nil, displayName: "Maya", verified: false)]
        d.contactDeviceList = ["zab2": [MyDeviceInfo(id: "aa", name: "Maya's iPhone", issuedAt: noon,
                                                     thisDevice: false, admin: false)]]
        let m = ContactModel(contact: "zab2", core: CoreService(device: d, runner: DirectRunner()))
        await m.load()
        XCTAssertEqual(m.devices.map(\.name), ["Maya's iPhone"])
    }
}
